/* psprecomp — the GE's rendering pipeline: state, vertices, rasterization.
 *
 * ge.c walks display lists; every state command it meets is forwarded here and
 * stored as-is in a 256-entry register file -- which is what the hardware is:
 * a command's 24-bit argument *is* the register. Derived values (addresses,
 * formats, matrices) are computed from that file at draw time, so a game that
 * sets state in any order, or relies on a value set many lists ago, gets what
 * the hardware would give it.
 *
 * ## What is implemented
 *
 *  - Every vertex format: position/normal/texture/colour in 8/16/float, colour
 *    5650/5551/4444/8888, index buffers (8/16-bit), morph targets (weights
 *    applied).
 *  - Per-vertex stages (ge_vertex.c): skinning with up to 8 bone matrices,
 *    lighting (4 lights, directional/point/spot, ambient/diffuse/specular,
 *    material update), and generated texture coordinates (texture matrix
 *    projection and shade mapping).
 *  - Through mode (screen-space vertices) and transformed geometry: world,
 *    view and projection matrices, viewport scale/centre, the screen offset,
 *    clipping against the near side of the camera (w > 0), back-face culling.
 *  - Points, lines, line strips, triangles, strips, fans and sprites.
 *  - Texturing: 5650/5551/4444/8888, CLUT4/8/16/32 with the CLUT mode's shift,
 *    mask and start, DXT1/3/5 in the PSP's block layout, swizzled storage,
 *    repeat/clamp, nearest and bilinear filtering, level 0 of the mip chain;
 *    UV scale/offset in transformed mode.
 *  - Texture functions modulate/decal/blend/replace/add, RGB vs RGBA, colour
 *    doubling; flat and Gouraud shading; material colour for colourless
 *    vertices.
 *  - Clear mode, scissor, alpha test, depth test with the 16-bit depth buffer
 *    and depth write mask, blending (all factors, all equations, fixed
 *    colours), colour and alpha write masks; framebuffers in all four formats.
 *  - Block transfers (TRXKICK), which is how sceGuCopyImage uploads data.
 *
 * ## What is not, and is counted instead
 *
 * Fog, stencil test, colour test, logic ops, dithering, curved
 * surfaces (Bezier/spline patches) and mip levels above 0. When a draw enables
 * one of these it still draws (without that stage), and the feature is counted
 * in psp_gpu_dump_stats() so a wrong-looking frame can be attributed.
 */

#include "psprecomp/hle.h"
#include "psprecomp/render.h"
#include "psprecomp/ge_vertex.h"

#include <math.h>
#include <emmintrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- the register file ------------------------------------------------------ */

static uint32_t R[256];                  /* last argument written per command */
static float    g_world[12], g_view[12], g_proj[16], g_tgen[12];
static float    g_bone[8 * 12];
static uint32_t g_world_i, g_view_i, g_proj_i, g_tgen_i, g_bone_i;
static uint8_t  g_clut[1024];            /* the CLUT cache, filled by CLOAD */
static uint64_t g_clut_hash;             /* FNV-1a of g_clut, updated by CLOAD */
static uint64_t g_pixels;
/* Profiling counters (rasterizer workload). */
static uint64_t c_tested, c_shaded, c_textured, c_linear, c_sprite_px, c_tri_px, c_blend, c_clear;

static uint64_t g_unsup_light, g_unsup_fog, g_unsup_stencil, g_unsup_ctest,
                g_unsup_logic, g_unsup_patch, g_clipped, g_culled, g_prims, g_texdraws;

/* A GE float argument is the top 24 bits of an IEEE single. */
static float ge_float(uint32_t arg) {
    uint32_t b = arg << 8;
    float f;
    memcpy(&f, &b, 4);
    return f;
}

void psp_gpu_reset(void) {
    memset(R, 0, sizeof R);
    memset(g_world, 0, sizeof g_world);
    memset(g_view, 0, sizeof g_view);
    memset(g_proj, 0, sizeof g_proj);
    memset(g_tgen, 0, sizeof g_tgen);
    memset(g_bone, 0, sizeof g_bone);
    g_world_i = g_view_i = g_proj_i = g_tgen_i = g_bone_i = 0;
    memset(g_clut, 0, sizeof g_clut);
    g_clut_hash = 0;
    /* Defaults where a zero register would be unusable rather than merely
     * unset: 8888 framebuffer, identity matrices, a full-screen scissor and
     * always-passing tests. Every game sets these explicitly. */
    R[0xD2] = 3;
    g_world[0] = g_world[4] = g_world[8] = 1.0f;
    g_view[0] = g_view[4] = g_view[8] = 1.0f;
    g_proj[0] = g_proj[5] = g_proj[10] = g_proj[15] = 1.0f;
    R[0xD4] = 0;
    R[0xD5] = 479 | (271u << 10);
    R[0xDB] = 1;                         /* alpha test: always */
    R[0xDE] = 1;                         /* depth test: always */
    g_unsup_light = g_unsup_fog = g_unsup_stencil = g_unsup_ctest = 0;
    g_unsup_logic = g_unsup_patch = g_clipped = g_culled = g_prims = g_texdraws = 0;
    g_pixels = 0;
}

/* ---- memory access ----------------------------------------------------------- */

static uint8_t *mem(uint32_t addr, uint32_t len) { return (uint8_t *)psp_mem_ptr(addr, len); }

static uint32_t rd32(uint32_t a) { uint8_t *p = mem(a, 4); uint32_t v = 0; if (p) memcpy(&v, p, 4); return v; }
static uint16_t rd16(uint32_t a) { uint8_t *p = mem(a, 2); uint16_t v = 0; if (p) memcpy(&v, p, 2); return v; }
static uint8_t  rd8 (uint32_t a) { uint8_t *p = mem(a, 1); return p ? *p : 0; }

/* ---- colours ----------------------------------------------------------------- */

/* Colours travel as 0xAABBGGRR, the PSP's own 8888 layout. */
static uint32_t c5650(uint16_t p) {
    uint32_t r = p & 0x1F, g = (p >> 5) & 0x3F, b = (p >> 11) & 0x1F;
    return 0xFF000000u | (((b << 3) | (b >> 2)) << 16) | (((g << 2) | (g >> 4)) << 8) | ((r << 3) | (r >> 2));
}
static uint32_t c5551(uint16_t p) {
    uint32_t r = p & 0x1F, g = (p >> 5) & 0x1F, b = (p >> 10) & 0x1F;
    return ((p & 0x8000) ? 0xFF000000u : 0) | (((b << 3) | (b >> 2)) << 16) |
           (((g << 3) | (g >> 2)) << 8) | ((r << 3) | (r >> 2));
}
static uint32_t c4444(uint16_t p) {
    uint32_t r = p & 0xF, g = (p >> 4) & 0xF, b = (p >> 8) & 0xF, a = (p >> 12) & 0xF;
    return ((a * 17) << 24) | ((b * 17) << 16) | ((g * 17) << 8) | (r * 17);
}
static uint32_t decode16(int fmt, uint16_t p) {
    return fmt == 0 ? c5650(p) : fmt == 1 ? c5551(p) : c4444(p);
}
static uint16_t encode16(int fmt, uint32_t c) {
    uint32_t r = c & 0xFF, g = (c >> 8) & 0xFF, b = (c >> 16) & 0xFF, a = c >> 24;
    switch (fmt) {
    case 0:  return (uint16_t)((r >> 3) | ((g >> 2) << 5) | ((b >> 3) << 11));
    case 1:  return (uint16_t)((r >> 3) | ((g >> 3) << 5) | ((b >> 3) << 10) | ((a >> 7) << 15));
    default: return (uint16_t)((r >> 4) | ((g >> 4) << 4) | ((b >> 4) << 8) | ((a >> 4) << 12));
    }
}

/* ---- textures ---------------------------------------------------------------- */

static uint32_t tex_addr(int lvl) {
    return (R[0xA0 + lvl] & 0xFFFFF0u) | ((R[0xA8 + lvl] & 0x0F0000u) << 8);
}
static uint32_t tex_bufw(int lvl) { return R[0xA8 + lvl] & 0x7FF; }
static uint32_t tex_w(int lvl) { return 1u << (R[0xB8 + lvl] & 0xF); }
static uint32_t tex_h(int lvl) { return 1u << ((R[0xB8 + lvl] >> 8) & 0xF); }

static uint32_t clut_lookup(uint32_t index) {
    uint32_t m = R[0xC5];
    uint32_t i = ((index >> ((m >> 2) & 0x1F)) & ((m >> 8) & 0xFF)) | (((m >> 16) & 0x1F) << 4);
    int fmt = (int)(m & 3);
    if (fmt == 3) { uint32_t v; memcpy(&v, g_clut + ((i * 4) & 1023), 4); return v; }
    uint16_t v;
    memcpy(&v, g_clut + ((i * 2) & 1023), 2);
    return decode16(fmt, v);
}

/* Byte offset of texel (x, y) for a format of `bpp` bits in a buffer of
 * `bufw` texels, honouring the swizzled layout (16-byte x 8-row blocks). */
static uint32_t texel_offset(uint32_t x, uint32_t y, uint32_t bufw, int bpp, int swizzled) {
    uint32_t row_bytes = bufw * (uint32_t)bpp / 8;
    uint32_t xb = x * (uint32_t)bpp / 8;              /* byte column (bpp 4 => half bytes) */
    if (!swizzled) return y * row_bytes + xb;
    uint32_t blocks_per_row = row_bytes / 16 ? row_bytes / 16 : 1;
    uint32_t bx = xb / 16, by = y / 8;
    return (by * blocks_per_row + bx) * 128 + (y % 8) * 16 + (xb % 16);
}

/* DXT colour block in the PSP's layout: 4 bytes of 2-bit indices (one byte
 * per row), then two 565 colours. */
static uint32_t dxt_color(uint32_t blk, uint32_t x, uint32_t y, int dxt1) {
    uint8_t lines = rd8(blk + y);
    uint16_t c0 = rd16(blk + 4), c1 = rd16(blk + 6);
    uint32_t a = c5650(c0), b = c5650(c1);
    uint32_t idx = (lines >> (x * 2)) & 3;
    if (idx == 0) return a;
    if (idx == 1) return b;
    uint32_t out = 0;
    if (c0 > c1 || !dxt1) {
        for (int s = 0; s < 24; s += 8) {
            uint32_t ca = (a >> s) & 0xFF, cb = (b >> s) & 0xFF;
            uint32_t v = idx == 2 ? (2 * ca + cb) / 3 : (ca + 2 * cb) / 3;
            out |= v << s;
        }
        return out | 0xFF000000u;
    }
    if (idx == 2) {
        for (int s = 0; s < 24; s += 8) out |= ((((a >> s) & 0xFF) + ((b >> s) & 0xFF)) / 2) << s;
        return out | 0xFF000000u;
    }
    return 0;                                         /* transparent black */
}

static uint32_t fetch_texel(uint32_t x, uint32_t y) {
    const int psm = (int)(R[0xC3] & 0xF);
    const uint32_t base = tex_addr(0), bufw = tex_bufw(0);
    const int sw = (int)(R[0xC2] & 1);
    switch (psm) {
    case 0: case 1: case 2:
        return decode16(psm, rd16(base + texel_offset(x, y, bufw, 16, sw)));
    case 3:
        return rd32(base + texel_offset(x, y, bufw, 32, sw));
    case 4: {                                         /* CLUT4 */
        uint8_t b = rd8(base + texel_offset(x, y, bufw, 4, sw));
        return clut_lookup((x & 1) ? (b >> 4) : (b & 0xF));
    }
    case 5: return clut_lookup(rd8(base + texel_offset(x, y, bufw, 8, sw)));
    case 6: return clut_lookup(rd16(base + texel_offset(x, y, bufw, 16, sw)));
    case 7: return clut_lookup(rd32(base + texel_offset(x, y, bufw, 32, sw)));
    case 8: case 9: case 10: {                        /* DXT1 / 3 / 5 */
        uint32_t bsz = psm == 8 ? 8 : 16;
        uint32_t blk = base + ((y / 4) * (bufw / 4) + (x / 4)) * bsz;
        uint32_t c = dxt_color(blk, x & 3, y & 3, psm == 8);
        if (psm == 9) {                               /* explicit 4-bit alpha after the colour */
            uint16_t row = rd16(blk + 8 + (y & 3) * 2);
            uint32_t a = (row >> ((x & 3) * 4)) & 0xF;
            c = (c & 0xFFFFFF) | ((a * 17) << 24);
        } else if (psm == 10) {                       /* interpolated alpha after the colour */
            uint32_t a0 = rd8(blk + 14), a1 = rd8(blk + 15);
            uint64_t bits = (uint64_t)rd32(blk + 8) | ((uint64_t)rd16(blk + 12) << 32);
            uint32_t k = (uint32_t)((bits >> (((y & 3) * 4 + (x & 3)) * 3)) & 7), a;
            if (k == 0) a = a0;
            else if (k == 1) a = a1;
            else if (a0 > a1) a = ((8 - k) * a0 + (k - 1) * a1) / 7;
            else if (k < 6) a = ((6 - k) * a0 + (k - 1) * a1) / 5;
            else a = k == 6 ? 0 : 255;
            c = (c & 0xFFFFFF) | (a << 24);
        }
        return c;
    }
    default:
        return 0xFFFF00FFu;
    }
}

static uint32_t wrap(int32_t v, uint32_t size, int clamp) {
    if (clamp) return v < 0 ? 0 : (v >= (int32_t)size ? size - 1 : (uint32_t)v);
    return (uint32_t)v & (size - 1);
}

/* Sample at texel-space (u, v). */
static uint32_t sample(float u, float v) {
    c_textured++;
    const uint32_t w = tex_w(0), h = tex_h(0);
    const int cu = (int)(R[0xC7] & 1), cv = (int)((R[0xC7] >> 8) & 1);
    const int linear = (int)((R[0xC6] >> 8) & 1);     /* magnification filter */
    if (linear) c_linear++;
    if (!linear) {
        return fetch_texel(wrap((int32_t)floorf(u), w, cu), wrap((int32_t)floorf(v), h, cv));
    }
    float fu = u - 0.5f, fv = v - 0.5f;
    int32_t x0 = (int32_t)floorf(fu), y0 = (int32_t)floorf(fv);
    float ax = fu - (float)x0, ay = fv - (float)y0;
    uint32_t t[4] = {
        fetch_texel(wrap(x0, w, cu), wrap(y0, h, cv)),
        fetch_texel(wrap(x0 + 1, w, cu), wrap(y0, h, cv)),
        fetch_texel(wrap(x0, w, cu), wrap(y0 + 1, h, cv)),
        fetch_texel(wrap(x0 + 1, w, cu), wrap(y0 + 1, h, cv)),
    };
    uint32_t out = 0;
    for (int s = 0; s < 32; s += 8) {
        float a = (float)((t[0] >> s) & 0xFF) * (1 - ax) + (float)((t[1] >> s) & 0xFF) * ax;
        float b = (float)((t[2] >> s) & 0xFF) * (1 - ax) + (float)((t[3] >> s) & 0xFF) * ax;
        out |= ((uint32_t)(a * (1 - ay) + b * ay + 0.5f) & 0xFF) << s;
    }
    return out;
}

/* ---- the fragment pipeline --------------------------------------------------- */

uint64_t psp_gpu_pixels(void) { return g_pixels; }

static uint32_t fb_addr(void) { return PSP_VRAM_BASE | (R[0x9C] & 0x1FFFF0u); }
static uint32_t fb_w(void)    { return R[0x9D] & 0x7FC; }
static uint32_t zb_addr(void) { return PSP_VRAM_BASE | (R[0x9E] & 0x1FFFF0u); }
static uint32_t zb_w(void)    { return R[0x9F] & 0x7FC; }

static int cmp(int func, uint32_t a, uint32_t b) {
    switch (func & 7) {
    case 0: return 0;
    case 1: return 1;
    case 2: return a == b;
    case 3: return a != b;
    case 4: return a < b;
    case 5: return a <= b;
    case 6: return a > b;
    default: return a >= b;
    }
}

static uint32_t mul8(uint32_t a, uint32_t b) { return (a * b + 127) / 255; }

/* One blend factor applied to one channel value. */
static uint32_t factor(int f, int is_src, uint32_t src, uint32_t dst, uint32_t fix, int ch) {
    uint32_t sa = src >> 24, da = dst >> 24;
    uint32_t other = ((is_src ? dst : src) >> ch) & 0xFF;
    switch (f) {
    case 0:  return other;                      /* the other operand's colour */
    case 1:  return 255 - other;
    case 2:  return sa;
    case 3:  return 255 - sa;
    case 4:  return da;
    case 5:  return 255 - da;
    case 6:  return sa * 2 > 255 ? 255 : sa * 2;
    case 7:  return sa * 2 > 255 ? 0 : 255 - sa * 2;
    case 8:  return da * 2 > 255 ? 255 : da * 2;
    case 9:  return da * 2 > 255 ? 0 : 255 - da * 2;
    default: return (fix >> ch) & 0xFF;          /* FIX */
    }
}

static uint32_t blend(uint32_t src, uint32_t dst) {
    const uint32_t m = R[0xDF];
    const int sf = (int)(m & 0xF), df = (int)((m >> 4) & 0xF), eq = (int)((m >> 8) & 0xF);
    uint32_t out = 0;
    for (int ch = 0; ch < 24; ch += 8) {
        int32_t s = (int32_t)mul8((src >> ch) & 0xFF, factor(sf, 1, src, dst, R[0xE0], ch));
        int32_t d = (int32_t)mul8((dst >> ch) & 0xFF, factor(df, 0, src, dst, R[0xE1], ch));
        int32_t sc = (int32_t)((src >> ch) & 0xFF), dc = (int32_t)((dst >> ch) & 0xFF), r;
        switch (eq) {
        case 0:  r = s + d; break;
        case 1:  r = s - d; break;
        case 2:  r = d - s; break;
        case 3:  r = sc < dc ? sc : dc; break;
        case 4:  r = sc > dc ? sc : dc; break;
        default: r = sc > dc ? sc - dc : dc - sc; break;
        }
        if (r < 0) r = 0;
        if (r > 255) r = 255;
        out |= (uint32_t)r << ch;
    }
    return out | (src & 0xFF000000u);
}

typedef struct {
    float x, y, z;         /* screen space; z is depth 0..65535 */
    float w;               /* 1/w for perspective correction (1 in through mode) */
    float u, v;            /* texel space, already divided where needed */
    float r, g, b, a;      /* 0..255 */
} vtx;

static int g_clear, g_tex, g_through;
static uint32_t g_fb, g_fbw, g_zb, g_zbw;
static int g_psm;
static int g_sx0, g_sy0, g_sx1, g_sy1;

static void setup_draw(void) {
    g_clear = (int)(R[0xD3] & 1);
    g_tex = !g_clear && (R[0x1E] & 1);
    g_fb = fb_addr(); g_fbw = fb_w();
    g_zb = zb_addr(); g_zbw = zb_w();
    g_psm = (int)(R[0xD2] & 3);
    g_sx0 = (int)(R[0xD4] & 0x3FF); g_sy0 = (int)((R[0xD4] >> 10) & 0x3FF);
    g_sx1 = (int)(R[0xD5] & 0x3FF); g_sy1 = (int)((R[0xD5] >> 10) & 0x3FF);
    if (g_sx1 > 511) g_sx1 = 511;
    if (g_sy1 > 511) g_sy1 = 511;
    if (!g_clear) {
        if (R[0x1F] & 1) g_unsup_fog++;
        if (R[0x24] & 1) g_unsup_stencil++;
        if (R[0x27] & 1) g_unsup_ctest++;
        if (R[0x28] & 1) g_unsup_logic++;
        if (g_tex) g_texdraws++;
    }
}

static void fragment(int x, int y, float z, uint32_t color) {
    if (x < g_sx0 || x > g_sx1 || y < g_sy0 || y > g_sy1) return;
    if (!g_fbw) return;
    const int bpp = g_psm == 3 ? 4 : 2;
    uint8_t *p = mem(g_fb + (uint32_t)(y * (int)g_fbw + x) * (uint32_t)bpp, (uint32_t)bpp);
    if (!p) return;
    uint16_t zv = (uint16_t)(z < 0 ? 0 : (z > 65535.0f ? 65535 : (int)z));
    uint8_t *zp = g_zbw ? mem(g_zb + (uint32_t)(y * (int)g_zbw + x) * 2, 2) : NULL;

    if (g_clear) {
        const uint32_t which = R[0xD3] >> 8;           /* 1 colour, 2 alpha/stencil, 4 depth */
        uint32_t old = bpp == 4 ? *(uint32_t *)p : decode16(g_psm, *(uint16_t *)p);
        uint32_t out = old;
        if (which & 1) out = (out & 0xFF000000u) | (color & 0xFFFFFFu);
        if (which & 2) out = (out & 0xFFFFFFu) | (color & 0xFF000000u);
        if (bpp == 4) *(uint32_t *)p = out; else *(uint16_t *)p = encode16(g_psm, out);
        if ((which & 4) && zp) *(uint16_t *)zp = zv;
        g_pixels++;
        c_clear++;
        return;
    }

    if (R[0x21] & 1) c_blend++;
    if ((R[0x22] & 1)) {                               /* alpha test */
        uint32_t t = R[0xDB], mask = (t >> 16) & 0xFF;
        if (!cmp((int)t, (color >> 24) & mask, ((t >> 8) & 0xFF) & mask)) return;
    }
    if ((R[0x23] & 1) && zp) {                         /* depth test */
        if (!cmp((int)R[0xDE], zv, *(uint16_t *)zp)) return;
    }
    uint32_t dst = bpp == 4 ? *(uint32_t *)p : decode16(g_psm, *(uint16_t *)p);
    uint32_t out = (R[0x21] & 1) ? blend(color, dst) : color;

    /* Write masks: set bits are preserved from the destination. */
    uint32_t mask = (R[0xE8] & 0xFFFFFF) | ((R[0xE9] & 0xFF) << 24);
    out = (out & ~mask) | (dst & mask);
    if (bpp == 4) *(uint32_t *)p = out; else *(uint16_t *)p = encode16(g_psm, out);
    if ((R[0x23] & 1) && zp && !(R[0xE7] & 1)) *(uint16_t *)zp = zv;
    g_pixels++;
}

/* Combine the interpolated colour with the texture. */
static uint32_t shade(const vtx *f, float u, float v) {
    c_shaded++;
    uint32_t cr = (uint32_t)f->r, cg = (uint32_t)f->g, cb = (uint32_t)f->b, ca = (uint32_t)f->a;
    if (!g_tex) return (ca << 24) | (cb << 16) | (cg << 8) | cr;
    uint32_t t = sample(u, v);
    uint32_t tr = t & 0xFF, tg = (t >> 8) & 0xFF, tb = (t >> 16) & 0xFF, ta = t >> 24;
    const uint32_t tf = R[0xC9];
    const int rgba = (int)((tf >> 8) & 1), dbl = (int)((tf >> 16) & 1);
    uint32_t r, g, b, a = ca;
    switch (tf & 7) {
    case 0:                                             /* modulate */
        r = mul8(cr, tr); g = mul8(cg, tg); b = mul8(cb, tb);
        if (rgba) a = mul8(ca, ta);
        break;
    case 1:                                             /* decal */
        if (rgba) {
            r = (tr * ta + cr * (255 - ta)) / 255; g = (tg * ta + cg * (255 - ta)) / 255;
            b = (tb * ta + cb * (255 - ta)) / 255;
        } else { r = tr; g = tg; b = tb; }
        break;
    case 2: {                                           /* blend with the env colour */
        uint32_t e = R[0xCA];
        r = (cr * (255 - tr) + (e & 0xFF) * tr) / 255;
        g = (cg * (255 - tg) + ((e >> 8) & 0xFF) * tg) / 255;
        b = (cb * (255 - tb) + ((e >> 16) & 0xFF) * tb) / 255;
        if (rgba) a = mul8(ca, ta);
        break;
    }
    case 3:                                             /* replace */
        r = tr; g = tg; b = tb;
        if (rgba) a = ta;
        break;
    default:                                            /* add */
        r = cr + tr; g = cg + tg; b = cb + tb;
        if (rgba) a = mul8(ca, ta);
        break;
    }
    if (dbl) { r *= 2; g *= 2; b *= 2; }
    if (r > 255) r = 255;
    if (g > 255) g = 255;
    if (b > 255) b = 255;
    return (a << 24) | (b << 16) | (g << 8) | r;
}

/* ---- primitives ---------------------------------------------------------------- */

static int clampi(int v, int lo, int hi) { return v < lo ? lo : (v > hi ? hi : v); }

static void ref_sprite(const vtx *a, const vtx *b) {
    float x0 = a->x < b->x ? a->x : b->x, x1 = a->x > b->x ? a->x : b->x;
    float y0 = a->y < b->y ? a->y : b->y, y1 = a->y > b->y ? a->y : b->y;
    int ix0 = clampi((int)ceilf(x0 - 0.5f), 0, 511), ix1 = clampi((int)ceilf(x1 - 0.5f), 0, 512);
    int iy0 = clampi((int)ceilf(y0 - 0.5f), 0, 511), iy1 = clampi((int)ceilf(y1 - 0.5f), 0, 512);
    /* Texture coordinates run from the first vertex's corner to the second's;
     * colour and depth are the second vertex's (flat). */
    const vtx *L = a->x <= b->x ? a : b, *Rr = a->x <= b->x ? b : a;
    const vtx *T = a->y <= b->y ? a : b, *B = a->y <= b->y ? b : a;
    float du = (x1 > x0) ? (Rr->u - L->u) / (x1 - x0) : 0;
    float dv = (y1 > y0) ? (B->v - T->v) / (y1 - y0) : 0;
    for (int y = iy0; y < iy1; y++) {
        float v = T->v + ((float)y + 0.5f - y0) * dv;
        for (int x = ix0; x < ix1; x++) {
            float u = L->u + ((float)x + 0.5f - x0) * du;
            c_sprite_px++;
            fragment(x, y, b->z, shade(b, u, v));
        }
    }
}

/* Edge-function triangle fill, sampling at pixel centres with a top-left rule
 * so shared edges are drawn exactly once. Attributes are interpolated
 * perspective-correctly through 1/w (w is 1 in through mode, where this
 * reduces to affine). Colour is flat (the last vertex's) unless Gouraud
 * shading is on. */
static void ref_tri(const vtx *a, const vtx *b, const vtx *c) {
    float area = (b->x - a->x) * (c->y - a->y) - (b->y - a->y) * (c->x - a->x);
    if (area == 0) return;
    if (area < 0) { const vtx *t = b; b = c; c = t; area = -area; }
    const int gouraud = (int)(R[0x50] & 1);
    const vtx *flat = c;

    int minx = clampi((int)floorf(fminf(a->x, fminf(b->x, c->x))), 0, 511);
    int maxx = clampi((int)ceilf(fmaxf(a->x, fmaxf(b->x, c->x))), 0, 511);
    int miny = clampi((int)floorf(fminf(a->y, fminf(b->y, c->y))), 0, 511);
    int maxy = clampi((int)ceilf(fmaxf(a->y, fmaxf(b->y, c->y))), 0, 511);
    if (minx < g_sx0) minx = g_sx0;
    if (maxx > g_sx1) maxx = g_sx1;
    if (miny < g_sy0) miny = g_sy0;
    if (maxy > g_sy1) maxy = g_sy1;

    for (int y = miny; y <= maxy; y++) {
        float py = (float)y + 0.5f;
        for (int x = minx; x <= maxx; x++) {
            float px = (float)x + 0.5f;
            c_tested++;
            float w0 = (c->x - b->x) * (py - b->y) - (c->y - b->y) * (px - b->x);
            float w1 = (a->x - c->x) * (py - c->y) - (a->y - c->y) * (px - c->x);
            float w2 = (b->x - a->x) * (py - a->y) - (b->y - a->y) * (px - a->x);
            if (w0 < 0 || w1 < 0 || w2 < 0) continue;
            /* Top-left rule for pixels exactly on an edge. */
            if (w0 == 0 && !((c->y == b->y && c->x < b->x) || c->y < b->y)) continue;
            if (w1 == 0 && !((a->y == c->y && a->x < c->x) || a->y < c->y)) continue;
            if (w2 == 0 && !((b->y == a->y && b->x < a->x) || b->y < a->y)) continue;
            float l0 = w0 / area, l1 = w1 / area, l2 = w2 / area;
            float q = l0 * a->w + l1 * b->w + l2 * c->w;      /* interpolated 1/w */
            float p0 = l0 * a->w / q, p1 = l1 * b->w / q, p2 = l2 * c->w / q;
            vtx f;
            f.z = l0 * a->z + l1 * b->z + l2 * c->z;
            if (gouraud) {
                f.r = p0 * a->r + p1 * b->r + p2 * c->r;
                f.g = p0 * a->g + p1 * b->g + p2 * c->g;
                f.b = p0 * a->b + p1 * b->b + p2 * c->b;
                f.a = p0 * a->a + p1 * b->a + p2 * c->a;
            } else {
                f.r = flat->r; f.g = flat->g; f.b = flat->b; f.a = flat->a;
            }
            c_tri_px++;
            float u = p0 * a->u + p1 * b->u + p2 * c->u;
            float v = p0 * a->v + p1 * b->v + p2 * c->v;
            fragment(x, y, f.z, shade(&f, u, v));
        }
    }
}

static void raster_line(const vtx *a, const vtx *b) {
    float dx = b->x - a->x, dy = b->y - a->y;
    int n = (int)fmaxf(fabsf(dx), fabsf(dy));
    if (n <= 0) n = 1;
    for (int i = 0; i < n; i++) {
        float t = (float)i / (float)n;
        vtx f = *b;
        f.r = a->r + (b->r - a->r) * t; f.g = a->g + (b->g - a->g) * t;
        f.b = a->b + (b->b - a->b) * t; f.a = a->a + (b->a - a->a) * t;
        fragment((int)(a->x + dx * t), (int)(a->y + dy * t), a->z + (b->z - a->z) * t,
                 shade(&f, a->u + (b->u - a->u) * t, a->v + (b->v - a->v) * t));
    }
}

/* ---- the fast path -------------------------------------------------------------
 *
 * The functions above are the reference: each pixel re-reads its state from the
 * register file and every memory access goes through psp_mem_ptr's region and
 * bounds checks. That is clear and it is slow -- the title screen of PSP2i
 * shades about 1.3 million fragments a frame, and at that rate those checks
 * were most of the frame.
 *
 * The fast path computes exactly the same thing. It resolves the draw's state
 * once per primitive (fast_setup) -- including host pointers for the colour
 * buffer, depth buffer and texture, each bounds-checked once for its whole
 * extent -- and then runs the same per-pixel arithmetic, in the same order, so
 * results are bit-identical. Where an extent check fails (a texture straddling
 * the end of RAM, say) or a format has no fast fetch (DXT), the draw falls back
 * to the reference path rather than guessing.
 *
 * PSP2I_GPU_VERIFY=1 renders every primitive through both paths from the same
 * VRAM snapshot and counts any byte that differs (verify_rasterize).
 */

static int g_ref;                        /* force the reference path */

/* ---- parallel rows ----------------------------------------------------------------
 *
 * A draw's fast-path triangles and sprites are rasterized by several threads at
 * once, each taking the rows y with y % tl_n == tl_k. Every pixel is computed
 * by exactly the same code as before and rows never overlap, so the output is
 * unchanged; draw order is kept because every worker finishes a draw before the
 * next one starts. Counters are per worker (padded against false sharing) and
 * folded into the globals after each draw. */
#ifdef _MSC_VER
#  define GPU_TLS __declspec(thread)
#else
#  define GPU_TLS _Thread_local
#endif
static GPU_TLS int tl_k = 0, tl_n = 1;

#define GPU_MAX_WORKERS 8
typedef struct {
    uint64_t pixels, tested, shaded, textured, linear, sprite, tri, blend, clear;
    char pad[64 - (9 * 8) % 64];
} worker_counters;
static worker_counters g_wc[GPU_MAX_WORKERS];
#define WC g_wc[tl_k]

static inline int first_row(int y0) {
    int r = ((tl_k - y0) % tl_n + tl_n) % tl_n;
    return y0 + r;
}



static struct {
    int      ok;                         /* the fast path can draw this primitive */
    uint8_t *fb;  int bpp;  uint32_t fbw;
    uint8_t *zb;  uint32_t zbw;
    int      tex_ok;                     /* texels can be fetched through tbase */
    const uint8_t *tbase;
    uint32_t tw, th, bufw;
    int      tpsm, swz, cu, cv, linear;
    uint32_t row_bytes;                  /* unswizzled pitch for this format */
    uint32_t clut_shift, clut_mask, clut_start;
    uint32_t pal[512];                   /* the CLUT, decoded for this draw */
} F;

/* Bytes spanned by texels (0..w-1, 0..h-1) of a `bpp`-bit texture with row
 * pitch `bufw`, in either layout: the furthest byte texel_offset can return,
 * plus the 4 bytes rd32 may read there. */
static uint32_t tex_extent(uint32_t w, uint32_t h, uint32_t bufw, int bpp, int swz) {
    uint32_t a = texel_offset(w - 1, h - 1, bufw, bpp, swz);
    uint32_t b = texel_offset(w - 1, 0, bufw, bpp, swz);
    uint32_t c = texel_offset(0, h - 1, bufw, bpp, swz);
    uint32_t m = a > b ? a : b;
    if (c > m) m = c;
    if (swz) {                                   /* any byte of the last block row */
        uint32_t row_bytes = bufw * (uint32_t)bpp / 8;
        uint32_t bpr = row_bytes / 16 ? row_bytes / 16 : 1;
        uint32_t blk = ((h - 1) / 8 * bpr + bpr) * 128;
        if (blk > m) m = blk;
    }
    return m + 4;
}

static void fast_setup(void) {
    F.ok = F.tex_ok = 0; F.fb = F.zb = NULL; F.tbase = NULL;
    if (g_ref || !g_fbw) return;
    F.bpp = g_psm == 3 ? 4 : 2;
    F.fbw = g_fbw;
    /* Every pixel the scissor admits must be addressable. */
    uint32_t fb_bytes = ((uint32_t)g_sy1 * g_fbw + (uint32_t)g_sx1 + 1) * (uint32_t)F.bpp;
    F.fb = mem(g_fb, fb_bytes);
    if (!F.fb) return;
    if (g_zbw) {
        uint32_t zb_bytes = ((uint32_t)g_sy1 * g_zbw + (uint32_t)g_sx1 + 1) * 2;
        F.zb = mem(g_zb, zb_bytes);
        if (!F.zb) return;
        F.zbw = g_zbw;
    }
    if (g_tex) {
        static const int bpp_of[11] = { 16, 16, 16, 32, 4, 8, 16, 32, 0, 0, 0 };
        F.tpsm = (int)(R[0xC3] & 0xF);
        F.tw = tex_w(0); F.th = tex_h(0); F.bufw = tex_bufw(0);
        F.swz = (int)(R[0xC2] & 1);
        F.cu = (int)(R[0xC7] & 1); F.cv = (int)((R[0xC7] >> 8) & 1);
        F.linear = (int)((R[0xC6] >> 8) & 1);
        if (F.tpsm <= 7 && F.bufw) {
            F.tbase = mem(tex_addr(0), tex_extent(F.tw, F.th, F.bufw, bpp_of[F.tpsm], F.swz));
            F.tex_ok = F.tbase != NULL;
            F.row_bytes = F.bufw * (uint32_t)bpp_of[F.tpsm] / 8;
            if (F.tpsm >= 4) {
                /* clut_lookup's arithmetic, split into the index (per texel)
                 * and the decode (once per entry, here). */
                const uint32_t m = R[0xC5];
                const int fmt = (int)(m & 3);
                F.clut_shift = (m >> 2) & 0x1F;
                F.clut_mask = (m >> 8) & 0xFF;
                F.clut_start = ((m >> 16) & 0x1F) << 4;
                for (uint32_t i = 0; i < 512; i++) {
                    if (fmt == 3) { uint32_t v; memcpy(&v, g_clut + ((i * 4) & 1023), 4); F.pal[i] = v; }
                    else { uint16_t v; memcpy(&v, g_clut + ((i * 2) & 1023), 2); F.pal[i] = decode16(fmt, v); }
                }
            }
        }
    }
    F.ok = 1;
}

static inline uint16_t ld16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static inline uint32_t ld32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static inline uint32_t clut_index(uint32_t index) {
    return ((index >> F.clut_shift) & F.clut_mask) | F.clut_start;
}

/* (int32_t)floorf(f), without the library call. Exact for every input: in
 * range it is truncation corrected for negative fractions; out of range and
 * NaN both conversions produce INT32_MIN, as cvttss2si does. */
static inline int32_t ifloor(float f) {
    int32_t i = (int32_t)f;
    if (i == INT32_MIN) return i;
    return (float)i > f ? i - 1 : i;
}

/* Byte offset of a texel: texel_offset, with the unswizzled case reduced to
 * a multiply-add on a precomputed pitch. */
static inline uint32_t fast_offset(uint32_t x, uint32_t y, int bpp) {
    if (F.swz) return texel_offset(x, y, F.bufw, bpp, 1);
    return y * F.row_bytes + x * (uint32_t)bpp / 8;
}

/* fetch_texel through the cached pointer, with CLUT entries read from the
 * per-draw decoded palette. Same offsets, same decoding. */
static inline uint32_t fast_texel(uint32_t x, uint32_t y) {
    if (!F.tex_ok) return fetch_texel(x, y);
    const uint8_t *t = F.tbase;
    switch (F.tpsm) {
    case 0: case 1: case 2:
        return decode16(F.tpsm, ld16(t + fast_offset(x, y, 16)));
    case 3:
        return ld32(t + fast_offset(x, y, 32));
    case 4: {
        uint8_t b = t[fast_offset(x, y, 4)];
        return F.pal[clut_index((x & 1) ? (b >> 4) : (b & 0xFu))];
    }
    case 5: return F.pal[clut_index(t[fast_offset(x, y, 8)])];
    case 6: return F.pal[clut_index(ld16(t + fast_offset(x, y, 16)))];
    default: return F.pal[clut_index(ld32(t + fast_offset(x, y, 32)))];
    }
}

/* sample(), with cached state. Bilinear filtering runs the reference's
 * per-channel arithmetic on all four channels at once: packed single
 * precision multiplies and adds are the same IEEE operations as the scalar
 * ones, in the same order, and truncation of these non-negative values is
 * the same conversion, so every channel comes out identical. */
static inline uint32_t fast_sample(float u, float v) {
    WC.textured++;
    const uint32_t w = F.tw, h = F.th;
    const int cu = F.cu, cv = F.cv;
    if (!F.linear) {
        return fast_texel(wrap(ifloor(u), w, cu), wrap(ifloor(v), h, cv));
    }
    WC.linear++;
    float fu = u - 0.5f, fv = v - 0.5f;
    int32_t x0 = ifloor(fu), y0 = ifloor(fv);
    float ax = fu - (float)x0, ay = fv - (float)y0;
    uint32_t xa = wrap(x0, w, cu), xb = wrap(x0 + 1, w, cu);
    uint32_t ya = wrap(y0, h, cv), yb = wrap(y0 + 1, h, cv);
    const __m128i z = _mm_setzero_si128();
#define CH4(t) _mm_cvtepi32_ps(_mm_unpacklo_epi16(_mm_unpacklo_epi8(_mm_cvtsi32_si128((int)(t)), z), z))
    __m128 t0 = CH4(fast_texel(xa, ya)), t1 = CH4(fast_texel(xb, ya));
    __m128 t2 = CH4(fast_texel(xa, yb)), t3 = CH4(fast_texel(xb, yb));
#undef CH4
    const __m128 iax = _mm_set1_ps(1 - ax), vax = _mm_set1_ps(ax);
    const __m128 iay = _mm_set1_ps(1 - ay), vay = _mm_set1_ps(ay);
    __m128 a = _mm_add_ps(_mm_mul_ps(t0, iax), _mm_mul_ps(t1, vax));
    __m128 b = _mm_add_ps(_mm_mul_ps(t2, iax), _mm_mul_ps(t3, vax));
    __m128 r = _mm_add_ps(_mm_add_ps(_mm_mul_ps(a, iay), _mm_mul_ps(b, vay)), _mm_set1_ps(0.5f));
    __m128i q = _mm_cvttps_epi32(r);
    q = _mm_and_si128(q, _mm_set1_epi32(0xFF));
    q = _mm_packs_epi32(q, z);
    q = _mm_packus_epi16(q, z);
    return (uint32_t)_mm_cvtsi128_si32(q);
}

/* shade(), verbatim but for the sampler. */
static inline uint32_t fast_shade(const vtx *f, float u, float v) {
    WC.shaded++;
    uint32_t cr = (uint32_t)f->r, cg = (uint32_t)f->g, cb = (uint32_t)f->b, ca = (uint32_t)f->a;
    if (!g_tex) return (ca << 24) | (cb << 16) | (cg << 8) | cr;
    uint32_t t = fast_sample(u, v);
    uint32_t tr = t & 0xFF, tg = (t >> 8) & 0xFF, tb = (t >> 16) & 0xFF, ta = t >> 24;
    const uint32_t tf = R[0xC9];
    const int rgba = (int)((tf >> 8) & 1), dbl = (int)((tf >> 16) & 1);
    uint32_t r, g, b, a = ca;
    switch (tf & 7) {
    case 0:
        r = mul8(cr, tr); g = mul8(cg, tg); b = mul8(cb, tb);
        if (rgba) a = mul8(ca, ta);
        break;
    case 1:
        if (rgba) {
            r = (tr * ta + cr * (255 - ta)) / 255; g = (tg * ta + cg * (255 - ta)) / 255;
            b = (tb * ta + cb * (255 - ta)) / 255;
        } else { r = tr; g = tg; b = tb; }
        break;
    case 2: {
        uint32_t e = R[0xCA];
        r = (cr * (255 - tr) + (e & 0xFF) * tr) / 255;
        g = (cg * (255 - tg) + ((e >> 8) & 0xFF) * tg) / 255;
        b = (cb * (255 - tb) + ((e >> 16) & 0xFF) * tb) / 255;
        if (rgba) a = mul8(ca, ta);
        break;
    }
    case 3:
        r = tr; g = tg; b = tb;
        if (rgba) a = ta;
        break;
    default:
        r = cr + tr; g = cg + tg; b = cb + tb;
        if (rgba) a = mul8(ca, ta);
        break;
    }
    if (dbl) { r *= 2; g *= 2; b *= 2; }
    if (r > 255) r = 255;
    if (g > 255) g = 255;
    if (b > 255) b = 255;
    return (a << 24) | (b << 16) | (g << 8) | r;
}

/* fragment(), for a pixel already known to be inside the scissor, with the
 * buffers addressed through the cached pointers. */
static inline void fast_fragment(int x, int y, float z, uint32_t color) {
    const int bpp = F.bpp;
    uint8_t *p = F.fb + ((uint32_t)y * F.fbw + (uint32_t)x) * (uint32_t)bpp;
    uint16_t zv = (uint16_t)(z < 0 ? 0 : (z > 65535.0f ? 65535 : (int)z));
    uint8_t *zp = F.zb ? F.zb + ((uint32_t)y * F.zbw + (uint32_t)x) * 2 : NULL;

    if (g_clear) {
        const uint32_t which = R[0xD3] >> 8;
        uint32_t old = bpp == 4 ? ld32(p) : decode16(g_psm, ld16(p));
        uint32_t out = old;
        if (which & 1) out = (out & 0xFF000000u) | (color & 0xFFFFFFu);
        if (which & 2) out = (out & 0xFFFFFFu) | (color & 0xFF000000u);
        if (bpp == 4) memcpy(p, &out, 4); else { uint16_t o = encode16(g_psm, out); memcpy(p, &o, 2); }
        if ((which & 4) && zp) memcpy(zp, &zv, 2);
        WC.pixels++;
        WC.clear++;
        return;
    }
    if (R[0x21] & 1) WC.blend++;
    if (R[0x22] & 1) {
        uint32_t t = R[0xDB], mask = (t >> 16) & 0xFF;
        if (!cmp((int)t, (color >> 24) & mask, ((t >> 8) & 0xFF) & mask)) return;
    }
    if ((R[0x23] & 1) && zp) {
        if (!cmp((int)R[0xDE], zv, ld16(zp))) return;
    }
    uint32_t dst = bpp == 4 ? ld32(p) : decode16(g_psm, ld16(p));
    uint32_t out = (R[0x21] & 1) ? blend(color, dst) : color;
    uint32_t mask = (R[0xE8] & 0xFFFFFF) | ((R[0xE9] & 0xFF) << 24);
    out = (out & ~mask) | (dst & mask);
    if (bpp == 4) memcpy(p, &out, 4); else { uint16_t o = encode16(g_psm, out); memcpy(p, &o, 2); }
    if ((R[0x23] & 1) && zp && !(R[0xE7] & 1)) memcpy(zp, &zv, 2);
    WC.pixels++;
}

/* ref_sprite, with the scissor applied to the loop bounds instead of per pixel
 * (fragment() discards those pixels, so the result is the same), and shading
 * only for pixels that can be written. */
static void fast_sprite(const vtx *a, const vtx *b) {
    float x0 = a->x < b->x ? a->x : b->x, x1 = a->x > b->x ? a->x : b->x;
    float y0 = a->y < b->y ? a->y : b->y, y1 = a->y > b->y ? a->y : b->y;
    int ix0 = clampi((int)ceilf(x0 - 0.5f), 0, 511), ix1 = clampi((int)ceilf(x1 - 0.5f), 0, 512);
    int iy0 = clampi((int)ceilf(y0 - 0.5f), 0, 511), iy1 = clampi((int)ceilf(y1 - 0.5f), 0, 512);
    const vtx *L = a->x <= b->x ? a : b, *Rr = a->x <= b->x ? b : a;
    const vtx *T = a->y <= b->y ? a : b, *B = a->y <= b->y ? b : a;
    float du = (x1 > x0) ? (Rr->u - L->u) / (x1 - x0) : 0;
    float dv = (y1 > y0) ? (B->v - T->v) / (y1 - y0) : 0;
    int sx0 = ix0 > g_sx0 ? ix0 : g_sx0, sx1 = ix1 < g_sx1 + 1 ? ix1 : g_sx1 + 1;
    int sy0 = iy0 > g_sy0 ? iy0 : g_sy0, sy1 = iy1 < g_sy1 + 1 ? iy1 : g_sy1 + 1;
    for (int y = first_row(sy0); y < sy1; y += tl_n) {
        float v = T->v + ((float)y + 0.5f - y0) * dv;
        for (int x = sx0; x < sx1; x++) {
            float u = L->u + ((float)x + 0.5f - x0) * du;
            WC.sprite++;
            fast_fragment(x, y, b->z, fast_shade(b, u, v));
        }
    }
}

/* ref_tri with the row-invariant halves of the edge functions hoisted out of
 * the inner loop. Each hoisted product is the same IEEE operation on the same
 * operands, so the edge values -- and the coverage they decide -- are
 * unchanged. The bounding box is already clipped to the scissor. */
static void fast_tri(const vtx *a, const vtx *b, const vtx *c) {
    float area = (b->x - a->x) * (c->y - a->y) - (b->y - a->y) * (c->x - a->x);
    if (area == 0) return;
    if (area < 0) { const vtx *t = b; b = c; c = t; area = -area; }
    const int gouraud = (int)(R[0x50] & 1);
    const vtx *flat = c;

    int minx = clampi((int)floorf(fminf(a->x, fminf(b->x, c->x))), 0, 511);
    int maxx = clampi((int)ceilf(fmaxf(a->x, fmaxf(b->x, c->x))), 0, 511);
    int miny = clampi((int)floorf(fminf(a->y, fminf(b->y, c->y))), 0, 511);
    int maxy = clampi((int)ceilf(fmaxf(a->y, fmaxf(b->y, c->y))), 0, 511);
    if (minx < g_sx0) minx = g_sx0;
    if (maxx > g_sx1) maxx = g_sx1;
    if (miny < g_sy0) miny = g_sy0;
    if (maxy > g_sy1) maxy = g_sy1;

    const float e0x = c->x - b->x, e0y = c->y - b->y;
    const float e1x = a->x - c->x, e1y = a->y - c->y;
    const float e2x = b->x - a->x, e2y = b->y - a->y;
    const int tl0 = (c->y == b->y && c->x < b->x) || c->y < b->y;
    const int tl1 = (a->y == c->y && a->x < c->x) || a->y < c->y;
    const int tl2 = (b->y == a->y && b->x < a->x) || b->y < a->y;
    const int persp = gouraud || g_tex;

    for (int y = first_row(miny); y <= maxy; y += tl_n) {
        float py = (float)y + 0.5f;
        const float r0 = e0x * (py - b->y), r1 = e1x * (py - c->y), r2 = e2x * (py - a->y);
        for (int x = minx; x <= maxx; x++) {
            float px = (float)x + 0.5f;
            WC.tested++;
            float w0 = r0 - e0y * (px - b->x);
            float w1 = r1 - e1y * (px - c->x);
            float w2 = r2 - e2y * (px - a->x);
            if (w0 < 0 || w1 < 0 || w2 < 0) continue;
            if (w0 == 0 && !tl0) continue;
            if (w1 == 0 && !tl1) continue;
            if (w2 == 0 && !tl2) continue;
            float l0 = w0 / area, l1 = w1 / area, l2 = w2 / area;
            vtx f;
            f.z = l0 * a->z + l1 * b->z + l2 * c->z;
            if (!persp) {
                /* Flat and untextured: nothing below reads the perspective
                 * weights, so skip their three divisions. */
                f.r = flat->r; f.g = flat->g; f.b = flat->b; f.a = flat->a;
                WC.tri++;
                fast_fragment(x, y, f.z, fast_shade(&f, 0, 0));
                continue;
            }
            float q = l0 * a->w + l1 * b->w + l2 * c->w;
            float p0 = l0 * a->w / q, p1 = l1 * b->w / q, p2 = l2 * c->w / q;
            if (gouraud) {
                f.r = p0 * a->r + p1 * b->r + p2 * c->r;
                f.g = p0 * a->g + p1 * b->g + p2 * c->g;
                f.b = p0 * a->b + p1 * b->b + p2 * c->b;
                f.a = p0 * a->a + p1 * b->a + p2 * c->a;
            } else {
                f.r = flat->r; f.g = flat->g; f.b = flat->b; f.a = flat->a;
            }
            WC.tri++;
            float u = p0 * a->u + p1 * b->u + p2 * c->u;
            float v = p0 * a->v + p1 * b->v + p2 * c->v;
            fast_fragment(x, y, f.z, fast_shade(&f, u, v));
        }
    }
}

static void raster_sprite(const vtx *a, const vtx *b) {
    if (F.ok) fast_sprite(a, b); else ref_sprite(a, b);
}
static void raster_tri(const vtx *a, const vtx *b, const vtx *c) {
    if (F.ok) fast_tri(a, b, c); else ref_tri(a, b, c);
}

/* ---- vertices ------------------------------------------------------------------ */

#define VT_TEX(v)     ((v) & 3)
#define VT_COLOR(v)   (((v) >> 2) & 7)
#define VT_NORMAL(v)  (((v) >> 5) & 3)
#define VT_POS(v)     (((v) >> 7) & 3)
#define VT_WEIGHT(v)  (((v) >> 9) & 3)
#define VT_INDEX(v)   (((v) >> 11) & 3)
#define VT_NWEIGHT(v) ((((v) >> 14) & 7) + 1)
#define VT_MORPH(v)   ((((v) >> 18) & 7) + 1)
#define VT_THROUGH(v) (((v) >> 23) & 1)

typedef struct {
    int stride;
    int w_off, t_off, c_off, n_off, p_off;
} layout;

static int comp_size(int f) { return f == 1 ? 1 : f == 2 ? 2 : f == 3 ? 4 : 0; }

/* Components appear in a fixed order -- weights, texture, colour, normal,
 * position -- each aligned to its own size; the vertex is aligned to its
 * largest component. */
static void make_layout(uint32_t vt, layout *L) {
    static const int col_sz[8] = { 0, 0, 0, 0, 2, 2, 2, 4 };
    int off = 0, align = 1;
    L->w_off = L->t_off = L->c_off = L->n_off = L->p_off = -1;
#define PLACE(sz, n, outoff) do { int s_ = (sz); if (s_) { off = (off + s_ - 1) & ~(s_ - 1); \
        (outoff) = off; off += s_ * (n); if (s_ > align) align = s_; } } while (0)
    PLACE(comp_size((int)VT_WEIGHT(vt)), (int)VT_NWEIGHT(vt), L->w_off);
    PLACE(comp_size((int)VT_TEX(vt)), 2, L->t_off);
    PLACE(col_sz[VT_COLOR(vt)], 1, L->c_off);
    PLACE(comp_size((int)VT_NORMAL(vt)), 3, L->n_off);
    PLACE(comp_size((int)VT_POS(vt)), 3, L->p_off);
#undef PLACE
    L->stride = (off + align - 1) & ~(align - 1);
}

/* Read one component as a float: through mode takes integers as they are,
 * transformed mode normalises the fixed-point formats -- signed (positions,
 * normals) and unsigned (texture, weights) alike -- by 2^7 or 2^15, so 8-bit
 * 0x80 / 16-bit 0x8000 is 1.0 (the reference decoder's scale, which lets an
 * unsigned weight of 0x80 express exactly 1). */
static float comp(uint32_t a, int fmt, int is_signed, int normalise) {
    switch (fmt) {
    case 1: { int v = is_signed ? (int8_t)rd8(a) : rd8(a); return normalise ? (float)v * (1.0f / 128.0f) : (float)v; }
    case 2: { int v = is_signed ? (int16_t)rd16(a) : rd16(a); return normalise ? (float)v * (1.0f / 32768.0f) : (float)v; }
    case 3: { uint32_t b = rd32(a); float f; memcpy(&f, &b, 4); return f; }
    default: return 0;
    }
}

typedef struct { float pos[3], uv[2], rgba[4], nrm[3], w[8]; int has_color; } raw_vertex;

static void read_one(uint32_t base, uint32_t vt, const layout *L, raw_vertex *o) {
    const int through = (int)VT_THROUGH(vt);
    const int morphs = (int)VT_MORPH(vt);
    memset(o, 0, sizeof *o);
    /* Morph targets are stored back to back and blended by the morph weights. */
    for (int m = 0; m < morphs; m++) {
        uint32_t a = base + (uint32_t)(m * L->stride);
        float mw = morphs > 1 ? ge_float(R[0x2C + m]) : 1.0f;
        if (L->w_off >= 0 && !through) {
            const int ws = comp_size((int)VT_WEIGHT(vt));
            for (int k = 0; k < (int)VT_NWEIGHT(vt); k++)
                o->w[k] += mw * comp(a + (uint32_t)(L->w_off + k * ws), (int)VT_WEIGHT(vt), 0, 1);
        }
        if (L->n_off >= 0 && !through) {
            const int ns = comp_size((int)VT_NORMAL(vt));
            for (int k = 0; k < 3; k++)
                o->nrm[k] += mw * comp(a + (uint32_t)(L->n_off + k * ns), (int)VT_NORMAL(vt), 1, 1);
        }
        if (L->t_off >= 0) {
            o->uv[0] += mw * comp(a + (uint32_t)L->t_off, (int)VT_TEX(vt), 0, !through);
            o->uv[1] += mw * comp(a + (uint32_t)(L->t_off + comp_size((int)VT_TEX(vt))), (int)VT_TEX(vt), 0, !through);
        }
        if (L->c_off >= 0) {
            uint32_t c;
            switch (VT_COLOR(vt)) {
            case 4:  c = c5650(rd16(a + (uint32_t)L->c_off)); break;
            case 5:  c = c5551(rd16(a + (uint32_t)L->c_off)); break;
            case 6:  c = c4444(rd16(a + (uint32_t)L->c_off)); break;
            default: c = rd32(a + (uint32_t)L->c_off); break;
            }
            for (int k = 0; k < 4; k++) o->rgba[k] += mw * (float)((c >> (k * 8)) & 0xFF);
            o->has_color = 1;
        }
        if (L->p_off >= 0) {
            int ps = comp_size((int)VT_POS(vt));
            for (int k = 0; k < 3; k++) {
                /* Through-mode z is unsigned 16-bit; x and y are signed. */
                int sg = !(through && k == 2);
                o->pos[k] += mw * comp(a + (uint32_t)(L->p_off + k * ps), (int)VT_POS(vt), sg, !through);
            }
        }
    }
}

/* Apply a 4x3 matrix (12 floats, columns x, y, z then translation). */
static void mul43(const float *m, const float in[3], float out[3]) {
    out[0] = in[0] * m[0] + in[1] * m[3] + in[2] * m[6] + m[9];
    out[1] = in[0] * m[1] + in[1] * m[4] + in[2] * m[7] + m[10];
    out[2] = in[0] * m[2] + in[1] * m[5] + in[2] * m[8] + m[11];
}

/* World space to clip space: view, then projection. */
static void to_clip(const float w[3], float clip[4]) {
    float v[3];
    mul43(g_view, w, v);
    const float *p = g_proj;
    clip[0] = v[0] * p[0] + v[1] * p[4] + v[2] * p[8] + p[12];
    clip[1] = v[0] * p[1] + v[1] * p[5] + v[2] * p[9] + p[13];
    clip[2] = v[0] * p[2] + v[1] * p[6] + v[2] * p[10] + p[14];
    clip[3] = v[0] * p[3] + v[1] * p[7] + v[2] * p[11] + p[15];
}

/* Clip space to screen pixels: viewport scale and centre, then the screen
 * offset (12.4 fixed point). */
static void to_screen(const float clip[4], vtx *o) {
    float iw = 1.0f / clip[3];
    o->x = clip[0] * iw * ge_float(R[0x42]) + ge_float(R[0x45]) - (float)(R[0x4C] & 0xFFFF) / 16.0f;
    o->y = clip[1] * iw * ge_float(R[0x43]) + ge_float(R[0x46]) - (float)(R[0x4D] & 0xFFFF) / 16.0f;
    o->z = clip[2] * iw * ge_float(R[0x44]) + ge_float(R[0x47]);
    o->w = iw;
}

static void material_or_vertex(const raw_vertex *rv, vtx *o) {
    if (rv->has_color) {
        o->r = rv->rgba[0]; o->g = rv->rgba[1]; o->b = rv->rgba[2]; o->a = rv->rgba[3];
    } else {
        /* No vertex colour: the material ambient colour and alpha. */
        uint32_t c = R[0x55], a = R[0x58] & 0xFF;
        o->r = (float)(c & 0xFF); o->g = (float)((c >> 8) & 0xFF); o->b = (float)((c >> 16) & 0xFF);
        o->a = (float)a;
    }
}

/* Texture coordinates in texels. Through mode supplies texels; transformed
 * mode supplies normalised coordinates scaled by UV scale/offset. The
 * division by w for perspective correction is undone by the rasterizer, so
 * coordinates are stored pre-multiplied by nothing here. */
static void tex_coords(const raw_vertex *rv, vtx *o) {
    if (g_through) { o->u = rv->uv[0]; o->v = rv->uv[1]; return; }
    float su = ge_float(R[0x48]), sv = ge_float(R[0x49]);
    float ou = ge_float(R[0x4A]), ov = ge_float(R[0x4B]);
    if (su == 0 && sv == 0) { su = sv = 1.0f; }
    o->u = (rv->uv[0] * su + ou) * (float)tex_w(0);
    o->v = (rv->uv[1] * sv + ov) * (float)tex_h(0);
}

/* Generated texture coordinates, texture map modes 1 and 2 (mode 0 is
 * tex_coords). Mode 1 runs a source vector -- the model-space position, the
 * texture coordinates, or the (normalised) normal, by the projection mode --
 * through the texture matrix and divides by the third component; mode 2 is
 * shade mapping from two lights. Both take the UV scale but not the offset. */
static void tex_gen(int mode, const raw_vertex *rv, const float wn[3], vtx *o) {
    float su = ge_float(R[0x48]), sv = ge_float(R[0x49]);
    if (su == 0 && sv == 0) { su = sv = 1.0f; }
    float uv[2];
    if (mode == 2) {
        psp_ge_shade_map(R, wn, uv);
    } else {
        float src[3], t[3];
        switch ((R[0xC0] >> 8) & 3) {
        case 0:  memcpy(src, rv->pos, sizeof src); break;
        case 1:  src[0] = rv->uv[0]; src[1] = rv->uv[1]; src[2] = 0.0f; break;
        case 2: {
            float l = sqrtf(rv->nrm[0] * rv->nrm[0] + rv->nrm[1] * rv->nrm[1] + rv->nrm[2] * rv->nrm[2]);
            if (l > 0) { for (int k = 0; k < 3; k++) src[k] = rv->nrm[k] / l; }
            else { src[0] = src[1] = 0.0f; src[2] = 1.0f; }
            break;
        }
        default: memcpy(src, rv->nrm, sizeof src); break;
        }
        psp_ge_mul43(g_tgen, src, t);
        /* The GE divides per pixel; the vertex divide is exact while q is
         * constant across the triangle, which is the common case (q = 1). */
        const float q = t[2] != 0.0f ? t[2] : 1.0f;
        uv[0] = t[0] / q;
        uv[1] = t[1] / q;
    }
    o->u = uv[0] * su * (float)tex_w(0);
    o->v = uv[1] * sv * (float)tex_h(0);
}

/* ---- primitive assembly ---------------------------------------------------------- */

typedef struct { vtx s; float clip[4]; } pvtx;

/* Clip a triangle against w > EPS, then rasterize the pieces. */
#define W_EPS 1e-5f

static void lerp_clip(const pvtx *a, const pvtx *b, float t, pvtx *o) {
    for (int k = 0; k < 4; k++) o->clip[k] = a->clip[k] + (b->clip[k] - a->clip[k]) * t;
    o->s.u = a->s.u + (b->s.u - a->s.u) * t; o->s.v = a->s.v + (b->s.v - a->s.v) * t;
    o->s.r = a->s.r + (b->s.r - a->s.r) * t; o->s.g = a->s.g + (b->s.g - a->s.g) * t;
    o->s.b = a->s.b + (b->s.b - a->s.b) * t; o->s.a = a->s.a + (b->s.a - a->s.a) * t;
    to_screen(o->clip, &o->s);
}

/* ---- hardware backend: collecting triangles ------------------------------------- */

static const psp_gpu_backend *g_hw;
void psp_gpu_set_backend(const psp_gpu_backend *be) { g_hw = be; }
const psp_gpu_backend *psp_gpu_get_backend(void) { return g_hw; }

static int g_collect;                    /* triangles go to g_hwv, not the rasterizer */
static psp_gpu_vertex *g_hwv;
static int g_hwn, g_hwcap;
static uint64_t g_hw_draws, g_hw_fallback;

static void hw_push(const vtx *s, const vtx *col) {
    if (g_hwn == g_hwcap) {
        int cap = g_hwcap ? g_hwcap * 2 : 4096;
        psp_gpu_vertex *nv = (psp_gpu_vertex *)realloc(g_hwv, (size_t)cap * sizeof *nv);
        if (!nv) return;
        g_hwv = nv;
        g_hwcap = cap;
    }
    psp_gpu_vertex *o = &g_hwv[g_hwn++];
    o->x = s->x; o->y = s->y; o->z = s->z; o->rhw = s->w;
    o->u = s->u; o->v = s->v;
    o->r = col->r; o->g = col->g; o->b = col->b; o->a = col->a;
}

/* One triangle, to the software rasterizer or the hardware list. Flat shading
 * takes the colour ref_tri would: the third vertex after it orders the
 * triangle counter-clockwise. */
static void tri_out(const vtx *a, const vtx *b, const vtx *c) {
    if (!g_collect) { raster_tri(a, b, c); return; }
    float area = (b->x - a->x) * (c->y - a->y) - (b->y - a->y) * (c->x - a->x);
    if (area == 0) return;
    if (R[0x50] & 1) { hw_push(a, a); hw_push(b, b); hw_push(c, c); }
    else {
        const vtx *flat = area < 0 ? b : c;
        hw_push(a, flat); hw_push(b, flat); hw_push(c, flat);
    }
}

/* A sprite as two triangles: texture coordinates run corner to corner, and
 * colour and depth are the second vertex's, as in ref_sprite. */
static void sprite_out(const vtx *a, const vtx *b) {
    if (!g_collect) { raster_sprite(a, b); return; }
    vtx v[4];
    v[0] = *b; v[0].x = a->x; v[0].y = a->y; v[0].u = a->u; v[0].v = a->v;
    v[1] = *b; v[1].x = b->x; v[1].y = a->y; v[1].u = b->u; v[1].v = a->v;
    v[2] = *b; v[2].x = a->x; v[2].y = b->y; v[2].u = a->u; v[2].v = b->v;
    v[3] = *b;
    for (int k = 0; k < 4; k++) { v[k].z = b->z; v[k].w = 1.0f; }
    hw_push(&v[0], b); hw_push(&v[1], b); hw_push(&v[2], b);
    hw_push(&v[1], b); hw_push(&v[3], b); hw_push(&v[2], b);
}

/* Back-face culling, by winding in screen space (the hardware culls after the
 * viewport transform, so a flipped viewport flips the winding as it should).
 *
 * The front-face register (0x9B) is 0 for counter-clockwise front faces and 1
 * for clockwise ones: sceGuFrontFace(GU_CCW) writes 0, GU_CW writes 1. This
 * used to be read the other way round, so every culled draw kept its back
 * faces and dropped its front ones -- PSP2i's character faces vanished from
 * the front and showed through the hair from behind, and floors seen from
 * above disappeared.
 *
 * Only vertices in front of the camera have screen positions, so the test
 * runs on the triangle after the w clip, never on one that still has a vertex
 * behind the camera (whose screen position is meaningless). */
static int culled_area(float area) {
    if (!(R[0x1D] & 1)) return 0;
    const int ccw = area < 0;                      /* screen y points down */
    const int front_is_ccw = !(R[0x9B] & 1);
    if (ccw == front_is_ccw) return 0;
    if (tl_k == 0) g_culled++;
    return 1;
}

static int culled(const vtx *a, const vtx *b, const vtx *c) {
    return culled_area((b->x - a->x) * (c->y - a->y) - (b->y - a->y) * (c->x - a->x));
}

static void emit_tri(const pvtx *a, const pvtx *b, const pvtx *c) {
    if (!g_through) {
        int in = (a->clip[3] > W_EPS) + (b->clip[3] > W_EPS) + (c->clip[3] > W_EPS);
        if (in == 0) { if (tl_k == 0) g_clipped++; return; }
        if (in < 3) {
            /* Sutherland-Hodgman against the single plane w = EPS. */
            const pvtx *v[3] = { a, b, c };
            pvtx out[4];
            int n = 0;
            for (int i = 0; i < 3; i++) {
                const pvtx *p = v[i], *q = v[(i + 1) % 3];
                int pin = p->clip[3] > W_EPS, qin = q->clip[3] > W_EPS;
                if (pin) out[n++] = *p;
                if (pin != qin) {
                    float t = (W_EPS - p->clip[3]) / (q->clip[3] - p->clip[3]);
                    lerp_clip(p, q, t, &out[n++]);
                }
            }
            if (tl_k == 0) g_clipped++;
            /* The clipped polygon is planar and convex: one winding for all. */
            float area2 = 0.0f;                    /* shoelace: twice the signed area */
            for (int i = 0; i < n; i++) {
                const vtx *p = &out[i].s, *q = &out[(i + 1) % n].s;
                area2 += p->x * q->y - q->x * p->y;
            }
            if (culled_area(area2)) return;
            for (int i = 1; i + 1 < n; i++) tri_out(&out[0].s, &out[i].s, &out[i + 1].s);
            return;
        }
        if (culled(&a->s, &b->s, &c->s)) return;
    }
    tri_out(&a->s, &b->s, &c->s);
}

static int g_null_backend(void) { return psp_render_current() == &psp_render_null; }

/* Draw `count` vertices of primitive `type` from the current vertex (and
 * index) buffers. */
static int   g_dump_req;
static long  g_dump_flip = -1;
static FILE *g_dump_file;

/* Describe every draw of the next whole frame into `path` (F12 in the host
 * window). Same format as PSP2I_GE_DUMP_FLIP, which goes to stderr. */
void psp_gpu_dump_next_frame(const char *path) {
    if (g_dump_req) return;                      /* one at a time */
    g_dump_file = fopen(path, "w");
    if (!g_dump_file) { fprintf(stderr, "ge-dump: cannot write %s\n", path); return; }
    g_dump_req = 1;
    g_dump_flip = -1;
    fprintf(stderr, "ge-dump: next frame -> %s\n", path);
}

/* PSP2I_GE_DUMP_FLIP=N: describe every draw of frame N (counted in display
 * flips) -- target, vertex format, primitive, texture, state, and for
 * transformed geometry the first vertices in clip space. */
static void dump_draw(uint32_t type, uint32_t n, const pvtx *buf) {
    static long want = -2, want_vb = -2;
    if (want == -2) { const char *e = getenv("PSP2I_GE_DUMP_FLIP"); want = e ? atol(e) : -1; }
    /* PSP2I_GE_DUMP_VBLANK=N: the first whole frame after vblank N (flip
     * numbers drift with loading times; vblanks line up with --press). */
    if (want_vb == -2) { const char *e = getenv("PSP2I_GE_DUMP_VBLANK"); want_vb = e ? atol(e) : -1; }
    if (want_vb >= 0 && want < 0 && psp_sched_vblank_count() >= (uint64_t)want_vb)
        want = (long)psp_display_flips() + 1;
    /* psp_gpu_dump_next_frame(): one frame on request, into a file. */
    if (g_dump_req) {
        if (g_dump_flip < 0) g_dump_flip = (long)psp_display_flips() + 1;
        if (psp_display_flips() > (uint64_t)g_dump_flip) {
            if (g_dump_file) { fclose(g_dump_file); g_dump_file = NULL; }
            fprintf(stderr, "ge-dump: frame %ld written\n", g_dump_flip);
            g_dump_req = 0; g_dump_flip = -1;
        }
    }
    FILE *out = stderr;
    if (g_dump_req && g_dump_file && psp_display_flips() == (uint64_t)g_dump_flip) out = g_dump_file;
    else if (want < 0 || psp_display_flips() != (uint64_t)want) return;
    const uint32_t vt = R[0x12];
    fprintf(out, "ge-dump: prim %u x%u fb 0x%06X/%u fmt %d z 0x%06X/%u vt 0x%06X%s%s%s%s%s%s%s",
            type, n, R[0x9C] & 0x1FFFF0u, R[0x9D] & 0x7FC, g_psm, R[0x9E] & 0x1FFFF0u, g_zbw, vt,
            VT_THROUGH(vt) ? " through" : "", g_clear ? " CLEAR" : "", (R[0x21] & 1) ? " blend" : "",
            (R[0x23] & 1) ? " ztest" : "", (R[0x22] & 1) ? " atest" : "", (R[0x17] & 1) ? " light" : "",
            (R[0x1D] & 1) ? " cull" : "");
    if (g_tex)
        fprintf(out, " tex 0x%08X psm %u %ux%u bufw %u", tex_addr(0), R[0xC3] & 0xF, tex_w(0), tex_h(0), tex_bufw(0));
    fprintf(out, " scissor %d,%d-%d,%d\n", g_sx0, g_sy0, g_sx1, g_sy1);
    /* The state that decides how a UI quad looks: texture function and env
     * colour, blending and fixed colours, alpha test, colour test, write
     * masks, material colour for colourless vertices, shading, CLUT mode,
     * texture filter and wrap. */
    fprintf(out, "    state tfunc 0x%06X env 0x%06X blend 0x%06X fix %06X/%06X atest 0x%06X ctest %u "
                 "mask rgb %06X a %02X zmask %u mat 0x%06X/%02X shade %u clut 0x%06X tflt 0x%06X twrap 0x%06X\n",
            R[0xC9], R[0xCA] & 0xFFFFFF, R[0xDF], R[0xE0] & 0xFFFFFF, R[0xE1] & 0xFFFFFF, R[0xDB],
            R[0x27] & 1, R[0xE8] & 0xFFFFFF, R[0xE9] & 0xFF, R[0xE7] & 1, R[0x55] & 0xFFFFFF, R[0x58] & 0xFF,
            R[0x50] & 1, R[0xC5], R[0xC6], R[0xC7]);
    for (uint32_t i = 0; i < n && i < 3; i++) {
        const pvtx *p = &buf[i];
        fprintf(out, "    v%u screen (%.1f, %.1f, z %.0f) uv (%.2f, %.2f) rgba (%.0f %.0f %.0f %.0f) clip (%.2f %.2f %.2f w %.3f)\n",
                i, p->s.x, p->s.y, p->s.z, p->s.u, p->s.v, p->s.r, p->s.g, p->s.b, p->s.a,
                p->clip[0], p->clip[1], p->clip[2], p->clip[3]);
    }
    if (!VT_THROUGH(vt)) {
        static uint64_t last;
        if (last != psp_display_flips()) {
            last = psp_display_flips();
            fprintf(out, "    world  %.3f %.3f %.3f | %.3f %.3f %.3f | %.3f %.3f %.3f | t %.3f %.3f %.3f\n",
                    g_world[0], g_world[1], g_world[2], g_world[3], g_world[4], g_world[5],
                    g_world[6], g_world[7], g_world[8], g_world[9], g_world[10], g_world[11]);
            fprintf(out, "    view   %.3f %.3f %.3f | %.3f %.3f %.3f | %.3f %.3f %.3f | t %.3f %.3f %.3f\n",
                    g_view[0], g_view[1], g_view[2], g_view[3], g_view[4], g_view[5],
                    g_view[6], g_view[7], g_view[8], g_view[9], g_view[10], g_view[11]);
            fprintf(out, "    proj   %.3f %.3f %.3f %.3f | %.3f %.3f %.3f %.3f | %.3f %.3f %.3f %.3f | %.3f %.3f %.3f %.3f\n",
                    g_proj[0], g_proj[1], g_proj[2], g_proj[3], g_proj[4], g_proj[5], g_proj[6], g_proj[7],
                    g_proj[8], g_proj[9], g_proj[10], g_proj[11], g_proj[12], g_proj[13], g_proj[14], g_proj[15]);
            fprintf(out, "    viewport scale %.1f %.1f %.1f centre %.1f %.1f %.1f offset %.1f %.1f\n",
                    ge_float(R[0x42]), ge_float(R[0x43]), ge_float(R[0x44]),
                    ge_float(R[0x45]), ge_float(R[0x46]), ge_float(R[0x47]),
                    (R[0x4C] & 0xFFFF) / 16.0, (R[0x4D] & 0xFFFF) / 16.0);
        }
    }
}

/* A PRIM count is 16 bits, so one buffer holds any primitive whole --
 * strips and fans never need stitching across batches. */
static pvtx g_vbuf[65536];
static int g_verify = -1;
static void rasterize(uint32_t type, const pvtx *buf, uint32_t n);
static void verify_rasterize(uint32_t type, const pvtx *buf, uint32_t n);
static int hw_draw(uint32_t type, const pvtx *buf, uint32_t n);

void psp_gpu_prim(uint32_t type, uint32_t count, uint32_t vaddr, uint32_t iaddr) {
    const uint32_t vt = R[0x12];
    layout L;
    make_layout(vt, &L);
    if (L.p_off < 0 || !L.stride || !count) return;
    g_through = (int)VT_THROUGH(vt);
    g_prims++;
    if (g_null_backend()) return;
    setup_draw();

    pvtx *buf = g_vbuf;
    const int morph_stride = L.stride * (int)VT_MORPH(vt);
    const int itype = (int)VT_INDEX(vt);
    const uint32_t n = count;

    /* Transformed geometry: skinning (with a weight format), lighting and
     * generated texture coordinates, all in ge_vertex.c. */
    const int skin = !g_through && L.w_off >= 0;
    const int lit = !g_through && (R[0x17] & 1);
    const int map_mode = g_through ? 0 : (int)(R[0xC0] & 3);
    psp_ge_lighting light;
    if (lit) psp_ge_lighting_from_regs(R, L.c_off >= 0, &light);

    for (uint32_t i = 0; i < n; i++) {
        uint32_t idx = i;
        if (itype == 1) idx = rd8(iaddr + i);
        else if (itype == 2) idx = rd16(iaddr + i * 2);
        else if (itype == 3) idx = rd32(iaddr + i * 4);
        raw_vertex rv;
        read_one(vaddr + idx * (uint32_t)morph_stride, vt, &L, &rv);
        pvtx *o = &buf[i];
        memset(o, 0, sizeof *o);
        material_or_vertex(&rv, &o->s);
        if (g_through) {
            tex_coords(&rv, &o->s);
            o->s.x = rv.pos[0]; o->s.y = rv.pos[1]; o->s.z = rv.pos[2]; o->s.w = 1.0f;
            o->clip[3] = 1.0f;
        } else {
            float mp[3], mn[3], wp[3], wn[3] = { 0, 0, 1 };
            if (skin) psp_ge_skin(g_bone, rv.w, (int)VT_NWEIGHT(vt), rv.pos, rv.nrm, mp, mn);
            else { memcpy(mp, rv.pos, sizeof mp); memcpy(mn, rv.nrm, sizeof mn); }
            psp_ge_mul43(g_world, mp, wp);
            if (lit || map_mode == 2) {
                if (R[0x51] & 1) for (int k = 0; k < 3; k++) mn[k] = -mn[k];   /* reverse normals */
                psp_ge_mul33(g_world, mn, wn);
                float l = sqrtf(wn[0] * wn[0] + wn[1] * wn[1] + wn[2] * wn[2]);
                if (l > 0) for (int k = 0; k < 3; k++) wn[k] /= l;
            }
            if (lit) {
                const float in[4] = { o->s.r / 255.0f, o->s.g / 255.0f, o->s.b / 255.0f, o->s.a / 255.0f };
                float c[4];
                psp_ge_light(&light, in, wp, wn, c);
                o->s.r = c[0] * 255.0f; o->s.g = c[1] * 255.0f; o->s.b = c[2] * 255.0f; o->s.a = c[3] * 255.0f;
            }
            if (map_mode == 1 || map_mode == 2) tex_gen(map_mode, &rv, wn, &o->s);
            else tex_coords(&rv, &o->s);
            to_clip(wp, o->clip);
            if (o->clip[3] > W_EPS) to_screen(o->clip, &o->s);
            else o->s.w = 0;
        }
    }

    dump_draw(type, n, buf);
    if (g_hw && !g_ref) { hw_draw(type, buf, n); return; }
    /* PSP2I_GPU_VERIFY=N checks every Nth primitive (1 = all of them). */
    if (g_verify < 0) { const char *e = getenv("PSP2I_GPU_VERIFY"); g_verify = e ? (atoi(e) > 0 ? atoi(e) : 1) : 0; }
    static uint64_t nth;
    if (g_verify && nth++ % (uint64_t)g_verify == 0) verify_rasterize(type, buf, n);
    else rasterize(type, buf, n);
}

/* ---- the worker pool -------------------------------------------------------------- */

static void rasterize_rows(uint32_t type, const pvtx *buf, uint32_t n);

static struct {
    uint32_t type, n;
    const pvtx *buf;
    unsigned mxcsr;
} g_job;
static int g_nworkers = -1;              /* threads drawing, including the caller */
static uint64_t g_parallel_draws, g_serial_draws;

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
static HANDLE g_go[GPU_MAX_WORKERS];
static volatile LONG g_pending;

static DWORD WINAPI raster_worker(LPVOID arg) {
    const int k = (int)(intptr_t)arg;
    for (;;) {
        WaitForSingleObject(g_go[k], INFINITE);
        tl_k = k;
        tl_n = g_nworkers;
        _mm_setcsr(g_job.mxcsr);        /* identical float behaviour to the caller */
        rasterize_rows(g_job.type, g_job.buf, g_job.n);
        InterlockedDecrement(&g_pending);
    }
}

static void pool_init(void) {
    const char *env = getenv("PSP2I_RENDER_THREADS");
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    int n = env ? atoi(env) : (int)si.dwNumberOfProcessors / 2;    /* physical cores, roughly */
    if (n < 1) n = 1;
    if (n > GPU_MAX_WORKERS) n = GPU_MAX_WORKERS;
    for (int k = 1; k < n; k++) {
        g_go[k] = CreateEventA(NULL, FALSE, FALSE, NULL);
        HANDLE t = g_go[k] ? CreateThread(NULL, 0, raster_worker, (LPVOID)(intptr_t)k, 0, NULL) : NULL;
        if (!t) { n = k; break; }
        CloseHandle(t);
    }
    g_nworkers = n;
}

static void run_parallel(uint32_t type, const pvtx *buf, uint32_t n) {
    g_job.type = type; g_job.buf = buf; g_job.n = n; g_job.mxcsr = _mm_getcsr();
    g_pending = g_nworkers - 1;
    for (int k = 1; k < g_nworkers; k++) SetEvent(g_go[k]);
    tl_k = 0; tl_n = g_nworkers;
    rasterize_rows(type, buf, n);
    while (g_pending) YieldProcessor();
    tl_k = 0; tl_n = 1;
}
#else
static void pool_init(void) { g_nworkers = 1; }
static void run_parallel(uint32_t type, const pvtx *buf, uint32_t n) { rasterize_rows(type, buf, n); }
#endif

/* Rough pixel area of a primitive, to keep small draws on one thread where
 * waking the workers would cost more than it saves. */
static uint32_t draw_area(uint32_t type, const pvtx *buf, uint32_t n) {
    float area = 0;
    uint32_t step = type == 6 ? 2 : 1;
    for (uint32_t i = 0; i + 1 < n; i += step) {
        float w = fabsf(buf[i + 1].s.x - buf[i].s.x), h = fabsf(buf[i + 1].s.y - buf[i].s.y);
        if (w > 512) w = 512;
        if (h > 512) h = 512;
        area += type == 6 ? w * h : w * h * 0.5f;
        if (area > 1e7f) break;
    }
    return (uint32_t)area;
}

static void fold_counters(void) {
    for (int k = 0; k < GPU_MAX_WORKERS; k++) {
        worker_counters *w = &g_wc[k];
        g_pixels += w->pixels; c_tested += w->tested; c_shaded += w->shaded;
        c_textured += w->textured; c_linear += w->linear; c_sprite_px += w->sprite;
        c_tri_px += w->tri; c_blend += w->blend; c_clear += w->clear;
        memset(w, 0, sizeof *w);
    }
}

/* Rasterize an assembled primitive. */
static void rasterize(uint32_t type, const pvtx *buf, uint32_t n) {
    fast_setup();
    if (g_nworkers < 0) pool_init();
    const int splittable = F.ok && type >= 3 && type <= 6;
    if (splittable && g_nworkers > 1 && draw_area(type, buf, n) >= 4096) {
        g_parallel_draws++;
        run_parallel(type, buf, n);
    } else {
        g_serial_draws++;
        rasterize_rows(type, buf, n);
    }
    fold_counters();
}

/* Rasterize the rows of the primitive that belong to this worker (all rows
 * when tl_n is 1). Points and lines are never split. */
static void rasterize_rows(uint32_t type, const pvtx *buf, uint32_t n) {
    switch (type) {
    case 0:                                             /* points */
        for (uint32_t i = 0; i < n; i++)
            if (buf[i].clip[3] > W_EPS)
                fragment((int)buf[i].s.x, (int)buf[i].s.y, buf[i].s.z, shade(&buf[i].s, buf[i].s.u, buf[i].s.v));
        break;
    case 1:                                             /* lines */
        for (uint32_t i = 0; i + 1 < n; i += 2) raster_line(&buf[i].s, &buf[i + 1].s);
        break;
    case 2:                                             /* line strip */
        for (uint32_t i = 0; i + 1 < n; i++) raster_line(&buf[i].s, &buf[i + 1].s);
        break;
    case 3:                                             /* triangles */
        for (uint32_t i = 0; i + 2 < n; i += 3) emit_tri(&buf[i], &buf[i + 1], &buf[i + 2]);
        break;
    case 4:                                             /* strip: alternate winding */
        for (uint32_t i = 0; i + 2 < n; i++) {
            if (i & 1) emit_tri(&buf[i + 1], &buf[i], &buf[i + 2]);
            else       emit_tri(&buf[i], &buf[i + 1], &buf[i + 2]);
        }
        break;
    case 5:                                             /* fan */
        for (uint32_t i = 1; i + 1 < n; i++) emit_tri(&buf[0], &buf[i], &buf[i + 1]);
        break;
    case 6:                                             /* sprites */
        for (uint32_t i = 0; i + 1 < n; i += 2)
            if (buf[i].clip[3] > W_EPS && buf[i + 1].clip[3] > W_EPS)
                sprite_out(&buf[i].s, &buf[i + 1].s);
        break;
    default:
        break;
    }
}


/* PSP2I_GPU_VERIFY: draw the primitive with the reference path, keep the
 * result, restore VRAM, draw it again with the fast path, and compare. Every
 * byte the two disagree on is counted; the first few primitives that differ
 * are described. Drawing only ever writes VRAM (colour and depth buffers), so
 * comparing VRAM compares everything. */
static uint64_t g_verify_prims, g_verify_bad_prims, g_verify_bad_bytes;

static void verify_rasterize(uint32_t type, const pvtx *buf, uint32_t n) {
    static uint8_t *snap, *refout;
    uint8_t *vram = (uint8_t *)psp_mem_ptr(PSP_VRAM_BASE, PSP_VRAM_SIZE);
    if (!snap) { snap = (uint8_t *)malloc(PSP_VRAM_SIZE); refout = (uint8_t *)malloc(PSP_VRAM_SIZE); }
    if (!vram || !snap || !refout) { rasterize(type, buf, n); return; }
    memcpy(snap, vram, PSP_VRAM_SIZE);
    const uint64_t px0 = g_pixels;
    g_ref = 1;
    rasterize(type, buf, n);
    g_ref = 0;
    memcpy(refout, vram, PSP_VRAM_SIZE);
    memcpy(vram, snap, PSP_VRAM_SIZE);
    const uint64_t px_ref = g_pixels - px0;
    g_pixels = px0;
    rasterize(type, buf, n);
    g_verify_prims++;
    if (memcmp(vram, refout, PSP_VRAM_SIZE) != 0 || g_pixels - px0 != px_ref) {
        uint64_t bad = 0;
        uint32_t first = 0xFFFFFFFFu;
        for (uint32_t i = 0; i < PSP_VRAM_SIZE; i++)
            if (vram[i] != refout[i]) { if (first == 0xFFFFFFFFu) first = i; bad++; }
        g_verify_bad_bytes += bad;
        if (g_verify_bad_prims++ < 8)
            fprintf(stderr, "gpu verify: prim type %u x%u differs: %llu bytes, first at VRAM+0x%X "
                            "(ref 0x%02X fast 0x%02X); pixels ref %llu fast %llu; tex %d psm %u fbpsm %d\n",
                    type, n, (unsigned long long)bad, first,
                    first != 0xFFFFFFFFu ? refout[first] : 0, first != 0xFFFFFFFFu ? vram[first] : 0,
                    (unsigned long long)px_ref, (unsigned long long)(g_pixels - px0),
                    g_tex, R[0xC3] & 0xF, g_psm);
    }
}

uint64_t psp_gpu_verify_report(FILE *out) {
    if (g_verify > 0)
        fprintf(out, "    gpu verify: %llu primitives compared, %llu differed (%llu bytes)\n",
                (unsigned long long)g_verify_prims, (unsigned long long)g_verify_bad_prims,
                (unsigned long long)g_verify_bad_bytes);
    return g_verify_bad_prims;
}

/* ---- hardware backend: draw state and helpers ------------------------------------ */

static void fill_hw_state(psp_gpu_state *st) {
    memset(st, 0, sizeof *st);
    st->fb_addr = g_fb; st->fb_stride = g_fbw; st->fb_fmt = g_psm;
    st->zb_addr = g_zb; st->zb_stride = g_zbw;
    st->sx0 = g_sx0; st->sy0 = g_sy0; st->sx1 = g_sx1; st->sy1 = g_sy1;
    st->clear = g_clear;
    st->clear_which = (R[0xD3] >> 8) & 7;
    st->tex = g_tex;
    if (g_tex) {
        st->tex_addr = tex_addr(0); st->tex_w = tex_w(0); st->tex_h = tex_h(0);
        st->tex_bufw = tex_bufw(0);
        st->tex_psm = (int)(R[0xC3] & 0xF); st->tex_swz = (int)(R[0xC2] & 1);
        uint64_t k = (uint64_t)st->tex_addr;
        k = k * 1099511628211ull ^ ((uint64_t)st->tex_psm << 1 | (uint64_t)st->tex_swz);
        k = k * 1099511628211ull ^ ((uint64_t)st->tex_w << 16 | st->tex_h);
        k = k * 1099511628211ull ^ st->tex_bufw;
        /* CLUT formats: the CLUT mode AND the palette's contents. Without the
         * contents a backend that validates a texture once per frame reused
         * the first palette for every later draw of the same image that
         * frame -- PSP2i recolours its CLUT4 UI atlas per element, so after
         * its save flow changed the palette order, dialogue text came out
         * black and the HUD frame, prompt boxes and highlights vanished. */
        if (st->tex_psm >= 4 && st->tex_psm <= 7) {
            k = k * 1099511628211ull ^ (R[0xC5] | 0x100000000ull);
            k = k * 1099511628211ull ^ g_clut_hash;
        }
        st->tex_key = k;
        st->tex_linear = (int)((R[0xC6] >> 8) & 1);
        st->tex_clamp_u = (int)(R[0xC7] & 1); st->tex_clamp_v = (int)((R[0xC7] >> 8) & 1);
        st->tfunc = (int)(R[0xC9] & 7); st->trgba = (int)((R[0xC9] >> 8) & 1);
        st->tdbl = (int)((R[0xC9] >> 16) & 1);
        st->env = R[0xCA] & 0xFFFFFF;
    }
    st->atest = (int)(R[0x22] & 1);
    st->afunc = (int)(R[0xDB] & 7); st->aref = (R[0xDB] >> 8) & 0xFF; st->amask = (R[0xDB] >> 16) & 0xFF;
    st->ztest = (int)(R[0x23] & 1); st->zfunc = (int)(R[0xDE] & 7); st->zwrite = !(R[0xE7] & 1);
    st->blend = (int)(R[0x21] & 1);
    st->bsrc = (int)(R[0xDF] & 0xF); st->bdst = (int)((R[0xDF] >> 4) & 0xF); st->beq = (int)((R[0xDF] >> 8) & 0xF);
    st->fixa = R[0xE0] & 0xFFFFFF; st->fixb = R[0xE1] & 0xFFFFFF;
    st->mask_rgb = R[0xE8] & 0xFFFFFF; st->mask_a = R[0xE9] & 0xFF;
}

void psp_gpu_decode_texture(uint32_t *out) {
    const uint32_t w = tex_w(0), h = tex_h(0);
    fast_setup();                                  /* cached texture pointer and palette */
    for (uint32_t y = 0; y < h; y++)
        for (uint32_t x = 0; x < w; x++)
            out[y * w + x] = F.ok && g_tex ? fast_texel(x, y) : fetch_texel(x, y);
}

static uint64_t hash_bytes(uint64_t h, const uint8_t *p, size_t n) {
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t v;
        memcpy(&v, p + i, 8);
        h = (h ^ v) * 0x9E3779B97F4A7C15ull;
        h ^= h >> 29;
    }
    for (; i < n; i++) h = (h ^ p[i]) * 0x100000001B3ull;
    return h;
}

uint64_t psp_gpu_texture_hash(void) {
    static const int bpp_of[11] = { 16, 16, 16, 32, 4, 8, 16, 32, 4, 8, 8 };
    const int psm = (int)(R[0xC3] & 0xF);
    const uint32_t w = tex_w(0), h = tex_h(0), bufw = tex_bufw(0);
    uint32_t bytes;
    if (psm >= 8) bytes = (bufw / 4 ? bufw / 4 : 1) * (h / 4 ? h / 4 : 1) * (psm == 8 ? 8u : 16u);
    else bytes = tex_extent(w, h, bufw ? bufw : 1, bpp_of[psm > 10 ? 3 : psm], (int)(R[0xC2] & 1));
    uint64_t hsh = 0xCBF29CE484222325ull;
    const uint8_t *p = mem(tex_addr(0), bytes);
    if (p) hsh = hash_bytes(hsh, p, bytes);
    if (psm >= 4 && psm <= 7) hsh = hash_bytes(hsh, g_clut, sizeof g_clut) ^ R[0xC5];
    return hsh;
}

/* Bytes of the colour buffer the scissor can reach (for coherence hooks). */
static uint32_t fb_span(void) { return ((uint32_t)g_sy1 + 1) * g_fbw * (g_psm == 3 ? 4u : 2u); }
static uint32_t zb_span(void) { return ((uint32_t)g_sy1 + 1) * g_zbw * 2u; }

/* Draw on the hardware backend. Returns 1 if handled. Draws the backend
 * refuses, and points and lines, are rasterized in software against a VRAM
 * the backend has synchronised first and is told about afterwards. */
static int hw_draw(uint32_t type, const pvtx *buf, uint32_t n) {
    if (type >= 3 && type <= 6) {
        g_collect = 1;
        g_hwn = 0;
        rasterize_rows(type, buf, n);
        g_collect = 0;
        if (!g_hwn) return 1;
        psp_gpu_state st;
        fill_hw_state(&st);
        if (g_hw->draw(&st, g_hwv, g_hwn) == 0) { g_hw_draws++; return 1; }
        g_hw_fallback++;
    }
    if (g_fbw) g_hw->sync_vram(g_fb, fb_span());
    if (g_zbw) g_hw->sync_vram(g_zb, zb_span());
    rasterize(type, buf, n);
    if (g_fbw) g_hw->vram_written(g_fb, fb_span());
    if (g_zbw) g_hw->vram_written(g_zb, zb_span());
    return 1;
}

/* ---- block transfer ------------------------------------------------------------- */

/* A GE sync (sceGeDrawSync / sceGeListSync) is where a game may start
 * touching what the GE drew with the CPU -- the GE runs asynchronously on
 * the hardware, so no correct game reads or writes rendered VRAM before one.
 * With a hardware backend the newest pixels live in its render targets, not
 * in emulated VRAM, so make VRAM current now and have every target re-check
 * VRAM before its next draw (picking up whatever the CPU writes meanwhile).
 *
 * PSP2i copies 0xDC000 bytes of upper VRAM to RAM and back with plain loads
 * and stores around each save. Without this, D3D11 handed it stale VRAM: the
 * copy that comes back clobbered its UI atlas, and the HUD, prompt boxes and
 * menu highlights vanished (and dialogue text went black) until restart.
 * The software rasterizer draws into VRAM directly, so there it is a no-op. */
void psp_gpu_cpu_sync(void) {
    if (!g_hw) return;
    g_hw->sync_vram(PSP_VRAM_BASE, 0x200000u);
    g_hw->vram_written(PSP_VRAM_BASE, 0x200000u);
}

static void block_transfer(uint32_t arg) {
    const int bpp = (arg & 1) ? 4 : 2;
    uint32_t src = (R[0xB2] & 0xFFFFF0u) | ((R[0xB3] & 0x0F0000u) << 8);
    uint32_t dst = (R[0xB4] & 0xFFFFF0u) | ((R[0xB5] & 0x0F0000u) << 8);
    uint32_t sw = R[0xB3] & 0x7FF, dw = R[0xB5] & 0x7FF;
    uint32_t sx = R[0xEB] & 0x3FF, sy = (R[0xEB] >> 10) & 0x3FF;
    uint32_t dx = R[0xEC] & 0x3FF, dy = (R[0xEC] >> 10) & 0x3FF;
    uint32_t w = (R[0xEE] & 0x3FF) + 1, h = ((R[0xEE] >> 10) & 0x3FF) + 1;
    if (g_hw) g_hw->sync_vram(src, ((sy + h) * sw) * (uint32_t)bpp);
    /* The destination too: a backend render target over these bytes may be
     * ahead of VRAM, and its next readback writes whole rows -- it would
     * overwrite what this transfer stores. Flushing first makes VRAM hold
     * both, and vram_written below has the target pick the result up.
     * Without it PSP2i's save flow, which parks its UI atlas in VRAM inside
     * the scene target's rows and copies it back afterwards, got stale
     * pixels back on D3D11: HUD, prompt boxes and highlights vanished and
     * dialogue text turned black for the rest of the session. */
    if (g_hw) g_hw->sync_vram(dst, ((dy + h) * dw) * (uint32_t)bpp);
    for (uint32_t y = 0; y < h; y++) {
        uint8_t *s = mem(src + ((sy + y) * sw + sx) * (uint32_t)bpp, w * (uint32_t)bpp);
        uint8_t *d = mem(dst + ((dy + y) * dw + dx) * (uint32_t)bpp, w * (uint32_t)bpp);
        if (s && d) memmove(d, s, w * (uint32_t)bpp);
    }
    if (g_hw) g_hw->vram_written(dst, ((dy + h) * dw) * (uint32_t)bpp);
}

/* ---- state commands -------------------------------------------------------------- */

/* Store a state command. Matrix uploads, CLUT loads and transfers act on the
 * write; everything else is read back from R[] when drawing. */
void psp_gpu_cmd(uint32_t cmd, uint32_t arg) {
    R[cmd & 0xFF] = arg;
    switch (cmd) {
    case 0x2A: g_bone_i = arg % 96; break;
    case 0x2B: g_bone[g_bone_i] = ge_float(arg); g_bone_i = (g_bone_i + 1) % 96; break;
    case 0x3A: g_world_i = arg % 12; break;
    case 0x3B: g_world[g_world_i] = ge_float(arg); g_world_i = (g_world_i + 1) % 12; break;
    case 0x3C: g_view_i = arg % 12; break;
    case 0x3D: g_view[g_view_i] = ge_float(arg); g_view_i = (g_view_i + 1) % 12; break;
    case 0x3E: g_proj_i = arg % 16; break;
    case 0x3F: g_proj[g_proj_i] = ge_float(arg); g_proj_i = (g_proj_i + 1) % 16; break;
    case 0x40: g_tgen_i = arg % 12; break;
    case 0x41: g_tgen[g_tgen_i] = ge_float(arg); g_tgen_i = (g_tgen_i + 1) % 12; break;
    case 0xC4: {                                        /* CLOAD: copy CLUT entries now */
        uint32_t n = (arg & 0x3F) * 32;
        uint32_t src = (R[0xB0] & 0xFFFFF0u) | ((R[0xB1] & 0x0F0000u) << 8);
        uint8_t *p = mem(src, n);
        if (p && n <= sizeof g_clut) memcpy(g_clut, p, n);
        /* Hash the palette now, so the texture key can carry it (see
         * fill_hw_state): one CLUT4/8 image drawn with different palettes is
         * a different texture to a backend's cache. */
        uint64_t h = 0xCBF29CE484222325ull;
        for (size_t i = 0; i < sizeof g_clut; i++) h = (h ^ g_clut[i]) * 1099511628211ull;
        g_clut_hash = h;
        break;
    }
    case 0xEA: block_transfer(arg); break;
    case 0x05: case 0x06: g_unsup_patch++; break;
    default: break;
    }
}

uint32_t psp_gpu_reg(uint32_t cmd) { return R[cmd & 0xFF]; }

void psp_gpu_dump_stats(FILE *out) {
    psp_gpu_verify_report(out);
    fprintf(out, "    raster work: tri bbox tested %llu, tri px %llu, sprite px %llu, shaded %llu, textured %llu (bilinear %llu), blended %llu, clear px %llu\n",
            (unsigned long long)c_tested, (unsigned long long)c_tri_px, (unsigned long long)c_sprite_px,
            (unsigned long long)c_shaded, (unsigned long long)c_textured, (unsigned long long)c_linear,
            (unsigned long long)c_blend, (unsigned long long)c_clear);
    if (g_hw) fprintf(out, "    hardware backend %s: %llu draws, %llu fell back to software\n", g_hw->name,
            (unsigned long long)g_hw_draws, (unsigned long long)g_hw_fallback);
    fprintf(out, "    render threads %d; draws split across them %llu, drawn on one %llu\n",
            g_nworkers, (unsigned long long)g_parallel_draws, (unsigned long long)g_serial_draws);
    fprintf(out, "    draws %llu (%llu textured), %llu triangles culled, %llu clipped\n",
            (unsigned long long)g_prims, (unsigned long long)g_texdraws,
            (unsigned long long)g_culled, (unsigned long long)g_clipped);
    if (g_unsup_light || g_unsup_fog || g_unsup_stencil || g_unsup_ctest || g_unsup_logic || g_unsup_patch)
        fprintf(out, "    drawn without: lighting %llu, fog %llu, stencil %llu, colour test %llu, "
                     "logic op %llu; patches skipped %llu\n",
                (unsigned long long)g_unsup_light, (unsigned long long)g_unsup_fog,
                (unsigned long long)g_unsup_stencil, (unsigned long long)g_unsup_ctest,
                (unsigned long long)g_unsup_logic, (unsigned long long)g_unsup_patch);
}

/* Bytes one PRIM of `count` vertices consumes, for the auto-advancing vertex
 * and index pointers. */
uint32_t psp_gpu_vertex_bytes(uint32_t count) {
    layout L;
    make_layout(R[0x12], &L);
    return count * (uint32_t)L.stride * (uint32_t)VT_MORPH(R[0x12]);
}

uint32_t psp_gpu_index_bytes(uint32_t count) {
    uint32_t t = VT_INDEX(R[0x12]);
    return count * (t == 1 ? 1u : t == 2 ? 2u : 4u);
}
