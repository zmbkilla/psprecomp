/* Rasterizer tests — display list in, pixels out.
 *
 * These use hand-built display lists rather than game data, which is the point:
 * the game cannot yet reach its own draw calls, so waiting for it to render
 * would leave this code completely unmeasured until the last blocker clears.
 * A synthetic list exercises the same path the game will take.
 *
 * The checks are on *where* pixels land, not just how many. A rasterizer that
 * fills the whole screen and one that fills the right rectangle both report a
 * nonzero pixel count, and only one of them is correct.
 */

#include "psprecomp/hle.h"
#include "psprecomp/render.h"
#include "psprecomp/mem.h"
#include "psprecomp/cpu.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        if (!(cond)) {                                         \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);        \
            printf(__VA_ARGS__);                               \
            printf("\n");                                      \
            failures++;                                        \
        }                                                      \
    } while (0)

#define FB     0x04000000u          /* eDRAM */
#define LIST   0x08800000u
#define VERTS  0x08810000u

/* VTYPE: 8888 colour, 16-bit position, through mode. */
#define VTYPE_2D  ((7u << 2) | (2u << 7) | (1u << 23))

static uint32_t call(uint32_t nid, uint32_t a0, uint32_t a1, uint32_t a2,
                     uint32_t a3) {
    psp_cpu.r[PSP_REG_A0] = a0;
    psp_cpu.r[PSP_REG_A1] = a1;
    psp_cpu.r[PSP_REG_A2] = a2;
    psp_cpu.r[PSP_REG_A3] = a3;
    psp_hle_call(nid);
    return psp_cpu.r[PSP_REG_V0];
}

static uint32_t *g_list;
static uint32_t g_pc;

static void cmd(uint8_t op, uint32_t arg) {
    psp_write32(LIST + g_pc, ((uint32_t)op << 24) | (arg & 0xFFFFFF));
    g_pc += 4;
}

static void begin_list(void) {
    g_pc = 0;
    (void)g_list;
    /* Addresses do not fit in a 24-bit argument. FBP carries the low 24 bits
     * and FBW smuggles bits 24-31 in its own top byte; VADDR is relative to
     * GE_BASE. Getting this wrong yields a plausible-looking address and
     * silently draws nothing. */
    cmd(0x10, (VERTS >> 8) & 0xFF0000);            /* BASE */
    cmd(0x9C, FB & 0xFFFFFF);                      /* FBP */
    cmd(0x9D, ((FB >> 8) & 0xFF0000) | 480);       /* FBW + address high byte */
    cmd(0x12, VTYPE_2D);                           /* VTYPE */
    cmd(0x01, VERTS & 0xFFFFFF);                   /* VADDR */
}

static void end_list(void) {
    cmd(0x0F, 0);                    /* FINISH */
    cmd(0x0C, 0);                    /* END */
    call(0xAB49E76A, LIST, 0, 0, 0); /* sceGeListEnQueue */
}

/* One 16-bit-position, 8888-colour vertex. Colour precedes position. */
static void vertex(int idx, int x, int y, uint32_t rgba) {
    uint32_t a = VERTS + (uint32_t)idx * 12;   /* 4 colour + 6 pos, padded to 12 */
    psp_write32(a, rgba);
    psp_write16(a + 4, (uint16_t)x);
    psp_write16(a + 6, (uint16_t)y);
    psp_write16(a + 8, 0);
}

static uint32_t pixel(int x, int y) {
    return psp_read32(FB + (uint32_t)(y * 480 + x) * 4);
}

static void clear_fb(void) {
    for (int y = 0; y < 272; y++)
        for (int x = 0; x < 480; x++)
            psp_write32(FB + (uint32_t)(y * 480 + x) * 4, 0);
}

/* A sprite is the PSP's 2D quad: two vertices, opposite corners. */
static void test_sprite(void) {
    psp_ge_reset();
    clear_fb();
    begin_list();
    vertex(0, 100, 50, 0xFF0000FFu);
    vertex(1, 200, 150, 0xFF0000FFu);
    cmd(0x04, (6u << 16) | 2);       /* PRIM sprites, 2 vertices */
    end_list();

    CHECK(psp_ge_pixels() == 100 * 100, "sprite pixel count: %llu (want 10000)",
          (unsigned long long)psp_ge_pixels());
    CHECK(pixel(150, 100) == 0xFF0000FFu, "sprite interior: 0x%08X", pixel(150, 100));
    CHECK(pixel(99, 100) == 0, "left of sprite should be untouched: 0x%08X", pixel(99, 100));
    CHECK(pixel(150, 49) == 0, "above sprite should be untouched: 0x%08X", pixel(150, 49));
    /* Half-open on the far edge, so adjacent sprites tile without overlapping. */
    CHECK(pixel(200, 100) == 0, "far edge is exclusive: 0x%08X", pixel(200, 100));
}

static void test_triangle(void) {
    psp_ge_reset();
    clear_fb();
    begin_list();
    vertex(0, 10, 10, 0xFF00FF00u);
    vertex(1, 110, 10, 0xFF00FF00u);
    vertex(2, 10, 110, 0xFF00FF00u);
    cmd(0x04, (3u << 16) | 3);       /* PRIM triangles */
    end_list();

    CHECK(psp_ge_pixels() > 4000, "triangle should cover ~5000 px, got %llu",
          (unsigned long long)psp_ge_pixels());
    CHECK(pixel(20, 20) == 0xFF00FF00u, "inside triangle: 0x%08X", pixel(20, 20));
    /* The hypotenuse runs from (110,10) to (10,110); (100,100) is well past it. */
    CHECK(pixel(100, 100) == 0, "outside hypotenuse: 0x%08X", pixel(100, 100));
}

/* Winding must not matter while back-face culling is unimplemented, or half of
 * any real model silently disappears. */
static void test_winding(void) {
    psp_ge_reset();
    clear_fb();
    begin_list();
    vertex(0, 10, 10, 0xFFFFFFFFu);
    vertex(1, 10, 110, 0xFFFFFFFFu);
    vertex(2, 110, 10, 0xFFFFFFFFu);
    cmd(0x04, (3u << 16) | 3);
    end_list();
    CHECK(pixel(20, 20) == 0xFFFFFFFFu, "reversed winding still fills: 0x%08X",
          pixel(20, 20));
}

/* Off-screen geometry must clip, not scribble outside the framebuffer or wrap
 * to the opposite edge. */
static void test_clipping(void) {
    psp_ge_reset();
    clear_fb();
    begin_list();
    vertex(0, -50, -50, 0xFFFF0000u);
    vertex(1, 50, 50, 0xFFFF0000u);
    cmd(0x04, (6u << 16) | 2);
    end_list();

    CHECK(psp_ge_pixels() == 50 * 50, "clipped sprite: %llu (want 2500)",
          (unsigned long long)psp_ge_pixels());
    CHECK(pixel(0, 0) == 0xFFFF0000u, "clipped sprite covers origin");
    CHECK(pixel(479, 271) == 0, "far corner untouched: 0x%08X", pixel(479, 271));
}

/* Transformed geometry is not implemented. It must be *counted*, not drawn at
 * the wrong place — wrong pixels are harder to diagnose than no pixels. */
static void test_transformed_is_skipped(void) {
    psp_ge_reset();
    clear_fb();
    g_pc = 0;
    cmd(0x10, (VERTS >> 8) & 0xFF0000);
    cmd(0x9C, FB & 0xFFFFFF);
    cmd(0x9D, ((FB >> 8) & 0xFF0000) | 480);
    cmd(0x12, VTYPE_2D & ~(1u << 23));   /* through bit cleared */
    cmd(0x01, VERTS & 0xFFFFFF);
    vertex(0, 10, 10, 0xFFFFFFFFu);
    vertex(1, 110, 110, 0xFFFFFFFFu);
    cmd(0x04, (6u << 16) | 2);
    end_list();

    CHECK(psp_ge_pixels() == 0, "transformed geometry must not be drawn, got %llu px",
          (unsigned long long)psp_ge_pixels());
}

/* Back-face culling of transformed geometry. The front-face register 0x9B is
 * 0 for counter-clockwise (sceGuFrontFace(GU_CCW)) and 1 for clockwise. It was
 * read inverted, which dropped PSP2i's character faces and floors. Identity
 * matrices, a game-style viewport (y scale negative, so NDC y is up), and a
 * triangle that is counter-clockwise on screen. */
static uint32_t f24(float f) { uint32_t b; memcpy(&b, &f, 4); return b >> 8; }

static int draw_culled_triangle(uint32_t front_face) {
    psp_ge_reset();
    clear_fb();
    g_pc = 0;
    cmd(0x10, (VERTS >> 8) & 0xFF0000);
    cmd(0x9C, FB & 0xFFFFFF);
    cmd(0x9D, ((FB >> 8) & 0xFF0000) | 480);
    cmd(0xD4, 0);                                   /* scissor 0,0 - 479,271 */
    cmd(0xD5, (271u << 10) | 479u);
    cmd(0x12, (7u << 2) | (3u << 7));               /* 8888 colour, float position, transformed */
    cmd(0x01, VERTS & 0xFFFFFF);
    static const float I43[12] = { 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0 };
    static const float I44[16] = { 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1 };
    cmd(0x3A, 0); for (int i = 0; i < 12; i++) cmd(0x3B, f24(I43[i]));
    cmd(0x3C, 0); for (int i = 0; i < 12; i++) cmd(0x3D, f24(I43[i]));
    cmd(0x3E, 0); for (int i = 0; i < 16; i++) cmd(0x3F, f24(I44[i]));
    cmd(0x42, f24(240.0f)); cmd(0x43, f24(-136.0f)); cmd(0x44, f24(0.0f));
    cmd(0x45, f24(2048.0f)); cmd(0x46, f24(2048.0f)); cmd(0x47, f24(0.0f));
    cmd(0x4C, 1808u * 16); cmd(0x4D, 1912u * 16);   /* screen offset, 12.4 */
    cmd(0x1D, 1);                                   /* culling on */
    cmd(0x9B, front_face);
    /* NDC (-0.5,-0.5), (0.5,-0.5), (0,0.5): counter-clockwise with y up, and
     * still counter-clockwise on screen once the viewport flips y. */
    static const float P[3][2] = { { -0.5f, -0.5f }, { 0.5f, -0.5f }, { 0.0f, 0.5f } };
    for (int i = 0; i < 3; i++) {
        uint32_t a = VERTS + (uint32_t)i * 16, w;
        psp_write32(a, 0xFFFFFFFFu);
        memcpy(&w, &P[i][0], 4); psp_write32(a + 4, w);
        memcpy(&w, &P[i][1], 4); psp_write32(a + 8, w);
        psp_write32(a + 12, 0);
    }
    cmd(0x04, (3u << 16) | 3);
    end_list();
    return pixel(240, 136) == 0xFFFFFFFFu;
}

static void test_cull_front_face(void) {
    CHECK(draw_culled_triangle(0), "front face CCW (0x9B = 0): a CCW triangle is drawn");
    CHECK(!draw_culled_triangle(1), "front face CW (0x9B = 1): a CCW triangle is culled");
}

static void test_triangle_strip(void) {
    psp_ge_reset();
    clear_fb();
    begin_list();
    vertex(0, 10, 10, 0xFFFFFFFFu);
    vertex(1, 110, 10, 0xFFFFFFFFu);
    vertex(2, 10, 110, 0xFFFFFFFFu);
    vertex(3, 110, 110, 0xFFFFFFFFu);
    cmd(0x04, (4u << 16) | 4);       /* strip: 4 vertices -> 2 triangles */
    end_list();

    /* Two triangles sharing an edge tile the square without a seam. */
    CHECK(pixel(20, 20) == 0xFFFFFFFFu, "strip tri 0: 0x%08X", pixel(20, 20));
    CHECK(pixel(100, 100) == 0xFFFFFFFFu, "strip tri 1: 0x%08X", pixel(100, 100));
}

/* A backend's texture cache identifies textures by tex_key. For CLUT formats
 * the key must change with the palette's CONTENTS, not just the CLUT mode:
 * PSP2i draws one CLUT4 UI atlas with several palettes per frame, and the
 * D3D11 cache (which re-validates a key once per frame) reused the first
 * palette for every later draw -- black dialogue text, missing HUD frame,
 * prompt boxes and selection highlights after the game's save flow. */
#define TEXDATA 0x08820000u
#define CLUTA   0x08830000u
#define CLUTB   0x08830040u
static uint64_t g_keys[8];
static int g_nkeys;
static int key_draw(const psp_gpu_state *st, const psp_gpu_vertex *v, int n) {
    (void)v; (void)n;
    if (st->tex && g_nkeys < 8) g_keys[g_nkeys++] = st->tex_key;
    return 0;
}
static void key_sync(uint32_t a, uint32_t b) { (void)a; (void)b; }
static const psp_gpu_backend KEY_BACKEND = { "key-probe", key_draw, key_sync, key_sync };

static void clut_sprite(uint32_t clut_addr) {
    cmd(0xB0, clut_addr & 0xFFFFF0u);              /* CBP */
    cmd(0xB1, (clut_addr >> 8) & 0x0F0000u);       /* CBW: address bits 24-27 */
    cmd(0xC5, 3);                                  /* CMODE: 8888 */
    cmd(0xC4, 2);                                  /* CLOAD: 2 x 32 bytes = 16 entries */
    cmd(0x04, (6u << 16) | 2);                     /* sprite */
}

static void test_clut_in_texture_key(void) {
    psp_render_select("software");
    psp_ge_reset();
    clear_fb();
    for (uint32_t i = 0; i < 16; i++) {
        psp_write32(CLUTA + i * 4, 0xFF000000u | i);              /* two different palettes */
        psp_write32(CLUTB + i * 4, 0xFFFFFFFFu - i);
    }
    for (uint32_t i = 0; i < 32; i++) psp_write8(TEXDATA + i, 0x11);  /* 8x8 CLUT4 */
    g_pc = 0;
    cmd(0x10, (VERTS >> 8) & 0xFF0000);
    cmd(0x9C, FB & 0xFFFFFF);
    cmd(0x9D, ((FB >> 8) & 0xFF0000) | 480);
    cmd(0xD4, 0);
    cmd(0xD5, (271u << 10) | 479u);
    cmd(0x12, 2u | (7u << 2) | (2u << 7) | (1u << 23));   /* 16-bit uv, 8888, 16-bit pos, through */
    cmd(0x01, VERTS & 0xFFFFFF);
    cmd(0x1E, 1);                                  /* texturing on */
    cmd(0xA0, TEXDATA & 0xFFFFF0u);                /* TBP0 */
    cmd(0xA8, ((TEXDATA >> 8) & 0x0F0000u) | 8);   /* TBW0 */
    cmd(0xB8, 3u | (3u << 8));                     /* TSIZE0 8x8 */
    cmd(0xC3, 4);                                  /* TPSM CLUT4 */
    /* uv(u16 x2), colour, pos(s16 x3) -> 16-byte vertices */
    static const int16_t XY[2][2] = { { 10, 10 }, { 18, 18 } };
    for (int i = 0; i < 2; i++) {
        uint32_t a = VERTS + (uint32_t)i * 16;
        psp_write16(a, (uint16_t)(i * 8)); psp_write16(a + 2, (uint16_t)(i * 8));
        psp_write32(a + 4, 0xFFFFFFFFu);
        psp_write16(a + 8, (uint16_t)XY[i][0]); psp_write16(a + 10, (uint16_t)XY[i][1]);
        psp_write16(a + 12, 0);
    }
    clut_sprite(CLUTA);
    clut_sprite(CLUTB);
    clut_sprite(CLUTA);
    g_nkeys = 0;
    psp_gpu_set_backend(&KEY_BACKEND);
    end_list();
    psp_gpu_set_backend(NULL);
    CHECK(g_nkeys == 3, "three textured draws reached the backend, got %d", g_nkeys);
    if (g_nkeys == 3) {
        CHECK(g_keys[0] != g_keys[1], "a different palette gives a different texture key");
        CHECK(g_keys[0] == g_keys[2], "the same palette gives the same texture key");
    }
}

/* The backend interface itself. The software path is the reference every other
 * backend is diffed against, so selection has to be predictable: an unknown
 * name must not silently leave you rendering into nothing. */
static void test_backend_selection(void) {
    CHECK(psp_render_current() != NULL, "there is always a backend");
    CHECK(strcmp(psp_render_current()->name, "software") == 0,
          "software is the default, got %s", psp_render_current()->name);

    CHECK(psp_render_select("null") == 0, "null backend selectable");
    CHECK(strcmp(psp_render_current()->name, "null") == 0, "null is active");

    /* An unknown name keeps the current backend rather than falling back to
     * something arbitrary -- a typo should not silently change what renders. */
    CHECK(psp_render_select("vulkan-that-does-not-exist") != 0,
          "unknown backend rejected");
    CHECK(strcmp(psp_render_current()->name, "null") == 0,
          "rejected selection leaves the backend alone");

    CHECK(psp_render_select(NULL) != 0, "NULL name rejected");

    /* The null backend must draw nothing: it is what bring-up uses to ask
     * "did the game request a draw" without pixels confusing the answer. */
    psp_ge_reset();
    clear_fb();
    begin_list();
    vertex(0, 10, 10, 0xFFFFFFFFu);
    vertex(1, 60, 60, 0xFFFFFFFFu);
    cmd(0x04, (6u << 16) | 2);
    end_list();
    CHECK(psp_ge_pixels() == 0, "null backend wrote %llu pixels",
          (unsigned long long)psp_ge_pixels());

    CHECK(psp_render_select("software") == 0, "software reselectable");
}

/* Points and lines on a hardware backend: every pixel the software
 * rasterizer writes arrives as a 1x1 quad on exactly that pixel, with that
 * pixel's colour, and the backend is never asked to sync VRAM (which, on
 * D3D11, was a pipeline stall per draw). */
static psp_gpu_vertex g_rec[8192];
static int g_nrec, g_nsync;
static int rec_draw(const psp_gpu_state *st, const psp_gpu_vertex *v, int n) {
    (void)st;
    for (int i = 0; i < n && g_nrec < 8192; i++) g_rec[g_nrec++] = v[i];
    return 0;
}
static void rec_sync(uint32_t a, uint32_t b) { (void)a; (void)b; g_nsync++; }
static const psp_gpu_backend REC_BACKEND = { "record", rec_draw, rec_sync, rec_sync };

static void lines_and_points_list(void) {
    begin_list();
    cmd(0xD4, 0);
    cmd(0xD5, (271u << 10) | 479u);
    /* lines: shallow, steep, diagonal, reversed, with a colour ramp */
    vertex(0, 10, 10, 0xFF0000FFu);  vertex(1, 90, 30, 0xFFFF0000u);
    vertex(2, 20, 40, 0xFF00FF00u);  vertex(3, 30, 120, 0xFF00FF00u);
    vertex(4, 100, 100, 0xFFFFFFFFu); vertex(5, 60, 60, 0xFF808080u);
    cmd(0x04, (1u << 16) | 6);                     /* PRIM lines, 6 vertices */
    cmd(0x01, (VERTS + 6 * 12) & 0xFFFFFF);
    vertex(6, 200, 10, 0xFF112233u); vertex(7, 260, 50, 0xFF445566u); vertex(8, 210, 90, 0xFF778899u);
    cmd(0x04, (2u << 16) | 3);                     /* PRIM line strip */
    cmd(0x01, (VERTS + 9 * 12) & 0xFFFFFF);
    vertex(9, 300, 200, 0xFFABCDEFu); vertex(10, 301, 200, 0xFF00FFFFu); vertex(11, 450, 5, 0xFFFF00FFu);
    cmd(0x04, (0u << 16) | 3);                     /* PRIM points */
    end_list();
}

static void test_points_lines_on_backend(void) {
    psp_render_select("software");
    psp_gpu_set_backend(NULL);
    psp_ge_reset();
    clear_fb();
    lines_and_points_list();
    static uint32_t ref[272][480];
    int nref = 0;
    for (int y = 0; y < 272; y++)
        for (int x = 0; x < 480; x++) { ref[y][x] = pixel(x, y); if (ref[y][x]) nref++; }
    CHECK(nref > 200, "the software reference drew the lines and points (%d pixels)", nref);

    psp_ge_reset();
    clear_fb();
    g_nrec = g_nsync = 0;
    psp_gpu_set_backend(&REC_BACKEND);
    lines_and_points_list();
    psp_gpu_set_backend(NULL);
    CHECK(g_nsync == 0, "points and lines never sync VRAM on a backend (%d syncs)", g_nsync);
    CHECK(g_nrec % 6 == 0, "pixels arrive as 6-vertex quads (%d vertices)", g_nrec);

    static uint8_t hit[272][480];
    memset(hit, 0, sizeof hit);
    int bad_shape = 0, bad_px = 0, bad_col = 0, quads = 0;
    for (int q = 0; q + 6 <= g_nrec; q += 6) {
        float x0 = 1e9f, y0 = 1e9f, x1 = -1e9f, y1 = -1e9f;
        for (int k = 0; k < 6; k++) {
            const psp_gpu_vertex *v = &g_rec[q + k];
            if (v->x < x0) x0 = v->x; if (v->x > x1) x1 = v->x;
            if (v->y < y0) y0 = v->y; if (v->y > y1) y1 = v->y;
        }
        quads++;
        if (x1 - x0 != 1.0f || y1 - y0 != 1.0f) { bad_shape++; continue; }
        const int x = (int)x0, y = (int)y0;
        if (x < 0 || y < 0 || x >= 480 || y >= 272 || !ref[y][x]) { bad_px++; continue; }
        hit[y][x] = 1;
        const psp_gpu_vertex *v = &g_rec[q];
        const uint32_t want = ref[y][x];
        const int dr = (int)(v->r + 0.5f) - (int)(want & 0xFF), dg = (int)(v->g + 0.5f) - (int)((want >> 8) & 0xFF);
        const int db = (int)(v->b + 0.5f) - (int)((want >> 16) & 0xFF);
        if (dr < -1 || dr > 1 || dg < -1 || dg > 1 || db < -1 || db > 1) bad_col++;
    }
    int missing = 0;
    for (int y = 0; y < 272; y++) for (int x = 0; x < 480; x++) if (ref[y][x] && !hit[y][x]) missing++;
    CHECK(bad_shape == 0, "every quad is one pixel (%d are not)", bad_shape);
    CHECK(bad_px == 0, "no quad lands where the reference drew nothing (%d do)", bad_px);
    CHECK(missing == 0, "every reference pixel is covered (%d missing of %d)", missing, nref);
    CHECK(bad_col == 0, "quad colours match the reference to one step (%d differ)", bad_col);
    CHECK(quads >= nref, "one quad per reference pixel at least (%d quads, %d pixels)", quads, nref);
}

int main(void) {
    if (psp_mem_init() != 0) { printf("memory init failed\n"); return 1; }
    psp_cpu_reset();
    psp_hle_init();
    psp_cpu.r[PSP_REG_SP] = 0x08F00000u;

    test_sprite();
    test_triangle();
    test_winding();
    test_clipping();
    test_transformed_is_skipped();
    test_triangle_strip();
    test_cull_front_face();
    test_clut_in_texture_key();
    test_points_lines_on_backend();
    test_backend_selection();

    psp_mem_free();
    printf(failures ? "raster: %d failure(s)\n" : "raster: all tests passed\n", failures);
    return failures ? 1 : 0;
}
