/* psprecomp — sceLibFont: the PSP's system fonts (PGF).
 *
 * The firmware's font library renders glyphs from the PGF files in
 * flash0:/font/. Games ask for a font by index into the library's font list
 * (the firmware registry: jpn0 first, then ltn0..ltn15, then kr0), query a
 * character's metrics, and have the library draw the glyph into a buffer of
 * their own, which they then upload as a texture. So the whole job is: parse
 * the PGF, find the glyph, decode its bitmap, and copy it into the guest's
 * buffer in the pixel format asked for.
 *
 * ## The PGF format (what this implements)
 *
 * Little-endian. A 0x188-byte header (revision 2; revision 3 adds a 20-byte
 * extension and compressed char maps, accepted but its compressed tables only
 * skipped), then four metric tables of (x, y) s32 pairs -- dimension, x
 * adjust, y adjust, advance -- then a bit-packed shadow map, a bit-packed char
 * map (code - firstGlyph -> glyph index) and a bit-packed pointer table (glyph
 * index -> 32-bit word offset into the glyph data). Bit fields are read LSB
 * first. Each glyph starts with:
 *
 *     size:14 w:7 h:7 left:7 top:7 (signed) flags:6 shadowFlags:7 shadowId:9
 *     dimension, x adjust, y adjust, advance: each an 8-bit table index if its
 *     flag bit (0x04, 0x08, 0x10, 0x20) is set, else two inline s32s
 *
 * followed by a 4-bit-per-pixel bitmap, nibble run-length coded: a nibble n < 8
 * means "the next value, n+1 times"; n >= 8 means "16-n literal values". Pixels
 * run along rows if flags & 3 == 1, else down columns. Metrics are 26.6 fixed
 * point.
 *
 * Only the four calls PSP2i imports are implemented: NewLib, Open,
 * GetCharInfo and GetCharGlyphImage.
 */

#include "psprecomp/hle.h"
#include "psprecomp/font.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- PGF parsing ---------------------------------------------------------- */

static int32_t rd_s32(const uint8_t *p) { int32_t v; memcpy(&v, p, 4); return v; }
static uint16_t rd_u16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }

/* `n` bits (n <= 32) starting at bit `pos` of `base`, LSB first. */
uint32_t psp_pgf_bits(const uint8_t *base, size_t limit_bytes, uint64_t pos, int n) {
    uint64_t v = 0;
    for (int i = 0; i < n; i++) {
        uint64_t b = pos + (uint64_t)i;
        if ((b >> 3) >= limit_bytes) break;
        v |= (uint64_t)((base[b >> 3] >> (b & 7)) & 1) << i;
    }
    return (uint32_t)v;
}

static size_t packed_bytes(int32_t count, int32_t bpe) {
    return (size_t)((((int64_t)count * bpe + 31) & ~31LL) / 8);
}

int psp_pgf_parse(psp_pgf *f, const uint8_t *data, size_t size) {
    memset(f, 0, sizeof *f);
    if (size < 0x188 || memcmp(data + 4, "PGF0", 4) != 0) return -1;
    f->data = data;
    f->size = size;
    f->revision    = rd_s32(data + 8);
    f->map_len     = rd_s32(data + 16);
    f->ptr_len     = rd_s32(data + 20);
    f->map_bpe     = rd_s32(data + 24);
    f->ptr_bpe     = rd_s32(data + 28);
    f->first_glyph = rd_u16(data + 0xB6);
    f->last_glyph  = rd_u16(data + 0xB8);
    f->max_glyph_w = rd_u16(data + 0xFC);
    f->max_glyph_h = rd_u16(data + 0xFE);
    const int ntab[4] = { data[0x102], data[0x103], data[0x104], data[0x105] };
    const int32_t shadow_len = rd_s32(data + 0x16C), shadow_bpe = rd_s32(data + 0x170);
    if (f->map_bpe <= 0 || f->map_bpe > 32 || f->ptr_bpe <= 0 || f->ptr_bpe > 32) return -1;

    size_t o = rd_u16(data + 2);                   /* header size */
    int32_t c1_len = 0, c2_len = 0;
    if (f->revision == 3) {
        if (o + 20 > size) return -1;
        c1_len = rd_u16(data + o + 4);
        c2_len = rd_u16(data + o + 12);
        o += 20;
    }
    for (int t = 0; t < 4; t++) {
        f->tab[t] = data + o;
        f->tab_len[t] = ntab[t];
        o += (size_t)ntab[t] * 8;
    }
    o += packed_bytes(shadow_len, shadow_bpe);
    if (f->revision == 3) o += (size_t)(c1_len + c2_len) * 4;
    f->map = data + o;
    o += packed_bytes(f->map_len, f->map_bpe);
    f->ptrs = data + o;
    o += packed_bytes(f->ptr_len, f->ptr_bpe);
    if (o > size) return -1;
    f->glyphs = data + o;
    f->glyphs_size = size - o;
    return 0;
}

static void table_entry(const psp_pgf *f, int t, uint32_t i, int32_t out[2]) {
    if ((int)i < f->tab_len[t]) {
        out[0] = rd_s32(f->tab[t] + i * 8);
        out[1] = rd_s32(f->tab[t] + i * 8 + 4);
    } else {
        out[0] = out[1] = 0;
    }
}

int psp_pgf_find(const psp_pgf *f, uint32_t code, psp_pgf_glyph *g) {
    memset(g, 0, sizeof *g);
    if (code < f->first_glyph || code > f->last_glyph) return -1;
    const uint32_t idx = code - f->first_glyph;
    if ((int32_t)idx >= f->map_len) return -1;
    const size_t map_bytes = (size_t)(f->ptrs - f->map);
    const uint32_t gi = psp_pgf_bits(f->map, map_bytes, (uint64_t)idx * (uint32_t)f->map_bpe, f->map_bpe);
    if ((int32_t)gi >= f->ptr_len) return -1;
    const size_t ptr_bytes = (size_t)(f->glyphs - f->ptrs);
    uint64_t p = (uint64_t)psp_pgf_bits(f->ptrs, ptr_bytes, (uint64_t)gi * (uint32_t)f->ptr_bpe, f->ptr_bpe) * 32;
    if ((p >> 3) >= f->glyphs_size) return -1;

#define TAKE(n) (p += (n), psp_pgf_bits(f->glyphs, f->glyphs_size, p - (n), (n)))
    (void)TAKE(14);                                            /* glyph size */
    g->w = (int)TAKE(7);
    g->h = (int)TAKE(7);
    int v = (int)TAKE(7); g->left = v >= 64 ? v - 128 : v;
    v = (int)TAKE(7);     g->top  = v >= 64 ? v - 128 : v;
    g->flags = (int)TAKE(6);
    g->shadow_flags = (int)TAKE(7);
    g->shadow_id = (int)TAKE(9);
    int32_t *const metric[4] = { g->dimension, g->x_adjust, g->y_adjust, g->advance };
    for (int t = 0; t < 4; t++) {
        if (g->flags & (0x04 << t)) table_entry(f, t, TAKE(8), metric[t]);
        else { metric[t][0] = (int32_t)TAKE(32); metric[t][1] = (int32_t)TAKE(32); }
    }
#undef TAKE
    g->bitmap_bit = p;
    return 0;
}

int psp_pgf_decode(const psp_pgf *f, const psp_pgf_glyph *g, uint8_t *out) {
    const int w = g->w, h = g->h, n = w * h;
    const int rows = (g->flags & 3) == 1;
    memset(out, 0, (size_t)(n > 0 ? n : 0));
    uint64_t p = g->bitmap_bit;
    int i = 0;
    while (i < n && (p >> 3) < f->glyphs_size) {
        const int nib = (int)psp_pgf_bits(f->glyphs, f->glyphs_size, p, 4);
        p += 4;
        int count, value = 0;
        if (nib < 8) {
            value = (int)psp_pgf_bits(f->glyphs, f->glyphs_size, p, 4);
            p += 4;
            count = nib + 1;
        } else {
            count = 16 - nib;
        }
        for (int k = 0; k < count && i < n; k++, i++) {
            if (nib >= 8) { value = (int)psp_pgf_bits(f->glyphs, f->glyphs_size, p, 4); p += 4; }
            const int x = rows ? i % w : i / h, y = rows ? i / w : i % h;
            out[y * w + x] = (uint8_t)value;
        }
    }
    return i == n ? 0 : -1;
}

/* ---- the library ----------------------------------------------------------- */

/* The firmware's font registry, in order: sceFontOpen's index selects from it. */
static const char *const FONT_FILES[] = {
    "jpn0.pgf",
    "ltn0.pgf", "ltn1.pgf", "ltn2.pgf", "ltn3.pgf", "ltn4.pgf", "ltn5.pgf", "ltn6.pgf", "ltn7.pgf",
    "ltn8.pgf", "ltn9.pgf", "ltn10.pgf", "ltn11.pgf", "ltn12.pgf", "ltn13.pgf", "ltn14.pgf", "ltn15.pgf",
    "kr0.pgf",
};
#define NFONTS ((int)(sizeof FONT_FILES / sizeof FONT_FILES[0]))

#define LIB_HANDLE_BASE  0x0F000000u
#define FONT_HANDLE_BASE 0x0F100000u
#define MAX_OPEN 16

#define ERR_FONT_INVALID_LIBID     0x80460002u
#define ERR_FONT_INVALID_PARAMETER 0x80460003u
#define ERR_FONT_FILE_OPEN_FAILED  0x80460005u
#define ERR_FONT_TOO_MANY_OPEN     0x80460009u

typedef struct { int used; uint8_t *data; psp_pgf pgf; int index; } open_font;
static open_font g_font[MAX_OPEN];
static uint32_t  g_libs;
static uint32_t  g_alt_char = 0x5F;   /* drawn for codes the font lacks */

void psp_font_reset(void) {
    for (int i = 0; i < MAX_OPEN; i++) free(g_font[i].data);
    memset(g_font, 0, sizeof g_font);
    g_libs = 0;
}

void psp_font_init(void) { psp_font_reset(); }

static open_font *font_arg(uint32_t h) {
    uint32_t i = h - FONT_HANDLE_BASE;
    return (i < MAX_OPEN && g_font[i].used) ? &g_font[i] : NULL;
}

static uint8_t *load_file(const char *guest, size_t *size) {
    char host[1024];
    psp_io_host_path(guest, host, sizeof host);
    FILE *fp = fopen(host, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *buf = n > 0 ? (uint8_t *)malloc((size_t)n) : NULL;
    if (buf && fread(buf, 1, (size_t)n, fp) != (size_t)n) { free(buf); buf = NULL; }
    fclose(fp);
    *size = (size_t)n;
    return buf;
}

/* (const SceFontNewLibParams *params, u32 *errorCode) -> library handle */
static void hle_NewLib(void) {
    if (psp_arg(1)) psp_write32(psp_arg(1), 0);
    psp_ret(LIB_HANDLE_BASE + (++g_libs));
}

/* (lib, index, mode, u32 *errorCode) -> font handle */
static void hle_Open(void) {
    const uint32_t lib = psp_arg(0), index = psp_arg(1), err = psp_arg(3);
    uint32_t e = 0, handle = 0;
    if (lib <= LIB_HANDLE_BASE || lib > LIB_HANDLE_BASE + g_libs) e = ERR_FONT_INVALID_LIBID;
    else if ((int)index < 0 || (int)index >= NFONTS) e = ERR_FONT_INVALID_PARAMETER;
    else {
        int slot = -1;
        for (int i = 0; i < MAX_OPEN; i++) if (!g_font[i].used) { slot = i; break; }
        if (slot < 0) e = ERR_FONT_TOO_MANY_OPEN;
        else {
            char path[64];
            snprintf(path, sizeof path, "flash0:/font/%s", FONT_FILES[index]);
            size_t size = 0;
            uint8_t *data = load_file(path, &size);
            if (!data || psp_pgf_parse(&g_font[slot].pgf, data, size) != 0) {
                free(data);
                fprintf(stderr, "psprecomp: sceFontOpen: cannot load %s (put the PSP font files in "
                                "<root>/flash/font/)\n", path);
                e = ERR_FONT_FILE_OPEN_FAILED;
            } else {
                g_font[slot].used = 1;
                g_font[slot].data = data;
                g_font[slot].index = (int)index;
                handle = FONT_HANDLE_BASE + (uint32_t)slot;
                fprintf(stderr, "psprecomp: sceFontOpen(%u) -> %s, glyphs U+%04X..U+%04X\n", index,
                        FONT_FILES[index], g_font[slot].pgf.first_glyph, g_font[slot].pgf.last_glyph);
            }
        }
    }
    if (err) psp_write32(err, e);
    psp_ret(handle);
}

/* The glyph for `code`, falling back to the alternate character. */
static int find_glyph(const open_font *f, uint32_t code, psp_pgf_glyph *g) {
    if (psp_pgf_find(&f->pgf, code, g) == 0) return 0;
    return psp_pgf_find(&f->pgf, g_alt_char, g);
}

/* SceFontCharInfo: bitmapWidth, bitmapHeight, bitmapLeft, bitmapTop (u32),
 * then 26.6 metrics: width, height, ascender, descender, bearingHX,
 * bearingHY, bearingVX, bearingVY, advanceH, advanceV, then s16 shadowFlags,
 * s16 shadowId. */
static void hle_GetCharInfo(void) {
    open_font *f = font_arg(psp_arg(0));
    const uint32_t code = psp_arg(1), info = psp_arg(2);
    if (!f || !info) { psp_ret(ERR_FONT_INVALID_PARAMETER); return; }
    psp_pgf_glyph g;
    if (find_glyph(f, code, &g) != 0) memset(&g, 0, sizeof g);
    psp_write32(info + 0,  (uint32_t)g.w);
    psp_write32(info + 4,  (uint32_t)g.h);
    psp_write32(info + 8,  (uint32_t)g.left);
    psp_write32(info + 12, (uint32_t)g.top);
    psp_write32(info + 16, (uint32_t)g.dimension[0]);
    psp_write32(info + 20, (uint32_t)g.dimension[1]);
    psp_write32(info + 24, (uint32_t)g.y_adjust[0]);
    psp_write32(info + 28, (uint32_t)(g.y_adjust[0] - g.dimension[1]));
    psp_write32(info + 32, (uint32_t)g.x_adjust[0]);
    psp_write32(info + 36, (uint32_t)g.y_adjust[0]);
    psp_write32(info + 40, (uint32_t)g.x_adjust[1]);
    psp_write32(info + 44, (uint32_t)g.y_adjust[1]);
    psp_write32(info + 48, (uint32_t)g.advance[0]);
    psp_write32(info + 52, (uint32_t)g.advance[1]);
    psp_write16(info + 56, (uint16_t)g.shadow_flags);
    psp_write16(info + 58, (uint16_t)g.shadow_id);
    psp_ret(0);
}

/* Write one glyph pixel (0..15) into the guest buffer, keeping the brighter
 * of the new and existing value so overlapping glyphs do not erase each
 * other. */
static void put_pixel(uint32_t buf, uint32_t bpl, int fmt, int x, int y, int v) {
    switch (fmt) {
    case 0: case 1: {                              /* 4 bpp, low or high nibble first */
        const uint32_t a = buf + (uint32_t)y * bpl + (uint32_t)x / 2;
        uint8_t b = psp_read8(a);
        const int hi = ((x & 1) != 0) == (fmt == 0);
        int old = hi ? b >> 4 : b & 0xF;
        if (v < old) v = old;
        b = hi ? (uint8_t)((b & 0x0F) | (v << 4)) : (uint8_t)((b & 0xF0) | v);
        psp_write8(a, b);
        break;
    }
    case 2: {                                      /* 8 bpp */
        const uint32_t a = buf + (uint32_t)y * bpl + (uint32_t)x;
        int nv = v * 17, old = psp_read8(a);
        psp_write8(a, (uint8_t)(nv > old ? nv : old));
        break;
    }
    case 3: {                                      /* 24 bpp grey */
        const uint32_t a = buf + (uint32_t)y * bpl + (uint32_t)x * 3;
        int nv = v * 17, old = psp_read8(a);
        if (nv > old) for (int k = 0; k < 3; k++) psp_write8(a + (uint32_t)k, (uint8_t)nv);
        break;
    }
    default: {                                     /* 32 bpp: white, glyph in alpha */
        const uint32_t a = buf + (uint32_t)y * bpl + (uint32_t)x * 4;
        int nv = v * 17, old = psp_read8(a + 3);
        if (nv > old) psp_write32(a, 0x00FFFFFFu | ((uint32_t)nv << 24));
        break;
    }
    }
}

/* SceFontGlyphImage: u32 pixelFormat, s32 xPos64, s32 yPos64, u16 bufWidth,
 * u16 bufHeight, u16 bytesPerLine, u16 pad, u32 buffer. The glyph bitmap's
 * top-left goes at (xPos64 >> 6, yPos64 >> 6); callers position it using the
 * left/top values from GetCharInfo. */
static void hle_GetCharGlyphImage(void) {
    open_font *f = font_arg(psp_arg(0));
    const uint32_t code = psp_arg(1), img = psp_arg(2);
    if (!f || !img) { psp_ret(ERR_FONT_INVALID_PARAMETER); return; }
    const int fmt = (int)psp_read32(img);
    const int x0 = (int32_t)psp_read32(img + 4) >> 6, y0 = (int32_t)psp_read32(img + 8) >> 6;
    const int bw = psp_read16(img + 12), bh = psp_read16(img + 14);
    const uint32_t bpl = psp_read16(img + 16), buf = psp_read32(img + 20);
    psp_pgf_glyph g;
    if (find_glyph(f, code, &g) != 0 || g.w <= 0 || g.h <= 0) { psp_ret(0); return; }
    uint8_t *px = (uint8_t *)malloc((size_t)g.w * (size_t)g.h);
    if (!px) { psp_ret(ERR_FONT_INVALID_PARAMETER); return; }
    psp_pgf_decode(&f->pgf, &g, px);
    for (int y = 0; y < g.h; y++) {
        const int yy = y0 + y;
        if (yy < 0 || yy >= bh) continue;
        for (int x = 0; x < g.w; x++) {
            const int xx = x0 + x, v = px[y * g.w + x];
            if (xx < 0 || xx >= bw || !v) continue;
            put_pixel(buf, bpl, fmt, xx, yy, v);
        }
    }
    free(px);
    psp_ret(0);
}

void psp_font_register(void) {
    psp_hle_register(0x67F17ED7, "sceLibFont", "sceFontNewLib",            hle_NewLib);
    psp_hle_register(0xA834319D, "sceLibFont", "sceFontOpen",              hle_Open);
    psp_hle_register(0xDCC80C2F, "sceLibFont", "sceFontGetCharInfo",       hle_GetCharInfo);
    psp_hle_register(0x980F4895, "sceLibFont", "sceFontGetCharGlyphImage", hle_GetCharGlyphImage);
}
