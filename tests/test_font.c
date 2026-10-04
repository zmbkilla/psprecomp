/* PGF font tests.
 *
 * The synthetic part needs no game data: the bit reader, the nibble
 * run-length bitmap decoder (both pixel orders), and glyph-header parsing
 * through a minimal hand-built PGF. The real-font part runs only when
 * PSPRECOMP_FONT_DIR points at a directory holding the PSP's jpn0.pgf, and
 * pins values read from it independently. */

#include "psprecomp/font.h"

#include <stdio.h>
#include <stdlib.h>
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

/* A little LSB-first bit writer for building test data. */
typedef struct { uint8_t buf[512]; uint64_t pos; } bitw;
static void put(bitw *w, uint32_t v, int n) {
    for (int i = 0; i < n; i++, w->pos++)
        if ((v >> i) & 1) w->buf[w->pos >> 3] |= (uint8_t)(1u << (w->pos & 7));
}

static void test_bits(void) {
    const uint8_t b[4] = { 0xB4, 0x0F, 0x00, 0x80 };     /* 1011 0100, 0000 1111, ..., 1000 0000 */
    CHECK(psp_pgf_bits(b, 4, 0, 4) == 0x4, "low nibble first: got 0x%X", psp_pgf_bits(b, 4, 0, 4));
    CHECK(psp_pgf_bits(b, 4, 4, 4) == 0xB, "then the high nibble");
    CHECK(psp_pgf_bits(b, 4, 4, 8) == 0xFB, "a field straddling bytes, got 0x%X", psp_pgf_bits(b, 4, 4, 8));
    CHECK(psp_pgf_bits(b, 4, 31, 1) == 1, "the last bit");
    CHECK(psp_pgf_bits(b, 4, 30, 8) == 2, "bits past the end read as zero, got 0x%X", psp_pgf_bits(b, 4, 30, 8));
}

static void test_rle(void) {
    /* A 3x2 bitmap: 5 5 5 / 1 2 3, rows. "n<8: next value n+1 times" then
     * "n>=8: 16-n literals". */
    bitw w;
    memset(&w, 0, sizeof w);
    put(&w, 2, 4); put(&w, 5, 4);                         /* 3 x 5 */
    put(&w, 13, 4); put(&w, 1, 4); put(&w, 2, 4); put(&w, 3, 4);   /* 3 literals */
    psp_pgf f;
    memset(&f, 0, sizeof f);
    f.glyphs = w.buf;
    f.glyphs_size = sizeof w.buf;
    psp_pgf_glyph g;
    memset(&g, 0, sizeof g);
    g.w = 3; g.h = 2; g.flags = 1;                        /* rows */
    uint8_t px[6];
    CHECK(psp_pgf_decode(&f, &g, px) == 0, "row bitmap decodes completely");
    const uint8_t want_rows[6] = { 5, 5, 5, 1, 2, 3 };
    CHECK(memcmp(px, want_rows, 6) == 0, "row order: %u %u %u / %u %u %u",
          px[0], px[1], px[2], px[3], px[4], px[5]);

    g.flags = 2;                                          /* columns */
    CHECK(psp_pgf_decode(&f, &g, px) == 0, "column bitmap decodes completely");
    /* Same value stream, filled down columns: (0,0)=5 (0,1)=5 (1,0)=5 (1,1)=1 (2,0)=2 (2,1)=3 */
    const uint8_t want_cols[6] = { 5, 5, 2, 5, 1, 3 };
    CHECK(memcmp(px, want_cols, 6) == 0, "column order: %u %u %u / %u %u %u",
          px[0], px[1], px[2], px[3], px[4], px[5]);
}

/* A minimal revision-2 PGF holding one glyph ('A'), built field by field. */
static void test_parse_synthetic(void) {
    static uint8_t file[0x188 + 64];
    memset(file, 0, sizeof file);
    file[2] = 0x88; file[3] = 0x01;                       /* header size 0x188 */
    memcpy(file + 4, "PGF0", 4);
    file[8] = 2;                                          /* revision */
    file[16] = 1;                                         /* char map length */
    file[20] = 1;                                         /* char pointer length */
    file[24] = 8;                                         /* char map bpe */
    file[28] = 8;                                         /* char pointer bpe */
    file[0xB6] = 'A'; file[0xB8] = 'A';                   /* first / last glyph */
    file[0x105] = 1;                                      /* one advance-table entry */
    uint8_t *p = file + 0x188;
    p[0] = 0x00; p[1] = 0x01;                             /* advance table: x = 0x100 (4 px) ... */
    p += 8;
    p[0] = 0;  p += 4;                                    /* char map: 'A' -> glyph 0 (8 bits, padded to 32) */
    p[0] = 0;  p += 4;                                    /* pointer table: glyph 0 at word 0 */
    bitw w;
    memset(&w, 0, sizeof w);
    put(&w, 0, 14); put(&w, 2, 7); put(&w, 1, 7);         /* size, w=2, h=1 */
    put(&w, 127, 7); put(&w, 9, 7);                       /* left = -1, top = 9 */
    put(&w, 0x01 | 0x20, 6);                              /* rows; advance from the table */
    put(&w, 0, 7); put(&w, 0, 9);                         /* shadow */
    put(&w, 640, 32); put(&w, 576, 32);                   /* dimension inline */
    put(&w, 64, 32); put(&w, 0, 32);                      /* x adjust inline */
    put(&w, 576, 32); put(&w, 0, 32);                     /* y adjust inline */
    put(&w, 0, 8);                                        /* advance: table entry 0 */
    put(&w, 1, 4); put(&w, 15, 4);                        /* bitmap: 15, 15 */
    memcpy(p, w.buf, 40);

    psp_pgf f;
    CHECK(psp_pgf_parse(&f, file, sizeof file) == 0, "synthetic PGF parses");
    psp_pgf_glyph g;
    CHECK(psp_pgf_find(&f, 'A', &g) == 0, "glyph found");
    CHECK(psp_pgf_find(&f, 'B', &g) != 0, "a code outside the font is absent");
    psp_pgf_find(&f, 'A', &g);
    CHECK(g.w == 2 && g.h == 1, "size %dx%d", g.w, g.h);
    CHECK(g.left == -1 && g.top == 9, "left/top are signed 7-bit: %d %d", g.left, g.top);
    CHECK(g.dimension[0] == 640 && g.x_adjust[0] == 64 && g.y_adjust[0] == 576, "inline metrics");
    CHECK(g.advance[0] == 0x100, "advance from the table, got %d", g.advance[0]);
    uint8_t px[2];
    CHECK(psp_pgf_decode(&f, &g, px) == 0 && px[0] == 15 && px[1] == 15, "bitmap %u %u", px[0], px[1]);
}

static void test_real_font(void) {
    const char *dir = getenv("PSPRECOMP_FONT_DIR");
    if (!dir) { printf("(PSPRECOMP_FONT_DIR not set: real-font checks skipped)\n"); return; }
    char path[1024];
    snprintf(path, sizeof path, "%s/jpn0.pgf", dir);
    FILE *fp = fopen(path, "rb");
    if (!fp) { printf("(cannot open %s: real-font checks skipped)\n", path); return; }
    fseek(fp, 0, SEEK_END);
    long n = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc((size_t)n);
    if (!buf || fread(buf, 1, (size_t)n, fp) != (size_t)n) { fclose(fp); free(buf); return; }
    fclose(fp);

    psp_pgf f;
    CHECK(psp_pgf_parse(&f, buf, (size_t)n) == 0, "jpn0.pgf parses");
    CHECK(f.first_glyph == 0x20 && f.last_glyph == 0xFFEE, "jpn0 covers U+0020..U+FFEE");
    psp_pgf_glyph g;
    CHECK(psp_pgf_find(&f, 'A', &g) == 0, "jpn0 has 'A'");
    CHECK(g.w == 16 && g.h == 15 && g.left == 0 && g.top == 14, "'A' bitmap 16x15 at (0,14), got %dx%d at (%d,%d)",
          g.w, g.h, g.left, g.top);
    CHECK(g.advance[0] == 1008, "'A' advance 1008/64, got %d", g.advance[0]);
    uint8_t px[16 * 15];
    CHECK(psp_pgf_decode(&f, &g, px) == 0, "'A' bitmap decodes completely");
    int ink = 0;
    for (int i = 0; i < 16 * 15; i++) ink += px[i] != 0;
    CHECK(ink > 40 && ink < 200, "'A' has a plausible amount of ink: %d pixels", ink);
    CHECK(psp_pgf_find(&f, 0x3076, &g) == 0 && g.w > 0, "jpn0 has U+3076 (the kana PSP2i checks for)");
    free(buf);
}

int main(void) {
    test_bits();
    test_rle();
    test_parse_synthetic();
    test_real_font();
    if (failures) { printf("\n%d check(s) failed\n", failures); return 1; }
    printf("all font checks passed\n");
    return 0;
}
