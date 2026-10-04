/* psprecomp — PGF font parsing (the PSP's system font format), used by the
 * sceLibFont HLE in src/hle/font.c. Exposed for tests. */
#ifndef PSPRECOMP_FONT_H
#define PSPRECOMP_FONT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t *data;
    size_t size;
    int32_t revision;
    int32_t map_len, ptr_len, map_bpe, ptr_bpe;
    uint32_t first_glyph, last_glyph;
    uint32_t max_glyph_w, max_glyph_h;
    const uint8_t *tab[4];       /* dimension, x adjust, y adjust, advance: (x, y) s32 pairs */
    int tab_len[4];
    const uint8_t *map, *ptrs, *glyphs;
    size_t glyphs_size;
} psp_pgf;

typedef struct {
    int w, h, left, top;         /* bitmap size and placement, pixels */
    int flags, shadow_flags, shadow_id;
    int32_t dimension[2], x_adjust[2], y_adjust[2], advance[2];   /* 26.6 fixed point */
    uint64_t bitmap_bit;         /* bit offset of the bitmap in the glyph data */
} psp_pgf_glyph;

/* Parse a PGF file held in memory (not copied). 0 on success. */
int psp_pgf_parse(psp_pgf *f, const uint8_t *data, size_t size);
/* Look up the glyph for a character code. 0 on success, -1 if absent. */
int psp_pgf_find(const psp_pgf *f, uint32_t code, psp_pgf_glyph *g);
/* Decode the glyph's bitmap into w*h values 0..15, row-major. 0 on success. */
int psp_pgf_decode(const psp_pgf *f, const psp_pgf_glyph *g, uint8_t *out);
/* `n` bits at bit `pos`, LSB first (bits past `limit_bytes` read as 0). */
uint32_t psp_pgf_bits(const uint8_t *base, size_t limit_bytes, uint64_t pos, int n);

#ifdef __cplusplus
}
#endif

#endif /* PSPRECOMP_FONT_H */
