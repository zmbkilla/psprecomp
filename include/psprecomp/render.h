/* psprecomp � render backend interface. See docs/RENDERER.md.
 *
 * Display-list *interpretation* has one implementation (src/hle/ge.c);
 * *presentation* is pluggable. The split matters because the software
 * rasterizer is the oracle every other backend is checked against, and it has
 * to keep working on a machine with no GPU.
 *
 * Primitives arrive assembled � vertex format decoding happens once, in the
 * interpreter, rather than being duplicated (and mis-duplicated) per backend.
 */
#ifndef PSPRECOMP_RENDER_H
#define PSPRECOMP_RENDER_H

#include <stdint.h>

/* A vertex after format decoding: screen space, colour resolved.
 * Texture coordinates extend this rather than replacing it. */
typedef struct {
    int      x, y;
    uint32_t rgba;
} psp_vertex;

/* GE primitive types, from the PRIM argument's type field. */
enum {
    PSP_PRIM_POINTS = 0,
    PSP_PRIM_LINES,
    PSP_PRIM_LINE_STRIP,
    PSP_PRIM_TRIANGLES,
    PSP_PRIM_TRIANGLE_STRIP,
    PSP_PRIM_TRIANGLE_FAN,
    PSP_PRIM_SPRITES
};

typedef struct {
    const char *name;

    int  (*init)(int width, int height);
    void (*shutdown)(void);

    /* GE_FBP / GE_FBW: the framebuffer being drawn into. */
    void (*set_target)(uint32_t addr, uint32_t stride, int fmt);

    /* One assembled primitive. `count` vertices, already in screen space. */
    void (*draw)(int prim, const psp_vertex *v, int count);

    /* End of a display list � a natural point to flush batched work. */
    void (*finish)(void);

    /* sceDisplaySetFrameBuf � show what has accumulated. */
    void (*present)(void);
} psp_render_backend;

/* Select a backend by name ("software", "null", ...). Returns 0 on success,
 * -1 if the name is unknown, leaving the current backend in place. */
int psp_render_select(const char *name);

/* The active backend. Never NULL � defaults to software. */
const psp_render_backend *psp_render_current(void);

/* Backends provided by the runtime. */
extern const psp_render_backend psp_render_software;
extern const psp_render_backend psp_render_null;

/* Pixels written by the active backend -- the proof of life during bring-up. */
uint64_t psp_render_pixels(void);
void     psp_render_reset_pixels(void);

/* ---- hardware rasterizer backend ---------------------------------------------
 *
 * The GE pipeline in src/hle/gpu.c always does vertex work on the CPU
 * (decoding, transforms, near-plane clipping, culling). With a hardware backend
 * installed, it hands each draw over as a triangle list in screen space plus
 * the decoded draw state, instead of rasterizing in software. The backend owns
 * any copy of VRAM it keeps on the GPU and must keep emulated VRAM coherent
 * through sync_vram / vram_written. */

typedef struct {
    float x, y;            /* screen pixels (pixel centres at +0.5) */
    float z;               /* depth 0..65535 */
    float rhw;             /* 1/w (1 in through mode) */
    float u, v;            /* texel coordinates */
    float r, g, b, a;      /* 0..255 */
} psp_gpu_vertex;

typedef struct {
    uint32_t fb_addr, fb_stride;      /* colour buffer (VRAM address, pixels per row) */
    int      fb_fmt;                  /* 0 5650, 1 5551, 2 4444, 3 8888 */
    uint32_t zb_addr, zb_stride;      /* depth buffer; zb_stride 0 = none */
    int      sx0, sy0, sx1, sy1;      /* scissor, inclusive */
    int      clear;                   /* clear mode */
    uint32_t clear_which;             /* 1 colour, 2 alpha/stencil, 4 depth */
    int      tex;                     /* texturing on */
    uint32_t tex_addr, tex_w, tex_h, tex_bufw;
    int      tex_psm, tex_swz;
    uint64_t tex_key;                 /* identifies format, size and CLUT state */
    int      tex_linear, tex_clamp_u, tex_clamp_v;
    int      tfunc, trgba, tdbl;
    uint32_t env;                     /* texture environment colour, 0xBBGGRR */
    int      atest; int afunc; uint32_t aref, amask;
    int      ztest; int zfunc; int zwrite;
    int      blend; int bsrc, bdst, beq; uint32_t fixa, fixb;
    uint32_t mask_rgb, mask_a;        /* write masks: set bits are preserved */
} psp_gpu_state;

typedef struct {
    const char *name;
    /* Draw a triangle list. Returns 0 on success; nonzero makes the caller
     * rasterize this draw in software instead. */
    int  (*draw)(const psp_gpu_state *st, const psp_gpu_vertex *v, int nverts);
    /* Bring emulated VRAM up to date for [addr, addr+bytes) (CPU or display
     * is about to read it). */
    void (*sync_vram)(uint32_t addr, uint32_t bytes);
    /* Emulated VRAM in [addr, addr+bytes) was written outside the backend. */
    void (*vram_written)(uint32_t addr, uint32_t bytes);
    /* Nonzero: the backend keeps VRAM coherent on every CPU access itself
     * (psp_mem_set_vram_hook), so a GE sync needs no flush. */
    int  coherent_on_access;
} psp_gpu_backend;

void psp_gpu_set_backend(const psp_gpu_backend *be);   /* NULL = software */
const psp_gpu_backend *psp_gpu_get_backend(void);

/* GE sync point (sceGeDrawSync/ListSync): bring emulated VRAM up to date with
 * the hardware backend's render targets, and have the targets re-check VRAM
 * for CPU writes before their next draw. No-op for the software rasterizer. */
void psp_gpu_cpu_sync(void);

/* Diagnostics: describe every draw of the next whole frame (target, vertex
 * format, state, first vertices) into the text file `path`. */
void psp_gpu_dump_next_frame(const char *path);

/* For backends: decode the current texture (level 0, as the draw state
 * describes it) into tex_w*tex_h RGBA8 pixels, 0xAABBGGRR. */
void psp_gpu_decode_texture(uint32_t *out);
/* For backends: a hash of the current texture's bytes (and CLUT). */
uint64_t psp_gpu_texture_hash(void);

#endif