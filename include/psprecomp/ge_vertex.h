/* psprecomp — the GE's per-vertex stages: skinning, lighting and texture
 * coordinate generation.
 *
 * These run on the decoded vertex before projection, and they are the same
 * for every backend: a backend receives vertices that are already skinned,
 * lit and carry their final texture coordinates. Keeping them here, as pure
 * functions of the register file, means a new backend (or a GPU vertex
 * shader port) has one reference to match, and the tests exercise them
 * without a display list.
 *
 * Reference behaviour is PPSSPP's software transform (Lighter, the texture
 * map modes), which matches the hardware closely enough for games to use.
 */
#ifndef PSPRECOMP_GE_VERTEX_H
#define PSPRECOMP_GE_VERTEX_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A GE 4x3 matrix: 12 floats, columns x, y, z, then the translation. */
void psp_ge_mul43(const float *m, const float in[3], float out[3]);
/* The same matrix applied to a direction: no translation. */
void psp_ge_mul33(const float *m, const float in[3], float out[3]);

/* Skinning: the position (and normal) is the weighted sum of the vertex
 * transformed by each bone matrix. `bones` holds `n` 4x3 matrices back to
 * back (the GE has 8). `nrm`/`nrm_out` may be NULL. */
void psp_ge_skin(const float *bones, const float *weights, int n,
                 const float pos[3], const float nrm[3], float pos_out[3], float nrm_out[3]);

/* Lighting state, decoded once per draw from the register file. */
typedef struct {
    int   enabled[4];
    int   type[4];          /* 0 directional, 1 point, 2 spot (3 = spot) */
    int   comp[4];          /* 0 diffuse, 1 diffuse + specular, 2 powered diffuse */
    float pos[4][3], dir[4][3], att[4][3];
    float spot_exp[4], spot_cut[4];
    float ambient[4][3], diffuse[4][3], specular[4][3];   /* light colours, 0..1 */
    float mat_emissive[3], mat_ambient[4], mat_diffuse[3], mat_specular[3];
    float global_ambient[4];
    float shininess;
    int   mat_update;       /* bit 0 ambient, 1 diffuse, 2 specular from the vertex colour */
} psp_ge_lighting;

/* Decode the lighting registers. `regs[cmd]` is the 24-bit argument last
 * written for GE command `cmd` (the 256-entry register file). Material update applies only when the vertex
 * format carries a colour. */
void psp_ge_lighting_from_regs(const uint32_t *regs, int vertex_has_color, psp_ge_lighting *L);

/* Light one vertex. `color` is the unlit colour, 0..1 (the vertex colour, or
 * the material ambient colour and alpha when the vertex has none). `pos` and
 * `nrm` are in world space; `nrm` is unit length. `out` receives the lit
 * colour, 0..1: the primary colour with the specular term added (the GE's
 * separate-specular mode adds it after texturing; see gpu.c). */
void psp_ge_light(const psp_ge_lighting *L, const float color[4], const float pos[3],
                  const float nrm[3], float out[4]);

/* Shade (environment) mapping, texture map mode 2: u and v from two lights'
 * directions against the world-space normal, in 0..1 before UV scale. */
void psp_ge_shade_map(const uint32_t *regs, const float nrm[3], float uv[2]);

#ifdef __cplusplus
}
#endif

#endif /* PSPRECOMP_GE_VERTEX_H */
