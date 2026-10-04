/* GE per-vertex stages: skinning, lighting, shade mapping (ge_vertex.c).
 * Hand-computed expectations; no game data. */

#include "psprecomp/ge_vertex.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define NEAR(a, b) (fabsf((a) - (b)) < 1e-4f)
#define CHECK(cond, ...)                                       \
    do {                                                       \
        if (!(cond)) {                                         \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);        \
            printf(__VA_ARGS__);                               \
            printf("\n");                                      \
            failures++;                                        \
        }                                                      \
    } while (0)

/* The 24-bit argument for a float, as a display list carries it. */
static uint32_t a24(float f) { uint32_t b; memcpy(&b, &f, 4); return b >> 8; }

static void identity43(float *m) { memset(m, 0, 12 * sizeof *m); m[0] = m[4] = m[8] = 1.0f; }

static void test_skin(void) {
    /* Bone 0 translates by +2 x, bone 1 rotates 90 degrees about z
     * (x -> y). Half of each: the vertex lands between the two results. */
    float bones[24];
    identity43(bones);
    bones[9] = 2.0f;
    memset(bones + 12, 0, 12 * sizeof *bones);
    bones[12 + 1] = 1.0f;   /* x column -> +y */
    bones[12 + 3] = -1.0f;  /* y column -> -x */
    bones[12 + 8] = 1.0f;
    const float w[2] = { 0.5f, 0.5f }, p[3] = { 1, 0, 0 }, n[3] = { 1, 0, 0 };
    float po[3], no[3];
    psp_ge_skin(bones, w, 2, p, n, po, no);
    CHECK(NEAR(po[0], 1.5f) && NEAR(po[1], 0.5f) && NEAR(po[2], 0.0f),
          "skinned position (1.5, 0.5, 0), got (%g, %g, %g)", po[0], po[1], po[2]);
    /* Normals skip the translation: 0.5 * (1,0,0) + 0.5 * (0,1,0). */
    CHECK(NEAR(no[0], 0.5f) && NEAR(no[1], 0.5f), "skinned normal (0.5, 0.5, 0), got (%g, %g, %g)",
          no[0], no[1], no[2]);
}

static void test_light_directional(void) {
    uint32_t R[256];
    memset(R, 0, sizeof R);
    R[0x18] = 1;                                /* light 0 on, directional, diffuse only */
    R[0x63] = a24(0); R[0x64] = a24(0); R[0x65] = a24(2.0f);   /* towards +z (length ignored) */
    R[0x90] = 0xFFFFFF;                          /* diffuse colour white */
    R[0x56] = 0x0080FF;                          /* material diffuse: r 1, g 0.5, b 0 */
    R[0x55] = 0x000000; R[0x58] = 0xFF;          /* material ambient black, alpha 1 */
    R[0x5C] = 0x000000; R[0x5D] = 0x80;          /* global ambient black, alpha ~0.5 */
    psp_ge_lighting L;
    psp_ge_lighting_from_regs(R, 0, &L);
    const float in[4] = { 1, 1, 1, 1 }, pos[3] = { 0, 0, 0 };
    float out[4];
    const float up[3] = { 0, 0, 1 };
    psp_ge_light(&L, in, pos, up, out);
    CHECK(NEAR(out[0], 1.0f) && fabsf(out[1] - 128.0f / 255.0f) < 1e-3f && NEAR(out[2], 0.0f),
          "facing the light: material diffuse, got (%g, %g, %g)", out[0], out[1], out[2]);
    CHECK(fabsf(out[3] - (128.0f / 255.0f)) < 1e-3f, "alpha is ambient alpha x material alpha, got %g", out[3]);

    /* At 60 degrees the diffuse term halves; facing away it is zero. */
    const float tilt[3] = { 0.8660254f, 0, 0.5f };
    psp_ge_light(&L, in, pos, tilt, out);
    CHECK(fabsf(out[0] - 0.5f) < 1e-3f, "N.L = 0.5 halves the diffuse, got %g", out[0]);
    const float away[3] = { 0, 0, -1 };
    psp_ge_light(&L, in, pos, away, out);
    CHECK(NEAR(out[0], 0.0f), "facing away is unlit, got %g", out[0]);

    /* Material update: diffuse from the vertex colour instead. */
    R[0x53] = 2;
    psp_ge_lighting_from_regs(R, 1, &L);
    const float blue[4] = { 0, 0, 1, 1 };
    psp_ge_light(&L, blue, pos, up, out);
    CHECK(NEAR(out[0], 0.0f) && NEAR(out[2], 1.0f), "material update takes the vertex colour, got (%g, %g, %g)",
          out[0], out[1], out[2]);
    /* ...but only when the vertex format has a colour. */
    psp_ge_lighting_from_regs(R, 0, &L);
    psp_ge_light(&L, blue, pos, up, out);
    CHECK(NEAR(out[0], 1.0f), "no vertex colour: material diffuse, got %g", out[0]);
}

static void test_light_point(void) {
    uint32_t R[256];
    memset(R, 0, sizeof R);
    R[0x18] = 1;
    R[0x5F] = 1u << 8;                           /* point light */
    R[0x63] = a24(0); R[0x64] = a24(0); R[0x65] = a24(2.0f);
    R[0x7B] = a24(0); R[0x7C] = a24(0); R[0x7D] = a24(1.0f);   /* 1 / d^2 */
    R[0x90] = 0xFFFFFF;
    R[0x56] = 0xFFFFFF;
    psp_ge_lighting L;
    psp_ge_lighting_from_regs(R, 0, &L);
    const float in[4] = { 1, 1, 1, 1 }, pos[3] = { 0, 0, 0 }, up[3] = { 0, 0, 1 };
    float out[4];
    psp_ge_light(&L, in, pos, up, out);
    CHECK(fabsf(out[0] - 0.25f) < 1e-3f, "point light at distance 2 with 1/d^2: 0.25, got %g", out[0]);
}

static void test_ambient_emissive_specular(void) {
    uint32_t R[256];
    memset(R, 0, sizeof R);
    R[0x54] = 0x000020;                          /* emissive r = 32/255 */
    R[0x5C] = 0x404040;                          /* global ambient 64/255 */
    R[0x55] = 0xFFFFFF; R[0x58] = 0xFF; R[0x5D] = 0xFF;
    R[0x18] = 1;
    R[0x5F] = 1;                                 /* directional, diffuse + specular */
    R[0x63] = a24(0); R[0x64] = a24(0); R[0x65] = a24(1.0f);
    R[0x91] = 0xFFFFFF;                          /* specular white */
    R[0x57] = 0xFFFFFF;
    R[0x5B] = a24(4.0f);
    psp_ge_lighting L;
    psp_ge_lighting_from_regs(R, 0, &L);
    const float in[4] = { 1, 1, 1, 1 }, pos[3] = { 0, 0, 0 }, up[3] = { 0, 0, 1 };
    float out[4];
    psp_ge_light(&L, in, pos, up, out);
    /* Half vector = normal, so specular = 1: everything saturates. */
    CHECK(NEAR(out[0], 1.0f) && NEAR(out[1], 1.0f), "specular toward the viewer saturates, got (%g, %g)",
          out[0], out[1]);
    R[0x91] = 0;
    psp_ge_lighting_from_regs(R, 0, &L);
    psp_ge_light(&L, in, pos, up, out);
    CHECK(fabsf(out[0] - 96.0f / 255.0f) < 1e-3f && fabsf(out[1] - 64.0f / 255.0f) < 1e-3f,
          "emissive + ambient: (96, 64)/255, got (%g, %g)", out[0] * 255, out[1] * 255);
}

static void test_shade_map(void) {
    uint32_t R[256];
    memset(R, 0, sizeof R);
    R[0xC1] = 0 | (1u << 8);                     /* u from light 0, v from light 1 */
    R[0x63] = a24(1.0f); R[0x64] = a24(0); R[0x65] = a24(0);
    R[0x66] = a24(0); R[0x67] = a24(3.0f); R[0x68] = a24(0);
    const float n[3] = { 1, 0, 0 };
    float uv[2];
    psp_ge_shade_map(R, n, uv);
    CHECK(NEAR(uv[0], 1.0f) && NEAR(uv[1], 0.5f), "shade map (1, 0.5), got (%g, %g)", uv[0], uv[1]);
}

int main(void) {
    test_skin();
    test_light_directional();
    test_light_point();
    test_ambient_emissive_specular();
    test_shade_map();
    if (failures) { printf("\n%d check(s) failed\n", failures); return 1; }
    printf("all GE vertex-stage checks passed\n");
    return 0;
}
