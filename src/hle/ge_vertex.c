/* psprecomp — the GE's per-vertex stages. See include/psprecomp/ge_vertex.h. */

#include "psprecomp/ge_vertex.h"

#include <math.h>
#include <string.h>

/* A GE float argument is the top 24 bits of an IEEE single. */
static float f24(uint32_t arg) {
    uint32_t b = arg << 8;
    float f;
    memcpy(&f, &b, 4);
    return f;
}

/* An RGB colour argument (R in the low byte), as 0..1. */
static void rgb(uint32_t arg, float out[3]) {
    for (int k = 0; k < 3; k++) out[k] = (float)((arg >> (8 * k)) & 0xFF) / 255.0f;
}

void psp_ge_mul43(const float *m, const float in[3], float out[3]) {
    float x = in[0], y = in[1], z = in[2];
    out[0] = x * m[0] + y * m[3] + z * m[6] + m[9];
    out[1] = x * m[1] + y * m[4] + z * m[7] + m[10];
    out[2] = x * m[2] + y * m[5] + z * m[8] + m[11];
}

void psp_ge_mul33(const float *m, const float in[3], float out[3]) {
    float x = in[0], y = in[1], z = in[2];
    out[0] = x * m[0] + y * m[3] + z * m[6];
    out[1] = x * m[1] + y * m[4] + z * m[7];
    out[2] = x * m[2] + y * m[5] + z * m[8];
}

void psp_ge_skin(const float *bones, const float *weights, int n,
                 const float pos[3], const float nrm[3], float pos_out[3], float nrm_out[3]) {
    float p[3] = { 0, 0, 0 }, q[3] = { 0, 0, 0 };
    for (int i = 0; i < n; i++) {
        const float w = weights[i];
        if (w == 0.0f) continue;
        float t[3];
        psp_ge_mul43(bones + 12 * i, pos, t);
        for (int k = 0; k < 3; k++) p[k] += w * t[k];
        if (nrm) {
            psp_ge_mul33(bones + 12 * i, nrm, t);
            for (int k = 0; k < 3; k++) q[k] += w * t[k];
        }
    }
    memcpy(pos_out, p, sizeof p);
    if (nrm && nrm_out) memcpy(nrm_out, q, sizeof q);
}

void psp_ge_lighting_from_regs(const uint32_t *R, int vertex_has_color, psp_ge_lighting *L) {
    memset(L, 0, sizeof *L);
    for (int l = 0; l < 4; l++) {
        L->enabled[l] = (int)(R[0x18 + l] & 1);
        L->comp[l] = (int)(R[0x5F + l] & 3);
        L->type[l] = (int)((R[0x5F + l] >> 8) & 3);
        for (int k = 0; k < 3; k++) {
            L->pos[l][k] = f24(R[0x63 + l * 3 + k]);
            L->dir[l][k] = f24(R[0x6F + l * 3 + k]);
            L->att[l][k] = f24(R[0x7B + l * 3 + k]);
        }
        L->spot_exp[l] = f24(R[0x87 + l]);
        L->spot_cut[l] = f24(R[0x8B + l]);
        rgb(R[0x8F + l * 3], L->ambient[l]);
        rgb(R[0x90 + l * 3], L->diffuse[l]);
        rgb(R[0x91 + l * 3], L->specular[l]);
    }
    rgb(R[0x54], L->mat_emissive);
    rgb(R[0x55], L->mat_ambient);
    L->mat_ambient[3] = (float)(R[0x58] & 0xFF) / 255.0f;
    rgb(R[0x56], L->mat_diffuse);
    rgb(R[0x57], L->mat_specular);
    rgb(R[0x5C], L->global_ambient);
    L->global_ambient[3] = (float)(R[0x5D] & 0xFF) / 255.0f;
    L->shininess = f24(R[0x5B]);
    L->mat_update = vertex_has_color ? (int)(R[0x53] & 7) : 0;
}

static float dot3(const float a[3], const float b[3]) { return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]; }

void psp_ge_light(const psp_ge_lighting *L, const float color[4], const float pos[3],
                  const float nrm[3], float out[4]) {
    const float *amb = (L->mat_update & 1) ? color : L->mat_ambient;
    const float *dif = (L->mat_update & 2) ? color : L->mat_diffuse;
    const float *spc = (L->mat_update & 4) ? color : L->mat_specular;

    /* Emissive plus the global ambient light on the material's ambient
     * colour; the alpha comes from this term alone. */
    float sum[4], spec[3] = { 0, 0, 0 };
    for (int k = 0; k < 3; k++) sum[k] = L->mat_emissive[k] + L->global_ambient[k] * amb[k];
    sum[3] = L->global_ambient[3] * amb[3];

    for (int l = 0; l < 4; l++) {
        if (!L->enabled[l]) continue;
        float to[3];
        if (L->type[l] == 0) memcpy(to, L->pos[l], sizeof to);        /* directional: pos is the direction */
        else for (int k = 0; k < 3; k++) to[k] = L->pos[l][k] - pos[k];
        const float dist = sqrtf(dot3(to, to));
        float d = 0.0f;
        if (dist > 0.0f) {
            for (int k = 0; k < 3; k++) to[k] /= dist;
            d = dot3(to, nrm);
        }
        if (d < 0.0f) d = 0.0f;
        if (L->comp[l] == 2) d = powf(d, L->shininess);

        float scale = 1.0f;
        if (L->type[l] != 0) {
            const float a = L->att[l][0] + L->att[l][1] * dist + L->att[l][2] * dist * dist;
            scale = a > 0.0f ? 1.0f / a : 1.0f;
            if (scale > 1.0f) scale = 1.0f;
            if (scale < 0.0f) scale = 0.0f;
            if (L->type[l] >= 2) {                                     /* spot */
                const float len = sqrtf(dot3(L->dir[l], L->dir[l]));
                const float ang = len > 0.0f ? dot3(L->dir[l], to) / len : 0.0f;
                scale = ang >= L->spot_cut[l] ? scale * powf(ang, L->spot_exp[l]) : 0.0f;
            }
        }

        for (int k = 0; k < 3; k++)
            sum[k] += (L->ambient[l][k] * amb[k] + L->diffuse[l][k] * dif[k] * d) * scale;

        if (L->comp[l] == 1) {
            /* The hardware's half vector uses a fixed viewer at +z. */
            float h[3] = { to[0], to[1], to[2] + 1.0f };
            const float hl = sqrtf(dot3(h, h));
            const float s = hl > 0.0f ? dot3(h, nrm) / hl : 0.0f;
            if (s > 0.0f) {
                const float p = powf(s, L->shininess) * scale;
                for (int k = 0; k < 3; k++) spec[k] += L->specular[l][k] * spc[k] * p;
            }
        }
    }

    for (int k = 0; k < 3; k++) sum[k] += spec[k];
    for (int k = 0; k < 4; k++) out[k] = sum[k] < 0.0f ? 0.0f : sum[k] > 1.0f ? 1.0f : sum[k];
}

void psp_ge_shade_map(const uint32_t *R, const float nrm[3], float uv[2]) {
    const int ls[2] = { (int)(R[0xC1] & 3), (int)((R[0xC1] >> 8) & 3) };
    for (int i = 0; i < 2; i++) {
        float p[3];
        for (int k = 0; k < 3; k++) p[k] = f24(R[0x63 + ls[i] * 3 + k]);
        const float len = sqrtf(dot3(p, p));
        if (len > 0.0f) for (int k = 0; k < 3; k++) p[k] /= len;
        else { p[0] = p[1] = 0.0f; p[2] = 1.0f; }
        uv[i] = (1.0f + dot3(p, nrm)) * 0.5f;
    }
}
