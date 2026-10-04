/* psprecomp — the VFPU. See include/psprecomp/vfpu.h. */

#include "psprecomp/vfpu.h"
#include "psprecomp/recomp_rt.h"

#include <math.h>

#include <stdio.h>
#include <string.h>

/* ---- prefix state ----------------------------------------------------------
 *
 * vpfxs / vpfxt rewrite the *source* operands of the next VFPU arithmetic
 * instruction, per lane (bits for lane i):
 *
 *     swizzle   (p >> 2i) & 3     which source lane to read
 *     abs       (p >> 8+i) & 1    take |x| -- or, with cst, pick the high
 *                                 half of the constant table
 *     cst       (p >> 12+i) & 1   read a constant instead of a register:
 *                                 { 0, 1, 2, 1/2, 3, 1/3, 1/4, 1/6 }[swz + 4*abs]
 *     neg       (p >> 16+i) & 1   negate (after abs / constant selection)
 *
 * vpfxd rewrites the *destination*:
 *
 *     sat       (p >> 2i) & 3     1 = clamp to [0, 1], 3 = clamp to [-1, 1]
 *     mask      (p >> 8+i) & 1    do not write this lane
 *
 * A prefix applies to exactly one following arithmetic instruction and is
 * then gone. The swizzle can name any lane of the quad the operand starts in,
 * even for a narrower operation, so sources are read as a full quad first.
 */

static uint32_t g_prefix[3];      /* vpfxs, vpfxt, vpfxd */
static int      g_prefix_set[3];
static uint64_t g_traps;

void psp_vfpu_reset(void) {
    memset(g_prefix, 0, sizeof g_prefix);
    memset(g_prefix_set, 0, sizeof g_prefix_set);
    g_traps = 0;
}

void psp_vfpu_set_prefix(int which, uint32_t value) {
    if (which < 0 || which > 2) return;
    g_prefix[which] = value & 0xFFFFFu;
    g_prefix_set[which] = 1;
}

int psp_vfpu_prefix_pending(void) {
    return g_prefix_set[0] || g_prefix_set[1] || g_prefix_set[2];
}

uint64_t psp_vfpu_trap_count(void) { return g_traps; }

void psp_vfpu_unimplemented(uint32_t addr, const char *what) {
    /* First few only: a VFPU-heavy inner loop would otherwise produce
     * megabytes of identical lines and hide everything else. */
    if (g_traps < 16)
        fprintf(stderr, "psprecomp: VFPU %s at 0x%08X not implemented\n", what, addr);
    else if (g_traps == 16)
        fprintf(stderr, "psprecomp: (further VFPU traps suppressed)\n");
    g_traps++;
}

static void consume(void) { memset(g_prefix_set, 0, sizeof g_prefix_set); }

/* ---- register addressing ------------------------------------------------- */

int psp_vfpu_regs(uint32_t vreg, int size, int out[4]) {
    const int mtx       = (vreg >> 2) & 7;
    const int col       = vreg & 3;
    int transpose       = (vreg >> 5) & 1;
    int row = 0, len = 1;

    switch (size) {
    case 1: row = (vreg >> 5) & 3; transpose = 0; len = 1; break;
    case 2: row = (vreg >> 5) & 2;                len = 2; break;
    case 3: row = (vreg >> 6) & 1;                len = 3; break;
    default:row = (vreg >> 5) & 2;                len = 4; break;
    }

    for (int i = 0; i < len; i++) {
        /* Transposed access walks columns instead of rows -- the same storage
         * seen the other way round, which is what makes a matrix transpose
         * free on this hardware. */
        const int step = (row + i) & 3;
        out[i] = transpose ? mtx * 4 + step * 32 + col
                           : mtx * 4 + col  * 32 + step;
    }
    return len;
}

/* The full quad an operand starts in: what a prefix swizzle indexes. */
static void quad_regs(uint32_t vreg, int size, int out[4]) {
    const int mtx = (vreg >> 2) & 7;
    const int col = vreg & 3;
    int transpose = (vreg >> 5) & 1;
    int row;
    switch (size) {
    case 1: row = (vreg >> 5) & 3; transpose = 0; break;
    case 3: row = (vreg >> 6) & 1; break;
    default: row = (vreg >> 5) & 2; break;
    }
    for (int i = 0; i < 4; i++) {
        const int step = (row + i) & 3;
        out[i] = transpose ? mtx * 4 + step * 32 + col : mtx * 4 + col * 32 + step;
    }
}

static const float PFX_CONST[8] = {
    0.0f, 1.0f, 2.0f, 0.5f, 3.0f, 1.0f / 3.0f, 0.25f, 1.0f / 6.0f
};

/* Read `size` lanes of a source operand through prefix `which` (0 = s, 1 = t). */
static int read_src(uint32_t vreg, int size, float out[4], int which) {
    int q[4];
    quad_regs(vreg, size, q);
    float raw[4];
    for (int i = 0; i < 4; i++) raw[i] = psp_cpu.v[q[i]];
    if (!g_prefix_set[which]) {
        for (int i = 0; i < size; i++) out[i] = raw[i];
        return size;
    }
    const uint32_t p = g_prefix[which];
    for (int i = 0; i < size; i++) {
        const int swz = (int)(p >> (2 * i)) & 3;
        const int abs_ = (int)(p >> (8 + i)) & 1;
        const int cst = (int)(p >> (12 + i)) & 1;
        const int neg = (int)(p >> (16 + i)) & 1;
        float x;
        if (cst) x = PFX_CONST[swz + 4 * abs_];
        else {
            x = raw[swz];
            if (abs_) x = fabsf(x);
        }
        out[i] = neg ? -x : x;
    }
    return size;
}

/* Read raw bit patterns (integer interpretations), honouring the swizzle only:
 * abs/neg/constant are float operations and do not apply to integer data. */
static void read_src_bits(uint32_t vreg, int size, uint32_t out[4], int which) {
    int q[4];
    quad_regs(vreg, size, q);
    uint32_t p = g_prefix_set[which] ? g_prefix[which] : 0xE4u;
    for (int i = 0; i < size; i++) out[i] = psp_f32_to_bits(psp_cpu.v[q[(p >> (2 * i)) & 3]]);
}

/* Write `size` lanes through the destination prefix. */
static void write_dst(uint32_t vreg, int size, const float in[4]) {
    int d[4];
    psp_vfpu_regs(vreg, size, d);
    const uint32_t p = g_prefix_set[2] ? g_prefix[2] : 0;
    for (int i = 0; i < size; i++) {
        if ((p >> (8 + i)) & 1) continue;          /* masked */
        float x = in[i];
        switch ((p >> (2 * i)) & 3) {
        case 1: x = x < 0.0f ? 0.0f : (x > 1.0f ? 1.0f : x); break;
        case 3: x = x < -1.0f ? -1.0f : (x > 1.0f ? 1.0f : x); break;
        default: break;
        }
        psp_cpu.v[d[i]] = x;
    }
}

static void write_dst_bits(uint32_t vreg, int size, const uint32_t in[4]) {
    int d[4];
    psp_vfpu_regs(vreg, size, d);
    const uint32_t p = g_prefix_set[2] ? g_prefix[2] : 0;
    for (int i = 0; i < size; i++) {
        if ((p >> (8 + i)) & 1) continue;
        psp_cpu.v[d[i]] = psp_bits_to_f32(in[i]);
    }
}

/* ---- load / store -------------------------------------------------------- */

void psp_lv_s(uint32_t vt, uint32_t addr) {
    int r[4];
    psp_vfpu_regs(vt, 1, r);
    psp_cpu.v[r[0]] = psp_read_f32(addr & ~3u);
}

void psp_sv_s(uint32_t vt, uint32_t addr) {
    int r[4];
    psp_vfpu_regs(vt, 1, r);
    psp_write_f32(addr & ~3u, psp_cpu.v[r[0]]);
}

void psp_lv_q(uint32_t vt, uint32_t addr) {
    int r[4];
    psp_vfpu_regs(vt, 4, r);
    addr &= ~15u;                       /* quad access is 16-byte aligned */
    for (int i = 0; i < 4; i++)
        psp_cpu.v[r[i]] = psp_read_f32(addr + (uint32_t)i * 4);
}

void psp_sv_q(uint32_t vt, uint32_t addr) {
    int r[4];
    psp_vfpu_regs(vt, 4, r);
    addr &= ~15u;
    for (int i = 0; i < 4; i++)
        psp_write_f32(addr + (uint32_t)i * 4, psp_cpu.v[r[i]]);
}

/* ---- moves between the integer and vector files -------------------------- */

/* mtv / mfv carry an 8-bit register number: 0..127 a vector register, 128..
 * the control registers (PFXS, PFXT, PFXD, CC, INF4, -, -, REV, RCX0..7). */
void psp_mtv(uint32_t reg, uint32_t value) {
    if (reg < 128) {
        int r[4];
        psp_vfpu_regs(reg, 1, r);
        psp_cpu.v[r[0]] = psp_bits_to_f32(value);
        return;
    }
    switch (reg - 128) {
    case 0: psp_vfpu_set_prefix(0, value); break;
    case 1: psp_vfpu_set_prefix(1, value); break;
    case 2: psp_vfpu_set_prefix(2, value); break;
    case 3: psp_cpu.vfpu_cc = value & 0x3F; break;
    default: break;                 /* INF4, REV, RCX: random-number state */
    }
}

uint32_t psp_mfv(uint32_t reg) {
    if (reg < 128) {
        int r[4];
        psp_vfpu_regs(reg, 1, r);
        return psp_f32_to_bits(psp_cpu.v[r[0]]);
    }
    switch (reg - 128) {
    case 0: return g_prefix[0];
    case 1: return g_prefix[1];
    case 2: return g_prefix[2];
    case 3: return psp_cpu.vfpu_cc;
    default: return 0;
    }
}

/* ---- arithmetic ---------------------------------------------------------- */

#define BINOP(name, expr)                                                    \
    void psp_##name(uint32_t vd, uint32_t vs, uint32_t vt, int size) {       \
        float s[4], t[4], out[4];                                            \
        read_src(vs, size, s, 0);                                            \
        read_src(vt, size, t, 1);                                            \
        /* Every source is read before any destination is written: vd may   \
         * alias vs or vt. */                                                \
        for (int i = 0; i < size; i++) {                                     \
            float a = s[i], b = t[i];                                        \
            out[i] = (expr);                                                 \
        }                                                                    \
        write_dst(vd, size, out);                                            \
        consume();                                                           \
    }

BINOP(vadd, a + b)
BINOP(vsub, a - b)
BINOP(vmul, a * b)
BINOP(vdiv, a / b)
BINOP(vmin, a < b ? a : b)
BINOP(vmax, a > b ? a : b)
/* Set-if: 1.0 or 0.0 per lane. A NaN compares false either way. */
BINOP(vsge, a >= b ? 1.0f : 0.0f)
BINOP(vslt, a <  b ? 1.0f : 0.0f)

/* Dot product: sums all lanes into a single destination lane. */
void psp_vdot(uint32_t vd, uint32_t vs, uint32_t vt, int size) {
    float s[4], t[4], out[4];
    read_src(vs, size, s, 0);
    read_src(vt, size, t, 1);
    float sum = 0.0f;
    for (int i = 0; i < size; i++) sum += s[i] * t[i];
    out[0] = sum;
    write_dst(vd, 1, out);
    consume();
}

/* Scale: every lane of vs multiplied by the scalar in vt. */
void psp_vscl(uint32_t vd, uint32_t vs, uint32_t vt, int size) {
    float s[4], t[4], out[4];
    read_src(vs, size, s, 0);
    read_src(vt, 1, t, 1);
    for (int i = 0; i < size; i++) out[i] = s[i] * t[0];
    write_dst(vd, size, out);
    consume();
}

/* vcrs.t -- the half cross product: (s.y*t.z, s.z*t.x, s.x*t.y). */
void psp_vcrs(uint32_t vd, uint32_t vs, uint32_t vt, int size) {
    float s[4], t[4], out[4];
    read_src(vs, 3, s, 0);
    read_src(vt, 3, t, 1);
    out[0] = s[1] * t[2];
    out[1] = s[2] * t[0];
    out[2] = s[0] * t[1];
    write_dst(vd, size < 3 ? size : 3, out);
    consume();
}

/* vcrsp.t is the full cross product; the same encoding at quad width is
 * vqmul.q, the quaternion product (x, y, z, w with w the scalar part). */
void psp_vcrsp(uint32_t vd, uint32_t vs, uint32_t vt, int size) {
    float s[4], t[4], out[4];
    if (size == 4) {
        read_src(vs, 4, s, 0);
        read_src(vt, 4, t, 1);
        out[0] =  s[0] * t[3] + s[1] * t[2] - s[2] * t[1] + s[3] * t[0];
        out[1] = -s[0] * t[2] + s[1] * t[3] + s[2] * t[0] + s[3] * t[1];
        out[2] =  s[0] * t[1] - s[1] * t[0] + s[2] * t[3] + s[3] * t[2];
        out[3] = -s[0] * t[0] - s[1] * t[1] - s[2] * t[2] + s[3] * t[3];
        write_dst(vd, 4, out);
    } else {
        read_src(vs, 3, s, 0);
        read_src(vt, 3, t, 1);
        out[0] = s[1] * t[2] - s[2] * t[1];
        out[1] = s[2] * t[0] - s[0] * t[2];
        out[2] = s[0] * t[1] - s[1] * t[0];
        write_dst(vd, 3, out);
    }
    consume();
}

/* ---- unary element-wise ops (VFPU4) -------------------------------------- */

static float sat0(float v) { return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v); }
static float sat1(float v) { return v < -1.0f ? -1.0f : (v > 1.0f ? 1.0f : v); }

void psp_vunary(int op, uint32_t vd, uint32_t vs, int size) {
    float s[4], out[4];
    read_src(vs, size, s, 0);
    for (int i = 0; i < size; i++) {
        const float a = s[i];
        float r;
        switch (op) {
        case PSP_VU_MOV:  r = a;            break;
        case PSP_VU_ABS:  r = fabsf(a);     break;
        case PSP_VU_NEG:  r = -a;           break;
        case PSP_VU_ZERO: r = 0.0f;         break;
        case PSP_VU_ONE:  r = 1.0f;         break;
        case PSP_VU_RCP:  r = 1.0f / a;     break;
        case PSP_VU_NRCP: r = -1.0f / a;    break;
        case PSP_VU_RSQ:  r = 1.0f / psp_fsqrt(a); break;
        case PSP_VU_SQRT: r = psp_fsqrt(a); break;
        /* The PSP's trig takes its argument in *quarter turns*: vsin(x) is
         * sin(x * pi/2), not sin(x). Treating it as radians gives a result
         * that is smooth, plausible, and wrong -- rotations end up at the
         * wrong angle rather than visibly broken. */
        case PSP_VU_SIN:  r = sinf(a * 1.5707963267948966f);  break;
        case PSP_VU_COS:  r = cosf(a * 1.5707963267948966f);  break;
        case PSP_VU_NSIN: r = -sinf(a * 1.5707963267948966f); break;
        case PSP_VU_ASIN: r = asinf(a) * 0.6366197723675814f; break;  /* 2/pi */
        case PSP_VU_EXP2: r = powf(2.0f, a);   break;
        case PSP_VU_REXP2:r = 1.0f / powf(2.0f, a); break;
        case PSP_VU_LOG2: r = logf(a) * 1.4426950408889634f; break;   /* 1/ln2 */
        case PSP_VU_SAT0: r = sat0(a);      break;
        case PSP_VU_SAT1: r = sat1(a);      break;
        /* Unscaled conversions; the scaled forms go through psp_vf2i/psp_vi2f. */
        case PSP_VU_F2IZ: r = psp_bits_to_f32((uint32_t)(int32_t)a); break;
        case PSP_VU_I2F:  r = (float)(int32_t)psp_f32_to_bits(a);    break;
        default:          psp_vfpu_unimplemented(psp_cpu.pc, "vunary"); consume(); return;
        }
        out[i] = r;
    }
    write_dst(vd, size, out);
    consume();
}

/* vf2in / vf2iz / vf2iu / vf2id: float to int after scaling by 2^scale, with
 * the rounding mode the instruction names. Out-of-range values saturate, and
 * NaN converts to 0x7FFFFFFF. */
void psp_vf2i(int mode, uint32_t vd, uint32_t vs, uint32_t scale, int size) {
    float s[4];
    uint32_t out[4];
    read_src(vs, size, s, 0);
    for (int i = 0; i < size; i++) {
        double x = ldexp((double)s[i], (int)scale);
        int32_t r;
        if (x != x)                     r = 0x7FFFFFFF;
        else if (x >= 2147483647.0)     r = 0x7FFFFFFF;
        else if (x <= -2147483648.0)    r = (int32_t)0x80000000u;
        else {
            switch (mode) {
            case PSP_VF2I_NEAREST: r = (int32_t)nearbyint(x); break;   /* ties to even */
            case PSP_VF2I_ZERO:    r = (int32_t)x;            break;
            case PSP_VF2I_UP:      r = (int32_t)ceil(x);      break;
            default:               r = (int32_t)floor(x);     break;
            }
        }
        out[i] = (uint32_t)r;
    }
    write_dst_bits(vd, size, out);
    consume();
}

/* vi2f: int to float, then scaled by 2^-scale. */
void psp_vi2f(uint32_t vd, uint32_t vs, uint32_t scale, int size) {
    uint32_t s[4];
    float out[4];
    read_src_bits(vs, size, s, 0);
    for (int i = 0; i < size; i++) out[i] = (float)ldexp((double)(int32_t)s[i], -(int)scale);
    write_dst(vd, size, out);
    consume();
}

/* vcmovt / vcmovf: copy vs to vd under a condition code. imm3 0..5 tests one
 * CC bit for all lanes; 6 tests CC bit i for lane i. `tf` = 0 is the "true"
 * form. Lanes not copied keep the destination's value. */
void psp_vcmov(uint32_t vd, uint32_t vs, int size, int tf, int imm3) {
    float s[4], cur[4];
    int d[4];
    read_src(vs, size, s, 0);
    psp_vfpu_regs(vd, size, d);
    for (int i = 0; i < size; i++) cur[i] = psp_cpu.v[d[i]];
    const uint32_t cc = psp_cpu.vfpu_cc;
    const int want = tf ? 0 : 1;
    for (int i = 0; i < size; i++) {
        int bit = imm3 < 6 ? imm3 : (imm3 == 6 ? i : -1);
        if (bit >= 0 && (int)((cc >> bit) & 1) == want) cur[i] = s[i];
    }
    write_dst(vd, size, cur);
    consume();
}

/* vrot: build a rotation row from one angle (quarter turns). imm5 bits 1..0
 * pick the cosine lane, bits 3..2 the sine lane, bit 4 negates the sine. If
 * the two lanes coincide, every *other* lane gets the sine and the named lane
 * the cosine; otherwise the remaining lanes are zero. */
void psp_vrot(uint32_t vd, uint32_t vs, uint32_t imm5, int size) {
    float a[4], out[4];
    read_src(vs, 1, a, 0);
    const float ang = a[0] * 1.5707963267948966f;
    float sn = sinf(ang);
    const float cs = cosf(ang);
    if (imm5 & 0x10) sn = -sn;
    const int ci = (int)(imm5 & 3), si = (int)((imm5 >> 2) & 3);
    for (int i = 0; i < size; i++) {
        if (si == ci) out[i] = (i == ci) ? cs : sn;
        else          out[i] = (i == ci) ? cs : (i == si ? sn : 0.0f);
    }
    write_dst(vd, size, out);
    consume();
}

/* ---- VFPU9 (opcode 0x34, rs = 2) ------------------------------------------ */

void psp_vfpu9(int op, uint32_t vd, uint32_t vs, int size) {
    float s[4], out[8];
    int osize = size;
    read_src(vs, size, s, 0);
    switch (op) {
    case PSP_V9_BFY1:                      /* (s0+s1, s0-s1, s2+s3, s2-s3) */
        out[0] = s[0] + s[1]; out[1] = s[0] - s[1];
        if (size == 4) { out[2] = s[2] + s[3]; out[3] = s[2] - s[3]; }
        break;
    case PSP_V9_BFY2:                      /* (s0+s2, s1+s3, s0-s2, s1-s3) */
        out[0] = s[0] + s[2]; out[1] = s[1] + s[3];
        out[2] = s[0] - s[2]; out[3] = s[1] - s[3];
        break;
    case PSP_V9_OCP:                       /* one's complement: 1 - x */
        for (int i = 0; i < size; i++) out[i] = 1.0f - s[i];
        break;
    case PSP_V9_SOCP:                      /* (sat0(1-x), sat0(x)) per lane; doubles the width */
        for (int i = 0; i < size; i++) { out[2 * i] = sat0(1.0f - s[i]); out[2 * i + 1] = sat0(s[i]); }
        osize = size * 2;
        if (osize > 4) osize = 4;
        break;
    case PSP_V9_FAD:                       /* funnel add: sum of lanes */
        out[0] = 0.0f;
        for (int i = 0; i < size; i++) out[0] += s[i];
        osize = 1;
        break;
    case PSP_V9_AVG:
        out[0] = 0.0f;
        for (int i = 0; i < size; i++) out[0] += s[i];
        out[0] /= (float)size;
        osize = 1;
        break;
    case PSP_V9_SGN:                       /* -1, 0 or 1 */
        for (int i = 0; i < size; i++) out[i] = s[i] > 0.0f ? 1.0f : (s[i] < 0.0f ? -1.0f : 0.0f);
        break;
    default:
        psp_vfpu_unimplemented(psp_cpu.pc, "vfpu9");
        consume();
        return;
    }
    write_dst(vd, osize, out);
    consume();
}

/* ---- VFPU7 packing conversions (opcode 0x34, rs = 1) ---------------------- */

void psp_vconv(int op, uint32_t vd, uint32_t vs, int size) {
    uint32_t s[4], out[4] = { 0, 0, 0, 0 };
    int osize;
    read_src_bits(vs, size, s, 0);
    switch (op) {
    case PSP_V7_UC2I:   /* one word of bytes -> up to 4 ints: byte * 0x01010101 >> 1 */
        for (int i = 0; i < 4; i++) out[i] = (((s[0] >> (8 * i)) & 0xFF) * 0x01010101u) >> 1;
        osize = 4;
        break;
    case PSP_V7_C2I:    /* signed bytes into the top byte of each int */
        for (int i = 0; i < 4; i++) out[i] = ((s[0] >> (8 * i)) & 0xFF) << 24;
        osize = 4;
        break;
    case PSP_V7_US2I:   /* halfwords -> ints: h << 15 */
    case PSP_V7_S2I:    /* halfwords into the top half: h << 16 */
        osize = size * 2;
        if (osize > 4) osize = 4;
        for (int i = 0; i < osize; i++) {
            uint32_t h = (s[i / 2] >> (16 * (i & 1))) & 0xFFFF;
            out[i] = op == PSP_V7_US2I ? h << 15 : h << 16;
        }
        break;
    case PSP_V7_I2UC:   /* ints -> unsigned bytes: negative is 0, else bits 30..23 */
    case PSP_V7_I2C:    /* ints -> signed bytes: bits 31..24 */
        for (int i = 0; i < size; i++) {
            uint32_t b = op == PSP_V7_I2UC ? ((int32_t)s[i] < 0 ? 0 : (s[i] >> 23) & 0xFF)
                                           : (s[i] >> 24) & 0xFF;
            out[0] |= b << (8 * i);
        }
        osize = 1;
        break;
    case PSP_V7_I2US:
    case PSP_V7_I2S:
        osize = (size + 1) / 2;
        for (int i = 0; i < size; i++) {
            uint32_t h = op == PSP_V7_I2US ? ((int32_t)s[i] < 0 ? 0 : (s[i] >> 15) & 0xFFFF)
                                           : (s[i] >> 16) & 0xFFFF;
            out[i / 2] |= h << (16 * (i & 1));
        }
        break;
    default:
        psp_vfpu_unimplemented(psp_cpu.pc, "vfpu7");
        consume();
        return;
    }
    write_dst_bits(vd, osize, out);
    consume();
}

/* ---- matrix ops without a multiply --------------------------------------- */

/* A matrix register names `size` consecutive columns, each a vector of `size`
 * lanes. Writing one column at a time through the same addressing the vector
 * ops use keeps the two consistent -- which matters because a game builds a
 * matrix with these and then transforms with vtfm. */
static void matrix_cols(uint32_t vd, int size, int cols[4][4]) {
    /* Build a fresh vector register per column: matrix, column index, row 0.
     * An earlier version modified bits 6:5 of the incoming register, which
     * varies the *row* field and so walked rows while claiming to walk
     * columns -- every matrix op addressed the wrong elements. */
    const uint32_t mtx       = (vd >> 2) & 7;
    const uint32_t transpose = (vd >> 5) & 1;
    for (int c = 0; c < size; c++) {
        uint32_t vreg = (mtx << 2) | (uint32_t)c | (transpose << 5);
        psp_vfpu_regs(vreg, size, cols[c]);
    }
}

/* Read a whole matrix out into [col][row] order. */
static void matrix_read(uint32_t v, int size, float m[4][4]) {
    int cols[4][4];
    matrix_cols(v, size, cols);
    for (int c = 0; c < size; c++)
        for (int r = 0; r < size; r++) m[c][r] = psp_cpu.v[cols[c][r]];
}

static void matrix_write(uint32_t v, int size, const float m[4][4]) {
    int cols[4][4];
    matrix_cols(v, size, cols);
    for (int c = 0; c < size; c++)
        for (int r = 0; r < size; r++) psp_cpu.v[cols[c][r]] = m[c][r];
}

/* Matrix instructions take no prefixes; any pending one is discarded. */

void psp_vmidt(uint32_t vd, int size) {
    int cols[4][4];
    matrix_cols(vd, size, cols);
    for (int c = 0; c < size; c++)
        for (int r = 0; r < size; r++)
            psp_cpu.v[cols[c][r]] = (c == r) ? 1.0f : 0.0f;
    consume();
}

/* vidt -- an identity *vector*: all zeroes but for a single 1.0.
 *
 * Which element gets the 1 is encoded in the destination register number
 * rather than given as an operand: it is the register's column index (vd & 3
 * for a quad, vd & 1 for a pair), so vidt.q on C000..C030 yields the columns
 * of the identity matrix. An earlier version read bits 6-7 instead, which put
 * every column's 1.0 in row 0 -- PSP2i's translation matrices came out as all
 * ones across row 0, and the projections composed from them had their
 * diagonals in row 0 (character creation drew its whole scene on one row). */
void psp_vidt(uint32_t vd, int size) {
    float out[4];
    const int one = (int)(vd & (size == 2 ? 1u : 3u));
    for (int i = 0; i < size; i++) out[i] = (i == one) ? 1.0f : 0.0f;
    write_dst(vd, size, out);
    consume();
}

/* vcst -- load a constant from the VFPU's built-in table.
 *
 * The index is in the vs field. Values follow the hardware table; index 0 is
 * zero and anything past the end reads as zero rather than as garbage. */
void psp_vcst(uint32_t vd, uint32_t which, int size) {
    static const float K[20] = {
        0.0f,
        3.4028235e38f,          /* max float          */
        1.41421356f,            /* sqrt(2)            */
        0.70710678f,            /* sqrt(1/2)          */
        1.12837917f,            /* 2/sqrt(pi)         */
        0.63661977f,            /* 2/pi               */
        0.31830989f,            /* 1/pi               */
        0.78539816f,            /* pi/4               */
        1.57079633f,            /* pi/2               */
        3.14159265f,            /* pi                 */
        2.71828183f,            /* e                  */
        1.44269504f,            /* log2(e)            */
        0.43429448f,            /* log10(e)           */
        0.69314718f,            /* ln(2)              */
        2.30258509f,            /* ln(10)             */
        6.28318531f,            /* 2*pi               */
        0.52359878f,            /* pi/6               */
        0.30103000f,            /* log10(2)           */
        3.32192809f,            /* log2(10)           */
        0.86602540f,            /* sqrt(3)/2          */
    };

    const float k = which < 20 ? K[which] : 0.0f;
    float out[4];
    for (int i = 0; i < size; i++) out[i] = k;
    write_dst(vd, size, out);
    consume();
}

void psp_vmzero(uint32_t vd, int size) {
    int cols[4][4];
    matrix_cols(vd, size, cols);
    for (int c = 0; c < size; c++)
        for (int r = 0; r < size; r++) psp_cpu.v[cols[c][r]] = 0.0f;
    consume();
}

void psp_vmone(uint32_t vd, int size) {
    int cols[4][4];
    matrix_cols(vd, size, cols);
    for (int c = 0; c < size; c++)
        for (int r = 0; r < size; r++) psp_cpu.v[cols[c][r]] = 1.0f;
    consume();
}

void psp_vmmov(uint32_t vd, uint32_t vs, int size) {
    float tmp[4][4];
    matrix_read(vs, size, tmp);
    matrix_write(vd, size, tmp);
    consume();
}

/* ---- matrix multiply and transform --------------------------------------- */

/* Scale every element of a matrix by a scalar. Orientation-independent, so
 * this one is unambiguous. */
void psp_vmscl(uint32_t vd, uint32_t vs, uint32_t vt, int size) {
    float m[4][4];
    int t[4];
    matrix_read(vs, size, m);
    psp_vfpu_regs(vt, 1, t);
    const float k = psp_cpu.v[t[0]];
    for (int c = 0; c < size; c++)
        for (int r = 0; r < size; r++) m[c][r] *= k;
    matrix_write(vd, size, m);
    consume();
}

/* Transform a vector by a matrix. The hardware multiplies by the TRANSPOSE of
 * the matrix register as addressed: vd[i] = sum over k of S[col i][row k] *
 * vt[k] (PPSSPP Int_Vtfm: d[i] += s[i*4+k] * t[k] over its column-major
 * ReadMatrix). Code that wants M * v therefore names the transposed view --
 * PSP2i loads a column-major matrix into M100 with lv.q and transforms with
 * E100 (36 of its 37 vhtfm sites). An earlier version computed S * v, which
 * gave M^T * v for exactly that code.
 *
 * `size` is the matrix order. psp_vhtfm is the homogeneous form: the source
 * vector has one lane fewer and an implicit 1.0 in the last position, and the
 * result has all `order` lanes -- PSP2i's vertex clip test reads the w lane
 * of a vhtfm4 result, which the earlier three-lane write left stale. */
static void transform(uint32_t vd, uint32_t vs, uint32_t vt, int order, int homogeneous) {
    float m[4][4];
    int d[4], t[4];
    matrix_read(vs, order, m);
    const int vn = homogeneous ? order - 1 : order;
    psp_vfpu_regs(vt, vn, t);
    psp_vfpu_regs(vd, order, d);

    float in[4], out[4];
    for (int i = 0; i < vn; i++) in[i] = psp_cpu.v[t[i]];
    if (homogeneous) in[order - 1] = 1.0f;
    for (int i = 0; i < order; i++) {
        float sum = 0.0f;
        for (int k = 0; k < order; k++) sum += m[i][k] * in[k];
        out[i] = sum;
    }
    /* vd may be one of the sources, so write only after the whole result is
     * computed. */
    for (int i = 0; i < order; i++) psp_cpu.v[d[i]] = out[i];
    consume();
}

void psp_vtfm(uint32_t vd, uint32_t vs, uint32_t vt, int size)  { transform(vd, vs, vt, size, 0); }
void psp_vhtfm(uint32_t vd, uint32_t vs, uint32_t vt, int size) { transform(vd, vs, vt, size, 1); }

/* Matrix product with the same convention as the transform above: the result
 * is S^T * T, where S and T are the matrices as addressed (PPSSPP Int_Vmmul:
 * d[a*4+b] = sum s[b*4+c] * t[a*4+c]). Each column of the result is a column
 * of T transformed by S, exactly as psp_vtfm would. That is why assemblers
 * flip vs's transpose bit for `vmmul.q M000, M100, M200` (= M100 * M200).
 *
 * The earlier S * T was unverified and wrong: PSP2i's multiply 0x08D7AED4
 * (vmmul E000, M200, E100 on out = a * b) produced a * b^T, so every
 * projection it composed came out transposed. That is invisible for a near
 * plane of 1 (the matrix is then nearly symmetric) and squeezed the gameplay
 * field ~200x toward the screen centre once its near plane was 201. */
void psp_vmmul(uint32_t vd, uint32_t vs, uint32_t vt, int size) {
    float a[4][4], b[4][4], out[4][4];
    matrix_read(vs, size, a);
    matrix_read(vt, size, b);

    for (int c = 0; c < size; c++)
        for (int r = 0; r < size; r++) {
            float sum = 0.0f;
            for (int k = 0; k < size; k++) sum += a[r][k] * b[c][k];
            out[c][r] = sum;
        }
    matrix_write(vd, size, out);
    consume();
}

/* Compare, writing one condition bit per lane plus the any/all summary bits
 * that vcmov and the bvt/bvf branches read. Lanes beyond the operand width
 * keep their previous condition bits. */
void psp_vcmp(uint32_t cond, uint32_t vs, uint32_t vt, int size) {
    float s[4], t[4];
    read_src(vs, size, s, 0);
    read_src(vt, size, t, 1);

    uint32_t cc = 0;
    int all = 1, any = 0;
    for (int i = 0; i < size; i++) {
        float a = s[i], b = t[i];
        int r;
        switch (cond & 0xF) {
        case 0:  r = 0;                         break;   /* FL  */
        case 1:  r = (a == b);                  break;   /* EQ  */
        case 2:  r = (a <  b);                  break;   /* LT  */
        case 3:  r = (a <= b);                  break;   /* LE  */
        case 4:  r = 1;                         break;   /* TR  */
        case 5:  r = (a != b);                  break;   /* NE  */
        case 6:  r = (a >= b);                  break;   /* GE  */
        case 7:  r = (a >  b);                  break;   /* GT  */
        case 8:  r = (a == 0.0f);               break;   /* EZ  */
        case 9:  r = (a != a);                  break;   /* EN: NaN */
        case 10: r = isinf(a) != 0;             break;   /* EI: infinity */
        case 11: r = (a != a) || isinf(a);      break;   /* ES: NaN or infinity */
        case 12: r = (a != 0.0f);               break;   /* NZ  */
        case 13: r = (a == a);                  break;   /* NN  */
        case 14: r = !isinf(a);                 break;   /* NI  */
        default: r = !((a != a) || isinf(a));   break;   /* NS  */
        }
        if (r) { cc |= 1u << i; any = 1; } else { all = 0; }
    }
    if (any) cc |= 1u << 4;
    if (all) cc |= 1u << 5;
    const uint32_t affected = ((1u << size) - 1) | (1u << 4) | (1u << 5);
    psp_cpu.vfpu_cc = (psp_cpu.vfpu_cc & ~affected) | cc;
    consume();
}

/* viim / vfim -- write a single lane from an immediate encoded in the
 * instruction. Only the destination prefix can apply. */
void psp_vimm(uint32_t vd, float value) {
    float out[4] = { value, 0, 0, 0 };
    write_dst(vd, 1, out);
    consume();
}
