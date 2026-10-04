/* VFPU tests — synthetic data only.
 *
 * Two things get pinned here. The first is register addressing, because the
 * layout is what makes a matrix row and column alias correctly and everything
 * else is built on it. The second is prefix semantics: swizzle, constants,
 * negation, saturation and write masking, each consumed by exactly one
 * instruction. Ignoring a prefix produces silently wrong numbers, which is
 * the one failure mode this project has spent its whole life avoiding.
 */

#include "psprecomp/vfpu.h"

#include <math.h>
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

#define CHECK_F(got, want, label)                                            \
    CHECK((got) > (want) - 1e-5f && (got) < (want) + 1e-5f,                   \
          "%s: got %f, want %f", (label), (double)(got), (double)(want))

static void test_register_addressing(void) {
    int r[4];

    /* A quad in matrix 0, column 0 is four consecutive rows: indices
     * 0, 1, 2, 3 under the mtx*4 + col*32 + row layout. */
    int n = psp_vfpu_regs(0x00, 4, r);
    CHECK(n == 4, "a quad names four registers, got %d", n);
    CHECK(r[0] == 0 && r[1] == 1 && r[2] == 2 && r[3] == 3,
          "quad M000: got %d,%d,%d,%d", r[0], r[1], r[2], r[3]);

    /* A single names exactly one. */
    n = psp_vfpu_regs(0x00, 1, r);
    CHECK(n == 1 && r[0] == 0, "single names one register");

    /* The transpose bit (bit 5) walks the other axis. Column-major access of
     * the same matrix must land on a *different* set of registers -- if it did
     * not, transposing a matrix would be a no-op and every rotation would be
     * wrong. */
    int rowwise[4], colwise[4];
    psp_vfpu_regs(0x00, 4, rowwise);
    psp_vfpu_regs(0x20, 4, colwise);
    CHECK(memcmp(rowwise, colwise, sizeof rowwise) != 0,
          "transposed access reaches different registers");
    CHECK(colwise[0] == 0 && colwise[1] == 32 && colwise[2] == 64 && colwise[3] == 96,
          "transposed quad strides by column: got %d,%d,%d,%d",
          colwise[0], colwise[1], colwise[2], colwise[3]);

    /* Every index must stay inside the 128-register file, for every width and
     * every possible field value. */
    for (uint32_t vreg = 0; vreg < 128; vreg++) {
        for (int size = 1; size <= 4; size++) {
            int idx[4];
            int len = psp_vfpu_regs(vreg, size, idx);
            for (int i = 0; i < len; i++) {
                if (idx[i] < 0 || idx[i] >= 128) {
                    printf("FAIL vreg=0x%02X size=%d lane %d -> %d (out of range)\n",
                           vreg, size, i, idx[i]);
                    failures++;
                }
            }
        }
    }
}

static void test_load_store(void) {
    const uint32_t AT = 0x08860000u;

    /* Quad round-trip through guest memory. */
    float in[4] = { 1.5f, -2.25f, 3.75f, 0.5f };
    for (int i = 0; i < 4; i++) psp_write_f32(AT + (uint32_t)i * 4, in[i]);

    psp_lv_q(0x00, AT);
    int r[4];
    psp_vfpu_regs(0x00, 4, r);
    for (int i = 0; i < 4; i++) CHECK_F(psp_cpu.v[r[i]], in[i], "lv.q lane");

    psp_sv_q(0x00, AT + 64);
    for (int i = 0; i < 4; i++)
        CHECK_F(psp_read_f32(AT + 64 + (uint32_t)i * 4), in[i], "sv.q lane");

    /* Quad addresses are 16-byte aligned; a misaligned address is masked down
     * rather than faulting, which is what the hardware does. */
    psp_lv_q(0x04, AT + 7);
    int r2[4];
    psp_vfpu_regs(0x04, 4, r2);
    CHECK_F(psp_cpu.v[r2[0]], in[0], "misaligned lv.q masks the address");

    psp_lv_s(0x08, AT + 4);
    int r3[4];
    psp_vfpu_regs(0x08, 1, r3);
    CHECK_F(psp_cpu.v[r3[0]], in[1], "lv.s");
}

/* Load a quad register from an array, for the arithmetic tests. */
static void set_quad(uint32_t vreg, const float f[4]) {
    int r[4];
    psp_vfpu_regs(vreg, 4, r);
    for (int i = 0; i < 4; i++) psp_cpu.v[r[i]] = f[i];
}
static void get_quad(uint32_t vreg, float f[4]) {
    int r[4];
    psp_vfpu_regs(vreg, 4, r);
    for (int i = 0; i < 4; i++) f[i] = psp_cpu.v[r[i]];
}

static void test_arithmetic(void) {
    psp_vfpu_reset();

    const float a[4] = { 1.0f, 2.0f, 3.0f, 4.0f };
    const float b[4] = { 5.0f, 6.0f, 7.0f, 8.0f };
    float out[4];

    /* Three different matrices so vd, vs and vt do not alias. */
    set_quad(0x00, a);
    set_quad(0x04, b);

    psp_vadd(0x08, 0x00, 0x04, 4);
    get_quad(0x08, out);
    for (int i = 0; i < 4; i++) CHECK_F(out[i], a[i] + b[i], "vadd lane");

    psp_vmul(0x08, 0x00, 0x04, 4);
    get_quad(0x08, out);
    for (int i = 0; i < 4; i++) CHECK_F(out[i], a[i] * b[i], "vmul lane");

    psp_vsub(0x08, 0x04, 0x00, 4);
    get_quad(0x08, out);
    for (int i = 0; i < 4; i++) CHECK_F(out[i], b[i] - a[i], "vsub lane");

    /* vdot collapses to one lane: 1*5 + 2*6 + 3*7 + 4*8 = 70. */
    psp_vdot(0x08, 0x00, 0x04, 4);
    int d[4];
    psp_vfpu_regs(0x08, 1, d);
    CHECK_F(psp_cpu.v[d[0]], 70.0f, "vdot");

    /* vscl multiplies every lane by a scalar. */
    int s[4];
    psp_vfpu_regs(0x0C, 1, s);
    psp_cpu.v[s[0]] = 3.0f;
    psp_vscl(0x10, 0x00, 0x0C, 4);
    get_quad(0x10, out);
    for (int i = 0; i < 4; i++) CHECK_F(out[i], a[i] * 3.0f, "vscl lane");

    /* Destination aliasing a source must still be correct: every source lane
     * has to be read before any destination lane is written. */
    set_quad(0x00, a);
    set_quad(0x04, b);
    psp_vadd(0x00, 0x00, 0x04, 4);
    get_quad(0x00, out);
    for (int i = 0; i < 4; i++) CHECK_F(out[i], a[i] + b[i], "vadd into its own source");
}

static void test_prefixes(void) {
    psp_vfpu_reset();

    const float a[4] = { 1.0f, 2.0f, 3.0f, 4.0f };
    float out[4];
    set_quad(0x00, a);
    set_quad(0x04, a);

    uint64_t before = psp_vfpu_trap_count();

    /* Source swizzle: 0x55 reads lane 1 into every lane. */
    psp_vfpu_set_prefix(0, 0x00000055);
    CHECK(psp_vfpu_prefix_pending(), "prefix registers as pending");
    psp_vadd(0x08, 0x00, 0x04, 4);
    get_quad(0x08, out);
    for (int i = 0; i < 4; i++) CHECK_F(out[i], a[1] + a[i], "vpfxs swizzle [y,y,y,y]");
    CHECK(!psp_vfpu_prefix_pending(), "the prefix is consumed by one instruction");
    CHECK(psp_vfpu_trap_count() == before, "a prefixed op computes, it does not trap");

    /* And only one: the next op is unprefixed. */
    psp_vadd(0x08, 0x00, 0x04, 4);
    get_quad(0x08, out);
    for (int i = 0; i < 4; i++) CHECK_F(out[i], a[i] + a[i], "prefix gone after one use");

    /* Constants: cst bits set, swizzle 1 with abs clear selects 1.0; with abs
     * set the same swizzle selects the high table entry 1/3. */
    psp_vfpu_set_prefix(1, 0x0000F055);
    psp_vadd(0x08, 0x00, 0x04, 4);
    get_quad(0x08, out);
    for (int i = 0; i < 4; i++) CHECK_F(out[i], a[i] + 1.0f, "vpfxt constant 1");
    psp_vfpu_set_prefix(1, 0x0000FF55);
    psp_vadd(0x08, 0x00, 0x04, 4);
    get_quad(0x08, out);
    for (int i = 0; i < 4; i++) CHECK_F(out[i], a[i] + 1.0f / 3.0f, "vpfxt constant 1/3");

    /* Negate lane 0 of s, identity swizzle elsewhere. */
    psp_vfpu_set_prefix(0, 0x000100E4);
    psp_vadd(0x08, 0x00, 0x04, 4);
    get_quad(0x08, out);
    CHECK_F(out[0], 0.0f, "vpfxs negate lane 0: -1 + 1");
    CHECK_F(out[1], 4.0f, "other lanes untouched");

    /* Destination: saturate lane 0 to [0,1], mask lane 3. */
    const float keep = 42.0f;
    int d[4];
    psp_vfpu_regs(0x08, 4, d);
    psp_cpu.v[d[3]] = keep;
    psp_vfpu_set_prefix(2, 0x00000801);
    psp_vadd(0x08, 0x00, 0x04, 4);
    get_quad(0x08, out);
    CHECK_F(out[0], 1.0f, "vpfxd sat0 clamps 2.0 to 1.0");
    CHECK_F(out[2], 6.0f, "unsaturated lane written");
    CHECK_F(out[3], keep, "masked lane not written");
}

static void test_compare(void) {
    psp_vfpu_reset();

    const float a[4] = { 1.0f, 2.0f, 3.0f, 4.0f };
    const float b[4] = { 1.0f, 9.0f, 0.0f, 4.0f };
    set_quad(0x00, a);
    set_quad(0x04, b);

    psp_vcmp(1 /* EQ */, 0x00, 0x04, 4);
    /* Lanes 0 and 3 are equal, so bits 0 and 3, plus "any" but not "all". */
    CHECK((psp_cpu.vfpu_cc & 0xF) == 0x9,
          "vcmp EQ per-lane bits: got 0x%X", psp_cpu.vfpu_cc & 0xF);
    CHECK(psp_cpu.vfpu_cc & (1u << 4), "the any-lane bit is set");
    CHECK(!(psp_cpu.vfpu_cc & (1u << 5)), "the all-lanes bit is not");

    psp_vcmp(1, 0x00, 0x00, 4);
    CHECK(psp_cpu.vfpu_cc & (1u << 5), "comparing a vector to itself sets all-lanes");
}

/* Read/write a whole matrix through the same addressing the ops use. */
static void set_matrix(uint32_t v, int n, const float m[4][4]) {
    const uint32_t mtx = (v >> 2) & 7;
    for (int c = 0; c < n; c++) {
        int r[4];
        psp_vfpu_regs((mtx << 2) | (uint32_t)c, n, r);
        for (int i = 0; i < n; i++) psp_cpu.v[r[i]] = m[c][i];
    }
}
static void get_matrix(uint32_t v, int n, float m[4][4]) {
    const uint32_t mtx = (v >> 2) & 7;
    for (int c = 0; c < n; c++) {
        int r[4];
        psp_vfpu_regs((mtx << 2) | (uint32_t)c, n, r);
        for (int i = 0; i < n; i++) m[c][i] = psp_cpu.v[r[i]];
    }
}

static void test_matrix_ops(void) {
    psp_vfpu_reset();
    float m[4][4], out[4][4];

    /* vmidt must produce a real identity: ones on the diagonal, zeros
     * elsewhere. This is what catches the column-addressing bug -- a helper
     * that walks rows while claiming to walk columns still writes four ones,
     * just in the wrong places, so only checking the off-diagonal zeros
     * distinguishes them. */
    psp_vmidt(0x00, 4);
    get_matrix(0x00, 4, out);
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            CHECK_F(out[c][r], (c == r) ? 1.0f : 0.0f, "vmidt element");

    psp_vmzero(0x04, 4);
    get_matrix(0x04, 4, out);
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) CHECK_F(out[c][r], 0.0f, "vmzero element");

    /* vmmov must copy every element, including off-diagonal ones -- a
     * diagonal-only copy would pass an identity round-trip. */
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) m[c][r] = (float)(c * 4 + r + 1);
    set_matrix(0x08, 4, m);
    psp_vmmov(0x0C, 0x08, 4);
    get_matrix(0x0C, 4, out);
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) CHECK_F(out[c][r], m[c][r], "vmmov element");

    /* Scaling is orientation-independent, so it can be checked outright. */
    int k[4];
    psp_vfpu_regs(0x40, 1, k);
    psp_cpu.v[k[0]] = 2.5f;
    psp_vmscl(0x10, 0x08, 0x40, 4);
    get_matrix(0x10, 4, out);
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) CHECK_F(out[c][r], m[c][r] * 2.5f, "vmscl element");
}

static void test_matrix_transform(void) {
    psp_vfpu_reset();
    float m[4][4], v[4];

    /* The hardware transforms by the TRANSPOSE of the matrix as addressed
     * (PPSSPP Int_Vtfm), so code that wants M * v names the transposed view:
     * transforming a basis vector through E200 yields M200's column, and
     * through M200 itself yields its row. An identity test passes either
     * way; these do not. */
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) m[c][r] = (float)(c * 4 + r + 1);
    set_matrix(0x08, 4, m);

    for (int basis = 0; basis < 4; basis++) {
        int t[4], d[4];
        psp_vfpu_regs(0x40, 4, t);
        for (int i = 0; i < 4; i++) psp_cpu.v[t[i]] = (i == basis) ? 1.0f : 0.0f;

        psp_vtfm(0x44, 0x28, 0x40, 4);                     /* E200 */
        psp_vfpu_regs(0x44, 4, d);
        for (int r = 0; r < 4; r++)
            CHECK_F(psp_cpu.v[d[r]], m[basis][r], "vtfm through the transposed view: the column");
        psp_vtfm(0x44, 0x08, 0x40, 4);                     /* M200 */
        psp_vfpu_regs(0x44, 4, d);
        for (int r = 0; r < 4; r++)
            CHECK_F(psp_cpu.v[d[r]], m[r][basis], "vtfm through the matrix as addressed: the row");
    }

    /* vmmul is S^T * T (PPSSPP Int_Vmmul). With the identity as S the
     * result is T; with the identity as T it is S transposed. */
    psp_vmidt(0x00, 4);
    psp_vmmul(0x0C, 0x08, 0x00, 4);
    float out[4][4];
    get_matrix(0x0C, 4, out);
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) CHECK_F(out[c][r], m[r][c], "vmmul(M, I) == M^T");

    psp_vmmul(0x0C, 0x00, 0x08, 4);
    get_matrix(0x0C, 4, out);
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) CHECK_F(out[c][r], m[c][r], "vmmul(I, M) == M");

    /* vmmul and vtfm must agree: vmmul(A, B) = A^T B, and transforming by
     * that (vtfm applies the transpose) is B^T (A x) -- A x through A's
     * transposed view, then B as addressed. */
    float a[4][4], b[4][4];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) {
            a[c][r] = (float)((c + 1) * (r + 2) % 7) - 3.0f;
            b[c][r] = (float)((c + 3) * (r + 1) % 5) - 2.0f;
        }
    /* Every operand needs its OWN matrix. A register's matrix is (vreg>>2)&7,
     * so 0x08 and 0x48 are both matrix 2 -- an earlier version of this test
     * used both and quietly overwrote A while computing B*x, then blamed the
     * implementation. Matrices here: A=2, B=4, AB=5, x=6, results in 7/0/1. */
    set_matrix(0x08, 4, a);   /* matrix 2 */
    set_matrix(0x10, 4, b);   /* matrix 4 */

    int t[4];
    psp_vfpu_regs(0x18, 4, t);            /* matrix 6 */
    const float in[4] = { 1.0f, -2.0f, 0.5f, 3.0f };
    for (int i = 0; i < 4; i++) psp_cpu.v[t[i]] = in[i];

    /* vtfm by vmmul(A, B) */
    psp_vmmul(0x14, 0x08, 0x10, 4);       /* matrix 5 */
    psp_vtfm(0x1C, 0x14, 0x18, 4);        /* matrix 7 */
    float combined[4];
    int d[4];
    psp_vfpu_regs(0x1C, 4, d);
    for (int i = 0; i < 4; i++) combined[i] = psp_cpu.v[d[i]];

    /* B^T (A x) */
    psp_vtfm(0x00, 0x28, 0x18, 4);        /* matrix 0 = A x (E200) */
    psp_vtfm(0x04, 0x10, 0x00, 4);        /* matrix 1 = B^T (A x) */
    psp_vfpu_regs(0x04, 4, d);
    for (int i = 0; i < 4; i++)
        CHECK_F(psp_cpu.v[d[i]], combined[i],
                "vmmul and vtfm agree: vtfm(vmmul(A, B), x) == B^T (A x)");

    /* PSP2i's matrix multiply, 0x08D7AED4 (out, a, b): lv.q a's columns into
     * M100 and b's into M200, `vmmul.q E000, M200, E100`, sv.q M000's
     * columns. It must store a * b -- the earlier S * T stored a * b^T, and
     * every projection the game composed came out transposed. */
    float ga[4][4], gb[4][4], want[4][4];
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) {
            ga[c][r] = (float)(c * 4 + r + 1);
            gb[c][r] = (float)((c * 3 + r * 5) % 7) - 2.0f;
        }
    for (int c = 0; c < 4; c++)                /* want = a * b, column-major */
        for (int r = 0; r < 4; r++) {
            float sum = 0.0f;
            for (int k = 0; k < 4; k++) sum += ga[k][r] * gb[c][k];
            want[c][r] = sum;
        }
    set_matrix(0x04, 4, ga);                   /* M100 */
    set_matrix(0x08, 4, gb);                   /* M200 */
    psp_vmmul(32, 8, 36, 4);                   /* E000, M200, E100 */
    get_matrix(0x00, 4, out);
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++) CHECK_F(out[c][r], want[c][r], "the game's multiply stores a * b");

    /* vhtfm4: three source lanes plus an implicit 1, and all four result
     * lanes written (PSP2i's clip test reads the w lane). Through E100 the
     * result is M * (x, y, z, 1). */
    psp_vfpu_regs(0x18, 4, t);
    for (int i = 0; i < 4; i++) psp_cpu.v[t[i]] = 0.0f;
    psp_cpu.v[t[0]] = 1.0f; psp_cpu.v[t[1]] = 2.0f; psp_cpu.v[t[2]] = 3.0f;
    psp_vfpu_regs(0x1C, 4, d);
    psp_cpu.v[d[3]] = -999.0f;
    psp_vhtfm(0x1C, 36, 0x18, 4);              /* E100 = transposed view of ga */
    for (int r = 0; r < 4; r++) {
        const float e = ga[0][r] * 1.0f + ga[1][r] * 2.0f + ga[2][r] * 3.0f + ga[3][r];
        CHECK_F(psp_cpu.v[d[r]], e, "vhtfm4 through E100: M * (x, y, z, 1), all four lanes");
    }
}

/* vidt: the 1.0 goes in the lane given by the register's column bits (vd & 3
 * for a quad, vd & 1 for a pair), so vidt.q on C000, C010, C020, C030 builds
 * the identity matrix column by column. This is exactly how PSP2i builds its
 * translation matrices (0x08D7AD18); taking the lane from bits 6..7 instead
 * put every column's 1.0 in row 0, and every projection the game composed
 * from those matrices came out with its diagonal in row 0. */
static void test_vidt(void) {
    psp_vfpu_reset();
    for (uint32_t c = 0; c < 4; c++) psp_vidt(c, 4);       /* C000, C010, C020, C030 */
    float m[4][4];
    get_matrix(0x00, 4, m);
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            CHECK_F(m[c][r], (c == r) ? 1.0f : 0.0f, "vidt.q column by column builds the identity");

    /* Pair: the lane is vd & 1. */
    int d[4];
    psp_vidt(0x09, 2);                                      /* column 1 of matrix 2, rows 0-1 */
    psp_vfpu_regs(0x09, 2, d);
    CHECK_F(psp_cpu.v[d[0]], 0.0f, "vidt.p on an odd column: lane 0 is 0");
    CHECK_F(psp_cpu.v[d[1]], 1.0f, "vidt.p on an odd column: lane 1 is 1");
}

/* The no-prefix fast paths (direct register access) must give bit-identical
 * results to the general prefix-aware path. Identity prefixes (swizzle
 * x,y,z,w; no abs/neg/constant; no saturation or masking) force the general
 * path without changing the result. Covers every op with a fast path, every
 * size, and destinations that alias a source. */
typedef void (*binop_fn)(uint32_t, uint32_t, uint32_t, int);

static void fill_regs(unsigned seed) {
    for (int i = 0; i < 128; i++) {
        seed = seed * 1103515245u + 12345u;
        psp_cpu.v[i] = (float)((int)(seed >> 8) % 20001 - 10000) / 997.0f;
    }
}

static void test_fast_paths(void) {
    static const struct { const char *name; binop_fn fn; } OPS[] = {
        { "vadd", psp_vadd }, { "vsub", psp_vsub }, { "vmul", psp_vmul }, { "vdiv", psp_vdiv },
        { "vmin", psp_vmin }, { "vmax", psp_vmax }, { "vsge", psp_vsge }, { "vslt", psp_vslt },
        { "vscl", psp_vscl }, { "vdot", psp_vdot },
    };
    static const uint32_t REGS[] = { 0x00, 0x05, 0x13, 0x20, 0x27, 0x41, 0x62, 0x7F, 0x1A, 0x55 };
    float fast[128], slow[128];
    int bad = 0, runs = 0;
    for (size_t o = 0; o < sizeof OPS / sizeof OPS[0]; o++)
        for (int size = 1; size <= 4; size++)
            for (size_t a = 0; a < 10; a++)
                for (size_t b = 0; b < 10; b++) {
                    const uint32_t vs = REGS[a], vt = REGS[b];
                    const uint32_t vd = (a + b) % 3 == 0 ? vs : (a + b) % 3 == 1 ? vt : REGS[(a * 3 + b) % 10];
                    fill_regs((unsigned)(o * 7919 + size * 104729 + a * 31 + b));
                    OPS[o].fn(vd, vs, vt, size);
                    memcpy(fast, psp_cpu.v, sizeof fast);
                    fill_regs((unsigned)(o * 7919 + size * 104729 + a * 31 + b));
                    psp_vfpu_set_prefix(0, 0xE4);
                    psp_vfpu_set_prefix(1, 0xE4);
                    psp_vfpu_set_prefix(2, 0);
                    OPS[o].fn(vd, vs, vt, size);
                    memcpy(slow, psp_cpu.v, sizeof slow);
                    runs++;
                    if (memcmp(fast, slow, sizeof fast) != 0 && bad++ < 5)
                        printf("FAIL fast path %s size %d vd %02X vs %02X vt %02X differs\n",
                               OPS[o].name, size, vd, vs, vt);
                }
    CHECK(bad == 0, "%d of %d fast-path runs differ from the prefix path", bad, runs);
    CHECK(!psp_vfpu_prefix_pending(), "prefixes consumed");
}

/* vf2i / vi2f scale by 2^scale with an exact multiply instead of ldexp:
 * every rounding mode and scale must match an ldexp reference, including
 * NaN, infinities, denormals and out-of-range values. */
static int32_t ref_f2i(int mode, float s, int scale) {
    double x = ldexp((double)s, scale);
    if (x != x) return 0x7FFFFFFF;
    if (x >= 2147483647.0) return 0x7FFFFFFF;
    if (x <= -2147483648.0) return (int32_t)0x80000000u;
    switch (mode) {
    case PSP_VF2I_NEAREST: return (int32_t)nearbyint(x);
    case PSP_VF2I_ZERO:    return (int32_t)x;
    case PSP_VF2I_UP:      return (int32_t)ceil(x);
    default:               return (int32_t)floor(x);
    }
}

static void test_scaled_conversions(void) {
    static const float F[] = { 0.0f, -0.0f, 1.0f, -1.0f, 0.5f, -0.5f, 1.5f, 2.5f, -2.5f, 3.75f, 1e-30f, -1e-30f,
                               1.17549435e-38f, 1e-45f, 65535.9f, -65536.1f, 1e9f, -3e9f, 3.4e38f, -3.4e38f };
    int bad = 0;
    int r[4];
    psp_vfpu_regs(0x00, 1, r);
    for (int mode = 0; mode < 4; mode++)
        for (int sc = 0; sc < 32; sc++)
            for (size_t i = 0; i < sizeof F / sizeof F[0] + 3; i++) {
                float f = i < sizeof F / sizeof F[0] ? F[i] : i == sizeof F / sizeof F[0] ? INFINITY
                        : i == sizeof F / sizeof F[0] + 1 ? -INFINITY : NAN;
                psp_cpu.v[r[0]] = f;
                psp_vf2i(mode, 0x01, 0x00, (uint32_t)sc, 1);
                int r1[4];
                psp_vfpu_regs(0x01, 1, r1);
                uint32_t got;
                memcpy(&got, &psp_cpu.v[r1[0]], 4);
                if ((int32_t)got != ref_f2i(mode, f, sc) && bad++ < 5)
                    printf("FAIL vf2i mode %d scale %d of %g: got %d want %d\n", mode, sc, (double)f, (int32_t)got, ref_f2i(mode, f, sc));
            }
    static const int32_t I[] = { 0, 1, -1, 2, 3, 12345, -12345, 0x7FFFFFFF, (int32_t)0x80000000u, 0x00FFFFFF, 0x01000001, -0x01000001 };
    for (int sc = 0; sc < 32; sc++)
        for (size_t i = 0; i < sizeof I / sizeof I[0]; i++) {
            uint32_t bits = (uint32_t)I[i];
            memcpy(&psp_cpu.v[r[0]], &bits, 4);
            psp_vi2f(0x01, 0x00, (uint32_t)sc, 1);
            int r1[4];
            psp_vfpu_regs(0x01, 1, r1);
            const float want = (float)ldexp((double)I[i], -sc);
            if (memcmp(&psp_cpu.v[r1[0]], &want, 4) != 0 && bad++ < 5)
                printf("FAIL vi2f scale %d of %d: got %g want %g\n", sc, I[i], (double)psp_cpu.v[r1[0]], (double)want);
        }
    CHECK(bad == 0, "%d scaled conversions differ from the ldexp reference", bad);
}

/* Source prefixes are decoded once when set: random prefixes on vadd must
 * match a reference that decodes the prefix bits itself. */
static float ref_src(uint32_t p, const float quad[4], int i) {
    static const float K[8] = { 0.0f, 1.0f, 2.0f, 0.5f, 3.0f, 1.0f / 3.0f, 0.25f, 1.0f / 6.0f };
    const int swz = (int)(p >> (2 * i)) & 3, ab = (int)(p >> (8 + i)) & 1;
    const int cst = (int)(p >> (12 + i)) & 1, neg = (int)(p >> (16 + i)) & 1;
    float x = cst ? K[swz + 4 * ab] : (ab ? fabsf(quad[swz]) : quad[swz]);
    return neg ? -x : x;
}

static void test_prefix_decode(void) {
    unsigned seed = 12345;
    int bad = 0;
    for (int n = 0; n < 2000; n++) {
        seed = seed * 1103515245u + 12345u; const uint32_t ps = (seed >> 4) & 0xFFFFFu;
        seed = seed * 1103515245u + 12345u; const uint32_t pt = (seed >> 4) & 0xFFFFFu;
        const int size = 1 + n % 4;
        fill_regs((unsigned)n);
        float qs[4], qt[4];
        int r[4];
        psp_vfpu_regs(0x00, 4, r); for (int i = 0; i < 4; i++) qs[i] = psp_cpu.v[r[i]];
        psp_vfpu_regs(0x04, 4, r); for (int i = 0; i < 4; i++) qt[i] = psp_cpu.v[r[i]];
        /* sizes below 4 index the same quad: the operands start at lane 0 */
        psp_vfpu_set_prefix(0, ps);
        psp_vfpu_set_prefix(1, pt);
        psp_vadd(0x08, 0x00, 0x04, size);
        int d[4];
        psp_vfpu_regs(0x08, size, d);
        for (int i = 0; i < size; i++) {
            const float want = ref_src(ps, qs, i) + ref_src(pt, qt, i);
            if (memcmp(&psp_cpu.v[d[i]], &want, 4) != 0 && bad++ < 5)
                printf("FAIL prefix decode: size %d lane %d prefixes %05X/%05X\n", size, i, ps, pt);
        }
    }
    CHECK(bad == 0, "%d prefixed lanes differ from the reference decoder", bad);
}

int main(void) {
    if (psp_mem_init() != 0) { printf("memory init failed\n"); return 1; }
    psp_cpu_reset();
    psp_vfpu_reset();

    test_register_addressing();
    test_load_store();
    test_arithmetic();
    test_prefixes();
    test_compare();
    test_matrix_ops();
    test_matrix_transform();
    test_vidt();
    test_fast_paths();
    test_scaled_conversions();
    test_prefix_decode();

    psp_mem_free();

    if (failures) {
        printf("\n%d check(s) failed\n", failures);
        return 1;
    }
    printf("all VFPU checks passed\n");
    return 0;
}
