/* psprecomp — the VFPU.
 *
 * 128 single-precision registers, addressed as 8 matrices of 4x4. A single
 * 7-bit register field can name a scalar, a 2/3/4-element row, a column, or a
 * whole matrix, depending on the instruction's width bits and a transpose bit.
 *
 * ## Register layout
 *
 * The file is indexed `v[matrix*4 + column*32 + row]`. That looks arbitrary
 * and is not: it is the layout that makes a row and a column of the same
 * matrix alias the same storage the way the hardware does. A game that writes
 * a matrix by columns and reads it by rows -- which is exactly what a
 * transpose does -- only works if this matches.
 *
 * ## Prefixes
 *
 * `vpfxs`/`vpfxt`/`vpfxd` do not compute anything -- they set a register that
 * rewrites the *operands of the next instruction*: swizzling lanes, taking
 * absolute values, substituting constants, negating, saturating and masking
 * writes. They are implemented (see src/vfpu.c for the bit layout): every
 * element-wise operation reads its sources and writes its destination through
 * them, and they are consumed by that one instruction. Matrix instructions do
 * not take prefixes and simply discard a pending one.
 */
#ifndef PSPRECOMP_VFPU_H
#define PSPRECOMP_VFPU_H

#include "cpu.h"
#include "mem.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve a 7-bit register field and width into up to four indices into
 * psp_cpu.v[]. Returns the number of lanes. */
int psp_vfpu_regs(uint32_t vreg, int size, int out[4]);

/* Load/store. Quad forms are 16-byte aligned on hardware; the address is
 * masked rather than faulting, which is what the hardware does. */
void psp_lv_s(uint32_t vt, uint32_t addr);
void psp_lv_q(uint32_t vt, uint32_t addr);
void psp_sv_s(uint32_t vt, uint32_t addr);
void psp_sv_q(uint32_t vt, uint32_t addr);

/* Element-wise arithmetic across `size` lanes. */
void psp_vadd(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vsub(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vmul(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vdiv(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vmin(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vmax(uint32_t vd, uint32_t vs, uint32_t vt, int size);

/* Reductions. vdot writes one lane; vscl scales a vector by a scalar. */
void psp_vdot(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vscl(uint32_t vd, uint32_t vs, uint32_t vt, int size);

/* Comparison, writing the VFPU condition codes. */
void psp_vcmp(uint32_t cond, uint32_t vs, uint32_t vt, int size);

/* Unary element-wise ops (VFPU4). One entry point rather than eighteen, since
 * they differ only in the scalar function applied per lane. */
enum {
    PSP_VU_MOV = 0, PSP_VU_ABS, PSP_VU_NEG, PSP_VU_ZERO, PSP_VU_ONE,
    PSP_VU_RCP, PSP_VU_RSQ, PSP_VU_SQRT, PSP_VU_SIN, PSP_VU_COS,
    PSP_VU_EXP2, PSP_VU_LOG2, PSP_VU_SAT0, PSP_VU_SAT1,
    PSP_VU_NRCP, PSP_VU_NSIN, PSP_VU_REXP2, PSP_VU_ASIN,
    PSP_VU_F2IZ, PSP_VU_I2F
};
void psp_vunary(int op, uint32_t vd, uint32_t vs, int size);

/* Matrix ops that need no multiply: identity, zero, one, and copy. `size` is
 * the matrix order (2, 3 or 4). */
void psp_vmidt(uint32_t vd, int size);
void psp_vidt(uint32_t vd, int size);
void psp_vimm(uint32_t vd, float value);
void psp_vcst(uint32_t vd, uint32_t which, int size);
void psp_vmzero(uint32_t vd, int size);
void psp_vmone(uint32_t vd, int size);
void psp_vmmov(uint32_t vd, uint32_t vs, int size);

/* Matrix multiply, transform and scale. See the note in vfpu.c: the operand
 * orientation of vmmul is not independently verified. */
void psp_vmscl(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vtfm(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vmmul(uint32_t vd, uint32_t vs, uint32_t vt, int size);
/* Homogeneous transform: vector one lane narrower than the matrix order,
 * with an implicit 1.0 in the last lane. `size` is the matrix order. */
void psp_vhtfm(uint32_t vd, uint32_t vs, uint32_t vt, int size);

/* Set-if comparisons (1.0 / 0.0 per lane) and the cross products. vcrsp at
 * quad width is vqmul, the quaternion product. */
void psp_vsge(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vslt(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vcrs(uint32_t vd, uint32_t vs, uint32_t vt, int size);
void psp_vcrsp(uint32_t vd, uint32_t vs, uint32_t vt, int size);

/* Scaled conversions: vf2i* multiply by 2^scale then round; vi2f divides. */
enum { PSP_VF2I_NEAREST = 0, PSP_VF2I_ZERO, PSP_VF2I_UP, PSP_VF2I_DOWN };
void psp_vf2i(int mode, uint32_t vd, uint32_t vs, uint32_t scale, int size);
void psp_vi2f(uint32_t vd, uint32_t vs, uint32_t scale, int size);

/* Conditional move on the VFPU condition codes. */
void psp_vcmov(uint32_t vd, uint32_t vs, int size, int tf, int imm3);
/* Rotation row from one angle; imm5 places cosine and sine. */
void psp_vrot(uint32_t vd, uint32_t vs, uint32_t imm5, int size);

/* VFPU9 (opcode 0x34, rs 2), by rt sub-opcode. */
enum {
    PSP_V9_BFY1 = 0x02, PSP_V9_BFY2 = 0x03, PSP_V9_OCP = 0x04, PSP_V9_SOCP = 0x05,
    PSP_V9_FAD = 0x06, PSP_V9_AVG = 0x07, PSP_V9_SGN = 0x0A
};
void psp_vfpu9(int op, uint32_t vd, uint32_t vs, int size);

/* VFPU7 integer packing conversions (opcode 0x34, rs 1), by rt sub-opcode. */
enum {
    PSP_V7_UC2I = 0x18, PSP_V7_C2I = 0x19, PSP_V7_US2I = 0x1A, PSP_V7_S2I = 0x1B,
    PSP_V7_I2UC = 0x1C, PSP_V7_I2C = 0x1D, PSP_V7_I2US = 0x1E, PSP_V7_I2S = 0x1F
};
void psp_vconv(int op, uint32_t vd, uint32_t vs, int size);

/* mtv / mfv: 8-bit register number, 128+ being the control registers. */
void     psp_mtv(uint32_t reg, uint32_t value);
uint32_t psp_mfv(uint32_t reg);

/* Prefix state. Set by vpfxs/vpfxt/vpfxd; consumed (and cleared) by the next
 * arithmetic instruction. */
void psp_vfpu_set_prefix(int which, uint32_t value);
int  psp_vfpu_prefix_pending(void);
/* For generated code: nonzero while a prefix is pending (then the runtime
 * call is used); psp_vfpu_consume() drops pending prefixes, as an operation
 * that takes none (vtfm, vhtfm) does. */
extern int psp_vfpu_pfx_any;
void psp_vfpu_consume(void);
void psp_vfpu_reset(void);

/* Reports an instruction the VFPU cannot yet execute, by address and name. */
void psp_vfpu_unimplemented(uint32_t addr, const char *what);
uint64_t psp_vfpu_trap_count(void);

#ifdef __cplusplus
}
#endif

#endif /* PSPRECOMP_VFPU_H */
