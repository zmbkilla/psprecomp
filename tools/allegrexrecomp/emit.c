/* The C emitter. See emit.h. */

#include "emit.h"
#include "decode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Generated register names: r_a0, r_sp, ... The generated header #defines each
 * onto psp_cpu.r[N]. Naming them beats indexing because the emitted code then
 * reads like the assembly it came from. */
static const char *const RN[32] = {
    "r_zero","r_at","r_v0","r_v1","r_a0","r_a1","r_a2","r_a3",
    "r_t0","r_t1","r_t2","r_t3","r_t4","r_t5","r_t6","r_t7",
    "r_s0","r_s1","r_s2","r_s3","r_s4","r_s5","r_s6","r_s7",
    "r_t8","r_t9","r_k0","r_k1","r_gp","r_sp","r_fp","r_ra"
};

typedef struct {
    FILE *out;
    const a_analysis *an;
    const a_func *func;
    uint8_t *is_label;     /* per word, within the current function */
    uint8_t *is_slot;      /* per word: consumed as a delay slot */
    uint32_t *entries;     /* interior labels that got a dispatch thunk */
    int nentries, centries;
    const uint32_t *hooks; /* functions with a run-time hook (emit_opts) */
    int nhooks;
} ectx;

static void entry_push(ectx *c, uint32_t a) {
    if (c->nentries == c->centries) {
        int n = c->centries ? c->centries * 2 : 1024;
        uint32_t *p = (uint32_t *)realloc(c->entries, (size_t)n * sizeof *p);
        if (!p) return;                  /* out of memory: lose the thunk, not the run */
        c->entries = p;
        c->centries = n;
    }
    c->entries[c->nentries++] = a;
}

/* vfim carries a half-precision float. Expanding it here keeps the runtime
 * dealing only in single precision. */
static float half_to_float(uint16_t h) {
    const uint32_t sign = (uint32_t)(h >> 15) << 31;
    const uint32_t exp  = (h >> 10) & 0x1F;
    const uint32_t man  = h & 0x3FF;
    uint32_t bits;
    if (exp == 0)        bits = sign | (man ? ((127 - 15 + 1) << 23) | (man << 13) : 0);
    else if (exp == 31)  bits = sign | 0x7F800000u | (man << 13);
    else                 bits = sign | ((exp + 127 - 15) << 23) | (man << 13);
    float f;
    memcpy(&f, &bits, sizeof f);
    return f;
}
/* ---- helpers ------------------------------------------------------------- */

static uint32_t widx(const a_analysis *an, uint32_t addr) {
    return (addr - an->base) >> 2;
}

static int owned_by(const a_analysis *an, uint32_t addr, uint32_t owner) {
    if (addr < an->base || addr >= an->base + an->size) return 0;
    return an->owner[widx(an, addr)] == owner;
}

static uint32_t fetch(const a_analysis *an, uint32_t addr) {
    const uint8_t *p = an->code + (addr - an->base);
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int is_import(const a_analysis *an, uint32_t addr) {
    return an->stub_size && addr >= an->stub_addr &&
           addr < an->stub_addr + an->stub_size;
}

/* Is `addr` a discovered function entry? Binary search over the sorted list. */
static int is_function(const a_analysis *an, uint32_t addr) {
    int lo = 0, hi = an->nfuncs - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (an->funcs[mid].addr == addr) return 1;
        if (an->funcs[mid].addr < addr) lo = mid + 1; else hi = mid - 1;
    }
    return 0;
}

/* Emit the address + disassembly comment that precedes every statement. */
static void comment(ectx *c, const a_insn *in) {
    char text[128];
    a_format(in, text, sizeof text);
    fprintf(c->out, "    /* %08X  %s */\n", in->addr, text);
}

/* Emit a call to whatever lives at a static target. */
static void emit_static_call(ectx *c, uint32_t target) {
    if (is_import(c->an, target)) {
        fprintf(c->out, "    psp_import_%08X();\n", target);
    } else if (is_function(c->an, target)) {
        /* Check the stack across the call. A callee that consumes stack and
         * does not return it corrupts every callee-saved register its caller
         * restores afterwards, and the corruption surfaces far away. Checking
         * at the call site catches it wherever the imbalance actually occurs --
         * including across split bodies, where no single body owns both halves
         * of a frame and a per-body check is blind. */
        fprintf(c->out, "    { uint32_t _spc = r_sp; psp_func_%08X();"
                        " PSP_SP_CALL(0x%08Xu, _spc, r_sp); }\n", target, target);
    } else {
        /* Discovery did not reach it. Going through the dispatch table means
         * the failure is named at run time instead of failing to link. */
        fprintf(c->out, "    psp_dispatch(0x%08Xu);  /* not discovered */\n", target);
    }
}

/* After a call returns, $ra holds the address the callee actually returned
 * to: a normal `jr $ra` leaves it equal to the link the caller set. When it
 * differs, the callee left by some other route -- reloaded $ra from an outer
 * frame and returned *past* this call (hand-written code does this: a
 * subroutine reached by `bal` bails out through its parent's epilogue). The
 * hardware is then executing in an outer caller, so this C frame must return
 * too, and so on until the frame whose call site matches.
 *
 * Observed: the inflate routine at 0x08DE0C40 calls its bit decoder with
 * bltzal; on end-of-stream the decoder exits through the inflate epilogue.
 * Without this check the C call simply returned into the middle of inflate,
 * which kept decoding past the end of the data with its frame already
 * popped. */
static void emit_return_check(ectx *c, const char *ind, uint32_t link) {
    fprintf(c->out, "%sif (r_ra != 0x%08Xu) return;  /* returned past this call: keep unwinding */\n",
            ind, link);
}

/* The function whose entry is `addr`, or NULL. */
static const a_func *func_at(const a_analysis *an, uint32_t addr) {
    int lo = 0, hi = an->nfuncs - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (an->funcs[mid].addr == addr) return &an->funcs[mid];
        if (an->funcs[mid].addr < addr) lo = mid + 1; else hi = mid - 1;
    }
    return NULL;
}

/* Does `f` contain a call whose delay slot reloads $ra (`jal g ; lw $ra, ..`)?
 * Such a function returns to its *caller's* caller, which is the only way a
 * direct call can come back with $ra pointing into the callee (below). */
static int reloads_ra_in_slot(const a_analysis *an, const a_func *f) {
    for (uint32_t a = f->start; a + 4 < f->end; a += 4) {
        if (!owned_by(an, a, f->addr)) continue;
        a_insn in, s;
        a_decode(fetch(an, a), a, &in);
        if (!in.is_call || in.is_branch) continue;
        a_decode(fetch(an, a + 4), a + 4, &s);
        if (s.op == A_LW && s.rt == 31) return 1;
    }
    return 0;
}

/* Is `target` a direct callee that can return into its own middle? */
static int callee_can_reenter(const a_analysis *an, uint32_t target) {
    const a_func *fc = func_at(an, target);
    if (!fc) return 0;
    /* The callee re-enters itself when *it* calls such a function. */
    for (uint32_t a = fc->start; a + 4 < fc->end; a += 4) {
        if (!owned_by(an, a, fc->addr)) continue;
        a_insn in;
        a_decode(fetch(an, a), a, &in);
        if (!in.is_call || in.is_indirect || !in.has_target) continue;
        const a_func *g = func_at(an, in.target);
        if (g && reloads_ra_in_slot(an, g)) return 1;
    }
    return 0;
}

/* The same check for a direct call, where the callee's extent is known.
 *
 * $ra can also come back pointing *into the callee itself*. Observed at
 * 0x08A8422C: the callee C calls a helper that pushes a frame and tail-calls
 * with `lw $ra` in the delay slot, so control returns into C with the
 * helper's 16-byte frame still on the stack; C's epilogue then runs twice --
 * the first `jr $ra` jumps back into C (popping the helper's frame), the
 * second really returns. Each `jr $ra` is a C `return`, so the first one
 * arrives here with $ra inside C. The hardware is still executing C, so
 * resume it there; any other mismatch is an unwind, as before. */
static void emit_direct_return_check(ectx *c, const char *ind, uint32_t link, uint32_t callee) {
    const a_func *fc = func_at(c->an, callee);
    if (!fc) { emit_return_check(c, ind, link); return; }
    fprintf(c->out,
            "%swhile (r_ra != 0x%08Xu) {  /* returned somewhere other than here */\n"
            "%s    if (r_ra - 0x%08Xu < 0x%Xu) psp_dispatch(r_ra);  /* back into the callee */\n"
            "%s    else return;  /* past this call: keep unwinding */\n"
            "%s}\n",
            ind, link, ind, fc->start, fc->end - fc->start, ind, ind);
}

/* ---- one non-control-flow instruction ------------------------------------ */

/* `ind` is the indentation, so a delay slot emitted inside an `if` body lines
 * up. Returns nothing: unhandled opcodes emit a trap rather than nothing, so
 * a gap is loud at run time instead of silently doing the wrong thing. */
static void emit_simple(ectx *c, const a_insn *in, const char *ind) {
    FILE *f = c->out;
    const char *rd = RN[in->rd], *rs = RN[in->rs], *rt = RN[in->rt];

    /* Writes to $zero are discarded by the hardware. Emitting them would
     * clobber a register the rest of the code assumes is always zero. */
    #define DEST_ZERO(reg) ((reg) == 0)

    switch (in->op) {
    case A_NOP:
        fprintf(f, "%s;\n", ind);
        return;

    /* --- ALU, register --- */
    case A_ADD: case A_ADDU:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = %s + %s;\n", ind, rd, rs, rt); return;
    case A_SUB: case A_SUBU:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = %s - %s;\n", ind, rd, rs, rt); return;
    case A_AND:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = %s & %s;\n", ind, rd, rs, rt); return;
    case A_OR:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = %s | %s;\n", ind, rd, rs, rt); return;
    case A_XOR:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = %s ^ %s;\n", ind, rd, rs, rt); return;
    case A_NOR:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = ~(%s | %s);\n", ind, rd, rs, rt); return;
    case A_SLT:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_slt(%s, %s);\n", ind, rd, rs, rt); return;
    case A_SLTU:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_sltu(%s, %s);\n", ind, rd, rs, rt); return;
    case A_MAX:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_max(%s, %s);\n", ind, rd, rs, rt); return;
    case A_MIN:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_min(%s, %s);\n", ind, rd, rs, rt); return;
    case A_MOVZ:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%sif (%s == 0) %s = %s;\n", ind, rt, rd, rs); return;
    case A_MOVN:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%sif (%s != 0) %s = %s;\n", ind, rt, rd, rs); return;

    /* --- ALU, immediate --- */
    case A_ADDI: case A_ADDIU:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = %s + %d;\n", ind, rt, rs, in->imm); return;
    case A_SLTI:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_slt(%s, (uint32_t)%d);\n", ind, rt, rs, in->imm); return;
    case A_SLTIU:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_sltu(%s, (uint32_t)%d);\n", ind, rt, rs, in->imm); return;
    case A_ANDI:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = %s & 0x%Xu;\n", ind, rt, rs, (unsigned)in->imm); return;
    case A_ORI:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = %s | 0x%Xu;\n", ind, rt, rs, (unsigned)in->imm); return;
    case A_XORI:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = %s ^ 0x%Xu;\n", ind, rt, rs, (unsigned)in->imm); return;
    case A_LUI:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = 0x%08Xu;\n", ind, rt, (unsigned)in->imm << 16); return;

    /* --- shifts. The helpers exist because C leaves shift-by->=32 undefined
       while MIPS masks the amount to five bits. --- */
    case A_SLL:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_sll(%s, %u);\n", ind, rd, rt, in->sa); return;
    case A_SRL:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_srl(%s, %u);\n", ind, rd, rt, in->sa); return;
    case A_SRA:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_sra(%s, %u);\n", ind, rd, rt, in->sa); return;
    case A_ROTR:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_rotr(%s, %u);\n", ind, rd, rt, in->sa); return;
    case A_SLLV:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_sll(%s, %s);\n", ind, rd, rt, rs); return;
    case A_SRLV:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_srl(%s, %s);\n", ind, rd, rt, rs); return;
    case A_SRAV:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_sra(%s, %s);\n", ind, rd, rt, rs); return;
    case A_ROTRV:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_rotr(%s, %s);\n", ind, rd, rt, rs); return;

    /* --- bit manipulation --- */
    case A_CLZ:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_clz(%s);\n", ind, rd, rs); return;
    case A_CLO:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_clo(%s);\n", ind, rd, rs); return;
    case A_SEB:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_seb(%s);\n", ind, rd, rt); return;
    case A_SEH:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_seh(%s);\n", ind, rd, rt); return;
    case A_WSBH:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_wsbh(%s);\n", ind, rd, rt); return;
    case A_WSBW:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_wsbw(%s);\n", ind, rd, rt); return;
    case A_BITREV:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_bitrev(%s);\n", ind, rd, rt); return;
    case A_EXT: {
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        unsigned pos = in->sa, size = in->rd + 1u;
        fprintf(f, "%s%s = psp_ext(%s, %u, %u);\n", ind, rt, rs, pos, size); return;
    }
    case A_INS: {
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        unsigned pos = in->sa, size = in->rd - in->sa + 1u;
        fprintf(f, "%s%s = psp_ins(%s, %s, %u, %u);\n", ind, rt, rt, rs, pos, size); return;
    }

    /* --- multiply / divide. These write HI/LO, never a GPR. --- */
    case A_MULT:  fprintf(f, "%spsp_mult(%s, %s);\n",  ind, rs, rt); return;
    case A_MULTU: fprintf(f, "%spsp_multu(%s, %s);\n", ind, rs, rt); return;
    case A_DIV:   fprintf(f, "%spsp_div(%s, %s);\n",   ind, rs, rt); return;
    case A_DIVU:  fprintf(f, "%spsp_divu(%s, %s);\n",  ind, rs, rt); return;
    case A_MADD:  fprintf(f, "%spsp_madd(%s, %s);\n",  ind, rs, rt); return;
    case A_MADDU: fprintf(f, "%spsp_maddu(%s, %s);\n", ind, rs, rt); return;
    case A_MSUB:  fprintf(f, "%spsp_msub(%s, %s);\n",  ind, rs, rt); return;
    case A_MSUBU: fprintf(f, "%spsp_msubu(%s, %s);\n", ind, rs, rt); return;
    case A_MFHI:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_cpu.hi;\n", ind, rd); return;
    case A_MFLO:
        if (DEST_ZERO(in->rd)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_cpu.lo;\n", ind, rd); return;
    case A_MTHI: fprintf(f, "%spsp_cpu.hi = %s;\n", ind, rs); return;
    case A_MTLO: fprintf(f, "%spsp_cpu.lo = %s;\n", ind, rs); return;

    /* --- loads --- */
    case A_LB:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = (uint32_t)(int32_t)(int8_t)psp_read8(%s + %d);\n",
                ind, rt, rs, in->imm); return;
    case A_LBU:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_read8(%s + %d);\n", ind, rt, rs, in->imm); return;
    case A_LH:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = (uint32_t)(int32_t)(int16_t)psp_read16(%s + %d);\n",
                ind, rt, rs, in->imm); return;
    case A_LHU:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_read16(%s + %d);\n", ind, rt, rs, in->imm); return;
    case A_LW: case A_LL:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_read32(%s + %d);\n", ind, rt, rs, in->imm); return;
    case A_LWL:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_lwl(%s, %s + %d);\n", ind, rt, rt, rs, in->imm); return;
    case A_LWR:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_lwr(%s, %s + %d);\n", ind, rt, rt, rs, in->imm); return;

    /* --- stores --- */
    case A_SB:
        fprintf(f, "%spsp_write8(%s + %d, (uint8_t)%s);\n", ind, rs, in->imm, rt); return;
    case A_SH:
        fprintf(f, "%spsp_write16(%s + %d, (uint16_t)%s);\n", ind, rs, in->imm, rt); return;
    case A_SW:
        fprintf(f, "%spsp_write32(%s + %d, %s);\n", ind, rs, in->imm, rt); return;
    case A_SWL:
        fprintf(f, "%spsp_swl(%s, %s + %d);\n", ind, rt, rs, in->imm); return;
    case A_SWR:
        fprintf(f, "%spsp_swr(%s, %s + %d);\n", ind, rt, rs, in->imm); return;
    case A_SC:
        /* No multiprocessor to contend with, so the store always succeeds. */
        fprintf(f, "%spsp_write32(%s + %d, %s);\n", ind, rs, in->imm, rt);
        if (!DEST_ZERO(in->rt)) fprintf(f, "%s%s = 1;\n", ind, rt);
        return;

    /* Cache and prefetch hints have no meaning without a cache model. */
    case A_CACHE: case A_PREF: case A_SYNC:
        fprintf(f, "%s;\n", ind); return;

    /* --- COP1, single precision only --- */
    case A_MTC1: fprintf(f, "%spsp_cpu.f[%u] = psp_bits_to_f32(%s);\n", ind, in->fs, rt); return;
    case A_MFC1:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_f32_to_bits(psp_cpu.f[%u]);\n", ind, rt, in->fs); return;
    case A_CTC1: fprintf(f, "%spsp_cpu.fcr31 = %s;\n", ind, rt); return;
    case A_CFC1:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_cpu.fcr31;\n", ind, rt); return;
    case A_LWC1:
        fprintf(f, "%spsp_cpu.f[%u] = psp_read_f32(%s + %d);\n", ind, in->ft, rs, in->imm); return;
    case A_SWC1:
        fprintf(f, "%spsp_write_f32(%s + %d, psp_cpu.f[%u]);\n", ind, rs, in->imm, in->ft); return;
    case A_ADD_S:
        fprintf(f, "%spsp_cpu.f[%u] = psp_cpu.f[%u] + psp_cpu.f[%u];\n", ind, in->fd, in->fs, in->ft); return;
    case A_SUB_S:
        fprintf(f, "%spsp_cpu.f[%u] = psp_cpu.f[%u] - psp_cpu.f[%u];\n", ind, in->fd, in->fs, in->ft); return;
    case A_MUL_S:
        fprintf(f, "%spsp_cpu.f[%u] = psp_cpu.f[%u] * psp_cpu.f[%u];\n", ind, in->fd, in->fs, in->ft); return;
    case A_DIV_S:
        fprintf(f, "%spsp_cpu.f[%u] = psp_cpu.f[%u] / psp_cpu.f[%u];\n", ind, in->fd, in->fs, in->ft); return;
    case A_MOV_S:
        fprintf(f, "%spsp_cpu.f[%u] = psp_cpu.f[%u];\n", ind, in->fd, in->fs); return;
    case A_NEG_S:
        fprintf(f, "%spsp_cpu.f[%u] = -psp_cpu.f[%u];\n", ind, in->fd, in->fs); return;
    case A_ABS_S:
        fprintf(f, "%spsp_cpu.f[%u] = psp_fabs(psp_cpu.f[%u]);\n", ind, in->fd, in->fs); return;
    case A_SQRT_S:
        fprintf(f, "%spsp_cpu.f[%u] = psp_fsqrt(psp_cpu.f[%u]);\n", ind, in->fd, in->fs); return;
    case A_CVT_S_W:
        fprintf(f, "%spsp_cpu.f[%u] = (float)(int32_t)psp_f32_to_bits(psp_cpu.f[%u]);\n",
                ind, in->fd, in->fs); return;
    case A_CVT_W_S: case A_TRUNC_W_S:
        fprintf(f, "%spsp_cpu.f[%u] = psp_bits_to_f32((uint32_t)(int32_t)psp_cpu.f[%u]);\n",
                ind, in->fd, in->fs); return;
    case A_C_COND_S:
        fprintf(f, "%spsp_fpu_set_cond(psp_fcmp(%u, psp_cpu.f[%u], psp_cpu.f[%u]));\n",
                ind, in->fcond, in->fs, in->ft); return;

    /* --- COP0. There is no privileged state to model. --- */
    case A_MFC0: case A_CFC0: case A_MFIC:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = 0;  /* no COP0 state modelled */\n", ind, rt); return;
    case A_MTC0: case A_CTC0: case A_MTIC:
        fprintf(f, "%s;  /* COP0 write ignored */\n", ind); return;

    /* --- VFPU: the subset with a real implementation. Everything else in the
       vector unit still falls through to a trap below, which is deliberate --
       see include/psprecomp/vfpu.h. --- */
    case A_LV_S:
        fprintf(f, "%spsp_lv_s(%u, %s + %d);\n", ind, in->vt, rs, in->imm & ~3); return;
    case A_LV_Q:
        fprintf(f, "%spsp_lv_q(%u, %s + %d);\n", ind, in->vt, rs, in->imm & ~3); return;
    case A_SV_S:
        fprintf(f, "%spsp_sv_s(%u, %s + %d);\n", ind, in->vt, rs, in->imm & ~3); return;
    case A_SV_Q:
        fprintf(f, "%spsp_sv_q(%u, %s + %d);\n", ind, in->vt, rs, in->imm & ~3); return;

    case A_VADD:
        fprintf(f, "%spsp_vadd(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VSUB:
        fprintf(f, "%spsp_vsub(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VMUL:
        fprintf(f, "%spsp_vmul(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VDIV:
        fprintf(f, "%spsp_vdiv(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VMIN:
        fprintf(f, "%spsp_vmin(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VMAX:
        fprintf(f, "%spsp_vmax(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VDOT:
        fprintf(f, "%spsp_vdot(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VSCL:
        fprintf(f, "%spsp_vscl(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VCMP:
        fprintf(f, "%spsp_vcmp(%u, %u, %u, %u);\n", ind, in->vd & 0xF, in->vs, in->vt, in->vsize); return;
    case A_VSGE:
        fprintf(f, "%spsp_vsge(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VSLT:
        fprintf(f, "%spsp_vslt(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VCRS:
        fprintf(f, "%spsp_vcrs(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VCRSP:
        fprintf(f, "%spsp_vcrsp(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;

    /* Moves between the integer and vector files. The register number is
     * the low eight bits: 0..127 a vector register, 128+ a control one. */
    case A_MTV:
        fprintf(f, "%spsp_mtv(%uu, %s);\n", ind, in->raw & 0xFF, rt); return;
    case A_MFV:
        if (DEST_ZERO(in->rt)) { fprintf(f, "%s;  /* result to $zero discarded */\n", ind); return; }
        fprintf(f, "%s%s = psp_mfv(%uu);\n", ind, rt, in->raw & 0xFF); return;

    /* Conversions carry a scale exponent in bits 20..16: vf2i* multiply by
     * 2^scale before rounding, vi2f divides after converting. Dropping it
     * turns fixed-point data into nonsense of the right type. */
    case A_VF2IN: case A_VF2IZ: case A_VF2IU: case A_VF2ID: {
        static const char *const MODE[] = { "PSP_VF2I_NEAREST", "PSP_VF2I_ZERO",
                                            "PSP_VF2I_UP", "PSP_VF2I_DOWN" };
        fprintf(f, "%spsp_vf2i(%s, %u, %u, %u, %u);\n", ind,
                MODE[in->op - A_VF2IN], in->vd, in->vs, (in->raw >> 16) & 0x1F, in->vsize);
        return;
    }
    case A_VI2F:
        fprintf(f, "%spsp_vi2f(%u, %u, %u, %u);\n", ind, in->vd, in->vs, (in->raw >> 16) & 0x1F, in->vsize);
        return;
    case A_VCMOV:
        fprintf(f, "%spsp_vcmov(%u, %u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vsize,
                (in->raw >> 19) & 1, (in->raw >> 16) & 7);
        return;
    case A_VROT:
        fprintf(f, "%spsp_vrot(%u, %u, %u, %u);\n", ind, in->vd, in->vs, (in->raw >> 16) & 0x1F, in->vsize);
        return;
    case A_VFPU7:
        fprintf(f, "%spsp_vconv(0x%02X, %u, %u, %u);\n", ind, in->rt, in->vd, in->vs, in->vsize); return;
    case A_VFPU9:
        fprintf(f, "%spsp_vfpu9(0x%02X, %u, %u, %u);\n", ind, in->rt, in->vd, in->vs, in->vsize); return;

    /* Prefixes gate the arithmetic above: with one pending, the next vector op
     * traps instead of computing the unprefixed answer. Emitting these is what
     * makes that guard fire at all -- without them the guard is dead code and
     * every prefixed operation silently produces the wrong number. */
    /* VFPU4 unary ops, all through one runtime entry point. */
    case A_VMOV: case A_VABS: case A_VNEG: case A_VZERO: case A_VONE:
    case A_VRCP: case A_VRSQ: case A_VSQRT: case A_VSIN: case A_VCOS:
    case A_VEXP2: case A_VLOG2: case A_VSAT0: case A_VSAT1:
    case A_VNRCP: case A_VNSIN: case A_VASIN: {
        static const struct { a_op op; const char *sel; } U[] = {
            { A_VMOV, "PSP_VU_MOV" },   { A_VABS, "PSP_VU_ABS" },
            { A_VNEG, "PSP_VU_NEG" },   { A_VZERO,"PSP_VU_ZERO" },
            { A_VONE, "PSP_VU_ONE" },   { A_VRCP, "PSP_VU_RCP" },
            { A_VRSQ, "PSP_VU_RSQ" },   { A_VSQRT,"PSP_VU_SQRT" },
            { A_VSIN, "PSP_VU_SIN" },   { A_VCOS, "PSP_VU_COS" },
            { A_VEXP2,"PSP_VU_EXP2" },  { A_VLOG2,"PSP_VU_LOG2" },
            { A_VSAT0,"PSP_VU_SAT0" },  { A_VSAT1,"PSP_VU_SAT1" },
            { A_VNRCP,"PSP_VU_NRCP" },  { A_VNSIN,"PSP_VU_NSIN" },
            { A_VASIN,"PSP_VU_ASIN" },
        };
        for (size_t k = 0; k < sizeof U / sizeof U[0]; k++) {
            if (U[k].op != in->op) continue;
            fprintf(f, "%spsp_vunary(%s, %u, %u, %u);\n",
                    ind, U[k].sel, in->vd, in->vs, in->vsize);
            return;
        }
        break;
    }

    /* Constant generators. These carry no source operand: what they produce is
     * encoded in the register number (vidt) or an index (vcst). */
    case A_VIDT:
        fprintf(f, "%spsp_vidt(%u, %u);\n", ind, in->vd, in->vsize);
        return;
    case A_VCST:
        /* The constant's index is bits 16-20 of the word (where vt would
         * be), not the vs field: vcst.s vd, VFPU_2_PI is 0xD0650000 | vd.
         * Taking vs (always 0 there) made every vcst load constant 0 --
         * in PSP2i that zeroed heading * 2/pi before vsin/vcos (0x08D2FF54),
         * so NPCs and enemies all moved along one world axis. */
        fprintf(f, "%spsp_vcst(%u, %u, %u);\n", ind, in->vd, (in->raw >> 16) & 31u, in->vsize);
        return;

    /* Immediate loads: the value is in the instruction, not a register. */
    case A_VIIM:
        fprintf(f, "%spsp_vimm(%u, %.9ff);\n", ind, in->vd, (double)in->imm);
        return;
    case A_VFIM: {
        /* Emit the exact bit pattern. A decimal literal either loses precision
         * on small half-floats (%f) or prints "1f"/"inff" (%g), neither of
         * which is the constant the hardware loads. */
        float v = half_to_float((uint16_t)in->imm);
        uint32_t bits;
        memcpy(&bits, &v, sizeof bits);
        fprintf(f, "%s{ union { uint32_t u; float f; } _k = { 0x%08Xu }; psp_vimm(%u, _k.f); }\n",
                ind, bits, in->vd);
        return;
    }

    /* Matrix ops that need no multiply. `vsize` is the matrix order here. */
    case A_VMMUL:
        fprintf(f, "%spsp_vmmul(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VTFM2: case A_VTFM3: case A_VTFM4: {
        const unsigned order = 2u + (unsigned)(in->op - A_VTFM2);
        if (in->vsize == order)
            fprintf(f, "%spsp_vtfm(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, order);
        else if (in->vsize + 1 == order)
            fprintf(f, "%spsp_vhtfm(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, order);
        else
            break;
        return;
    }
    case A_VMSCL:
        fprintf(f, "%spsp_vmscl(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VMIDT:
        fprintf(f, "%spsp_vmidt(%u, %u);\n", ind, in->vd, in->vsize); return;
    case A_VMZERO:
        fprintf(f, "%spsp_vmzero(%u, %u);\n", ind, in->vd, in->vsize); return;
    case A_VMONE:
        fprintf(f, "%spsp_vmone(%u, %u);\n", ind, in->vd, in->vsize); return;
    case A_VMMOV:
        fprintf(f, "%spsp_vmmov(%u, %u, %u);\n", ind, in->vd, in->vs, in->vsize); return;

    case A_VPFXS:
        fprintf(f, "%spsp_vfpu_set_prefix(0, 0x%06Xu);\n", ind, in->raw & 0xFFFFFF); return;
    case A_VPFXT:
        fprintf(f, "%spsp_vfpu_set_prefix(1, 0x%06Xu);\n", ind, in->raw & 0xFFFFFF); return;
    case A_VPFXD:
        fprintf(f, "%spsp_vfpu_set_prefix(2, 0x%06Xu);\n", ind, in->raw & 0xFFFFFF); return;

    case A_SYSCALL:
        fprintf(f, "%spsp_syscall(0x%05Xu);\n", ind, (in->raw >> 6) & 0xFFFFF); return;
    case A_BREAK:
        fprintf(f, "%spsp_unimplemented(0x%08Xu, \"break\");\n", ind, in->addr); return;

    default:
        break;
    }

    /* Anything unhandled — the VFPU, and any encoding the decoder does not
     * name — becomes a loud run-time trap. Emitting nothing here would produce
     * a program that runs and is quietly wrong, which is the single worst
     * outcome available. */
    fprintf(f, "%spsp_unimplemented(0x%08Xu, \"%s\");\n", ind, in->addr, a_mnemonic(in->op));
    #undef DEST_ZERO
}

/* ---- branch conditions --------------------------------------------------- */

static void branch_cond(char *buf, size_t n, const a_insn *in) {
    const char *rs = RN[in->rs], *rt = RN[in->rt];
    switch (in->op) {
    case A_BEQ: case A_BEQL:   snprintf(buf, n, "%s == %s", rs, rt); break;
    case A_BNE: case A_BNEL:   snprintf(buf, n, "%s != %s", rs, rt); break;
    case A_BLEZ: case A_BLEZL: snprintf(buf, n, "(int32_t)%s <= 0", rs); break;
    case A_BGTZ: case A_BGTZL: snprintf(buf, n, "(int32_t)%s > 0", rs); break;
    case A_BLTZ: case A_BLTZL:
    case A_BLTZAL: case A_BLTZALL: snprintf(buf, n, "(int32_t)%s < 0", rs); break;
    case A_BGEZ: case A_BGEZL:
    case A_BGEZAL: case A_BGEZALL: snprintf(buf, n, "(int32_t)%s >= 0", rs); break;
    case A_BC1T: case A_BC1TL: snprintf(buf, n, "psp_fpu_cond()"); break;
    case A_BC1F: case A_BC1FL: snprintf(buf, n, "!psp_fpu_cond()"); break;
    /* VFPU condition branches test one vcmp condition bit, selected by bits
     * 18-20 (0-3 per lane, 4 any, 5 all). These used to fall to the default
     * below -- never taken -- so PSP2i's polygon clipper (0x08D8B2C4) kept
     * and split every vertex at every frustum plane: 3 -> 192 vertices after
     * six planes, overrunning its stack buffers. */
    case A_BVF: case A_BVFL:   snprintf(buf, n, "!((psp_cpu.vfpu_cc >> %u) & 1)", (in->raw >> 18) & 7); break;
    case A_BVT: case A_BVTL:   snprintf(buf, n, "((psp_cpu.vfpu_cc >> %u) & 1)", (in->raw >> 18) & 7); break;
    default:                   snprintf(buf, n, "0 /* unhandled branch */"); break;
    }
}

/* Emit the standalone, labelled copy of a delay slot that is also a branch
 * target. `falls_through` says whether the construct just emitted can reach
 * the next address by falling through — if so it must jump past this copy
 * rather than running it a second time. */
static void emit_slot_alias(ectx *c, uint32_t a, const a_insn *slot, int falls_through) {
    const a_analysis *an = c->an;
    const uint32_t owner = c->func->addr;
    const uint32_t after = a + 8;

    if (falls_through) {
        if (owned_by(an, after, owner)) fprintf(c->out, "    goto L_%08X;\n", after);
        else {
            /* The code after the branch belongs to another body. Returning
             * here would skip it; continue there instead (see
             * mark_continuations). */
            emit_static_call(c, after);
            fprintf(c->out, "    return;\n");
        }
    }
    fprintf(c->out, "L_%08X:\n", a + 4);
    comment(c, slot);
    emit_simple(c, slot, "    ");
}

/* Was this import thunk reached by a direct call during discovery? Thunks
 * that were not are still emitted -- a game can call a firmware function
 * through a pointer -- but separately, so the two lists stay distinct. */
static int import_called(const a_analysis *an, uint32_t addr) {
    for (int i = 0; i < an->nimports; i++) if (an->imports[i] == addr) return 1;
    return 0;
}

/* ---- continuations --------------------------------------------------------
 *
 * Discovery splits routines: a block reached from elsewhere becomes its own
 * entry, and the instructions after it can end up owned by a different body
 * than the instructions before. Control then flows from one C body into the
 * *middle* of another, which is only expressible if that address is a label
 * of its owner -- a switch case and a dispatch thunk.
 *
 * Labels are decided per function as it is emitted, so a continuation into a
 * function emitted earlier would find no label. Mark every such address up
 * front: the end of each body, the start of each interior gap, and the
 * address after a branch whose delay slot ends the owned run. Over-marking is
 * harmless (an unused case); a missing label loses the rest of a routine.
 *
 * Observed: psp_func_08DCF894, a five-instruction loop split out of
 * 0x08DCF81C, ended by returning instead of continuing at 0x08DCF8A8. The
 * parent then returned too, so the routine's epilogue never ran -- $sp 48
 * bytes low, and $ra/$s1/$s2 later reloaded from the 0xFF stack fill. */
static void mark_one(ectx *c, uint32_t a) {
    const a_analysis *an = c->an;
    if (!a_in_range(an, a) || is_function(an, a)) return;
    if (an->owner[widx(an, a)] == A_NO_OWNER) return;
    c->is_label[widx(an, a)] = 1;
}

static void mark_continuations(ectx *c) {
    const a_analysis *an = c->an;
    for (int k = 0; k < an->nfuncs; k++) {
        const a_func *fn = &an->funcs[k];
        const uint32_t owner = fn->addr;
        mark_one(c, fn->end);
        for (uint32_t a = fn->start; a < fn->end; a += 4) {
            if (!owned_by(an, a, owner)) continue;
            if (!owned_by(an, a + 4, owner)) mark_one(c, a + 4);
            else if (!owned_by(an, a + 8, owner)) mark_one(c, a + 8);
        }
    }
}

/* ---- one function -------------------------------------------------------- */

static void emit_function(ectx *c, const a_func *fn) {
    const a_analysis *an = c->an;
    FILE *f = c->out;
    const uint32_t owner = fn->addr;

    /* Pass 1: which owned addresses are branch targets, and which are consumed
     * as delay slots. A delay slot is emitted inline with its branch, so the
     * main pass must skip it. */
    for (uint32_t a = fn->start; a < fn->end; a += 4) {
        if (!owned_by(an, a, owner)) continue;
        a_insn in;
        a_decode(fetch(an, a), a, &in);
        if (in.has_target && owned_by(an, in.target, owner))
            c->is_label[widx(an, in.target)] = 1;
        if (in.is_jump && !in.is_indirect && in.has_target &&
            owned_by(an, in.target, owner) && !is_function(an, in.target))
            c->is_label[widx(an, in.target)] = 1;
        if (in.has_delay_slot && owned_by(an, a + 4, owner))
            c->is_slot[widx(an, a + 4)] = 1;
        /* A return address is a place control can arrive by `jr $ra` other
         * than through the call: code that reloads $ra and jumps back into
         * its own function (see emit_return_check). Make it dispatchable. */
        if (in.is_call && !in.is_indirect && in.has_target &&
            owned_by(an, a + 8, owner) && !is_function(an, a + 8)) {
            const a_func *g = func_at(an, in.target);
            if (g && reloads_ra_in_slot(an, g)) c->is_label[widx(an, a + 8)] = 1;
        }
    }

    /* A delay slot can also be somebody's branch target. Arriving through the
     * branch, it runs as part of that transfer; arriving by a jump straight to
     * its address, it is an ordinary instruction. Both paths are real, so it
     * has to be emitted twice — inline with its branch, and again under its
     * own label. The fall-through path then needs somewhere to land past the
     * standalone copy, so the following address gets a label too.
     *
     * Exactly one site in Lumberjack's 2206 functions; ignoring it produced
     * the one compile error in 256,566 generated lines. */
    for (uint32_t a = fn->start; a + 4 < fn->end; a += 4) {
        if (!owned_by(an, a, owner)) continue;
        uint32_t i = widx(an, a);
        if (c->is_slot[i] && c->is_label[i] && owned_by(an, a + 4, owner))
            c->is_label[widx(an, a + 4)] = 1;
    }

    fprintf(f, "\n/* ---------------------------------------------------------------\n");
    fprintf(f, " * psp_func_%08X  --  %u instructions, %u bytes\n",
            fn->addr, fn->insns, fn->end - fn->addr);
    if (!fn->has_return)
        fprintf(f, " * No `jr $ra`: ends in a tail call, or discovery lost the trail.\n");
    if (fn->has_indirect)
        fprintf(f, " * Contains a computed jump routed through the dispatch table.\n");
    fprintf(f, " * ------------------------------------------------------------- */\n");

    /* A function's instructions do not always begin at its entry: a backward
     * jump can pull in a block that lies *below* the entry address, and
     * emission walks the whole owned range in address order. When that
     * happens the first statement in the body is not the first statement to
     * execute, so control has to be sent to the real entry explicitly.
     *
     * Without this, calling the function silently runs whatever happens to sit
     * lowest in its address range -- with none of the entry's setup having
     * run. Registers hold stale values and the damage surfaces far away. */
    c->is_label[widx(an, fn->addr)] = 1;

    /* The body takes the address to start at, and every label is reachable
     * through it.
     *
     * A recompiled function has exactly one C entry point, but the original
     * has as many as something can jump to. Direct branches within a function
     * are just `goto`, and cross-function branches are promoted to entries by
     * discovery -- but a *computed* jump (jump table, function pointer, a
     * return address handed around) resolves at runtime, and its target is
     * routinely a block in the middle of a function that discovery had no
     * static reason to make callable. Dispatch then misses on an address whose
     * code is right there in the file, sitting under a label nothing can reach.
     *
     * Rather than keep discovering these one crash at a time, every label gets
     * a thunk and a dispatch entry. The switch costs one jump on entry and
     * makes the whole class -- jump tables, indirect calls, cross-function
     * branches -- resolve by construction. */
    fprintf(f, "static void psp_body_%08X(uint32_t _entry) {\n", fn->addr);
    fprintf(f, "    PSP_ENTER(0x%08Xu);\n", fn->addr);
    /* A function must leave $sp as it found it. Any that does not corrupts
     * every callee-saved register its caller restores afterwards -- the
     * restores read `sp + offset`, so a shifted $sp reads a different slot and
     * loads a plausible wrong value rather than failing. Checking the
     * invariant directly is far cheaper than tracing the consequences. */
    fprintf(f, "    PSP_SP_ENTER();\n");

    int nlabels = 0;
    for (uint32_t a = fn->start; a < fn->end; a += 4)
        if (owned_by(an, a, owner) && c->is_label[widx(an, a)]) nlabels++;

    if (nlabels > 1 || fn->start != fn->addr) {
        fprintf(f, "    switch (_entry) {\n");
        for (uint32_t a = fn->start; a < fn->end; a += 4) {
            if (!owned_by(an, a, owner) || !c->is_label[widx(an, a)]) continue;
            if (c->is_slot[widx(an, a)]) continue;   /* only the inline copy is real */
            fprintf(f, "    case 0x%08Xu: goto L_%08X;\n", a, a);
        }
        fprintf(f, "    default: break;\n");
        fprintf(f, "    }\n");
    }

    int last_terminal = 0;
    for (uint32_t a = fn->start; a < fn->end; a += 4) {
        if (!owned_by(an, a, owner)) {
            /* An interior gap: these instructions belong to another function,
             * because discovery split this address range between two owners.
             *
             * Skipping them silently is wrong whenever the preceding
             * instruction can fall through. Control then lands on whatever the
             * *next owned* address happens to be, which is an arbitrary place
             * further down the function -- not where the hardware would go.
             *
             * Observed at 0x0000F49C: the not-taken path of a `beq` should run
             * an epilogue at 0x0000F4A0 and return, but that epilogue was owned
             * by another body, so execution fell into 0x0000F4C0 and read
             * memory through a register the skipped code would have set. The
             * result was a load from 0xFFFFC840 -- a plausible-looking address
             * produced by a base register of zero.
             *
             * This is the same defect as running off the end of a function into
             * the next, which is already handled below; it just happens in the
             * middle. Transfer control explicitly and stop emitting: everything
             * after the gap is reachable through its own entry. */
            if (!last_terminal) {
                fprintf(f, "    /* falls into 0x%08X, owned by another function */\n", a);
                emit_static_call(c, a);
                fprintf(f, "    PSP_SP_CHECK(0x%08Xu);\n    return;\n", a);
                last_terminal = 1;
            }
            continue;
        }
        uint32_t i = widx(an, a);
        if (c->is_slot[i] && !c->is_label[i]) continue;             /* emitted with its branch */

        a_insn in;
        a_decode(fetch(an, a), a, &in);

        if (c->is_label[i]) fprintf(f, "L_%08X: PSP_MARK(0x%08Xu);\n", a, a);
        /* `jalr` is indirect but it is a *call*: the callee returns and
         * execution continues after the delay slot. Treating it as terminal
         * dropped the continuation whenever the code after a jalr belonged to
         * another body -- observed at 0x089F0C20, a virtual call in the game's
         * main loop, after which the whole main thread returned and ended. */
        last_terminal = in.is_return || (in.is_indirect && !in.is_call) ||
                        (in.is_jump && !in.is_call);
        comment(c, &in);

        /* The delay-slot instruction, if this transfers control. */
        a_insn slot;
        int have_slot = 0;
        if (in.has_delay_slot && owned_by(an, a + 4, owner)) {
            a_decode(fetch(an, a + 4), a + 4, &slot);
            have_slot = 1;
        }

        if (in.is_branch) {
            char cond[128];
            branch_cond(cond, sizeof cond, &in);

            if (in.is_likely) {
                /* A "likely" branch nullifies its delay slot when NOT taken,
                 * so the slot belongs inside the taken path. The condition is
                 * naturally evaluated before it. */
                /* The link register is written whether or not the branch is
                 * taken, and before the delay slot (see the jal case below). */
                if (in.is_call) fprintf(f, "    %s = 0x%08Xu;\n", RN[31], a + 8);
                fprintf(f, "    if (%s) {\n", cond);
                if (have_slot) { comment(c, &slot); emit_simple(c, &slot, "        "); }
                if (owned_by(an, in.target, owner) && !in.is_call)
                    { if (in.target <= a) fprintf(f, "        PSP_LOOP(0x%08Xu);\n", in.target);
                      fprintf(f, "        goto L_%08X;\n", in.target); }
                else if (in.is_call) {
                    /* bltzall / bgezall: a conditional *call*. The callee
                     * returns here and execution continues after the slot. */
                    emit_static_call(c, in.target);
                    emit_return_check(c, "        ", a + 8);
                }
                else
                    { emit_static_call(c, in.target); fprintf(f, "        return;\n"); }
                fprintf(f, "    }\n");
            } else {
                /* An ordinary branch always executes its delay slot, and reads
                 * its condition registers BEFORE the slot runs. The slot may
                 * write one of those registers:
                 *
                 *     beq   $a0, $zero, target
                 *     addiu $a0, $a0, 1        <- branch already read old $a0
                 *
                 * so the condition is captured into a temporary first. Doing
                 * that unconditionally costs nothing (the compiler folds it
                 * away when there is no dependency) and removes an entire
                 * class of silent, once-in-a-thousand-iterations bugs. */
                fprintf(f, "    { int _c = (%s);\n", cond);
                if (in.is_call) fprintf(f, "      %s = 0x%08Xu;\n", RN[31], a + 8);
                if (have_slot) { comment(c, &slot); emit_simple(c, &slot, "      "); }
                if (owned_by(an, in.target, owner) && !in.is_call)
                    { if (in.target <= a) fprintf(f, "      if (_c) PSP_LOOP(0x%08Xu);\n", in.target);
                      fprintf(f, "      if (_c) goto L_%08X; }\n", in.target); }
                else {
                    fprintf(f, "      if (_c) { ");
                    if (is_import(an, in.target))      fprintf(f, "psp_import_%08X();", in.target);
                    else if (is_function(an, in.target)) fprintf(f, "psp_func_%08X();", in.target);
                    else                                fprintf(f, "psp_dispatch(0x%08Xu);", in.target);
                    /* bltzal / bgezal (and bal) are conditional *calls*: the
                     * callee returns to the instruction after the delay slot,
                     * so execution continues here. Returning instead abandoned
                     * the rest of the caller -- observed in the decompressor at
                     * 0x08DE0E54, which then parsed garbage. A plain branch out
                     * of the function is a tail transfer and does return. */
                    if (in.is_call)
                        fprintf(f, " if (r_ra != 0x%08Xu) return; } }\n", a + 8);
                    else
                        fprintf(f, " return; } }\n");
                }
            }
            if (have_slot && c->is_label[widx(an, a + 4)]) emit_slot_alias(c, a, &slot, 1);
            a += 4;                              /* consumed the delay slot */
            continue;
        }

        if (in.is_call) {                        /* jal / jalr */
            /* Order matters: the jump target is read and the link register
             * written by the jal/jalr itself, *then* the delay slot runs. A
             * slot that reloads $ra (`jal f ; lw $ra, 0($sp)`, a hand-made tail
             * call) leaves the caller's return address in $ra, so f returns
             * past this function. Emitting the slot first and the link second
             * lost that load: observed at 0x08D7689C, where the wrong $ra then
             * made every caller's return check unwind, all the way out of
             * user_main (New Game -> black screen). */
            const unsigned link_reg = (in.op == A_JALR) ? in.rd : 31u;
            if (in.is_indirect) fprintf(f, "    { uint32_t _t = %s;\n", RN[in.rs]);
            if (link_reg) fprintf(f, "    %s = 0x%08Xu;\n", RN[link_reg], a + 8);
            if (have_slot) { comment(c, &slot); emit_simple(c, &slot, "    "); }
            /* Set $ra.
             *
             * Recompiled calls are C calls and `jr $ra` is emitted as `return`,
             * so it is tempting to treat $ra as dead. It is not. Non-leaf
             * functions do `sw $ra, N($sp)` on entry and `lw $ra, N($sp)`
             * before returning, and code that takes a return address for any
             * other purpose reads it too. Leaving $ra stale means those saves
             * store garbage, and any later `jr` through a restored copy jumps
             * nowhere.
             *
             * That is what the 17 dispatch misses to 0x00000000 were, and why
             * $ra held a stack address at the stall. The branch-and-link forms
             * a few lines above already did this correctly; jal and jalr --
             * every ordinary call in the program -- did not. */
            if (in.is_indirect) fprintf(f, "    psp_dispatch(_t); }\n");
            else                emit_static_call(c, in.target);
            if (link_reg == 31u) {
                if (!in.is_indirect && callee_can_reenter(an, in.target))
                    emit_direct_return_check(c, "    ", a + 8, in.target);
                else
                    emit_return_check(c, "    ", a + 8);
            }
            if (have_slot && c->is_label[widx(an, a + 4)] && !slot.is_branch) emit_slot_alias(c, a, &slot, 1);
            a += 4;
            continue;
        }

        if (in.is_return) {                      /* jr $ra */
            if (have_slot) { comment(c, &slot); emit_simple(c, &slot, "    "); }
            /* Only a genuine `jr $ra` is expected to leave $sp as it found it.
             * Tail jumps and cross-function transfers are emitted as `return`
             * too, but their epilogue runs in the target, so $sp is correctly
             * still mid-frame there -- checking those reports every tail call
             * as a leak. */
            fprintf(f, "    PSP_SP_CHECK(0x%08Xu);\n", a);
            fprintf(f, "    return;\n");
            if (have_slot && c->is_label[widx(an, a + 4)] && !slot.is_branch) emit_slot_alias(c, a, &slot, 0);
            a += 4;
            continue;
        }

        if (in.is_indirect) {                    /* jr $rN — computed jump */
            if (have_slot) { comment(c, &slot); emit_simple(c, &slot, "    "); }
            fprintf(f, "    psp_dispatch(%s);\n    return;\n", RN[in.rs]);
            if (have_slot && c->is_label[widx(an, a + 4)] && !slot.is_branch) emit_slot_alias(c, a, &slot, 0);
            a += 4;
            continue;
        }

        if (in.is_jump) {                        /* j */
            if (have_slot) { comment(c, &slot); emit_simple(c, &slot, "    "); }
            if (owned_by(an, in.target, owner) && !is_function(an, in.target)) {
                fprintf(f, "    goto L_%08X;\n", in.target);
            } else {
                emit_static_call(c, in.target);  /* tail call */
                fprintf(f, "    return;\n");
            }
            if (have_slot && c->is_label[widx(an, a + 4)] && !slot.is_branch) emit_slot_alias(c, a, &slot, 0);
            a += 4;
            continue;
        }

        emit_simple(c, &in, "    ");
    }

    /* Fall-through into the next function.
     *
     * The walk stops when it reaches another function's entry, which is right
     * for a tail call but also happens when code simply *runs into* the next
     * function -- there is no instruction marking the boundary, only the fact
     * that something else calls that address. Ending the C function there
     * silently converts the fall-through into a return, and the caller
     * continues as though the second half never ran.
     *
     * That is invisible: no dispatch miss, no bad memory access, just less
     * work done. It got worse as discovery split more aggressively, which is
     * how it surfaced -- reach went *down* while every other measure improved.
     *
     * So if the last instruction emitted could fall through, and the address
     * after this function is another function's entry, continue there. */
    if (!last_terminal) {
        uint32_t next = fn->end;
        if (is_function(an, next)) {
            fprintf(f, "    /* falls through into the next function */\n");
            fprintf(f, "    psp_func_%08X();\n", next);
        } else if (a_in_range(an, next) && an->owner[widx(an, next)] != A_NO_OWNER) {
            /* ...or into the middle of one. Discovery split a routine and this
             * body is the piece before `next`: the rest of the routine, its
             * epilogue included, lives in another body under a label. Ending
             * here would return to the caller with the frame still open and
             * the callee-saved registers never restored. */
            fprintf(f, "    /* continues at 0x%08X, inside psp_func_%08X */\n",
                    next, an->owner[widx(an, next)]);
            fprintf(f, "    psp_dispatch(0x%08Xu);\n", next);
        }
    }
    fprintf(f, "}\n");

    /* The real entry, plus one thunk per interior label so anything that can be
     * jumped to can also be dispatched to. */
    int hooked = 0;
    for (int h = 0; h < c->nhooks; h++) if (c->hooks[h] == fn->addr) hooked = 1;
    if (hooked) {
        /* A hooked function: the hook (if one is registered at run time)
         * receives the original and decides what runs. */
        fprintf(f, "static void psp_orig_%08X(void) { psp_body_%08X(0x%08Xu); }\n",
                fn->addr, fn->addr, fn->addr);
        fprintf(f, "void psp_func_%08X(void) {\n"
                   "    psp_hook_fn h_ = psp_hook_find(0x%08Xu);\n"
                   "    if (h_) h_(psp_orig_%08X); else psp_orig_%08X();\n"
                   "}\n", fn->addr, fn->addr, fn->addr, fn->addr);
    } else {
        fprintf(f, "void psp_func_%08X(void) { psp_body_%08X(0x%08Xu); }\n",
                fn->addr, fn->addr, fn->addr);
    }
    for (uint32_t a = fn->start; a < fn->end; a += 4) {
        if (!owned_by(an, a, owner) || !c->is_label[widx(an, a)]) continue;
        if (c->is_slot[widx(an, a)] || a == fn->addr) continue;
        fprintf(f, "void psp_at_%08X(void) { psp_body_%08X(0x%08Xu); }\n",
                a, fn->addr, a);
        entry_push(c, a);
    }
}

/* ---- files --------------------------------------------------------------- */

static void emit_header(FILE *f, const a_analysis *an, const emit_opts *o) {
    fprintf(f,
        "/* Generated by allegrexrecomp -- do not edit.\n"
        " *\n"
        " * Module: %s\n"
        " * %d recompiled functions, %d imported firmware calls.\n"
        " *\n"
        " * Each psp_func_<addr> is one Allegrex routine translated to C. Every\n"
        " * statement carries its original address and disassembly as a comment.\n"
        " * Register names are macros onto psp_cpu.r[]; the semantics that are not\n"
        " * obvious in C (division edge cases, unaligned loads, shift masking) live\n"
        " * in <psprecomp/recomp_rt.h> so they exist in exactly one place.\n"
        " */\n"
        "#ifndef PSPRECOMP_GENERATED_H\n"
        "#define PSPRECOMP_GENERATED_H\n"
        "\n"
        "#include <psprecomp/recomp_rt.h>\n"
        "#include <psprecomp/dispatch.h>\n"
        "#include <psprecomp/vfpu.h>\n"
        "\n"
        "#ifdef __cplusplus\nextern \"C\" {\n#endif\n"
        "\n"
        "/* Build with -DPSPRECOMP_TRACE to record every function entry. Costs\n"
        " * one store per call when on, and nothing at all when off. A dispatch\n"
        " * miss then reports how the code arrived, not just where it went. */\n"
        "#ifdef PSPRECOMP_TRACE\n"
        "#  define PSP_ENTER(a) psp_trace_enter(a)\n"
        "#  define PSP_LOOP(a)  psp_trace_loop(a)\n"
        "#  define PSP_SP_ENTER()  uint32_t _sp0 = r_sp\n"
        "#  define PSP_SP_CHECK(a) psp_trace_sp(a, _sp0, r_sp)\n"
        "#  define PSP_SP_CALL(t,a,b) psp_trace_sp_call(t, a, b)\n"
        "#  define PSP_MARK(a)  psp_trace_mark(a)\n"
        "#else\n"
        "#  define PSP_ENTER(a) ((void)0)\n"
        "#  define PSP_LOOP(a)  ((void)0)\n"
        "#  define PSP_SP_ENTER()  ((void)0)\n"
        "#  define PSP_SP_CHECK(a) ((void)0)\n"
        "#  define PSP_SP_CALL(t,a,b) ((void)0)\n"
        "#  define PSP_MARK(a)  ((void)0)\n"
        "#endif\n"
        "\n"
        "/* Register aliases, so the generated code reads like the assembly. */\n",
        o->module ? o->module : "(unknown)", an->nfuncs, an->nimports);

    for (int i = 0; i < 32; i++)
        fprintf(f, "#define %-7s psp_cpu.r[%d]\n", RN[i], i);

    fprintf(f,
        "\n"
        "/* Register every recompiled function with the dispatch table. Call once\n"
        " * before running anything. */\n"
        "void psp_recomp_register(void);\n"
        "\n"
        "/* Provided by the host: a firmware call this module imports, and the\n"
        " * traps for anything not yet translated. */\n"
        "void psp_syscall(uint32_t id);\n"
        "void psp_unimplemented(uint32_t addr, const char *what);\n"
        "\n");

    for (int i = 0; i < an->nfuncs; i++)
        fprintf(f, "void psp_func_%08X(void);\n", an->funcs[i].addr);

    fprintf(f, "\n");
    for (int i = 0; i < an->nimports; i++)
        fprintf(f, "void psp_import_%08X(void);\n", an->imports[i]);
    for (int i = 0; i < o->nimports; i++)
        if (!import_called(an, o->imports[i].addr))
            fprintf(f, "void psp_import_%08X(void);\n", o->imports[i].addr);

    fprintf(f, "\n#ifdef __cplusplus\n}\n#endif\n\n#endif\n");
}

/* Find the import-table entry describing the thunk at `addr`. */
static const psp_import_entry *import_at(const emit_opts *o, uint32_t addr) {
    for (int i = 0; i < o->nimports; i++)
        if (o->imports[i].addr == addr) return &o->imports[i];
    return NULL;
}

static void emit_imports(FILE *f, const a_analysis *an, const emit_opts *o) {
    fprintf(f,
        "/* Generated by allegrexrecomp -- do not edit.\n"
        " *\n"
        " * The %d firmware functions this module imports. Each thunk dispatches\n"
        " * to the HLE layer by NID -- the identifier the hardware itself uses,\n"
        " * being SHA-1(function name) truncated to four bytes.\n"
        " *\n"
        " * A NID with no HLE implementation reports itself by name and returns 0.\n"
        " * Bringing a game up is largely the process of watching those messages\n"
        " * stop appearing.\n"
        " */\n"
        "#include \"%s_funcs.h\"\n"
        "#include <psprecomp/hle.h>\n\n",
        an->nimports, o->prefix);

    for (int i = 0; i < an->nimports; i++) {
        uint32_t addr = an->imports[i];
        const psp_import_entry *e = import_at(o, addr);
        if (e) {
            fprintf(f, "/* %s :: NID 0x%08X */\n", e->lib, e->nid);
            /* Trace import calls like any other function. A firmware call that
             * never happens is indistinguishable from one that happens and
             * does nothing, and untraceable stubs made a heap allocation
             * that never reached the kernel impossible to diagnose. */
            fprintf(f, "void psp_import_%08X(void) { PSP_ENTER(0x%08Xu); psp_hle_call(0x%08Xu); }\n\n",
                    addr, addr, e->nid);
        } else {
            /* The thunk is called but does not appear in the import table --
             * so we cannot name it or dispatch it. Trapping is the only honest
             * option; guessing a NID would route it to the wrong function. */
            fprintf(f,
                "/* not present in the import table */\n"
                "void psp_import_%08X(void) { psp_unimplemented(0x%08Xu, \"unlisted import\"); }\n\n",
                addr, addr);
        }
    }

    /* Imports no direct call reaches: still real entry points, reachable
     * through function pointers, so they get thunks and dispatch entries. */
    for (int i = 0; i < o->nimports; i++) {
        const psp_import_entry *e = &o->imports[i];
        if (import_called(an, e->addr)) continue;
        fprintf(f, "/* %s :: NID 0x%08X (not called directly) */\n", e->lib, e->nid);
        fprintf(f, "void psp_import_%08X(void) { PSP_ENTER(0x%08Xu); psp_hle_call(0x%08Xu); }\n\n",
                e->addr, e->addr, e->nid);
    }
}

int a_emit(const a_analysis *an, const emit_opts *o) {
    char path[1024];

    /* Header */
    snprintf(path, sizeof path, "%s/%s_funcs.h", o->outdir, o->prefix);
    FILE *h = fopen(path, "w");
    if (!h) { fprintf(stderr, "cannot write %s\n", path); return -1; }
    emit_header(h, an, o);
    fclose(h);

    /* Imports */
    snprintf(path, sizeof path, "%s/%s_imports.c", o->outdir, o->prefix);
    FILE *im = fopen(path, "w");
    if (!im) { fprintf(stderr, "cannot write %s\n", path); return -1; }
    emit_imports(im, an, o);
    fclose(im);

    /* Functions */
    snprintf(path, sizeof path, "%s/%s_funcs.c", o->outdir, o->prefix);
    FILE *f = fopen(path, "w");
    if (!f) { fprintf(stderr, "cannot write %s\n", path); return -1; }

    fprintf(f,
        "/* Generated by allegrexrecomp -- do not edit.\n"
        " *\n"
        " * Module: %s   --   %d functions, %llu instructions.\n"
        " */\n"
        "#include \"%s_funcs.h\"\n",
        o->module ? o->module : "(unknown)", an->nfuncs,
        (unsigned long long)an->insns, o->prefix);

    ectx c;
    c.out = f;
    c.an = an;
    c.is_label = (uint8_t *)calloc(an->nwords ? an->nwords : 1, 1);
    c.is_slot  = (uint8_t *)calloc(an->nwords ? an->nwords : 1, 1);
    c.entries = NULL;
    c.nentries = c.centries = 0;
    if (!c.is_label || !c.is_slot) {
        free(c.is_label); free(c.is_slot); fclose(f);
        return -1;
    }

    mark_continuations(&c);
    for (int i = 0; i < an->nfuncs; i++) {
        c.func = &an->funcs[i];
        c.hooks = o->hooks; c.nhooks = o->nhooks;
        emit_function(&c, &an->funcs[i]);
    }

    /* Registration */
    fprintf(f,
        "\n/* ---------------------------------------------------------------\n"
        " * Populate the dispatch table. Indirect calls -- function pointers,\n"
        " * vtables, callbacks, switch tables — resolve through this.\n"
        " * ------------------------------------------------------------- */\n"
        "void psp_recomp_register(void) {\n");
    for (int i = 0; i < an->nfuncs; i++)
        fprintf(f, "    psp_register(0x%08Xu, psp_func_%08X);\n",
                an->funcs[i].addr, an->funcs[i].addr);
    /* Import thunks too: a game can take the address of a firmware function
     * and call it through a pointer (observed: jalr to 0x08DFCE84). */
    for (int i = 0; i < an->nimports; i++)
        fprintf(f, "    psp_register(0x%08Xu, psp_import_%08X);\n",
                an->imports[i], an->imports[i]);
    for (int i = 0; i < o->nimports; i++)
        if (!import_called(an, o->imports[i].addr))
            fprintf(f, "    psp_register(0x%08Xu, psp_import_%08X);\n",
                    o->imports[i].addr, o->imports[i].addr);
    /* Interior labels last, so a real function entry always wins a collision. */
    for (int i = 0; i < c.nentries; i++)
        fprintf(f, "    psp_register_label(0x%08Xu, psp_at_%08X);\n",
                c.entries[i], c.entries[i]);
    fprintf(f, "}\n");

    free(c.is_label);
    free(c.is_slot);
    free(c.entries);
    fclose(f);

    printf("wrote %s/%s_funcs.c   (%d functions, %d interior entries)\n",
           o->outdir, o->prefix, an->nfuncs, c.nentries);
    printf("wrote %s/%s_funcs.h\n", o->outdir, o->prefix);
    printf("wrote %s/%s_imports.c (%d imports)\n", o->outdir, o->prefix, an->nimports);
    return 0;
}
