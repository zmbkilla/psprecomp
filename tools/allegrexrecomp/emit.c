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
    int *scc;              /* per function index: tail-call cycle id, 0 = none (see compute_tail_cycles) */
    int has_entry_switch;  /* the current body re-enters its entry switch on a computed jump */
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

/* ---- tail-call cycles -----------------------------------------------------
 * A tail transfer (`j` or a branch to another function's entry) is emitted as
 * a call followed by `return`. The C compiler may or may not turn that into a
 * jump; where it does not, functions that tail-transfer to each other in a
 * loop (A -> B -> A ...) grow the host stack by a frame per pass, and a long
 * loop overflows it (0xC00000FD). PSP2i has ~290 such cycles. Within a cycle,
 * the transfer instead sets psp_scc_next and returns; every entry into a cycle
 * member drains psp_scc_next in a loop, so control passes on without growing
 * the stack -- the old frame is gone first, as with a real jump.
 * Hooked functions stay out: a hook may run guest code after the original. */

static int is_hooked(const ectx *c, uint32_t addr) {
    for (int h = 0; h < c->nhooks; h++) if (c->hooks[h] == addr) return 1;
    return 0;
}

/* The function index an emitted tail transfer from `owner` to `t` would call,
 * or -1 when that transfer is not a cross-function call. Mirrors the emitter. */
static int tail_edge(const ectx *c, uint32_t owner, const a_insn *in) {
    const a_analysis *an = c->an;
    if (!in->has_target || in->is_call || in->is_indirect) return -1;
    if (in->target == owner || is_import(an, in->target)) return -1;
    if (in->is_jump) {
        if (owned_by(an, in->target, owner) && !is_function(an, in->target)) return -1;
    } else if (in->is_branch) {
        if (owned_by(an, in->target, owner)) return -1;
    } else return -1;
    const a_func *t = func_at(an, in->target);
    if (!t || is_hooked(c, t->addr)) return -1;
    return (int)(t - an->funcs);
}

/* Strongly connected components (> 1 member) of the tail-call graph: c->scc. */
static void compute_tail_cycles(ectx *c) {
    const a_analysis *an = c->an;
    const int n = an->nfuncs;
    c->scc = (int *)calloc((size_t)(n ? n : 1), sizeof(int));
    int *head = (int *)malloc(sizeof(int) * (size_t)(n + 1));
    int ne = 0, cap = 1024;
    int *to = (int *)malloc(sizeof(int) * (size_t)cap), *from = (int *)malloc(sizeof(int) * (size_t)cap);
    if (!c->scc || !head || !to || !from) { free(head); free(to); free(from); return; }
    for (int i = 0; i < n; i++) {
        const a_func *fn = &an->funcs[i];
        if (is_hooked(c, fn->addr)) continue;
        /* Running into another function (an interior gap owned by another
         * body, or the end of this one) is a tail transfer too; the emitter
         * writes it as a call. Missing those edges hid long loops split across
         * bodies -- the decompressor at 0x08D5DF38..0x08D5E1xx crashed a boss
         * fight that way. `terminal` mirrors the emitter's last_terminal. */
        int terminal = 0;
        for (uint32_t a = fn->start; a <= fn->end; a += 4) {
            int t = -1;
            if (a == fn->end || !owned_by(an, a, fn->addr)) {
                if (!terminal && is_function(an, a)) {
                    const a_func *tf = func_at(an, a);
                    if (tf && !is_hooked(c, tf->addr)) t = (int)(tf - an->funcs);
                }
                terminal = 1;
            } else {
                a_insn in;
                a_decode(fetch(an, a), a, &in);
                terminal = in.is_return || (in.is_indirect && !in.is_call) || (in.is_jump && !in.is_call);
                t = tail_edge(c, fn->addr, &in);
                if (in.has_delay_slot && owned_by(an, a + 4, fn->addr)) a += 4;   /* emitted with its branch */
            }
            if (t < 0 || t == i) continue;
            if (ne == cap) {
                cap *= 2;
                to = (int *)realloc(to, sizeof(int) * (size_t)cap);
                from = (int *)realloc(from, sizeof(int) * (size_t)cap);
                if (!to || !from) { free(head); free(to); free(from); return; }
            }
            from[ne] = i; to[ne] = t; ne++;
        }
    }
    /* CSR by source (edges were added in source order). */
    for (int i = 0, e = 0; i <= n; i++) { while (e < ne && from[e] < i) e++; head[i] = e; }

    /* Iterative Tarjan. */
    int *idx = (int *)malloc(sizeof(int) * (size_t)n), *low = (int *)malloc(sizeof(int) * (size_t)n);
    int *onst = (int *)calloc((size_t)n, sizeof(int)), *st = (int *)malloc(sizeof(int) * (size_t)n);
    int *cs = (int *)malloc(sizeof(int) * (size_t)n), *ce = (int *)malloc(sizeof(int) * (size_t)n);
    if (!idx || !low || !onst || !st || !cs || !ce) goto done;
    for (int i = 0; i < n; i++) idx[i] = -1;
    int counter = 0, sp = 0, nscc = 0;
    for (int root = 0; root < n; root++) {
        if (idx[root] >= 0) continue;
        int depth = 0;
        cs[0] = root; ce[0] = head[root];
        idx[root] = low[root] = counter++; st[sp++] = root; onst[root] = 1;
        while (depth >= 0) {
            const int v = cs[depth];
            if (ce[depth] < head[v + 1]) {
                const int w = to[ce[depth]++];
                if (idx[w] < 0) {
                    idx[w] = low[w] = counter++; st[sp++] = w; onst[w] = 1;
                    depth++; cs[depth] = w; ce[depth] = head[w];
                } else if (onst[w] && idx[w] < low[v]) low[v] = idx[w];
                continue;
            }
            if (low[v] == idx[v]) {
                int k = sp;
                while (st[k - 1] != v) k--;
                const int size = sp - (k - 1);
                if (size > 1) { nscc++; for (int j = k - 1; j < sp; j++) c->scc[st[j]] = nscc; }
                for (int j = k - 1; j < sp; j++) onst[st[j]] = 0;
                sp = k - 1;
            }
            depth--;
            if (depth >= 0 && low[v] < low[cs[depth]]) low[cs[depth]] = low[v];
        }
    }
    fprintf(stderr, "allegrexrecomp: %d tail-call cycles; their transfers go through psp_scc_next\n", nscc);
done:
    free(idx); free(low); free(onst); free(st); free(cs); free(ce);
    free(head); free(to); free(from);
}

/* Is this tail transfer from the current function to `target` inside a cycle? */
static int scc_transfer(const ectx *c, uint32_t target) {
    if (!c->scc) return 0;
    const int cur = (int)(c->func - c->an->funcs);
    const a_func *t = func_at(c->an, target);
    if (!t) return 0;
    const int ti = (int)(t - c->an->funcs);
    return c->scc[cur] != 0 && c->scc[cur] == c->scc[ti];
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
/* ---- inline VFPU ----------------------------------------------------------
 * The common vector operations are emitted as straight-line C with their
 * register lanes resolved here, at recompile time, instead of a runtime call
 * that maps registers and checks prefixes on every execution (about a quarter
 * of PSP2i's frame in VFPU-heavy scenes). The arithmetic is exactly the
 * runtime's no-prefix path (src/vfpu.c), so results are identical; while a
 * prefix is pending (psp_vfpu_pfx_any) the runtime call is used instead. */

/* Lanes of vector register `vreg` at `size` (1..4): src/vfpu.c regs_compute. */
static int vfpu_lanes(unsigned vreg, int size, int out[4]) {
    const int mtx = (vreg >> 2) & 7, col = vreg & 3;
    int transpose = (vreg >> 5) & 1, row = 0, len = 1;
    switch (size) {
    case 1: row = (vreg >> 5) & 3; transpose = 0; len = 1; break;
    case 2: row = (vreg >> 5) & 2;                len = 2; break;
    case 3: row = (vreg >> 6) & 1;                len = 3; break;
    default:row = (vreg >> 5) & 2;                len = 4; break;
    }
    for (int i = 0; i < len; i++) {
        const int step = (row + i) & 3;
        out[i] = transpose ? mtx * 4 + step * 32 + col : mtx * 4 + col * 32 + step;
    }
    return len;
}

/* Columns of matrix register `v` of order `size`: src/vfpu.c matrix_cols. */
static void vfpu_mcols(unsigned v, int size, int cols[4][4]) {
    const unsigned mtx = (v >> 2) & 7, transpose = (v >> 5) & 1;
    for (int c = 0; c < size; c++) vfpu_lanes((mtx << 2) | (unsigned)c | (transpose << 5), size, cols[c]);
}

enum { VB_ADD, VB_SUB, VB_MUL, VB_DIV, VB_MIN, VB_MAX, VB_SGE, VB_SLT, VB_DOT, VB_SCL };

/* vadd .. vslt, vdot, vscl. Returns 0 if not inlined (odd size). */
static int emit_vfpu_bin(FILE *f, const char *ind, const a_insn *in, int kind, const char *call) {
    const int n = in->vsize;
    if (n < 1 || n > 4) return 0;
    int S[4], T[4], D[4];
    vfpu_lanes(in->vs, n, S);
    vfpu_lanes(in->vt, kind == VB_SCL ? 1 : n, T);
    vfpu_lanes(in->vd, kind == VB_DOT ? 1 : n, D);
    fprintf(f, "%sif (!psp_vfpu_pfx_any) {", ind);
    if (kind == VB_DOT) {
        fprintf(f, " psp_cpu.v[%d] = 0.0f", D[0]);
        for (int i = 0; i < n; i++) fprintf(f, " + psp_cpu.v[%d] * psp_cpu.v[%d]", S[i], T[i]);
        fprintf(f, ";");
    } else {
        /* All sources are read before any destination is written: vd may alias. */
        for (int i = 0; i < n; i++) {
            fprintf(f, " const float _a%d = psp_cpu.v[%d], _b%d = psp_cpu.v[%d];",
                    i, S[i], i, kind == VB_SCL ? T[0] : T[i]);
        }
        for (int i = 0; i < n; i++) {
            fprintf(f, " psp_cpu.v[%d] = ", D[i]);
            switch (kind) {
            case VB_ADD: fprintf(f, "_a%d + _b%d", i, i); break;
            case VB_SUB: fprintf(f, "_a%d - _b%d", i, i); break;
            case VB_MUL: case VB_SCL: fprintf(f, "_a%d * _b%d", i, i); break;
            case VB_DIV: fprintf(f, "_a%d / _b%d", i, i); break;
            case VB_MIN: fprintf(f, "_a%d < _b%d ? _a%d : _b%d", i, i, i, i); break;
            case VB_MAX: fprintf(f, "_a%d > _b%d ? _a%d : _b%d", i, i, i, i); break;
            case VB_SGE: fprintf(f, "_a%d >= _b%d ? 1.0f : 0.0f", i, i); break;
            default:     fprintf(f, "_a%d < _b%d ? 1.0f : 0.0f", i, i); break;
            }
            fprintf(f, ";");
        }
    }
    fprintf(f, " } else %s(%u, %u, %u, %u);\n", call, in->vd, in->vs, in->vt, in->vsize);
    return 1;
}

/* vmov / vabs / vneg / vzero / vone. */
static int emit_vfpu_unary(FILE *f, const char *ind, const a_insn *in, const char *sel) {
    const int n = in->vsize;
    if (n < 1 || n > 4) return 0;
    int S[4], D[4];
    vfpu_lanes(in->vs, n, S);
    vfpu_lanes(in->vd, n, D);
    fprintf(f, "%sif (!psp_vfpu_pfx_any) {", ind);
    if (!strcmp(sel, "PSP_VU_ZERO") || !strcmp(sel, "PSP_VU_ONE")) {
        for (int i = 0; i < n; i++) fprintf(f, " psp_cpu.v[%d] = %s;", D[i], sel[7] == 'Z' ? "0.0f" : "1.0f");
    } else {
        for (int i = 0; i < n; i++) fprintf(f, " const float _a%d = psp_cpu.v[%d];", i, S[i]);
        for (int i = 0; i < n; i++) {
            if (!strcmp(sel, "PSP_VU_MOV"))      fprintf(f, " psp_cpu.v[%d] = _a%d;", D[i], i);
            else if (!strcmp(sel, "PSP_VU_ABS")) /* fabsf, bit for bit (gen does not include math.h) */
                fprintf(f, " psp_cpu.v[%d] = psp_bits_to_f32(psp_f32_to_bits(_a%d) & 0x7FFFFFFFu);", D[i], i);
            else                                 fprintf(f, " psp_cpu.v[%d] = -_a%d;", D[i], i);
        }
    }
    fprintf(f, " } else psp_vunary(%s, %u, %u, %u);\n", sel, in->vd, in->vs, in->vsize);
    return 1;
}

/* ---- prefixes resolved at recompile time -------------------------------------
 * PSP2i sets a prefix (vpfxs / vpfxt / vpfxd) right before most vector
 * operations in its hot routines (0x08D921F8, 0x08D8B864: swizzles, constants,
 * write masks), so the no-prefix inline path above almost never ran there and
 * each operation went through the runtime's prefix decoding -- the largest
 * single cost in a profile of the Clad 6 lobby at 60 fps. A prefix that
 * immediately precedes the operation is a constant: the lanes it selects are
 * resolved here (the "plan", exactly src/vfpu.c read_src / write_dst), and the
 * group -- prefixes plus operation -- is emitted as one unit: inline when no
 * other prefix is pending at run time, else the original prefix calls and the
 * runtime operation. */

/* The quad an operand starts in, which a swizzle indexes: src/vfpu.c quad_compute. */
static void vfpu_quad(unsigned vreg, int size, int out[4]) {
    const int mtx = (vreg >> 2) & 7, col = vreg & 3;
    int transpose = (vreg >> 5) & 1, row;
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

int a_vpfx_plan_src(unsigned vreg, int size, long prefix, a_vpfx_src out[4]) {
    if (size < 1 || size > 4) return 0;
    if (prefix < 0) {                                   /* the operand's own lanes */
        int L[4];
        vfpu_lanes(vreg, size, L);
        for (int i = 0; i < size; i++) { out[i].reg = L[i]; out[i].cst = -1; out[i].abs = out[i].neg = 0; }
        return size;
    }
    const unsigned long p = (unsigned long)prefix & 0xFFFFFul;
    int Q[4];
    vfpu_quad(vreg, size, Q);
    for (int i = 0; i < size; i++) {
        const int swz = (int)(p >> (2 * i)) & 3, abs_ = (int)(p >> (8 + i)) & 1;
        const int cst = (int)(p >> (12 + i)) & 1, neg = (int)(p >> (16 + i)) & 1;
        out[i].reg = cst ? -1 : Q[swz];
        out[i].cst = cst ? swz + 4 * abs_ : -1;
        out[i].abs = cst ? 0 : abs_;
        out[i].neg = neg;
    }
    return size;
}

int a_vpfx_plan_dst(unsigned vreg, int size, long prefix, a_vpfx_dst out[4]) {
    if (size < 1 || size > 4) return 0;
    int L[4];
    vfpu_lanes(vreg, size, L);
    const unsigned long p = prefix < 0 ? 0 : (unsigned long)prefix & 0xFFFFFul;
    for (int i = 0; i < size; i++) {
        out[i].reg = L[i];
        out[i].masked = (int)(p >> (8 + i)) & 1;
        const int s = (int)(p >> (2 * i)) & 3;
        out[i].sat = s == 1 || s == 3 ? s : 0;
    }
    return size;
}

/* A source lane as a C expression (src/vfpu.c PFX_CONST, fabsf as a bit mask). */
static void src_c(char *buf, size_t n, const a_vpfx_src *s) {
    static const char *const K[8] = { "0.0f", "1.0f", "2.0f", "0.5f", "3.0f", "(1.0f / 3.0f)", "0.25f", "(1.0f / 6.0f)" };
    char x[96];
    if (s->cst >= 0) snprintf(x, sizeof x, "%s", K[s->cst]);
    else if (s->abs) snprintf(x, sizeof x, "psp_bits_to_f32(psp_f32_to_bits(psp_cpu.v[%d]) & 0x7FFFFFFFu)", s->reg);
    else snprintf(x, sizeof x, "psp_cpu.v[%d]", s->reg);
    if (s->neg) snprintf(buf, n, "-(%s)", x);
    else snprintf(buf, n, "%s", x);
}

/* The operations a group can inline, and their runtime fallbacks. */
static int pfx_op_kind(const a_insn *in, const char **call) {
    switch (in->op) {
    case A_VADD: *call = "psp_vadd"; return VB_ADD;
    case A_VSUB: *call = "psp_vsub"; return VB_SUB;
    case A_VMUL: *call = "psp_vmul"; return VB_MUL;
    case A_VDIV: *call = "psp_vdiv"; return VB_DIV;
    case A_VMIN: *call = "psp_vmin"; return VB_MIN;
    case A_VMAX: *call = "psp_vmax"; return VB_MAX;
    case A_VSGE: *call = "psp_vsge"; return VB_SGE;
    case A_VSLT: *call = "psp_vslt"; return VB_SLT;
    case A_VDOT: *call = "psp_vdot"; return VB_DOT;
    case A_VSCL: *call = "psp_vscl"; return VB_SCL;
    case A_VMOV: *call = "PSP_VU_MOV"; return 100;
    case A_VABS: *call = "PSP_VU_ABS"; return 101;
    case A_VNEG: *call = "PSP_VU_NEG"; return 102;
    case A_VZERO: *call = "PSP_VU_ZERO"; return 103;
    case A_VONE: *call = "PSP_VU_ONE"; return 104;
    default: return -1;
    }
}

/* Emit the group starting with the prefix at a0 (see above). Returns 1 and
 * the operation's address in *last, or 0 to leave it to the usual path. */
static int emit_vfpu_pfx_group(ectx *c, uint32_t a0, uint32_t owner, uint32_t *last) {
    const a_analysis *an = c->an;
    FILE *f = c->out;
    if (c->is_slot[widx(an, a0)]) return 0;
    long pfx[3] = { -1, -1, -1 };
    a_insn pre[8], op;
    int np = 0;
    uint32_t a = a0;
    for (;;) {
        if (a != a0 && (!owned_by(an, a, owner) || c->is_label[widx(an, a)] || c->is_slot[widx(an, a)])) return 0;
        a_insn in;
        a_decode(fetch(an, a), a, &in);
        const int w = in.op == A_VPFXS ? 0 : in.op == A_VPFXT ? 1 : in.op == A_VPFXD ? 2 : -1;
        if (w >= 0) {
            if (np == 8) return 0;
            pre[np++] = in;
            pfx[w] = (long)(in.raw & 0xFFFFFu);
            a += 4;
            continue;
        }
        op = in;
        break;
    }
    const char *call = NULL;
    const int kind = pfx_op_kind(&op, &call);
    const int n = op.vsize;
    if (kind < 0 || n < 1 || n > 4) return 0;
    const int unary = kind >= 100, nosrc = kind == 103 || kind == 104;
    a_vpfx_src S[4], T[4];
    a_vpfx_dst D[4];
    if (!nosrc) a_vpfx_plan_src(op.vs, n, pfx[0], S);
    if (!unary) a_vpfx_plan_src(op.vt, kind == VB_SCL ? 1 : n, pfx[1], T);
    const int dn = kind == VB_DOT ? 1 : n;
    a_vpfx_plan_dst(op.vd, dn, pfx[2], D);

    for (int i = 1; i < np; i++) comment(c, &pre[i]);
    comment(c, &op);
    char e[160];
    fprintf(f, "    if (!psp_vfpu_pfx_any) {");
    if (!nosrc) for (int i = 0; i < n; i++) { src_c(e, sizeof e, &S[i]); fprintf(f, " const float _a%d = %s;", i, e); }
    if (!unary) for (int i = 0; i < (kind == VB_SCL ? 1 : n); i++) { src_c(e, sizeof e, &T[i]); fprintf(f, " const float _b%d = %s;", i, e); }
    for (int i = 0; i < dn; i++) {
        fprintf(f, " const float _r%d = ", i);
        if (kind == VB_DOT) {
            fprintf(f, "0.0f");
            for (int k = 0; k < n; k++) fprintf(f, " + _a%d * _b%d", k, k);
        } else switch (kind) {
        case VB_ADD: fprintf(f, "_a%d + _b%d", i, i); break;
        case VB_SUB: fprintf(f, "_a%d - _b%d", i, i); break;
        case VB_MUL: fprintf(f, "_a%d * _b%d", i, i); break;
        case VB_SCL: fprintf(f, "_a%d * _b0", i); break;
        case VB_DIV: fprintf(f, "_a%d / _b%d", i, i); break;
        case VB_MIN: fprintf(f, "_a%d < _b%d ? _a%d : _b%d", i, i, i, i); break;
        case VB_MAX: fprintf(f, "_a%d > _b%d ? _a%d : _b%d", i, i, i, i); break;
        case VB_SGE: fprintf(f, "_a%d >= _b%d ? 1.0f : 0.0f", i, i); break;
        case VB_SLT: fprintf(f, "_a%d < _b%d ? 1.0f : 0.0f", i, i); break;
        case 100: fprintf(f, "_a%d", i); break;
        case 101: fprintf(f, "psp_bits_to_f32(psp_f32_to_bits(_a%d) & 0x7FFFFFFFu)", i); break;
        case 102: fprintf(f, "-_a%d", i); break;
        case 103: fprintf(f, "0.0f"); break;
        default:  fprintf(f, "1.0f"); break;
        }
        fprintf(f, ";");
    }
    for (int i = 0; i < dn; i++) {
        if (D[i].masked) continue;
        if (D[i].sat == 1) fprintf(f, " psp_cpu.v[%d] = _r%d < 0.0f ? 0.0f : (_r%d > 1.0f ? 1.0f : _r%d);", D[i].reg, i, i, i);
        else if (D[i].sat == 3) fprintf(f, " psp_cpu.v[%d] = _r%d < -1.0f ? -1.0f : (_r%d > 1.0f ? 1.0f : _r%d);", D[i].reg, i, i, i);
        else fprintf(f, " psp_cpu.v[%d] = _r%d;", D[i].reg, i);
    }
    fprintf(f, " } else {");
    for (int i = 0; i < np; i++) {
        const int w = pre[i].op == A_VPFXS ? 0 : pre[i].op == A_VPFXT ? 1 : 2;
        fprintf(f, " psp_vfpu_set_prefix(%d, 0x%06Xu);", w, pre[i].raw & 0xFFFFFF);
    }
    if (unary) fprintf(f, " psp_vunary(%s, %u, %u, %u); }\n", call, op.vd, op.vs, op.vsize);
    else fprintf(f, " %s(%u, %u, %u, %u); }\n", call, op.vd, op.vs, op.vt, op.vsize);
    *last = a;
    return 1;
}

/* vtfm / vhtfm (order 2..4). They take no prefixes: always inline, then drop
 * any pending prefix as the runtime does. src/vfpu.c transform. */
static void emit_vfpu_tfm(FILE *f, const char *ind, const a_insn *in, int order, int homogeneous) {
    int cols[4][4], T[4], D[4];
    vfpu_mcols(in->vs, order, cols);
    const int vn = homogeneous ? order - 1 : order;
    vfpu_lanes(in->vt, vn, T);
    vfpu_lanes(in->vd, order, D);
    fprintf(f, "%sif (!psp_vfpu_pfx_any) {", ind);
    for (int k = 0; k < vn; k++) fprintf(f, " const float _i%d = psp_cpu.v[%d];", k, T[k]);
    if (homogeneous) fprintf(f, " const float _i%d = 1.0f;", order - 1);
    for (int i = 0; i < order; i++) {
        fprintf(f, " const float _o%d = 0.0f", i);
        for (int k = 0; k < order; k++) fprintf(f, " + psp_cpu.v[%d] * _i%d", cols[i][k], k);
        fprintf(f, ";");
    }
    for (int i = 0; i < order; i++) fprintf(f, " psp_cpu.v[%d] = _o%d;", D[i], i);
    /* With a prefix pending (which vtfm ignores and drops) the runtime call does the same. */
    fprintf(f, " } else psp_%s(%u, %u, %u, %d);\n", homogeneous ? "vhtfm" : "vtfm", in->vd, in->vs, in->vt, order);
}

/* lv.s / lv.q / sv.s / sv.q: no prefixes involved. src/vfpu.c psp_lv_q etc. */
static void emit_vfpu_mem(FILE *f, const char *ind, const a_insn *in, const char *rs, int quad, int store) {
    int R[4];
    vfpu_lanes(in->vt, quad ? 4 : 1, R);
    fprintf(f, "%s{ const uint32_t _ad = (uint32_t)(%s + %d) & %s;", ind, rs, in->imm & ~3, quad ? "~15u" : "~3u");
    for (int i = 0; i < (quad ? 4 : 1); i++) {
        if (store) fprintf(f, " psp_write_f32(_ad + %du, psp_cpu.v[%d]);", i * 4, R[i]);
        else       fprintf(f, " psp_cpu.v[%d] = psp_read_f32(_ad + %du);", R[i], i * 4);
    }
    fprintf(f, " }\n");
}

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
    case A_LV_S: emit_vfpu_mem(f, ind, in, rs, 0, 0); return;
    case A_LV_Q: emit_vfpu_mem(f, ind, in, rs, 1, 0); return;
    case A_SV_S: emit_vfpu_mem(f, ind, in, rs, 0, 1); return;
    case A_SV_Q: emit_vfpu_mem(f, ind, in, rs, 1, 1); return;

    case A_VADD:
        if (emit_vfpu_bin(f, ind, in, VB_ADD, "psp_vadd")) return;
        fprintf(f, "%spsp_vadd(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VSUB:
        if (emit_vfpu_bin(f, ind, in, VB_SUB, "psp_vsub")) return;
        fprintf(f, "%spsp_vsub(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VMUL:
        if (emit_vfpu_bin(f, ind, in, VB_MUL, "psp_vmul")) return;
        fprintf(f, "%spsp_vmul(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VDIV:
        if (emit_vfpu_bin(f, ind, in, VB_DIV, "psp_vdiv")) return;
        fprintf(f, "%spsp_vdiv(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VMIN:
        if (emit_vfpu_bin(f, ind, in, VB_MIN, "psp_vmin")) return;
        fprintf(f, "%spsp_vmin(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VMAX:
        if (emit_vfpu_bin(f, ind, in, VB_MAX, "psp_vmax")) return;
        fprintf(f, "%spsp_vmax(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VDOT:
        if (emit_vfpu_bin(f, ind, in, VB_DOT, "psp_vdot")) return;
        fprintf(f, "%spsp_vdot(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VSCL:
        if (emit_vfpu_bin(f, ind, in, VB_SCL, "psp_vscl")) return;
        fprintf(f, "%spsp_vscl(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VCMP:
        fprintf(f, "%spsp_vcmp(%u, %u, %u, %u);\n", ind, in->vd & 0xF, in->vs, in->vt, in->vsize); return;
    case A_VSGE:
        if (emit_vfpu_bin(f, ind, in, VB_SGE, "psp_vsge")) return;
        fprintf(f, "%spsp_vsge(%u, %u, %u, %u);\n", ind, in->vd, in->vs, in->vt, in->vsize); return;
    case A_VSLT:
        if (emit_vfpu_bin(f, ind, in, VB_SLT, "psp_vslt")) return;
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
            if (in->op >= A_VMOV && in->op <= A_VONE && emit_vfpu_unary(f, ind, in, U[k].sel)) return;
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
            emit_vfpu_tfm(f, ind, in, (int)order, 0);
        else if (in->vsize + 1 == order)
            emit_vfpu_tfm(f, ind, in, (int)order, 1);
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

    int computed_jumps = 0;                          /* `jr $rN` other than $ra */
    for (uint32_t a = fn->start; a < fn->end; a += 4) {
        if (!owned_by(an, a, owner)) continue;
        a_insn ji;
        a_decode(fetch(an, a), a, &ji);
        if (ji.is_indirect && !ji.is_call && !ji.is_return) computed_jumps++;
    }
    const int has_switch = nlabels > 1 || fn->start != fn->addr;
    c->has_entry_switch = has_switch && computed_jumps;
    if (has_switch) {
        /* A computed jump (`jr $rN`) into this function comes back here (see
         * the jr case): a jump table in a loop would otherwise nest a call per
         * pass and overflow the host stack. _jump marks such a re-entry, so an
         * address that is not one of these labels still goes to dispatch. */
        if (c->has_entry_switch) fprintf(f, "    int _jump = 0;\nL_entry_switch:\n");
        fprintf(f, "    switch (_entry) {\n");
        for (uint32_t a = fn->start; a < fn->end; a += 4) {
            if (!owned_by(an, a, owner) || !c->is_label[widx(an, a)]) continue;
            if (c->is_slot[widx(an, a)]) continue;   /* only the inline copy is real */
            fprintf(f, "    case 0x%08Xu: goto L_%08X;\n", a, a);
        }
        if (c->has_entry_switch) fprintf(f, "    default: if (_jump) { psp_dispatch(_entry); return; } break;\n");
        else fprintf(f, "    default: break;\n");
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
                if (is_function(an, a) && scc_transfer(c, a))
                    fprintf(f, "    psp_scc_next = 0x%08Xu;  /* tail transfer within a cycle */\n    return;\n", a);
                else {
                    emit_static_call(c, a);
                    fprintf(f, "    PSP_SP_CHECK(0x%08Xu);\n    return;\n", a);
                }
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
                else if (scc_transfer(c, in.target))
                    fprintf(f, "        psp_scc_next = 0x%08Xu;  /* tail transfer within a cycle */\n        return;\n", in.target);
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
                    else if (!in.is_call && scc_transfer(c, in.target))
                        fprintf(f, "psp_scc_next = 0x%08Xu;", in.target);
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
            /* The jump reads rs before its delay slot runs. */
            fprintf(f, "    { uint32_t _jt = %s;\n", RN[in.rs]);
            if (have_slot) { comment(c, &slot); emit_simple(c, &slot, "    "); }
            /* Into this function (a jump table): back through the entry switch --
             * a jump, not a nested call, so a switch in a loop keeps the host
             * stack flat. Elsewhere: dispatch. */
            if (c->has_entry_switch)
                fprintf(f, "    if (_jt - 0x%08Xu < 0x%Xu) { _entry = _jt; _jump = 1; PSP_LOOP(_jt); goto L_entry_switch; }\n",
                        fn->start, fn->end - fn->start);
            fprintf(f, "    psp_dispatch(_jt);\n    return; }\n");
            if (have_slot && c->is_label[widx(an, a + 4)] && !slot.is_branch) emit_slot_alias(c, a, &slot, 0);
            a += 4;
            continue;
        }

        if (in.is_jump) {                        /* j */
            if (have_slot) { comment(c, &slot); emit_simple(c, &slot, "    "); }
            if (in.target == owner) {
                /* A jump back to the function's own entry is a loop (a compiler's
                 * tail-recursion elimination, or `for (;;)`). Emitted as a call it
                 * would add a host stack frame per iteration and overflow the
                 * stack on a long loop (0xC00000FD): 296 functions of PSP2i do this. */
                if (in.target == a)     /* `j .` at the entry: a deliberate hang; stop the thread, keep the rest alive */
                    fprintf(f, "    psp_park_thread();\n    return;\n");
                else
                    fprintf(f, "    PSP_LOOP(0x%08Xu);\n    goto L_%08X;\n", in.target, in.target);
            } else if (owned_by(an, in.target, owner) && !is_function(an, in.target)) {
                fprintf(f, "    goto L_%08X;\n", in.target);
            } else if (scc_transfer(c, in.target)) {
                fprintf(f, "    psp_scc_next = 0x%08Xu;  /* tail transfer within a cycle */\n    return;\n", in.target);
            } else {
                emit_static_call(c, in.target);  /* tail call */
                fprintf(f, "    return;\n");
            }
            if (have_slot && c->is_label[widx(an, a + 4)] && !slot.is_branch) emit_slot_alias(c, a, &slot, 0);
            a += 4;
            continue;
        }

        if (in.op == A_VPFXS || in.op == A_VPFXT || in.op == A_VPFXD) {
            uint32_t last;
            if (emit_vfpu_pfx_group(c, a, owner, &last)) { a = last; continue; }   /* prefixes + operation */
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
            if (scc_transfer(c, next)) fprintf(f, "    psp_scc_next = 0x%08Xu;  /* tail transfer within a cycle */\n", next);
            else fprintf(f, "    psp_func_%08X();\n", next);
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
    } else if (c->scc && c->scc[c->func - an->funcs]) {
        /* A tail-call cycle member: entering it runs the cycle to its end
         * (see compute_tail_cycles); psp_step_X is one pass, for the drain. */
        fprintf(f, "static void psp_step_%08X(void) { psp_body_%08X(0x%08Xu); }\n",
                fn->addr, fn->addr, fn->addr);
        fprintf(f, "void psp_func_%08X(void) { psp_body_%08X(0x%08Xu); psp_scc_drain(); }\n",
                fn->addr, fn->addr, fn->addr);
    } else {
        fprintf(f, "void psp_func_%08X(void) { psp_body_%08X(0x%08Xu); }\n",
                fn->addr, fn->addr, fn->addr);
    }
    const int in_cycle = c->scc && c->scc[c->func - an->funcs];
    for (uint32_t a = fn->start; a < fn->end; a += 4) {
        if (!owned_by(an, a, owner) || !c->is_label[widx(an, a)]) continue;
        if (c->is_slot[widx(an, a)] || a == fn->addr) continue;
        fprintf(f, "void psp_at_%08X(void) { psp_body_%08X(0x%08Xu);%s }\n",
                a, fn->addr, a, in_cycle ? " psp_scc_drain();" : "");
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

    c.hooks = o->hooks; c.nhooks = o->nhooks;
    c.scc = NULL;
    compute_tail_cycles(&c);
    /* Tail transfers inside a cycle: see compute_tail_cycles. */
    fprintf(f,
        "\nstatic uint32_t psp_scc_next;   /* a pending tail transfer within a tail-call cycle */\n"
        "static void psp_scc_step(uint32_t t);\n"
        "static void psp_scc_drain(void) {\n"
        "    while (psp_scc_next) { const uint32_t t_ = psp_scc_next; psp_scc_next = 0; psp_scc_step(t_); }\n"
        "}\n");

    mark_continuations(&c);
    for (int i = 0; i < an->nfuncs; i++) {
        c.func = &an->funcs[i];
        c.hooks = o->hooks; c.nhooks = o->nhooks;
        emit_function(&c, &an->funcs[i]);
    }

    fprintf(f, "\nstatic void psp_scc_step(uint32_t t) {\n    switch (t) {\n");
    for (int i = 0; c.scc && i < an->nfuncs; i++)
        if (c.scc[i]) fprintf(f, "    case 0x%08Xu: psp_step_%08X(); break;\n", an->funcs[i].addr, an->funcs[i].addr);
    fprintf(f, "    default: psp_dispatch(t); break;\n    }\n}\n");
    free(c.scc);

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
