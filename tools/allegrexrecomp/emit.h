/* The C emitter — turning discovered functions into readable native C.
 *
 * One `psp_func_<addr>` per discovered function, every line carrying its
 * address and original disassembly as a comment, lowered to the helpers in
 * <psprecomp/recomp_rt.h>. The output is meant to be *read*, not merely
 * compiled: a recomp project is only useful to other people if they can open
 * the generated file and see what the original was doing.
 *
 * The hard part is delay slots. Every MIPS branch and jump executes the
 * instruction *after* it before control transfers, and "likely" branches
 * nullify theirs when not taken. See the notes in emit.c — that single
 * detail is where most of this file's care goes.
 */
#ifndef ALLEGREX_EMIT_H
#define ALLEGREX_EMIT_H

#include "analyze.h"
#include "container.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *outdir;     /* directory to write into */
    const char *prefix;     /* file/base name, e.g. "recomp" */
    const char *module;     /* module name, for the file header comment */

    /* The module's import table, so each generated thunk can dispatch to the
     * HLE layer by NID and carry the firmware function's library and NID in a
     * comment. Without it the thunks can only trap. */
    const psp_import_entry *imports;
    int                     nimports;

    /* Functions whose public entry goes through a run-time hook
     * (psp_hook_set, dispatch.h): the hook receives the original as a
     * callback and may wrap or replace it. Sorted or not; small. */
    const uint32_t *hooks;
    int             nhooks;
} emit_opts;

/* Emit <outdir>/<prefix>_funcs.c, <prefix>_funcs.h and <prefix>_imports.c.
 * Returns 0 on success. */
int a_emit(const a_analysis *an, const emit_opts *o);

/* VFPU prefixes resolved at recompile time (a vpfxs/vpfxt/vpfxd right before
 * an operation): which register or constant each source lane reads, and how
 * each destination lane is written -- exactly src/vfpu.c read_src/write_dst.
 * prefix < 0 = none. Exposed for tests (test_emit checks them against the
 * runtime). */
typedef struct { int reg; int cst; int abs, neg; } a_vpfx_src;   /* cst: -1, or 0..7 (PFX_CONST index) */
typedef struct { int reg; int masked; int sat; } a_vpfx_dst;     /* sat: 0 none, 1 [0,1], 3 [-1,1] */
int a_vpfx_plan_src(unsigned vreg, int size, long prefix, a_vpfx_src out[4]);
int a_vpfx_plan_dst(unsigned vreg, int size, long prefix, a_vpfx_dst out[4]);

#ifdef __cplusplus
}
#endif

#endif /* ALLEGREX_EMIT_H */
