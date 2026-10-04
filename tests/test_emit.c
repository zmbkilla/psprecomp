/* Emitter tests — synthetic code only, no game data.
 *
 * The function under test is eight instructions of hand-assembled MIPS chosen
 * to exercise the parts of emission that are actually hard: a conditional
 * branch with a delay slot, a backward-reachable label, and a `jr $ra` whose
 * delay slot must run before the return.
 *
 * The assertions are about the *shape* of the generated C, because that shape
 * is the contract. In particular the branch must read its condition into a
 * temporary before the delay slot runs — if that ever regresses, a delay slot
 * that writes a condition register silently changes which way the branch goes,
 * once in a thousand iterations, in a game nobody can debug.
 */

#include "analyze.h"
#include "emit.h"

#include <stdio.h>
#include <stdlib.h>
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

#define BASE 0x08804000u

/* addiu $sp,$sp,-16      prologue
 * sw    $ra,12($sp)
 * addu  $v0,$a0,$a1
 * beq   $v0,$zero,+2     -> the `jr $ra` at BASE+24
 * addiu $v0,$v0,1        delay slot: runs either way, and writes $v0 which
 *                        the branch above just read
 * lw    $ra,12($sp)
 * jr    $ra
 * addiu $sp,$sp,16       delay slot: runs before the return
 */
static const uint32_t CODE[] = {
    0x27BDFFF0u, 0xAFBF000Cu, 0x00851021u, 0x10400002u,
    0x24420001u, 0x8FBF000Cu, 0x03E00008u, 0x27BD0010u,
};

static char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    char *b = (char *)malloc((size_t)n + 1);
    if (!b) { fclose(f); return NULL; }
    size_t got = fread(b, 1, (size_t)n, f);
    b[got] = '\0';
    fclose(f);
    if (len) *len = got;
    return b;
}

/* Assert a substring appears, reporting what was missing if not. */
static void expect_contains(const char *hay, const char *needle, const char *why) {
    if (!strstr(hay, needle)) {
        printf("FAIL %s\n  expected to find: %s\n", why, needle);
        failures++;
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);   /* progress survives a crash */
    uint8_t code[sizeof CODE];
    for (size_t i = 0; i < sizeof CODE / sizeof CODE[0]; i++) {
        code[i * 4 + 0] = (uint8_t)(CODE[i]);
        code[i * 4 + 1] = (uint8_t)(CODE[i] >> 8);
        code[i * 4 + 2] = (uint8_t)(CODE[i] >> 16);
        code[i * 4 + 3] = (uint8_t)(CODE[i] >> 24);
    }

    a_analysis an;
    memset(&an, 0, sizeof an);
    an.code = code;
    an.base = BASE;
    an.size = (uint32_t)sizeof code;

    uint32_t seed = BASE;
    CHECK(a_discover(&an, &seed, 1) == 0, "discovery runs");
    CHECK(an.nfuncs == 1, "one function found, got %d", an.nfuncs);
    if (an.nfuncs != 1) return 1;
    CHECK(an.funcs[0].addr == BASE, "function entry is the seed");
    CHECK(an.funcs[0].has_return, "function reaches a `jr $ra`");
    CHECK(an.insns == 8, "all eight instructions visited, got %llu",
          (unsigned long long)an.insns);

    emit_opts o;
    memset(&o, 0, sizeof o);           /* no import table: imports must be NULL, not stack garbage */
    o.outdir = ".";
    o.prefix = "t_emit";
    o.module = "synthetic";
    CHECK(a_emit(&an, &o) == 0, "emission succeeds");

    char *src = slurp("./t_emit_funcs.c", NULL);
    CHECK(src != NULL, "generated .c is readable");
    if (!src) return 1;

    expect_contains(src, "void psp_func_08804000(void)",
                    "function is named after its address");

    /* The prologue, lowered to plain C. */
    expect_contains(src, "r_sp = r_sp + -16;", "addiu lowers to arithmetic");
    expect_contains(src, "psp_write32(r_sp + 12, r_ra);", "sw lowers to a memory write");
    expect_contains(src, "r_v0 = r_a0 + r_a1;", "addu lowers to addition");

    /* Every statement carries its address and disassembly. */
    expect_contains(src, "/* 08804000  addiu", "statements carry their disassembly");

    /* THE important one: the branch condition is captured into a temporary
     * *before* the delay slot executes, because the delay slot writes $v0 and
     * the hardware read the old value. */
    expect_contains(src, "int _c = (r_v0 == r_zero);",
                    "branch condition is captured before the delay slot");
    {
        const char *cond = strstr(src, "int _c = (r_v0 == r_zero);");
        const char *slot = strstr(src, "r_v0 = r_v0 + 1;");
        const char *jump = cond ? strstr(cond, "if (_c) goto") : NULL;
        CHECK(cond && slot && jump && cond < slot && slot < jump,
              "ordering must be condition -> delay slot -> branch");
    }

    /* The branch target is a label, and the return runs its delay slot first. */
    expect_contains(src, "L_08804018:", "branch target becomes a label");
    {
        const char *lbl = strstr(src, "L_08804018:");
        const char *slot = lbl ? strstr(lbl, "r_sp = r_sp + 16;") : NULL;
        const char *ret = slot ? strstr(slot, "return;") : NULL;
        CHECK(slot && ret, "the `jr $ra` delay slot is emitted before the return");
    }

    /* $zero is never assigned: `addu $v0,$a0,$a1` reads it, but nothing may
     * write it. A generated `r_zero =` would corrupt every later use. */
    CHECK(strstr(src, "r_zero =") == NULL, "nothing ever assigns $zero");

    free(src);

    /* The header declares the function and the registration entry point. */
    char *hdr = slurp("./t_emit_funcs.h", NULL);
    CHECK(hdr != NULL, "generated .h is readable");
    if (hdr) {
        expect_contains(hdr, "void psp_func_08804000(void);", "header declares the function");
        expect_contains(hdr, "void psp_recomp_register(void);", "header declares registration");
        expect_contains(hdr, "#define r_sp", "header defines register aliases");
        free(hdr);
    }

    /* Registration wires the address to the function. */
    src = slurp("./t_emit_funcs.c", NULL);
    if (src) {
        expect_contains(src, "psp_register(0x08804000u, psp_func_08804000);",
                        "the function is registered for indirect dispatch");
        free(src);
    }

    a_analysis_free(&an);

    /* A conditional call: `bltzal` links and branches only when taken, and the
     * callee returns to the instruction after the delay slot. The caller must
     * continue there -- emitting the taken path as `call; return;` silently
     * dropped the rest of the caller (observed in a game's decompressor).
     *
     *   A: bltzal $a0, B     B: jr $ra
     *      nop                  nop
     *      addiu $v0,$zero,7
     *      jr    $ra
     *      nop                                                              */
    {
        static const uint32_t CALLCODE[] = {
            0x04900004u, 0x00000000u, 0x24020007u, 0x03E00008u,
            0x00000000u, 0x03E00008u, 0x00000000u,
        };
        uint8_t cc[sizeof CALLCODE];
        for (size_t i = 0; i < sizeof CALLCODE / sizeof CALLCODE[0]; i++)
            for (int k = 0; k < 4; k++) cc[i * 4 + k] = (uint8_t)(CALLCODE[i] >> (8 * k));
        a_analysis an2;
        memset(&an2, 0, sizeof an2);
        an2.code = cc;
        an2.base = BASE;
        an2.size = (uint32_t)sizeof cc;
        uint32_t seed2 = BASE;
        CHECK(a_discover(&an2, &seed2, 1) == 0, "discovery runs (bltzal)");
        CHECK(an2.nfuncs == 2, "caller and conditional-call target, got %d", an2.nfuncs);
        o.prefix = "t_emit2";
        CHECK(a_emit(&an2, &o) == 0, "emission succeeds (bltzal)");
        char *s2 = slurp("./t_emit2_funcs.c", NULL);
        if (s2) {
            expect_contains(s2, "if (_c) { psp_func_08804014(); if (r_ra != 0x08804008u) return; } }",
                            "a conditional call continues after the callee returns "
                            "(unless the callee returned past it)");
            CHECK(strstr(s2, "psp_func_08804014(); return;") == NULL,
                  "a conditional call is not emitted as a tail transfer");
            expect_contains(s2, "r_ra = 0x08804008u;", "bltzal links past its delay slot");
            free(s2);
        }
        a_analysis_free(&an2);
    }

    /* A hooked function: its public entry asks the run-time hook table and
     * falls back to the original body. (CODE from the first test.) */
    {
        a_analysis an5;
        memset(&an5, 0, sizeof an5);
        an5.code = code;
        an5.base = BASE;
        an5.size = (uint32_t)sizeof code;
        uint32_t seed5 = BASE;
        CHECK(a_discover(&an5, &seed5, 1) == 0, "discovery runs (hook)");
        static const uint32_t HOOKS[1] = { BASE };
        emit_opts o5 = o;
        o5.prefix = "t_emit5";
        o5.hooks = HOOKS;
        o5.nhooks = 1;
        CHECK(a_emit(&an5, &o5) == 0, "emission succeeds (hook)");
        char *s5 = slurp("./t_emit5_funcs.c", NULL);
        if (s5) {
            expect_contains(s5, "static void psp_orig_08804000(void) { psp_body_08804000(0x08804000u); }",
                            "the original body stays callable");
            expect_contains(s5, "psp_hook_fn h_ = psp_hook_find(0x08804000u);",
                            "the hooked entry looks the hook up");
            expect_contains(s5, "if (h_) h_(psp_orig_08804000); else psp_orig_08804000();",
                            "the hook gets the original; no hook runs the original");
            free(s5);
        }
        a_analysis_free(&an5);
    }

    /* VFPU condition branches test the vcmp condition bit named by bits
     * 18-20. They used to be emitted as never taken, which made PSP2i's
     * polygon clipper keep and split every vertex at every plane.
     *
     *   0: bvt  cc5, 3     (rt = 5 << 2 | 1)
     *   1: nop
     *   2: addiu $v0, $zero, 1
     *   3: jr   $ra
     *   4: nop                                                              */
    {
        static const uint32_t BCODE[] = {
            0x49150002u, 0x00000000u, 0x24020001u, 0x03E00008u, 0x00000000u,
        };
        uint8_t bc[sizeof BCODE];
        for (size_t i = 0; i < sizeof BCODE / sizeof BCODE[0]; i++)
            for (int k = 0; k < 4; k++) bc[i * 4 + k] = (uint8_t)(BCODE[i] >> (8 * k));
        a_analysis an4;
        memset(&an4, 0, sizeof an4);
        an4.code = bc;
        an4.base = BASE;
        an4.size = (uint32_t)sizeof bc;
        uint32_t seed4 = BASE;
        CHECK(a_discover(&an4, &seed4, 1) == 0, "discovery runs (bvt)");
        o.prefix = "t_emit4";
        CHECK(a_emit(&an4, &o) == 0, "emission succeeds (bvt)");
        char *s4 = slurp("./t_emit4_funcs.c", NULL);
        if (s4) {
            expect_contains(s4, "int _c = (((psp_cpu.vfpu_cc >> 5) & 1));",
                            "bvt tests condition bit 5, read before the delay slot");
            CHECK(strstr(s4, "unhandled branch") == NULL, "no VFPU branch is left unhandled");
            free(s4);
        }
        a_analysis_free(&an4);
    }

    /* vcst takes its constant index from bits 16-20 of the word, not from the
     * vs field. The index used to be read from vs (always 0), so every vcst
     * loaded constant 0: PSP2i's heading-to-rotation routine (0x08D2FF54,
     * angle * VFPU_2_PI before vsin/vcos) became an identity rotation, and
     * NPCs and enemies all moved along the same world axis.
     *
     *   0: vcst.s v32, VFPU_2_PI   (0xD0650020, the word at 0x08D2FF60)
     *   1: vcst.s v0, VFPU_PI      (0xD0690000)
     *   2: jr $ra
     *   3: nop                                                              */
    {
        static const uint32_t CCODE[] = { 0xD0650020u, 0xD0690000u, 0x03E00008u, 0x00000000u };
        uint8_t cc[sizeof CCODE];
        for (size_t i = 0; i < sizeof CCODE / sizeof CCODE[0]; i++)
            for (int k = 0; k < 4; k++) cc[i * 4 + k] = (uint8_t)(CCODE[i] >> (8 * k));
        a_analysis an5;
        memset(&an5, 0, sizeof an5);
        an5.code = cc;
        an5.base = BASE;
        an5.size = (uint32_t)sizeof cc;
        uint32_t seed5 = BASE;
        CHECK(a_discover(&an5, &seed5, 1) == 0, "discovery runs (vcst)");
        o.prefix = "t_emit5";
        CHECK(a_emit(&an5, &o) == 0, "emission succeeds (vcst)");
        char *s5 = slurp("./t_emit5_funcs.c", NULL);
        if (s5) {
            expect_contains(s5, "psp_vcst(32, 5, 1);", "vcst.s v32, VFPU_2_PI loads constant 5");
            expect_contains(s5, "psp_vcst(0, 9, 1);", "vcst.s v0, VFPU_PI loads constant 9");
            free(s5);
        }
        a_analysis_free(&an5);
    }

    /* A computed jump into one of several entry points of a block, the
     * pointer adjusted in likely-branch delay slots (PSP2i's vertex decoder
     * at 0x08D8B978 picks its float path this way). Every adjusted pointer
     * is a `jr` target and must be a seed -- only the base used to be, so
     * the float path was not a dispatchable entry and the game stopped with
     * "indirect call to 0x08D8B9D0, which is not a recompiled function".
     *
     *   0: lui   $t3, 0x0880           6: jr  $t3
     *   1: addiu $t3, $t3, 0x4020  (8)  7: nop
     *   2: beql  $a3, $zero, 6          8..11: nop
     *   3:  addiu $t3, $t3, 8      (10) 12: jr $ra
     *   4: bgtzl $a3, 6                 13: nop
     *   5:  addiu $t3, $t3, 16     (12)                                     */
    {
        static const uint32_t JCODE[] = {
            0x3C0B0880u, 0x256B4020u, 0x50E00003u, 0x256B0008u, 0x5CE00001u,
            0x256B0010u, 0x01600008u, 0x00000000u, 0x00000000u, 0x00000000u,
            0x00000000u, 0x00000000u, 0x03E00008u, 0x00000000u,
        };
        uint8_t jc[sizeof JCODE];
        for (size_t i = 0; i < sizeof JCODE / sizeof JCODE[0]; i++)
            for (int k = 0; k < 4; k++) jc[i * 4 + k] = (uint8_t)(JCODE[i] >> (8 * k));
        a_analysis an3;
        memset(&an3, 0, sizeof an3);
        an3.code = jc;
        an3.base = BASE;
        an3.size = (uint32_t)sizeof jc;
        uint32_t ptrs[8];
        int n = a_scan_code_pointers(&an3, ptrs, 8);
        CHECK(n == 3, "base and both adjusted jump targets found, got %d", n);
        if (n == 3) {
            CHECK(ptrs[0] == BASE + 0x20, "base pointer, got 0x%08X", ptrs[0]);
            CHECK(ptrs[1] == BASE + 0x28, "base + 8 (beql slot), got 0x%08X", ptrs[1]);
            CHECK(ptrs[2] == BASE + 0x30, "base + 16 (bgtzl slot, relative to the base), got 0x%08X",
                  ptrs[2]);
        }
    }

    if (failures) {
        printf("\n%d check(s) failed\n", failures);
        return 1;
    }
    printf("all emitter checks passed (synthetic code, no game data)\n");
    return 0;
}
