/* HLE tests — the firmware layer, with no game data involved.
 *
 * The headline check is the first one: **every registered NID is verified
 * against the SHA-1 of its own declared name.** A PSP NID is defined as the
 * first four bytes of SHA-1(name), so this is not a convention we are choosing
 * to follow — it is the identity the hardware uses, and it makes the whole
 * table self-verifying. A mistyped NID or a wrong function name cannot get
 * past this, which matters because such a mistake produces a game that runs
 * and misbehaves in a way indistinguishable from a codegen bug.
 */

#include "psprecomp/hle.h"
#include "psprecomp/dispatch.h"
#include "crypto/sha1.h"
#include "psprecomp/net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
/* Two kernel32 calls, declared here: windows.h defines DELETE and OUT, which
 * the tests below use as names. */
__declspec(dllimport) unsigned long __stdcall GetCurrentThreadId(void);
__declspec(dllimport) void __stdcall Sleep(unsigned long ms);
#  define test_thread_id() ((unsigned long)GetCurrentThreadId())
#  define test_sleep_ms(n) Sleep(n)
#else
#  include <pthread.h>
#  include <unistd.h>
#  define test_thread_id() ((unsigned long)pthread_self())
#  define test_sleep_ms(n) usleep((n) * 1000)
#endif

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

/* Invoke a registered firmware call with o32 arguments. */
static uint32_t call(uint32_t nid, uint32_t a0, uint32_t a1, uint32_t a2,
                     uint32_t a3) {
    psp_cpu.r[PSP_REG_A0] = a0;
    psp_cpu.r[PSP_REG_A1] = a1;
    psp_cpu.r[PSP_REG_A2] = a2;
    psp_cpu.r[PSP_REG_A3] = a3;
    psp_hle_call(nid);
    return psp_cpu.r[PSP_REG_V0];
}

/* Stack arguments live at $sp+16 onward. */
static uint32_t call5(uint32_t nid, uint32_t a0, uint32_t a1, uint32_t a2,
                      uint32_t a3, uint32_t a4) {
    /* The fifth argument travels in $t0 (the PSP passes eight in registers;
     * see psp_arg). This used to write it to the stack only, so it never
     * arrived -- harmless while every test passed 0 there. */
    psp_cpu.r[PSP_REG_T0] = a4;
    psp_write32(psp_cpu.r[PSP_REG_SP] + 16, a4);
    return call(nid, a0, a1, a2, a3);
}

static void test_sha1_vectors(void) {
    /* FIPS 180-4 examples, so the hash itself is trusted before anything is
     * built on it. */
    uint8_t d[20];
    char hex[41];

    sha1("abc", 3, d);
    for (int i = 0; i < 20; i++) sprintf(hex + i * 2, "%02x", d[i]);
    CHECK(strcmp(hex, "a9993e364706816aba3e25717850c26c9cd0d89d") == 0,
          "SHA-1(\"abc\"): got %s", hex);

    sha1("", 0, d);
    for (int i = 0; i < 20; i++) sprintf(hex + i * 2, "%02x", d[i]);
    CHECK(strcmp(hex, "da39a3ee5e6b4b0d3255bfef95601890afd80709") == 0,
          "SHA-1(\"\"): got %s", hex);

    sha1("The quick brown fox jumps over the lazy dog", 43, d);
    for (int i = 0; i < 20; i++) sprintf(hex + i * 2, "%02x", d[i]);
    CHECK(strcmp(hex, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") == 0,
          "SHA-1(\"The quick brown fox...\"): got %s", hex);

    /* 56 bytes is the boundary case: the 0x80 terminator fits in the first
     * block but the 8-byte length does not, so padding spills into a second
     * block. An implementation that gets this wrong passes every shorter
     * vector. */
    const char *m = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    CHECK(strlen(m) == 56, "the two-block padding case is 56 bytes");
    sha1(m, 56, d);
    for (int i = 0; i < 20; i++) sprintf(hex + i * 2, "%02x", d[i]);
    CHECK(strcmp(hex, "c2db330f6083854c99d4b5bfb6e8f29f201be699") == 0,
          "SHA-1 of 56 'a's (two-block padding): got %s", hex);
}

/* THE important test: the registered table describes itself correctly. */
static void test_nids_match_names(void) {
    int n = 0;
    const psp_hle_entry *e = psp_hle_entries(&n);
    CHECK(n > 0, "something is registered");

    int checked = 0, unnamed = 0;
    for (int i = 0; i < n; i++) {
        /* A NID may be observed without being identified: the game calls it,
         * the NID is exact, and no plausible name hashes to it. Those are
         * registered unnamed rather than under an invented name, and are
         * skipped here by construction. Inventing a name to satisfy this check
         * would defeat the only thing that makes the table trustworthy. */
        if (!e[i].name) { unnamed++; continue; }        uint32_t want = psp_nid(e[i].name);
        if (want != e[i].nid) {
            printf("FAIL %s::%s\n  registered 0x%08X but SHA-1(name) gives 0x%08X\n",
                   e[i].lib, e[i].name, e[i].nid, want);
            failures++;
        }
        checked++;
    }
    printf("  verified %d NIDs against SHA-1 of their names\n", checked);
}

static void test_sysmem(void) {
    psp_sysmem_reset();

    const uint32_t NID_ALLOC = psp_nid("sceKernelAllocPartitionMemory");
    const uint32_t NID_FREE  = psp_nid("sceKernelFreePartitionMemory");
    const uint32_t NID_HEAD  = psp_nid("sceKernelGetBlockHeadAddr");

    uint32_t before = psp_sysmem_free();

    /* Low placement. */
    uint32_t uid = call5(NID_ALLOC, 2, 0, 0 /*Low*/, 0x1000, 0);
    CHECK(uid >= 0x00010000u, "low alloc returns a UID, got 0x%08X", uid);
    uint32_t lo = call(NID_HEAD, uid, 0, 0, 0);
    CHECK(lo != 0, "block has an address");

    /* High placement must land above the low one -- games depend on the
     * distinction, so it is not enough that both merely succeed. */
    uint32_t uid2 = call5(NID_ALLOC, 2, 0, 1 /*High*/, 0x1000, 0);
    uint32_t hi = call(NID_HEAD, uid2, 0, 0, 0);
    CHECK(hi > lo, "high allocation sits above the low one (lo=0x%08X hi=0x%08X)", lo, hi);

    /* Blocks must not overlap. */
    CHECK(lo + 0x1000 <= hi, "blocks do not overlap");

    /* Sizes round up to the hardware's 256-byte granule. */
    uint32_t uid3 = call5(NID_ALLOC, 2, 0, 0, 100, 0);
    CHECK(uid3 >= 0x00010000u, "a 100-byte request succeeds");
    CHECK(psp_sysmem_free() % 0x100 == 0, "allocations are granule-rounded");

    /* Freeing returns the memory. */
    uint32_t mid = psp_sysmem_free();
    CHECK(call(NID_FREE, uid, 0, 0, 0) == 0, "free succeeds");
    CHECK(psp_sysmem_free() > mid, "freeing returns memory");

    CHECK(call(NID_FREE, 0xDEADBEEF, 0, 0, 0) == SCE_KERNEL_ERROR_UNKNOWN_UID,
          "freeing an unknown UID is refused");
    CHECK(call(NID_HEAD, 0xDEADBEEF, 0, 0, 0) == 0,
          "an unknown UID has no address");

    /* An impossible request fails rather than returning a bogus block. */
    uint32_t huge = call5(NID_ALLOC, 2, 0, 0, 0x7F000000u, 0);
    CHECK(huge == SCE_KERNEL_ERROR_NO_MEMORY, "an oversized request fails, got 0x%08X", huge);

    call(NID_FREE, uid2, 0, 0, 0);
    call(NID_FREE, uid3, 0, 0, 0);
    CHECK(psp_sysmem_free() == before, "everything freed restores the heap");
}

static void test_semaphores(void) {
    psp_threadman_reset();

    const uint32_t CREATE = psp_nid("sceKernelCreateSema");
    const uint32_t WAIT   = psp_nid("sceKernelWaitSema");
    const uint32_t SIGNAL = psp_nid("sceKernelSignalSema");
    const uint32_t DELETE = psp_nid("sceKernelDeleteSema");

    uint32_t sem = call5(CREATE, 0, 0, 2 /*init*/, 4 /*max*/, 0);
    CHECK(sem != 0, "semaphore created");

    CHECK(call(WAIT, sem, 1, 0, 0) == 0, "wait succeeds while the count allows");
    CHECK(call(WAIT, sem, 1, 0, 0) == 0, "and again, down to zero");
    CHECK(call(WAIT, sem, 1, 0, 0) == SCE_KERNEL_ERROR_WAIT_TIMEOUT,
          "a wait that would block reports a timeout rather than hanging");

    CHECK(call(SIGNAL, sem, 1, 0, 0) == 0, "signal succeeds");
    CHECK(call(WAIT, sem, 1, 0, 0) == 0, "and the signalled count is available");

    /* A signal that would take the count past max is refused outright, and
     * the count is left as it was -- the firmware does not saturate. */
    CHECK(call(SIGNAL, sem, 100, 0, 0) == 0x800201AEu, "overflowing signal is refused (SEMA_OVF)");
    CHECK(call(WAIT, sem, 1, 0, 0) == SCE_KERNEL_ERROR_WAIT_TIMEOUT,
          "and the refused signal added nothing");
    CHECK(call(SIGNAL, sem, 4, 0, 0) == 0, "signalling up to max is fine");
    CHECK(call(WAIT, sem, 4, 0, 0) == 0, "and all of it is available");

    CHECK(call(DELETE, sem, 0, 0, 0) == 0, "delete succeeds");
    CHECK(call(WAIT, sem, 1, 0, 0) == 0x80020199u,
          "a deleted semaphore is gone (UNKNOWN_SEMID)");
}

static void test_event_flags(void) {
    psp_threadman_reset();

    const uint32_t CREATE = psp_nid("sceKernelCreateEventFlag");
    const uint32_t SET    = psp_nid("sceKernelSetEventFlag");
    const uint32_t CLEAR  = psp_nid("sceKernelClearEventFlag");
    const uint32_t WAIT   = psp_nid("sceKernelWaitEventFlag");

    uint32_t ef = call(CREATE, 0, 0, 0x0000, 0);
    CHECK(ef != 0, "event flag created");

    call(SET, ef, 0x0005, 0, 0);

    /* WAITOR is satisfied by any bit; WAITAND needs all of them. */
    CHECK(call5(WAIT, ef, 0x0004, 0x01 /*OR*/, 0, 0) == 0, "OR wait on a set bit");
    CHECK(call5(WAIT, ef, 0x0003, 0x00 /*AND*/, 0, 0) == SCE_KERNEL_ERROR_WAIT_TIMEOUT,
          "AND wait fails when only some bits are set");
    CHECK(call5(WAIT, ef, 0x0005, 0x00 /*AND*/, 0, 0) == 0,
          "AND wait succeeds when all bits are set");

    /* clear takes a mask of bits to KEEP. Getting that backwards leaves a game
     * waiting on a flag that never clears, so it is pinned explicitly. */
    call(CLEAR, ef, ~0x0004u, 0, 0);
    CHECK(call5(WAIT, ef, 0x0004, 0x01, 0, 0) == SCE_KERNEL_ERROR_WAIT_TIMEOUT,
          "the cleared bit is gone");
    CHECK(call5(WAIT, ef, 0x0001, 0x01, 0, 0) == 0,
          "the kept bit survives");
}

/* A recompiled thread entry: writes a marker so the test can prove it ran on
 * the stack the thread manager gave it. */
static uint32_t g_thread_sp;
static uint32_t g_thread_arg;
static int      g_thread_ran;

static void fake_thread_entry(void) {
    g_thread_ran++;
    g_thread_sp  = psp_cpu.r[PSP_REG_SP];
    g_thread_arg = psp_cpu.r[PSP_REG_A0];
    psp_cpu.r[PSP_REG_V0] = 0x1234;      /* exit status */
}

static void test_threads(void) {
    psp_sysmem_reset();
    psp_threadman_reset();
    psp_dispatch_reset();

    const uint32_t CREATE = psp_nid("sceKernelCreateThread");
    const uint32_t START  = psp_nid("sceKernelStartThread");
    const uint32_t WAITEND= psp_nid("sceKernelWaitThreadEnd");
    const uint32_t DELETE = psp_nid("sceKernelDeleteThread");
    const uint32_t GETID  = psp_nid("sceKernelGetThreadId");

    const uint32_t ENTRY = 0x08801000u;
    psp_register(ENTRY, fake_thread_entry);

    uint32_t thid = call5(CREATE, 0 /*name*/, ENTRY, 32 /*prio*/, 0x4000 /*stack*/, 0);
    CHECK(thid != 0, "thread created, got 0x%08X", thid);

    /* The caller's context must survive the thread running. */
    psp_cpu.r[PSP_REG_S0] = 0xC0FFEE;
    uint32_t caller_sp = psp_cpu.r[PSP_REG_SP];

    g_thread_ran = 0;
    uint32_t rc = call(START, thid, 7 /*arglen*/, 0xAAAA, 0);
    CHECK(rc == 0, "start succeeds");
    CHECK(g_thread_ran == 1, "the thread entry actually ran");
    CHECK(g_thread_arg == 7, "argument reached the thread, got %u", g_thread_arg);
    CHECK(g_thread_sp != caller_sp && g_thread_sp != 0,
          "the thread ran on its own stack (0x%08X vs caller 0x%08X)",
          g_thread_sp, caller_sp);
    CHECK((g_thread_sp & 15) == 0, "the thread stack pointer is 16-byte aligned");

    CHECK(psp_cpu.r[PSP_REG_S0] == 0xC0FFEE, "caller's registers restored");
    CHECK(psp_cpu.r[PSP_REG_SP] == caller_sp, "caller's stack pointer restored");

    /* sceKernelWaitThreadEnd(thid, SceUInt *timeout) returns the exit status;
     * its second argument is a timeout, which must not be written with it. */
    uint32_t tmo = 0x08802000u;
    psp_write32(tmo, 777);
    CHECK(call(WAITEND, thid, tmo, 0, 0) == 0x1234, "wait-for-end returns the exit status");
    CHECK(psp_read32(tmo) == 777, "and leaves the timeout argument alone, got %u", psp_read32(tmo));

    /* Deleting frees the stack. */
    uint32_t before_delete = psp_sysmem_free();
    CHECK(call(DELETE, thid, 0, 0, 0) == 0, "delete succeeds");
    CHECK(psp_sysmem_free() > before_delete, "deleting a thread frees its stack");

    CHECK(call(START, 0xDEADBEEF, 0, 0, 0) == SCE_KERNEL_ERROR_ILLEGAL_THID,
          "starting an unknown thread is refused");
    CHECK(call(GETID, 0, 0, 0, 0) == 0, "no current thread outside one");
}

static void test_guest_strings(void) {
    /* Names come out of guest memory, so the reader has to terminate and must
     * not run past the buffer. */
    const uint32_t at = 0x08803000u;
    const char *s = "sceThreadName";
    for (uint32_t i = 0; i <= strlen(s); i++) psp_write8(at + i, (uint8_t)s[i]);

    char buf[32];
    CHECK(strcmp(psp_str(at, buf, sizeof buf), s) == 0, "string round-trips");

    char small[6];
    psp_str(at, small, sizeof small);
    CHECK(strlen(small) == 5 && strncmp(small, s, 5) == 0,
          "an over-long string is truncated, not overflowed: \"%s\"", small);
}

/* Build a display list in guest memory and check the walk follows control flow
 * rather than merely counting words. The list deliberately contains a PRIM
 * that a JUMP skips over: if it gets counted, the walk is not following jumps. */
static void test_ge_display_list(void) {
    psp_ge_reset();

    const uint32_t LIST = 0x08820000u;
    uint32_t w[16], n = 0;

    /* GE addresses are 24-bit; BASE supplies the high byte. Setting it here
     * also exercises that path -- a list whose BASE is ignored jumps to the
     * wrong place and silently executes garbage. */
    w[n++] = (0x10u << 24) | 0x080000;              /* BASE  -> 0x08000000 */
    w[n++] = (0x12u << 24) | 0x000123;              /* VTYPE */
    w[n++] = (0x04u << 24) | (3u << 16) | 6;        /* PRIM triangles, 6 verts */
    w[n++] = (0x08u << 24) | 0x820020;              /* JUMP -> LIST + 0x20 */
    w[n++] = (0x04u << 24) | (0u << 16) | 99;       /* PRIM points -- SKIPPED */
    w[n++] = (0x00u << 24);
    w[n++] = (0x00u << 24);
    w[n++] = (0x00u << 24);
    /* word 8 == LIST + 0x20 */
    w[n++] = (0x04u << 24) | (6u << 16) | 2;        /* PRIM sprites, 2 verts */
    w[n++] = (0x0Fu << 24);                          /* FINISH */
    w[n++] = (0x0Cu << 24);                          /* END */

    for (uint32_t i = 0; i < n; i++) psp_write32(LIST + i * 4, w[i]);

    uint64_t before = psp_ge_command_count();
    /* sceGeListEnQueue(list, stall=0, cbid, arg) */
    uint32_t qid = call(psp_nid("sceGeListEnQueue"), LIST, 0, 0, 0);
    CHECK(qid != 0, "list enqueued, got 0x%08X", qid);

    uint64_t executed = psp_ge_command_count() - before;
    /* FINISH raises the finish interrupt; the END after it is what stops the
     * list, and it is executed like any other command. */
    CHECK(executed == 7, "walked BASE,VTYPE,PRIM,JUMP,PRIM,FINISH,END = 7, got %llu",
          (unsigned long long)executed);
    CHECK(psp_ge_vertex_count() == 8,
          "counted 6+2 vertices and skipped the jumped-over PRIM, got %llu",
          (unsigned long long)psp_ge_vertex_count());

    CHECK(call(psp_nid("sceGeDrawSync"), 0, 0, 0, 0) == 0, "draw sync succeeds");
    CHECK(call(psp_nid("sceGeEdramGetAddr"), 0, 0, 0, 0) == PSP_VRAM_BASE,
          "eDRAM is the VRAM window");
    CHECK(call(psp_nid("sceGeEdramGetSize"), 0, 0, 0, 0) == PSP_VRAM_SIZE,
          "eDRAM is 2 MB");
}

/* A list that jumps to itself must terminate rather than hang the host -- this
 * is a normal transient state while the CPU is still writing the list. */
static void test_ge_infinite_list(void) {
    psp_ge_reset();
    const uint32_t LIST = 0x08830000u;
    psp_write32(LIST + 0, (0x10u << 24) | 0x080000);   /* BASE */
    psp_write32(LIST + 4, (0x08u << 24) | 0x830000);   /* JUMP to itself */

    uint32_t qid = call(psp_nid("sceGeListEnQueue"), LIST, 0, 0, 0);
    CHECK(qid != 0, "a self-jumping list still returns");
}

static void test_sas_adpcm(void) {
    psp_sas_reset();

    /* One VAG block: shift 8, filter 0, then 28 nibbles. With filter 0 there is
     * no prediction, so each output sample is just the sign-extended nibble
     * scaled -- which makes a decode bug obvious rather than merely quieter. */
    const uint32_t VAG = 0x08840000u;
    psp_write8(VAG + 0, 0x08);        /* shift 8, filter 0 */
    psp_write8(VAG + 1, 0x00);        /* flags: not the end */
    for (uint32_t i = 0; i < 14; i++)
        psp_write8(VAG + 2 + i, 0x7Fu);   /* nibbles 0xF and 0x7 */

    CHECK(call5(psp_nid("__sceSasInit"), 0, 64 /*grain*/, 32, 0, 44100) == 0,
          "SAS init");

    /* sceSasSetVoice(core, voice, addr, size, loop) */
    CHECK(call5(psp_nid("__sceSasSetVoice"), 0, 0, VAG, 16, 0) == 0, "voice set");
    CHECK(call(psp_nid("__sceSasSetVolume"), 0, 0, 0x1000, 0x1000) == 0, "volume set");
    CHECK(call(psp_nid("__sceSasSetPitch"), 0, 0, 0x1000, 0) == 0, "pitch set");

    /* Before key-on nothing should be playing. */
    const uint32_t OUT = 0x08850000u;
    for (uint32_t i = 0; i < 64 * 4; i += 4) psp_write32(OUT + i, 0);
    call(psp_nid("__sceSasCore"), 0, OUT, 0, 0);
    CHECK(psp_sas_nonzero() == 0, "silence before key-on");

    CHECK(call(psp_nid("__sceSasSetKeyOn"), 0, 0, 0, 0) == 0, "key on");
    call(psp_nid("__sceSasCore"), 0, OUT, 0, 0);

    CHECK(psp_sas_frames() == 2, "two frames rendered, got %llu",
          (unsigned long long)psp_sas_frames());
    CHECK(psp_sas_nonzero() > 0, "audio was actually produced after key-on");

    /* The end flag is how a game knows a sound finished; a voice that never
     * reports ended is a common way for audio to stall after the first sound. */
    uint32_t ended = call(psp_nid("__sceSasGetEndFlag"), 0, 0, 0, 0);
    CHECK((ended & ~1u) != 0, "unused voices report ended, got 0x%08X", ended);
}

/* VAG loop markers drive looping (flag 6 loop start, flag 3 loop end, flag 7
 * end), and SetVoice's loop mode only enables the flag-3 jump. A voice set
 * up as looping used to restart a one-shot sample at its end flag forever --
 * PSP2i's menu "select" ping looped endlessly. */
static int sas_voice0_ended_after(uint32_t vag, uint32_t size, int loop, int frames) {
    psp_sas_reset();
    call5(psp_nid("__sceSasInit"), 0, 64, 32, 0, 44100);
    call5(psp_nid("__sceSasSetVoice"), 0, 0, vag, size, (uint32_t)loop);
    call(psp_nid("__sceSasSetVolume"), 0, 0, 0x1000, 0x1000);
    call(psp_nid("__sceSasSetPitch"), 0, 0, 0x1000, 0);
    call(psp_nid("__sceSasSetKeyOn"), 0, 0, 0, 0);
    const uint32_t OUT = 0x08850000u;
    for (int f = 0; f < frames; f++) call(psp_nid("__sceSasCore"), 0, OUT, 0, 0);
    return (int)(call(psp_nid("__sceSasGetEndFlag"), 0, 0, 0, 0) & 1u);
}

static void test_sas_loop_markers(void) {
    const uint32_t VAG = 0x08840000u;
    /* block 0: audio, flags 0; block 1: flags 7 (end) */
    for (uint32_t b = 0; b < 2; b++) {
        psp_write8(VAG + b * 16, 0x08);
        psp_write8(VAG + b * 16 + 1, b == 1 ? 7 : 0);
        for (uint32_t i = 0; i < 14; i++) psp_write8(VAG + b * 16 + 2 + i, 0x7Fu);
    }
    CHECK(sas_voice0_ended_after(VAG, 32, 1, 8), "a one-shot sample ends even on a looping voice");

    /* block 0: flags 6 (loop start); block 1: flags 3 (loop end) */
    const uint32_t VAG2 = 0x08841000u;
    for (uint32_t b = 0; b < 2; b++) {
        psp_write8(VAG2 + b * 16, 0x08);
        psp_write8(VAG2 + b * 16 + 1, b == 0 ? 6 : 3);
        for (uint32_t i = 0; i < 14; i++) psp_write8(VAG2 + b * 16 + 2 + i, 0x7Fu);
    }
    CHECK(!sas_voice0_ended_after(VAG2, 32, 1, 64), "a sample with loop markers keeps playing when looping");
    CHECK(sas_voice0_ended_after(VAG2, 32, 0, 8), "the same sample ends when the voice does not loop");
}

static void test_display(void) {
    psp_display_reset();

    CHECK(call(psp_nid("sceDisplaySetMode"), 0, 480, 272, 0) == 0, "set mode");
    /* (topaddr, bufferwidth, pixelformat, sync) */
    CHECK(call(psp_nid("sceDisplaySetFrameBuf"), PSP_VRAM_BASE, 512, 3, 0) == 0,
          "set framebuffer");
    CHECK(psp_display_framebuffer() == PSP_VRAM_BASE, "framebuffer recorded");

    uint64_t v0 = psp_display_vblanks();
    call(psp_nid("sceDisplayWaitVblank"), 0, 0, 0, 0);
    call(psp_nid("sceDisplayWaitVblankStartCB"), 0, 0, 0, 0);
    CHECK(psp_display_vblanks() == v0 + 2,
          "vblank waits advance the frame counter (the bring-up heartbeat)");
}

/* sceUtilitySavedata save -> load round trip through the HLE, as PSP2i does it
 * after character creation: AUTOSAVE (mode 1) with saveName "<>". "<>" means
 * no particular save, so the directory is the game name alone; using it
 * literally produced "NPJH50332<>", an invalid Windows path, and mode 1
 * failed with SAVE_ACCESS_ERROR (0x80110385). */
static int host_file_size(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    int n = (int)ftell(f);
    fclose(f);
    return n;
}

static void savedata_param(uint32_t p, uint32_t mode, uint32_t data, uint32_t size) {
    for (uint32_t i = 0; i < 0x600; i += 4) psp_write32(p + i, 0);
    psp_write32(p + 0x00, 0x600);                       /* base.size */
    psp_write32(p + 0x30, mode);
    const char *game = "NPJH50332", *save = "<>", *file = "SAVEDATA.BIN", *title = "Test Title";
    for (uint32_t i = 0; game[i]; i++)  psp_write8(p + 0x3C + i, (uint8_t)game[i]);
    for (uint32_t i = 0; save[i]; i++)  psp_write8(p + 0x4C + i, (uint8_t)save[i]);
    for (uint32_t i = 0; file[i]; i++)  psp_write8(p + 0x64 + i, (uint8_t)file[i]);
    for (uint32_t i = 0; title[i]; i++) psp_write8(p + 0x80 + i, (uint8_t)title[i]);
    psp_write32(p + 0x74, data);
    psp_write32(p + 0x78, size);                        /* buffer size */
    psp_write32(p + 0x7C, size);                        /* data size */
}

static uint32_t savedata_run(uint32_t p) {
    const uint32_t INIT = psp_nid("sceUtilitySavedataInitStart");
    const uint32_t STATUS = psp_nid("sceUtilitySavedataGetStatus");
    const uint32_t SHUT = psp_nid("sceUtilitySavedataShutdownStart");
    CHECK(call(INIT, p, 0, 0, 0) == 0, "savedata InitStart accepted");
    int guard = 0;
    while (call(STATUS, 0, 0, 0, 0) != 3 && guard++ < 16) {}
    uint32_t result = psp_read32(p + 0x1C);
    CHECK(call(SHUT, 0, 0, 0, 0) == 0, "savedata ShutdownStart accepted");
    guard = 0;
    while (call(STATUS, 0, 0, 0, 0) != 0 && guard++ < 16) {}
    return result;
}

static void test_savedata_roundtrip(void) {
    char root[256], path[512];
    snprintf(root, sizeof root, "psprecomp_test_savedata_%u", (unsigned)psp_cpu.r[PSP_REG_SP]);
    psp_io_set_root(root);
    const uint32_t P = 0x08840000u, DATA = 0x08842000u, BACK = 0x08844000u, N = 1000;
    for (uint32_t i = 0; i < N; i++) psp_write8(DATA + i, (uint8_t)(i * 7 + 3));

    savedata_param(P, 1, DATA, N);
    CHECK(savedata_run(P) == 0, "AUTOSAVE with saveName \"<>\" succeeds");
    snprintf(path, sizeof path, "%s/ms/PSP/SAVEDATA/NPJH50332/SAVEDATA.BIN", root);
    CHECK(host_file_size(path) == (int)N, "data file written to NPJH50332/ (size %d)", host_file_size(path));
    snprintf(path, sizeof path, "%s/ms/PSP/SAVEDATA/NPJH50332/PARAM.SFO", root);
    CHECK(host_file_size(path) > 20, "PARAM.SFO written");

    savedata_param(P, 0, BACK, N);
    for (uint32_t i = 0; i < N; i++) psp_write8(BACK + i, 0);
    CHECK(savedata_run(P) == 0, "AUTOLOAD finds the save");
    int same = 1;
    for (uint32_t i = 0; i < N; i++) same &= psp_read8(BACK + i) == (uint8_t)(i * 7 + 3);
    CHECK(same && psp_read32(P + 0x7C) == N, "loaded bytes match what was saved");

    savedata_param(P, 22, 0, 0);
    CHECK(savedata_run(P) == 0, "GETSIZE now reports an existing save (0, not RW_NO_DATA)");

    /* Tidy up the host files. */
    snprintf(path, sizeof path, "%s/ms/PSP/SAVEDATA/NPJH50332/SAVEDATA.BIN", root); remove(path);
    snprintf(path, sizeof path, "%s/ms/PSP/SAVEDATA/NPJH50332/PARAM.SFO", root); remove(path);
}

/* sceHttpSendRequest runs the transport on a host worker thread and parks
 * only the calling PSP thread (zmbkilla's fix in Komak57/ppsspp sceHttp.cpp):
 * the response still arrives intact, from a thread other than the caller's. */
static unsigned long g_http_main_thread, g_http_send_thread;
static char g_http_seen[256];
static int fake_send(const psp_http_request *q, psp_http_response *r) {
    g_http_send_thread = test_thread_id();
    snprintf(g_http_seen, sizeof g_http_seen, "%s %s://%s:%u%s %u", q->method, q->scheme, q->host, q->port, q->path, q->body_len);
    test_sleep_ms(50);                                  /* a slow server */
    r->status = 200;
    r->body = (uint8_t *)malloc(5);
    memcpy(r->body, "hello", 5);
    r->len = 5;
    return 0;
}
static void fake_log(const char *line) { (void)line; }

static void test_http_async(void) {
    static const psp_http_transport T = { fake_send, fake_log };
    psp_http_set_transport(&T);
    g_http_main_thread = test_thread_id();
    const uint32_t S = 0x08A00000u;
    psp_mem_write_block(S, "PSP2", 5);
    psp_mem_write_block(S + 0x10, "example.org", 12);
    psp_mem_write_block(S + 0x20, "https", 6);
    psp_mem_write_block(S + 0x30, "/cgi/front.fcgi", 16);
    psp_mem_write_block(S + 0x80, "abc", 3);
    CHECK(call(psp_nid("sceHttpInit"), 0x10000, 0, 0, 0) == 0, "sceHttpInit");
    const uint32_t tmpl = call(psp_nid("sceHttpCreateTemplate"), S, 1, 0, 0);
    const uint32_t conn = call5(psp_nid("sceHttpCreateConnection"), tmpl, S + 0x10, S + 0x20, 12020, 0);
    psp_cpu.r[PSP_REG_T1] = 0;
    const uint32_t req = call5(psp_nid("sceHttpCreateRequest"), conn, 1, S + 0x30, 0, 3);
    CHECK((int)tmpl > 0 && (int)conn > 0 && (int)req > 0, "http objects (%d %d %d)", (int)tmpl, (int)conn, (int)req);
    CHECK(call(psp_nid("sceHttpSendRequest"), req, S + 0x80, 3, 0) == 0, "sceHttpSendRequest");
    CHECK(strcmp(g_http_seen, "POST https://example.org:12020/cgi/front.fcgi 3") == 0, "the transport got the request (%s)", g_http_seen);
    CHECK(g_http_send_thread && g_http_send_thread != g_http_main_thread, "the transport ran on another host thread");
    CHECK(call(psp_nid("sceHttpGetStatusCode"), req, S + 0x40, 0, 0) == 0 && psp_read32(S + 0x40) == 200, "status 200");
    CHECK(call(psp_nid("sceHttpReadData"), req, S + 0x50, 16, 0) == 5 && !memcmp(psp_mem_ptr(S + 0x50, 5), "hello", 5), "body");
    CHECK(call(psp_nid("sceHttpSendRequest"), req, S + 0x80, 3, 0) == 0, "a second send on the same request");
    CHECK(call(psp_nid("sceHttpDeleteRequest"), req, 0, 0, 0) == 0, "delete");
    CHECK(call(psp_nid("sceHttpEnd"), 0, 0, 0, 0) == 0, "sceHttpEnd");
    psp_http_set_transport(NULL);
}

/* ---- sceMpeg: a synthetic PSMF movie --------------------------------------- */

#define MP_PACKS 6
static uint8_t g_mp_stream[MP_PACKS][2048];
static int g_mp_next;

/* The game's ring-buffer read callback: copy whole packets, return how many. */
static void mp_read_cb(void) {
    const uint32_t dest = psp_cpu.r[PSP_REG_A0], n = psp_cpu.r[PSP_REG_A1];
    uint32_t got = 0;
    while (got < n && g_mp_next < MP_PACKS) { psp_mem_write_block(dest + got * 2048, g_mp_stream[g_mp_next++], 2048); got++; }
    psp_cpu.r[PSP_REG_V0] = got;
}

/* One pack: pack header, one PES packet, padding to 2048 bytes. */
static void mp_pack(uint8_t *p, int id, int64_t pts, const uint8_t *pay, int n) {
    static const uint8_t PACK[14] = { 0, 0, 1, 0xBA, 0x44, 0, 4, 0, 4, 1, 1, 0x89, 0xC3, 0xF8 };
    memset(p, 0, 2048);
    memcpy(p, PACK, 14);
    uint8_t *q = p + 14;
    const int hl = pts >= 0 ? 5 : 0, len = 3 + hl + n;
    q[0] = 0; q[1] = 0; q[2] = 1; q[3] = (uint8_t)id; q[4] = (uint8_t)(len >> 8); q[5] = (uint8_t)len;
    q[6] = 0x81; q[7] = pts >= 0 ? 0x80 : 0; q[8] = (uint8_t)hl;
    if (pts >= 0) {
        q[9] = (uint8_t)(0x21 | ((pts >> 29) & 0x0E)); q[10] = (uint8_t)(pts >> 22);
        q[11] = (uint8_t)(((pts >> 14) & 0xFE) | 1); q[12] = (uint8_t)(pts >> 7); q[13] = (uint8_t)((pts << 1) | 1);
    }
    memcpy(q + 9 + hl, pay, (size_t)n);
    uint8_t *pad = q + 6 + len;
    const int left = (int)(p + 2048 - pad) - 6;
    pad[0] = 0; pad[1] = 0; pad[2] = 1; pad[3] = 0xBE; pad[4] = (uint8_t)(left >> 8); pad[5] = (uint8_t)left;
    memset(pad + 6, 0xFF, (size_t)left);
}

/* A codec that decodes every unit to a white picture, 480x272. */
static uint8_t g_mp_y[480], g_mp_uv[240];
static int g_mp_units;
static void *mp_open(void) { return &g_mp_units; }
static int mp_decode(void *d, const uint8_t *au, int size, int64_t pts, psp_video_frame *out) {
    (void)d;
    if (!au) return 0;
    CHECK(size >= 6 && au[3] == 1 && au[4] == 9, "a unit starts with its delimiter");
    g_mp_units++;
    memset(g_mp_y, 235, sizeof g_mp_y);
    memset(g_mp_uv, 128, sizeof g_mp_uv);
    out->width = 480; out->height = 272;
    out->y = g_mp_y; out->u = out->v = g_mp_uv;
    out->ystride = 0; out->uvstride = 0;      /* every line the same */
    out->pts = pts;
    return 1;
}
static void mp_close(void *d) { (void)d; }

static void test_mpeg_movie(void) {
    static const psp_video_codec CODEC = { "test", mp_open, mp_decode, mp_close };
    /* the stream: four pictures, one ATRAC3plus frame, a padding pack */
    for (int k = 0; k < 4; k++) {
        const uint8_t au[12] = { 0, 0, 0, 1, 9, 0xF0, 0, 0, 0, 1, 0x65, (uint8_t)k };
        mp_pack(g_mp_stream[k], 0xE0, 90000 + k * 3003, au, sizeof au);
    }
    {
        uint8_t a[4 + 8 + 744] = { 0, 0, 0, 0, 0x0F, 0xD0, 0x28, 0x5C };   /* sub-stream 0 */
        mp_pack(g_mp_stream[4], 0xBD, 90000, a, sizeof a);
        mp_pack(g_mp_stream[5], 0xBE, -1, a, 4);
    }
    g_mp_next = 0;

    const uint32_t B = 0x08B00000u, HDR = B, RING = B + 0x1000, MPEGP = B + 0x1100, AU = B + 0x1200,
                   ATTR = B + 0x1240, BUFP = B + 0x1250, INITP = B + 0x1260, DETAIL = B + 0x1280,
                   RANGE = B + 0x1300, OUT = B + 0x1400, MDATA = B + 0x10000, DATA = B + 0x20000,
                   PIX = B + 0x80000, CB = 0x08900100u;
    psp_register(CB, mp_read_cb);
    uint8_t h[0x90] = { 'P', 'S', 'M', 'F', '0', '0', '1', '5', 0, 0, 0x08, 0 };
    h[14] = (MP_PACKS * 2048) >> 8;
    h[0x54 + 3] = 0x01; h[0x54 + 4] = 0x5F; h[0x54 + 5] = 0x90;          /* first timestamp 90000 */
    h[142] = 30; h[143] = 17;
    psp_mem_write_block(HDR, h, sizeof h);

    psp_mpeg_set_video_codec(&CODEC);
    CHECK(call(psp_nid("sceMpegInit"), 0, 0, 0, 0) == 0, "sceMpegInit");
    const uint32_t rsize = call(psp_nid("sceMpegRingbufferQueryMemSize"), 16, 0, 0, 0);
    CHECK(rsize == 16 * (104 + 2048), "ring size %u", rsize);
    psp_cpu.r[PSP_REG_T1] = 0;
    CHECK(call5(psp_nid("sceMpegRingbufferConstruct"), RING, 16, DATA, rsize, CB) == 0, "ring construct");
    const uint32_t msize = call(psp_nid("sceMpegQueryMemSize"), 0, 0, 0, 0);
    psp_cpu.r[PSP_REG_T1] = 0; psp_cpu.r[PSP_REG_T2] = 0;
    CHECK(call5(psp_nid("sceMpegCreate"), MPEGP, MDATA, msize, RING, 512) == 0, "create");
    CHECK(!memcmp(psp_mem_ptr(psp_read32(MPEGP), 8), "LIBMPEG", 8), "the handle");
    CHECK(call(psp_nid("sceMpegQueryStreamOffset"), MPEGP, HDR, OUT, 0) == 0 && psp_read32(OUT) == 0x800, "stream offset");
    CHECK(call(psp_nid("sceMpegQueryStreamSize"), HDR, OUT, 0, 0) == 0 && psp_read32(OUT) == MP_PACKS * 2048, "stream size");
    const uint32_t vs = call(psp_nid("sceMpegRegistStream"), MPEGP, 0, 0, 0);
    const uint32_t as = call(psp_nid("sceMpegRegistStream"), MPEGP, 1, 0, 0);
    CHECK(call(psp_nid("sceMpegRingbufferAvailableSize"), RING, 0, 0, 0) == 16, "an empty ring");
    CHECK(call(psp_nid("sceMpegRingbufferPut"), RING, 16, 16, 0) == MP_PACKS, "put reads the whole stream");
    CHECK((int)call(psp_nid("sceMpegRingbufferAvailableSize"), RING, 0, 0, 0) < 16, "the ring reports data");

    psp_write32(RANGE, 0); psp_write32(RANGE + 4, 0); psp_write32(RANGE + 8, 480); psp_write32(RANGE + 12, 272);
    for (int k = 0; k < 4; k++) {
        CHECK(call(psp_nid("sceMpegGetAvcAu"), MPEGP, vs, AU, ATTR) == 0, "picture %d: au", k);
        CHECK(call(psp_nid("sceMpegAvcDecodeYCbCr"), MPEGP, AU, BUFP, INITP) == 0, "picture %d: decode", k);
        CHECK(call(psp_nid("sceMpegAvcDecodeDetail"), MPEGP, DETAIL, 0, 0) == 0 && psp_read32(DETAIL + 32) == 1 &&
              psp_read32(DETAIL + 4) == (uint32_t)k + 1 && psp_read32(DETAIL + 8) == 480, "picture %d: detail", k);
        CHECK(psp_read32(AU + 4) == (uint32_t)(90000 + k * 3003), "picture %d: pts %u", k, psp_read32(AU + 4));
        psp_write32(PIX, 0xDEADBEEF);
        CHECK(call5(psp_nid("sceMpegAvcCsc"), MPEGP, BUFP, RANGE, 512, PIX) == 0, "picture %d: csc", k);
        CHECK(psp_read32(PIX) == 0x00FFFFFFu && psp_read32(PIX + 479 * 4) == 0x00FFFFFFu &&
              psp_read32(PIX + 271 * 512 * 4) == 0x00FFFFFFu, "picture %d: white, alpha 0 (%08x)", k, psp_read32(PIX));
    }
    CHECK(g_mp_units == 4, "four units decoded (%d)", g_mp_units);
    CHECK(call(psp_nid("sceMpegGetAtracAu"), MPEGP, as, AU, ATTR) == 0, "audio au");
    CHECK(call(psp_nid("sceMpegAtracDecode"), MPEGP, AU, OUT, 1) == 0, "audio decode");
    CHECK(call(psp_nid("sceMpegGetAtracAu"), MPEGP, as, AU, ATTR) == 0x80618001u && psp_read32(AU + 12) == 0xFFFFFFFFu, "audio end");
    /* the end: one more decode finds nothing, then the end is reported */
    CHECK(call(psp_nid("sceMpegGetAvcAu"), MPEGP, vs, AU, ATTR) == 0, "au before the end");
    call(psp_nid("sceMpegAvcDecodeYCbCr"), MPEGP, AU, BUFP, INITP);
    CHECK(call(psp_nid("sceMpegAvcDecodeDetail"), MPEGP, DETAIL, 0, 0) == 0 && psp_read32(DETAIL + 32) == 0, "no picture");
    CHECK(call(psp_nid("sceMpegGetAvcAu"), MPEGP, vs, AU, ATTR) == 0x80618001u && psp_read32(AU + 12) == 0xFFFFFFFFu, "video end, dts -1");
    CHECK(call(psp_nid("sceMpegDelete"), MPEGP, 0, 0, 0) == 0, "delete");
    CHECK(call(psp_nid("sceMpegFinish"), 0, 0, 0, 0) == 0, "finish");
    psp_mpeg_set_video_codec(NULL);
}

/* ---- the scheduler: threads on host fibers ----------------------------------- */

static int g_sched_log[8], g_sched_n;
static uint32_t g_sched_sema;

static void sched_log(int v) { if (g_sched_n < 8) g_sched_log[g_sched_n++] = v; }

/* Lower priority than root: runs only while root waits. */
static void sched_child(void) {
    sched_log(2);
    call(psp_nid("sceKernelSignalSema"), g_sched_sema, 1, 0, 0);   /* wakes root, which preempts */
    sched_log(4);
    psp_cpu.r[PSP_REG_V0] = 0;
}

static void sched_root(void) {
    const uint32_t CHILD = 0x08801100u;
    psp_register(CHILD, sched_child);
    sched_log(1);
    g_sched_sema = call5(psp_nid("sceKernelCreateSema"), 0, 0, 0, 1, 0);
    psp_cpu.r[PSP_REG_T1] = 0;
    const uint32_t th = call5(psp_nid("sceKernelCreateThread"), 0, CHILD, 0x30, 0x4000, 0);
    call(psp_nid("sceKernelStartThread"), th, 0, 0, 0);
    call(psp_nid("sceKernelWaitSema"), g_sched_sema, 1, 0, 0);         /* blocks: the child runs */
    sched_log(3);
    call(psp_nid("sceKernelDelayThread"), 2000, 0, 0, 0);               /* the child finishes */
    sched_log(5);
    psp_cpu.r[PSP_REG_V0] = 0;
}

static void test_scheduler(void) {
    psp_sysmem_reset();
    psp_threadman_reset();
    psp_dispatch_reset();
    const uint32_t ROOT = 0x08801000u;
    psp_register(ROOT, sched_root);
    g_sched_n = 0;
    psp_sched_run(ROOT, 0, 0, 0x20, 0x4000, 0);
    CHECK(g_sched_n == 5, "both threads ran to the end (%d steps)", g_sched_n);
    for (int i = 0; i < g_sched_n && i < 5; i++)
        CHECK(g_sched_log[i] == i + 1, "step %d was %d: priorities and waits decide who runs", i + 1, g_sched_log[i]);
}

/* ---- file names ignore case, as on the PSP ------------------------------------ */

#ifdef _WIN32
int _mkdir(const char *path);
#  define test_mkdir(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  define test_mkdir(p) mkdir(p, 0777)
#endif

static void test_io_case(void) {
    char root[256], ms[300];
    snprintf(root, sizeof root, "psprecomp_test_case_%u", (unsigned)psp_cpu.r[PSP_REG_SP]);
    snprintf(ms, sizeof ms, "%s/ms", root);
    test_mkdir(root);
    test_mkdir(ms);
    psp_io_set_root(root);
    const uint32_t S = 0x08A10000u, BUF = 0x08A11000u;
    psp_mem_write_block(S + 0x000, "ms0:/Dir_A", 11);
    psp_mem_write_block(S + 0x040, "ms0:/Dir_A/Sub_B", 17);
    psp_mem_write_block(S + 0x080, "ms0:/Dir_A/Sub_B/File_C.bin", 28);
    psp_mem_write_block(S + 0x0C0, "ms0:/dir_a/SUB_b/file_c.BIN", 28);
    psp_mem_write_block(BUF, "abc", 3);
    CHECK(call(psp_nid("sceIoMkdir"), S, 0777, 0, 0) == 0, "mkdir Dir_A");
    CHECK(call(psp_nid("sceIoMkdir"), S + 0x40, 0777, 0, 0) == 0, "mkdir Sub_B");
    int fd = (int)call(psp_nid("sceIoOpen"), S + 0x80, 0x0602, 0777, 0);
    CHECK(fd >= 0, "create File_C.bin (%08x)", (unsigned)fd);
    CHECK(call(psp_nid("sceIoWrite"), (uint32_t)fd, BUF, 3, 0) == 3, "write");
    call(psp_nid("sceIoClose"), (uint32_t)fd, 0, 0, 0);
    fd = (int)call(psp_nid("sceIoOpen"), S + 0xC0, 1, 0, 0);
    CHECK(fd >= 0, "the same file in another case opens (%08x)", (unsigned)fd);
    psp_write32(BUF + 0x10, 0);
    CHECK(call(psp_nid("sceIoRead"), (uint32_t)fd, BUF + 0x10, 3, 0) == 3 &&
          !memcmp(psp_mem_ptr(BUF + 0x10, 3), "abc", 3), "and reads back");
    call(psp_nid("sceIoClose"), (uint32_t)fd, 0, 0, 0);
}

int main(void) {
    CHECK(psp_mem_init() == 0, "memory init");
    psp_cpu_reset();
    psp_cpu.r[PSP_REG_SP] = 0x08810000u;   /* a stack for the "caller" */
    psp_hle_init();

    printf("registered %d firmware functions\n", psp_hle_count());

    test_sha1_vectors();
    test_nids_match_names();
    test_sysmem();
    test_semaphores();
    test_event_flags();
    test_threads();
    test_guest_strings();
    test_ge_display_list();
    test_ge_infinite_list();
    test_sas_adpcm();
    test_sas_loop_markers();
    test_display();
    test_savedata_roundtrip();
    test_http_async();
    test_mpeg_movie();
    test_io_case();
    test_scheduler();                /* last: it leaves the scheduler state behind */

    psp_mem_free();

    if (failures) {
        printf("\n%d check(s) failed\n", failures);
        return 1;
    }
    printf("all HLE checks passed\n");
    return 0;
}
