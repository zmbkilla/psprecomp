/* psprecomp — high-level emulation of the PSP firmware.
 *
 * A PSP game does not touch hardware. It calls firmware entry points through
 * an import table, and every one of those calls is identified by a **NID** —
 * the first four bytes of SHA-1(function name), little-endian. That is a
 * verifiable fact rather than a convention, and `tests/test_hle.c` checks it
 * for every function registered here: a mistyped NID or a wrong name cannot
 * survive the test.
 *
 * Because the surface is a library rather than hardware, it is *implemented*,
 * not emulated. What a game needs is exactly its import table and nothing
 * else, which `allegrexrecomp funcs` reports — so the work is bounded and
 * knowable in advance.
 *
 * Calling convention is MIPS o32: arguments in $a0-$a3 then the stack, return
 * value in $v0. Handlers take no C arguments and use psp_arg()/psp_ret().
 */
#ifndef PSPRECOMP_HLE_H
#define PSPRECOMP_HLE_H

#include "cpu.h"
#include "mem.h"

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*psp_hle_fn)(void);

/* Register one firmware function. `name` is kept for diagnostics and is what
 * the NID is verified against. */
void psp_hle_register(uint32_t nid, const char *lib, const char *name, psp_hle_fn fn);
void psp_hle_register_unnamed(uint32_t nid, const char *lib, psp_hle_fn fn);
int psp_hle_is_named(int index);

/* Call a firmware function by NID. An unregistered NID reports itself by name
 * where possible and by number otherwise, rather than failing silently. */
void psp_hle_call(uint32_t nid);

/* Look up what is registered, for reporting. Returns NULL if absent. */
const char *psp_hle_name(uint32_t nid);
int         psp_hle_count(void);

/* Every registered entry, for the coverage report a game repo wants: which of
 * a module's imports actually exist yet. */
typedef struct {
    uint32_t    nid;
    const char *lib;
    const char *name;
} psp_hle_entry;

const psp_hle_entry *psp_hle_entries(int *count);

/* Print the recent firmware calls that returned zero. Zero is what a game most
 * often mistakes for an address, so this is the first thing to consult when a
 * wild pointer shows up far from its cause. */
void psp_hle_dump_recent(FILE *out);

/* Every unimplemented NID the game called, with call counts. */
void psp_hle_dump_unimplemented(FILE *out);
/* The most frequently called firmware functions, with counts. */
void psp_hle_dump_calls(FILE *out, int top);

/* Register everything the toolkit implements. Call once at startup. */
void psp_hle_init(void);

/* ---- o32 argument access ------------------------------------------------- */

/* Arguments 0-3 arrive in $a0-$a3; 4 and beyond are on the stack, at $sp+16
 * onward. The stack slots for the register arguments exist but are not
 * written by the caller, which is why the split is at 4 and not at 0. */
/* Firmware calls take arguments 5-8 in $t0-$t3, not on the stack.
 *
 * Plain o32 spills the fifth argument onward to `sp+16`, and that is what this
 * used to read. PSP firmware stubs do not: they load $t0-$t3 and branch, which
 * is visible in the delay slot of every such call --
 *
 *     000002EC  addu  $a3, $s1, $zero
 *     000002F0  jal   0x00091F14        ; sceKernelAllocPartitionMemory
 *     000002F4  addiu $t0, $zero, 4096  ; argument 5: the alignment
 *
 * Reading `sp+16` instead returned whatever happened to be on the stack. For
 * that call it produced 0x3AC85C where a power-of-two alignment belonged, so
 * the allocator rejected a 15.9 MB request with ILLEGAL_ATTR -- and every
 * failure this bring-up chased descended from it.
 *
 * Beyond eight, arguments do go on the stack. */
static inline uint32_t psp_arg(int n) {
    if (n < 4) return psp_cpu.r[PSP_REG_A0 + n];
    if (n < 8) return psp_cpu.r[PSP_REG_T0 + (n - 4)];
    return psp_read32(psp_cpu.r[PSP_REG_SP] + (uint32_t)n * 4);
}

static inline void psp_ret(uint32_t v) { psp_cpu.r[PSP_REG_V0] = v; }

/* Read a NUL-terminated string out of guest memory into a host buffer.
 * Always terminates; returns `dst`. */
const char *psp_str(uint32_t addr, char *dst, size_t cap);

/* ---- error codes --------------------------------------------------------- */
/* Only the ones the implemented functions can actually return. Games branch on
 * these, so returning a plausible-looking wrong value is worse than failing. */
#define SCE_KERNEL_ERROR_OK              0
#define SCE_KERNEL_ERROR_ERROR           0x80020001
#define SCE_KERNEL_ERROR_NOTIMPLEMENTED  0x80020002
#define SCE_KERNEL_ERROR_ILLEGAL_ADDR    0x80020005
#define SCE_KERNEL_ERROR_NO_MEMORY       0x80020190
#define SCE_KERNEL_ERROR_ILLEGAL_ATTR    0x80020191
#define SCE_KERNEL_ERROR_UNKNOWN_UID     0x800201A2
#define SCE_KERNEL_ERROR_ILLEGAL_MEMBLOCK 0x800201A9
#define SCE_KERNEL_ERROR_ILLEGAL_THID    0x80020197
#define SCE_KERNEL_ERROR_WAIT_TIMEOUT    0x800201A8

/* ---- the subsystems ------------------------------------------------------ */

void psp_sysmem_init(void);
void psp_sysmem_register(void);
void psp_sysmem_reset(void);

void psp_display_init(void);
void psp_display_register(void);
void psp_display_reset(void);
int      psp_display_capture(const char *path);
uint64_t psp_display_vblanks(void);
uint32_t psp_display_framebuffer(void);
void     psp_display_get(uint32_t *addr, uint32_t *stride, uint32_t *fmt);

void psp_ge_init(void);
void psp_ge_register(void);
void psp_ge_reset(void);
void psp_ge_dump_stats(FILE *out);
uint64_t psp_ge_command_count(void);
uint64_t psp_ge_vertex_count(void);
uint64_t psp_ge_pixels(void);

void psp_sas_init(void);
void psp_sas_register(void);
void psp_sas_reset(void);
uint64_t psp_sas_frames(void);
uint64_t psp_sas_nonzero(void);

void psp_io_init(void);
void psp_io_register(void);
void psp_io_reset(void);
void psp_io_set_root(const char *root);
/* The host path a guest path (disc0:, ms0:, flash0:, ...) maps to. */
void psp_io_host_path(const char *guest, char *out, size_t cap);
uint64_t psp_io_bytes_read(void);

void psp_misc_init(void);
void psp_misc_register(void);
void psp_misc_reset(void);
int  psp_exit_requested(void);
void psp_request_exit(void);       /* host side: window closed, time limit */
void psp_ctrl_set(uint32_t buttons, uint8_t ax, uint8_t ay);

/* Audio out: called for every buffer a game outputs through sceAudio, as
 * interleaved stereo s16 at 44.1 kHz with the channel volume applied. The
 * host plays it (or records it); without a sink the output is discarded and
 * only the timing is emulated. */
typedef void (*psp_audio_sink_fn)(int channel, const int16_t *stereo, uint32_t frames);
void psp_audio_set_sink(psp_audio_sink_fn fn);

/* ATRAC3 / ATRAC3plus decoding is supplied by the host (the runtime has no
 * codec of its own; see src/hle/atrac.c). Without one, sceAtracDecodeData
 * produces silence of the right length. */
typedef struct {
    const char *name;
    /* A decoder for one stream: ATRAC3plus (at3plus = 1) or ATRAC3, the
     * source channel count, nBlockAlign (bytes per frame) and sample rate.
     * NULL if the format is unsupported. */
    void *(*open)(int at3plus, int channels, int block_align, int sample_rate);
    /* Decode one frame of `size` bytes into interleaved stereo s16 (mono is
     * duplicated). Returns samples written (at most max_samples), or -1 if
     * the codec failed for good. */
    int   (*decode)(void *dec, const uint8_t *frame, int size, int16_t *stereo, int max_samples);
    /* Forget the previous frame (before a seek). */
    void  (*reset)(void *dec);
    void  (*close)(void *dec);
} psp_atrac_codec;
void psp_atrac_set_codec(const psp_atrac_codec *codec);
uint64_t psp_audio_blocks(void);

void psp_font_init(void);
void psp_font_register(void);
void psp_font_reset(void);

void psp_utility_init(void);
void psp_utility_register(void);
void psp_utility_reset(void);

/* PSP savedata encryption, supplied by the host (the toolkit carries none).
 * With it, saves are read and written as on hardware -- encrypted with the
 * game's key, hashes in PARAM.SFO -- so they are interchangeable with a PSP
 * or PPSSPP; without it, data files are stored as given. Modes: 1 (no key),
 * 3, 5 (with the game's 16-byte key). All return 0 on success; *out is
 * malloc'd. */
typedef struct {
    int (*decrypt)(int mode, const uint8_t *file, uint32_t file_len, const uint8_t *key,
                   const uint8_t *expected_hash, uint8_t **out, uint32_t *out_len);
    int (*encrypt)(int mode, const uint8_t *plain, uint32_t len, const uint8_t *key,
                   uint8_t **out, uint32_t *out_len, uint8_t hash[16]);
    /* SAVEDATA_PARAMS (128 bytes at params_off) of a zero-padded PARAM.SFO */
    int (*sfo_hash)(uint8_t *sfo, uint32_t sfo_size, uint32_t params_off, int mode);
} psp_savedata_crypto;
void psp_savedata_set_crypto(const psp_savedata_crypto *c);

void psp_atrac_init(void);
void psp_atrac_register(void);
void psp_atrac_reset(void);

void psp_modules_init(void);
void psp_modules_register(void);
void psp_modules_reset(void);

void psp_system_init(void);
void psp_system_register(void);
void psp_system_reset(void);

void psp_threadman_init(void);
void psp_threadman_register(void);
void psp_threadman_reset(void);

/* ---- the scheduler (opt-in; see src/hle/threadman.c) ---------------------
 *
 * Without psp_sched_run, threads run to completion inside StartThread and
 * blocking waits report a timeout. psp_sched_run gives every PSP thread its
 * own host fiber and schedules them the way the PSP kernel does. */
int      psp_sched_run(uint32_t entry, uint32_t arglen, uint32_t argp,
                       uint32_t prio, uint32_t stack_size, uint32_t gp);
int      psp_sched_active(void);
uint64_t psp_sched_now_us(void);
uint64_t psp_sched_idle_us(void);    /* host time with nothing runnable */
uint64_t psp_display_flips(void);    /* sceDisplaySetFrameBuf calls */
/* How many flips came 1, 2, 3 and 4+ vblanks after the previous one. */
void psp_display_flip_spacing(uint64_t out[4]);
/* Flips by host busy time since the previous one: <8, <16.7, <25, <33.3, <50, 50+ ms. */
void psp_display_frame_busy(uint64_t out[6]);
uint64_t psp_ge_host_us(void);       /* host time executing display lists */
uint64_t psp_gpu_host_us(void);      /* ...of which rasterizing primitives */
uint64_t psp_sched_vblank_count(void);
/* Called once per vblank on the scheduler's clock: present, pump input. */
void     psp_sched_set_vblank_hook(void (*fn)(void));
/* Block the calling PSP thread. Return immediately outside the scheduler. */
uint32_t psp_sched_wait_vblank(int allow_callbacks);
uint32_t psp_sched_sleep_until(uint64_t when_us);
/* Queue a notification for a callback; delivered on its owning thread. */
int      psp_sched_notify_callback(uint32_t cbid, uint32_t arg);
/* The preemption point every firmware call ends with. */
void     psp_sched_after_hle(void);
void     psp_sched_dump(FILE *out);
/* Call guest code as an interrupt handler would run (GE callbacks). */
uint32_t psp_sched_call_interrupt(uint32_t func, uint32_t a0, uint32_t a1);
/* Queue a call into guest code from a firmware library (up to five arguments,
 * the fifth in $t0), delivered at the next vblank on the interrupt stack. */
int      psp_sched_post_call(uint32_t func, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4);
/* The same with a sixth argument, in $t1. */
int      psp_sched_post_call6(uint32_t func, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5);

/* Interrupt mask state (sceKernelCpuSuspendIntr/ResumeIntr). */
int  psp_intr_enabled(void);

/* Bytes of user memory still available — the cheapest end-to-end check that
 * the allocator is behaving. */
uint32_t psp_sysmem_free(void);

/* Raw allocation for use by other HLE subsystems (thread stacks, mostly).
 * Returns 0 on failure. These bypass the UID table because nothing in the
 * guest ever refers to them. */
uint32_t psp_sysmem_alloc(uint32_t size, int from_high);
void     psp_sysmem_set_heap(uint32_t lo, uint32_t hi);
void     psp_sysmem_release(uint32_t addr);

#ifdef __cplusplus
}
#endif

#endif /* PSPRECOMP_HLE_H */
