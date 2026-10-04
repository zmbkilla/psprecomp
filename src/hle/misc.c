/* psprecomp — the smaller firmware libraries.
 *
 * Kernel_Library, UtilsForUser, StdioForUser, sceSuspendForUser,
 * LoadExecForUser, ModuleMgrForUser, sceCtrl and sceAudio. Individually small,
 * but collectively they are what a game's C runtime needs before main() gets
 * anywhere -- newlib's reentrancy setup alone wants interrupt masking, a
 * clock, and the standard file descriptors.
 */

#include "psprecomp/hle.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* ---- Kernel_Library ------------------------------------------------------
 * Interrupt masking. With no interrupts to mask, the pair only has to be
 * *consistent*: suspend returns a cookie that resume accepts. Games use them
 * to bracket short critical sections, and libc's lightweight mutexes are built
 * on them -- which is why a game stalls in its own startup without these. */

static uint32_t g_intr_enabled = 1;

int psp_intr_enabled(void) { return g_intr_enabled != 0; }

static void hle_CpuSuspendIntr(void) {
    uint32_t prev = g_intr_enabled;
    g_intr_enabled = 0;
    psp_ret(prev);                    /* the cookie resume expects */
}

static void hle_CpuResumeIntr(void) {
    g_intr_enabled = psp_arg(0);
    psp_ret(SCE_KERNEL_ERROR_OK);
}

/* ---- UtilsForUser -------------------------------------------------------- */

/* Cache maintenance. There is no cache to write back -- the recompiled code
 * and the GE share one flat backing store -- so these are genuinely no-ops
 * rather than unimplemented. */
static void hle_CacheOp(void) { psp_ret(SCE_KERNEL_ERROR_OK); }

static void hle_LibcTime(void) {
    time_t t = time(NULL);
    uint32_t out = psp_arg(0);
    if (out) psp_write32(out, (uint32_t)t);
    psp_ret((uint32_t)t);
}

static void hle_LibcClock(void) {
    /* Microseconds since start. A game that uses this for frame pacing needs
     * it to advance, so it is derived from the host clock rather than being a
     * constant -- a frozen clock makes a game either spin or run at infinite
     * speed, both of which look like a hang. */
    psp_ret((uint32_t)((uint64_t)clock() * 1000000ull / CLOCKS_PER_SEC));
}

static void hle_LibcGettimeofday(void) {
    uint32_t tv = psp_arg(0);
    if (tv) {
        time_t t = time(NULL);
        psp_write32(tv, (uint32_t)t);
        psp_write32(tv + 4, 0);
    }
    psp_ret(SCE_KERNEL_ERROR_OK);
}

/* General-purpose I/O pins, wired to the debug board. Nothing is connected. */
static void hle_GetGPI(void) { psp_ret(0); }

/* ---- StdioForUser -------------------------------------------------------- */
/* These return the file descriptors, which sceIoWrite then recognises. */
static void hle_Stdin(void)  { psp_ret(0); }
static void hle_Stdout(void) { psp_ret(1); }
static void hle_Stderr(void) { psp_ret(2); }

/* ---- sceSuspendForUser --------------------------------------------------- */
/* Power management around suspend. Nothing suspends here. */
static void hle_ok(void) { psp_ret(SCE_KERNEL_ERROR_OK); }

/* ---- LoadExecForUser ----------------------------------------------------- */

static int g_exit_requested;
int psp_exit_requested(void) { return g_exit_requested; }
void psp_request_exit(void) { g_exit_requested = 1; }

static void hle_ExitGame(void) {
    /* A game calling this is finished. Recording it rather than terminating
     * the process lets the host report what happened and dump its counters. */
    g_exit_requested = 1;
    fprintf(stderr, "psprecomp: the game called sceKernelExitGame\n");
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void hle_RegisterExitCallback(void) { psp_ret(SCE_KERNEL_ERROR_OK); }

/* ---- ModuleMgrForUser ---------------------------------------------------- */
/* A game-sharing microgame is self-contained and does not load further
 * modules, so these report a plausible identity rather than doing anything.
 * A title that genuinely loads PRXs at run time will need real ones. */
/* These report the id of the one loaded module.
 *
 * A previous note here recorded the opposite -- that returning an id was a
 * "plausible lie" and an error was the truthful answer -- on the strength of a
 * test showing byte-identical output either way. **That test was run while
 * `jal` never assigned `$ra`**, so every non-leaf function in the program was
 * returning through a stale register. A falsification obtained under broken
 * codegen is not a falsification.
 *
 * Re-run after that fix, the two answers differ clearly: returning an id makes
 * the game's own "libc:_getmodreent: no reent structure" diagnostic disappear
 * and drops bad memory accesses from 3 to 0.
 *
 * And an id is the *truthful* answer. The question is "which module owns this
 * address", a self-contained microgame is exactly one module, and the host has
 * loaded it. Reporting 1 states that; reporting UNKNOWN_MODULE denies a module
 * that demonstrably exists. */
#define SCE_KERNEL_ERROR_UNKNOWN_MODULE 0x80020139u
#define PSP_MAIN_MODULE_ID 1u

static void hle_GetModuleId(void)          { psp_ret(PSP_MAIN_MODULE_ID); }
static void hle_GetModuleIdByAddress(void) { psp_ret(PSP_MAIN_MODULE_ID); }

/* ---- sceCtrl ------------------------------------------------------------- */

static uint32_t g_buttons;
static uint8_t  g_analog_x = 128, g_analog_y = 128;
static uint32_t g_ctrl_frame;

void psp_ctrl_set(uint32_t buttons, uint8_t ax, uint8_t ay) {
    g_buttons = buttons;
    g_analog_x = ax;
    g_analog_y = ay;
}

static void hle_CtrlSet(void) { psp_ret(SCE_KERNEL_ERROR_OK); }

/* SceCtrlData: u32 timestamp, u32 buttons, u8 lx, u8 ly, then padding to 16. */
static void hle_ReadBufferPositive(void) {
    uint32_t buf = psp_arg(0), count = psp_arg(1);
    if (!count) count = 1;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t at = buf + i * 16;
        psp_write32(at, g_ctrl_frame++);
        psp_write32(at + 4, g_buttons);
        psp_write8(at + 8, g_analog_x);
        psp_write8(at + 9, g_analog_y);
        for (int k = 10; k < 16; k++) psp_write8(at + (uint32_t)k, 0);
    }
    psp_ret(count);
}

/* ---- sceAudio ------------------------------------------------------------ */

#define AUDIO_CHANNELS 8

typedef struct { int reserved; uint32_t samples; uint32_t format; uint64_t busy_until; } audio_ch;
static audio_ch g_audio[AUDIO_CHANNELS];
static uint64_t g_audio_blocks;

uint64_t psp_audio_blocks(void) { return g_audio_blocks; }

static void hle_ChReserve(void) {
    /* (channel, samplecount, format) -- channel -1 means "any". */
    int32_t ch = (int32_t)psp_arg(0);
    if (ch < 0) {
        for (int i = 0; i < AUDIO_CHANNELS; i++)
            if (!g_audio[i].reserved) { ch = i; break; }
    }
    if (ch < 0 || ch >= AUDIO_CHANNELS) { psp_ret(0x80000001); return; }
    g_audio[ch].reserved = 1;
    g_audio[ch].samples = psp_arg(1);
    g_audio[ch].format  = psp_arg(2);
    psp_ret((uint32_t)ch);
}

static void hle_ChRelease(void) {
    int32_t ch = (int32_t)psp_arg(0);
    if (ch < 0 || ch >= AUDIO_CHANNELS) { psp_ret(0x80000001); return; }
    g_audio[ch].reserved = 0;
    psp_ret(SCE_KERNEL_ERROR_OK);
}

/* Output hands one buffer to the hardware, which plays it at 44.1 kHz. The
 * blocking forms return once the hardware can accept the next buffer -- that
 * wait is what paces a game's audio thread, and under the scheduler it is a
 * real wait on the system clock. Without the scheduler there is no one to
 * yield to, so it returns at once and only the block count advances. */
#define AUDIO_RATE 44100u

static uint64_t buffer_us(const audio_ch *c) {
    return (uint64_t)c->samples * 1000000u / AUDIO_RATE;
}

/* The host's audio device, if it has one (psp_audio_set_sink). Each accepted
 * buffer is handed over as interleaved stereo s16 with the channel volume
 * already applied. */
static psp_audio_sink_fn g_sink;
void psp_audio_set_sink(psp_audio_sink_fn fn) { g_sink = fn; }

#define AUDIO_FORMAT_MONO 0x10u
#define AUDIO_VOLUME_MAX  0x8000

static void to_sink(uint32_t ch, const audio_ch *c, uint32_t buf, int lvol, int rvol) {
    if (!g_sink || !buf || !c->samples || c->samples > 65536) return;
    static int16_t pcm[65536 * 2];
    const int mono = (c->format & AUDIO_FORMAT_MONO) != 0;
    for (uint32_t i = 0; i < c->samples; i++) {
        int32_t l, r;
        if (mono) l = r = (int16_t)psp_read16(buf + i * 2);
        else {
            l = (int16_t)psp_read16(buf + i * 4);
            r = (int16_t)psp_read16(buf + i * 4 + 2);
        }
        pcm[i * 2]     = (int16_t)(l * lvol / AUDIO_VOLUME_MAX);
        pcm[i * 2 + 1] = (int16_t)(r * rvol / AUDIO_VOLUME_MAX);
    }
    g_sink((int)ch, pcm, c->samples);
}

/* (ch, vol, buf) or, panned, (ch, leftVol, rightVol, buf). */
static void output(int blocking, int panned) {
    uint32_t ch = psp_arg(0);
    if (ch >= AUDIO_CHANNELS) { psp_ret(0x80260003); return; }          /* INVALID_CHANNEL */
    if (!g_audio[ch].reserved) { psp_ret(0x80260008); return; }         /* NOT_RESERVED */
    audio_ch *c = &g_audio[ch];
    const int lvol = (int)(psp_arg(1) & 0xFFFF), rvol = (int)(psp_arg(panned ? 2 : 1) & 0xFFFF);
    const uint32_t buf = psp_arg(panned ? 3 : 2);
    g_audio_blocks++;
    if (psp_sched_active()) {
        uint64_t now = psp_sched_now_us();
        if (c->busy_until > now) {
            if (!blocking) { psp_ret(0x80260002); return; }    /* channel busy */
            psp_sched_sleep_until(c->busy_until);
            now = psp_sched_now_us();
        }
        c->busy_until = (c->busy_until > now ? c->busy_until : now) + buffer_us(c);
    }
    to_sink(ch, c, buf, lvol, rvol);
    psp_ret(c->samples);
}
static void hle_Output(void)               { output(1, 0); }
static void hle_OutputPanned(void)         { output(1, 1); }
static void hle_OutputPannedNonBlock(void) { output(0, 1); }

/* Samples still queued on the channel; zero means "ready for more". */
static void hle_GetChannelRestLength(void) {
    uint32_t ch = psp_arg(0);
    if (ch >= AUDIO_CHANNELS) { psp_ret(0x80260003); return; }          /* INVALID_CHANNEL */
    if (!g_audio[ch].reserved) { psp_ret(0x80260008); return; }         /* NOT_RESERVED */
    uint64_t now = psp_sched_now_us();
    audio_ch *c = &g_audio[ch];
    uint64_t left = c->busy_until > now ? (c->busy_until - now) * AUDIO_RATE / 1000000u : 0;
    psp_ret((uint32_t)(left > c->samples ? c->samples : left));
}

/* (channel, samplecount) */
static void hle_SetChannelDataLen(void) {
    uint32_t ch = psp_arg(0);
    if (ch >= AUDIO_CHANNELS) { psp_ret(0x80260003); return; }          /* INVALID_CHANNEL */
    if (!g_audio[ch].reserved) { psp_ret(0x80260008); return; }         /* NOT_RESERVED */
    g_audio[ch].samples = psp_arg(1);
    psp_ret(0);
}

void psp_misc_reset(void) {
    g_intr_enabled = 1;
    g_exit_requested = 0;
    g_buttons = 0;
    g_analog_x = g_analog_y = 128;
    g_ctrl_frame = 0;
    memset(g_audio, 0, sizeof g_audio);
    g_audio_blocks = 0;
}

void psp_misc_init(void) { psp_misc_reset(); }

void psp_misc_register(void) {
    psp_hle_register(0x092968F4, "Kernel_Library", "sceKernelCpuSuspendIntr", hle_CpuSuspendIntr);
    psp_hle_register(0x5F10D406, "Kernel_Library", "sceKernelCpuResumeIntr",  hle_CpuResumeIntr);

    psp_hle_register(0x79D1C3FA, "UtilsForUser", "sceKernelDcacheWritebackAll",           hle_CacheOp);
    psp_hle_register(0xB435DEC5, "UtilsForUser", "sceKernelDcacheWritebackInvalidateAll", hle_CacheOp);
    psp_hle_register(0x27CC57F0, "UtilsForUser", "sceKernelLibcTime",         hle_LibcTime);
    psp_hle_register(0x91E4F6A7, "UtilsForUser", "sceKernelLibcClock",        hle_LibcClock);
    psp_hle_register(0x71EC4271, "UtilsForUser", "sceKernelLibcGettimeofday", hle_LibcGettimeofday);
    psp_hle_register(0x37FB5C42, "UtilsForUser", "sceKernelGetGPI",           hle_GetGPI);

    psp_hle_register(0x172D316E, "StdioForUser", "sceKernelStdin",  hle_Stdin);
    psp_hle_register(0xA6BAB2E9, "StdioForUser", "sceKernelStdout", hle_Stdout);
    psp_hle_register(0xF78BA90A, "StdioForUser", "sceKernelStderr", hle_Stderr);

    psp_hle_register(0xEADB1BD7, "sceSuspendForUser", "sceKernelPowerLock",   hle_ok);
    psp_hle_register(0x3AEE7261, "sceSuspendForUser", "sceKernelPowerUnlock", hle_ok);
    psp_hle_register(0x090CCB3F, "sceSuspendForUser", "sceKernelPowerTick",   hle_ok);

    psp_hle_register(0x05572A5F, "LoadExecForUser", "sceKernelExitGame",             hle_ExitGame);
    psp_hle_register(0x4AC57943, "LoadExecForUser", "sceKernelRegisterExitCallback", hle_RegisterExitCallback);

    /* Observed but unidentified. The game calls this three times on its
     * heap-setup path, and an unimplemented call returns 0 -- which for a
     * module query means "no module" and makes heap establishment fail.
     * Eighteen plausible ModuleMgr names were tried against SHA-1 with no
     * match, so the name is genuinely unknown and is not invented here. */
    psp_hle_register_unnamed(0xF9275D98, "ModuleMgrForUser", hle_GetModuleId);
    psp_hle_register(0xF0A26395, "ModuleMgrForUser", "sceKernelGetModuleId",          hle_GetModuleId);
    psp_hle_register(0xD8B73127, "ModuleMgrForUser", "sceKernelGetModuleIdByAddress", hle_GetModuleIdByAddress);

    psp_hle_register(0x1F4011E6, "sceCtrl", "sceCtrlSetSamplingMode",     hle_CtrlSet);
    psp_hle_register(0x6A2774F3, "sceCtrl", "sceCtrlSetSamplingCycle",    hle_CtrlSet);
    psp_hle_register(0x1F803938, "sceCtrl", "sceCtrlReadBufferPositive",  hle_ReadBufferPositive);

    psp_hle_register(0x5EC81C55, "sceAudio", "sceAudioChReserve",            hle_ChReserve);
    psp_hle_register(0x6FC46853, "sceAudio", "sceAudioChRelease",            hle_ChRelease);
    psp_hle_register(0x136CAF51, "sceAudio", "sceAudioOutputBlocking",       hle_Output);
    psp_hle_register(0x13F592BC, "sceAudio", "sceAudioOutputPannedBlocking", hle_OutputPanned);
    psp_hle_register(0xE2D56B2D, "sceAudio", "sceAudioOutputPanned",         hle_OutputPannedNonBlock);
    psp_hle_register(0xB011922F, "sceAudio", "sceAudioGetChannelRestLength", hle_GetChannelRestLength);
    psp_hle_register(0xCB2E439E, "sceAudio", "sceAudioSetChannelDataLen",    hle_SetChannelDataLen);
    psp_hle_register(0x95FD0C2D, "sceAudio", "sceAudioChangeChannelConfig",  hle_ok);
    psp_hle_register(0xB7E1D8E7, "sceAudio", "sceAudioChangeChannelVolume",  hle_ok);
}
