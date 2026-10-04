/* psprecomp — small system libraries: sceUmdUser, scePower, sceRtc,
 * sceImpose, the rest of sceCtrl, the cache-range calls in UtilsForUser and
 * the volatile-memory lock in sceSuspendForUser.
 *
 * Each is a thin surface over a fact about the machine (the disc is in and
 * readable, the clock reads the host's clock, the 4 MB volatile region is at
 * 0x08400000), so each is implemented outright rather than stubbed.
 */

#include "psprecomp/hle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <sys/time.h>
#endif

/* ---- sceUmdUser ----------------------------------------------------------- */

/* Drive state bits. The disc is always present (the host directory stands in
 * for it); activation is what makes it READY. */
#define UMD_NOT_PRESENT 0x01
#define UMD_PRESENT     0x02
#define UMD_CHANGED     0x04
#define UMD_INITING     0x08
#define UMD_INITED      0x10
#define UMD_READY       0x20

static uint32_t g_umd_stat;
static uint32_t g_umd_cb;

static void umd_set(uint32_t stat) {
    g_umd_stat = stat;
    if (g_umd_cb) psp_sched_notify_callback(g_umd_cb, stat);
}

static void hle_UmdActivate(void)     { umd_set(UMD_PRESENT | UMD_INITED | UMD_READY); psp_ret(0); }
static void hle_UmdGetDriveStat(void) { psp_ret(g_umd_stat); }
static void hle_UmdCheckMedium(void)  { psp_ret(1); }
static void hle_UmdGetErrorStat(void) { psp_ret(0); }
static void hle_UmdCancelWait(void)   { psp_ret(0); }

/* Blocks until any of the requested bits is set. Activation is the only
 * transition, and it is made by a game thread, so waiting is per-vblank. */
static void hle_UmdWaitDriveStat(void) {
    uint32_t want = psp_arg(0);
    while (!(g_umd_stat & want) && psp_sched_active()) psp_sched_wait_vblank(0);
    psp_ret(0);
}

static void hle_UmdRegisterCallback(void)   { g_umd_cb = psp_arg(0); psp_ret(0); }
static void hle_UmdUnregisterCallback(void) {
    if (g_umd_cb != psp_arg(0)) { psp_ret(0x80010016); return; }
    g_umd_cb = 0;
    psp_ret(0);
}

/* ---- scePower ------------------------------------------------------------- */

/* Power-callback state word: AC power, battery present, 100% charge. */
#define POWER_CB_AC_POWER      0x00001000u
#define POWER_CB_BATTERY_EXIST 0x00000080u

static uint32_t g_power_cb[16];
static uint32_t g_cpu_mhz = 222, g_bus_mhz = 111;

/* (slot, cbid). Slot -1 picks a free one and returns it. The firmware
 * notifies a newly registered callback with the current power state at once. */
static void hle_PowerRegisterCallback(void) {
    int32_t slot = (int32_t)psp_arg(0);
    uint32_t cbid = psp_arg(1);
    if (slot == -1) {
        for (int i = 0; i < 16; i++) if (!g_power_cb[i]) { slot = i; break; }
        if (slot == -1) { psp_ret(0x80000022); return; }
    }
    if (slot < 0 || slot >= 16) { psp_ret(0x80000102); return; }
    if (g_power_cb[slot]) { psp_ret(0x80000020); return; }
    g_power_cb[slot] = cbid;
    psp_sched_notify_callback(cbid, POWER_CB_AC_POWER | POWER_CB_BATTERY_EXIST | 100);
    psp_ret((uint32_t)slot);
}

static void hle_PowerGetCpuClockFrequencyInt(void) { psp_ret(g_cpu_mhz); }
static void hle_PowerGetBusClockFrequencyInt(void) { psp_ret(g_bus_mhz); }

/* Unnamed (0x469989AD): called as (cpu, cpu, cpu / 2) with a zero-is-success
 * check -- the (pll, cpu, bus) shape of the clock setter. Speed is the host's
 * business, so only the reported frequencies change. */
static void hle_PowerSetClocks(void) {
    uint32_t cpu = psp_arg(1), bus = psp_arg(2);
    if (cpu < 1 || cpu > 333 || bus < 1 || bus > 167) { psp_ret(0x80000102); return; }
    g_cpu_mhz = cpu;
    g_bus_mhz = bus;
    psp_ret(0);
}

/* ---- sceRtc ---------------------------------------------------------------- */

/* Ticks are microseconds since 0001-01-01 00:00:00. */
#define RTC_UNIX_EPOCH_TICKS 62135596800000000ull
#define RTC_TICKS_PER_SEC 1000000ull

static uint64_t host_utc_us(void) {
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;   /* 100 ns since 1601 */
    return t / 10 - 11644473600000000ull;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000u + (uint64_t)tv.tv_usec;
#endif
}

static int64_t local_offset_us(void) {
    time_t now = time(NULL);
    struct tm lt, gt;
#ifdef _WIN32
    localtime_s(&lt, &now);
    gmtime_s(&gt, &now);
#else
    localtime_r(&now, &lt);
    gmtime_r(&now, &gt);
#endif
    lt.tm_isdst = 0;
    gt.tm_isdst = 0;
    return (int64_t)difftime(mktime(&lt), mktime(&gt)) * 1000000;
}

/* Civil date <-> day number (days since 1970-01-01), proleptic Gregorian. */
static int64_t days_from_civil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static void civil_from_days(int64_t z, int *y, unsigned *m, unsigned *d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = (unsigned)(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    *d = doy - (153 * mp + 2) / 5 + 1;
    *m = mp < 10 ? mp + 3 : mp - 9;
    *y = (int)((int64_t)yoe + era * 400 + (*m <= 2));
}

static uint64_t rd64(uint32_t a) { return (uint64_t)psp_read32(a) | ((uint64_t)psp_read32(a + 4) << 32); }
static void wr64(uint32_t a, uint64_t v) { psp_write32(a, (uint32_t)v); psp_write32(a + 4, (uint32_t)(v >> 32)); }

/* ScePspDateTime: u16 year, month, day, hour, minute, second; u32 microsecond. */
static void tick_to_date(uint64_t tick, uint32_t at) {
    uint64_t us_unix = tick - RTC_UNIX_EPOCH_TICKS;
    int64_t secs = (int64_t)(us_unix / RTC_TICKS_PER_SEC);
    int64_t days = secs / 86400, rem = secs % 86400;
    if (rem < 0) { rem += 86400; days--; }
    int y; unsigned m, d;
    civil_from_days(days, &y, &m, &d);
    psp_write16(at + 0,  (uint16_t)y);
    psp_write16(at + 2,  (uint16_t)m);
    psp_write16(at + 4,  (uint16_t)d);
    psp_write16(at + 6,  (uint16_t)(rem / 3600));
    psp_write16(at + 8,  (uint16_t)((rem / 60) % 60));
    psp_write16(at + 10, (uint16_t)(rem % 60));
    psp_write32(at + 12, (uint32_t)(tick % RTC_TICKS_PER_SEC));
}

static uint64_t date_to_tick(uint32_t at) {
    int64_t days = days_from_civil(psp_read16(at), psp_read16(at + 2), psp_read16(at + 4));
    int64_t secs = days * 86400 + psp_read16(at + 6) * 3600 + psp_read16(at + 8) * 60 + psp_read16(at + 10);
    return (uint64_t)(secs * (int64_t)RTC_TICKS_PER_SEC) + psp_read32(at + 12) + RTC_UNIX_EPOCH_TICKS;
}

static void hle_RtcGetTickResolution(void) { psp_ret((uint32_t)RTC_TICKS_PER_SEC); }

static void hle_RtcGetCurrentTick(void) {
    wr64(psp_arg(0), host_utc_us() + RTC_UNIX_EPOCH_TICKS);
    psp_ret(0);
}

static void hle_RtcGetCurrentClockLocalTime(void) {
    tick_to_date(host_utc_us() + RTC_UNIX_EPOCH_TICKS + (uint64_t)local_offset_us(), psp_arg(0));
    psp_ret(0);
}

static void hle_RtcConvertUtcToLocalTime(void) {
    wr64(psp_arg(1), rd64(psp_arg(0)) + (uint64_t)local_offset_us());
    psp_ret(0);
}

/* (ScePspDateTime *date, const u64 *tick) */
static void hle_RtcSetTick(void) {
    tick_to_date(rd64(psp_arg(1)), psp_arg(0));
    psp_ret(0);
}

/* (u64 *dst, const u64 *src, u64 n) -- the 64-bit count is register-aligned
 * into $a2:$a3. */
static void hle_RtcTickAddTicks(void) {
    uint64_t n = (uint64_t)psp_arg(2) | ((uint64_t)psp_arg(3) << 32);
    wr64(psp_arg(0), rd64(psp_arg(1)) + n);
    psp_ret(0);
}

static void hle_RtcTickAddSeconds(void) {
    uint64_t n = (uint64_t)psp_arg(2) | ((uint64_t)psp_arg(3) << 32);
    wr64(psp_arg(0), rd64(psp_arg(1)) + n * RTC_TICKS_PER_SEC);
    psp_ret(0);
}

/* (const ScePspDateTime *date, u64 *time): seconds since the Unix epoch. */
static void hle_RtcGetTime64_t(void) {
    wr64(psp_arg(1), (date_to_tick(psp_arg(0)) - RTC_UNIX_EPOCH_TICKS) / RTC_TICKS_PER_SEC);
    psp_ret(0);
}

/* (ScePspDateTime *date, u64 time) -- time in $a2:$a3. */
static void hle_RtcSetTime64_t(void) {
    uint64_t t = (uint64_t)psp_arg(2) | ((uint64_t)psp_arg(3) << 32);
    tick_to_date(t * RTC_TICKS_PER_SEC + RTC_UNIX_EPOCH_TICKS, psp_arg(0));
    psp_ret(0);
}

/* ---- sceImpose / sceCtrl / UtilsForUser / sceSuspendForUser ----------------- */

static uint32_t g_lang = 0, g_button = 1;   /* Japanese, circle confirms (a JP disc) */
static void hle_ImposeSetLanguageMode(void) { g_lang = psp_arg(0); g_button = psp_arg(1); psp_ret(0); }
static void hle_ImposeGetLanguageMode(void) {
    if (psp_arg(0)) psp_write32(psp_arg(0), g_lang);
    if (psp_arg(1)) psp_write32(psp_arg(1), g_button);
    psp_ret(0);
}

static void hle_CtrlSetIdleCancelThreshold(void) { psp_ret(0); }

/* No data cache sits between the recompiled code and the shared backing store,
 * so range write-back/invalidate have nothing to do. */
static void hle_CacheRange(void) { psp_ret(0); }

/* The 4 MB volatile region (normally the kernel's suspend buffer) lent to the
 * game: (type, void **ptr, int *size). */
#define VOLATILE_BASE 0x08400000u
#define VOLATILE_SIZE 0x00400000u
static int g_volatile_locked;
static void hle_VolatileMemLock(void) {
    if (g_volatile_locked) { psp_ret(0x802B0200); return; }   /* already locked */
    g_volatile_locked = 1;
    if (psp_arg(1)) psp_write32(psp_arg(1), VOLATILE_BASE);
    if (psp_arg(2)) psp_write32(psp_arg(2), VOLATILE_SIZE);
    psp_ret(0);
}
static void hle_VolatileMemUnlock(void) {
    if (!g_volatile_locked) { psp_ret(0x802B0200); return; }
    g_volatile_locked = 0;
    psp_ret(0);
}

/* ---- sceOpenPSID ------------------------------------------------------------ */

/* The console's 16-byte identity. A virtual console has no factory value, so
 * this one is a fixed default (stable across runs, so anything keyed on it --
 * save data, an online account -- stays consistent) that can be replaced with
 * PSPRECOMP_OPENPSID=<32 hex digits>. */
static void hle_GetOpenPSID(void) {
    uint8_t id[16] = { 0x10, 0x02, 0x00, 0x01, 0x70, 0x73, 0x70, 0x72,
                       0x65, 0x63, 0x6F, 0x6D, 0x70, 0x00, 0x00, 0x01 };
    const char *env = getenv("PSPRECOMP_OPENPSID");
    if (env && strlen(env) == 32) {
        for (int i = 0; i < 16; i++) {
            unsigned v;
            if (sscanf(env + 2 * i, "%2x", &v) == 1) id[i] = (uint8_t)v;
        }
    }
    uint32_t out = psp_arg(0);
    if (!out) { psp_ret(0x80010016); return; }
    for (uint32_t i = 0; i < 16; i++) psp_write8(out + i, id[i]);
    psp_ret(0);
}

/* ---- registration ----------------------------------------------------------- */

void psp_system_reset(void) {
    g_umd_stat = UMD_PRESENT | UMD_INITED;
    g_umd_cb = 0;
    memset(g_power_cb, 0, sizeof g_power_cb);
    g_cpu_mhz = 222;
    g_bus_mhz = 111;
    g_volatile_locked = 0;
}

void psp_system_init(void) { psp_system_reset(); }

void psp_system_register(void) {
    psp_hle_register(0xC6183D47, "sceUmdUser", "sceUmdActivate",              hle_UmdActivate);
    psp_hle_register(0x6B4A146C, "sceUmdUser", "sceUmdGetDriveStat",          hle_UmdGetDriveStat);
    psp_hle_register(0x8EF08FCE, "sceUmdUser", "sceUmdWaitDriveStat",         hle_UmdWaitDriveStat);
    psp_hle_register(0x46EBB729, "sceUmdUser", "sceUmdCheckMedium",           hle_UmdCheckMedium);
    psp_hle_register(0x20628E6F, "sceUmdUser", "sceUmdGetErrorStat",          hle_UmdGetErrorStat);
    psp_hle_register(0x6AF9B50A, "sceUmdUser", "sceUmdCancelWaitDriveStat",   hle_UmdCancelWait);
    psp_hle_register(0xAEE7404D, "sceUmdUser", "sceUmdRegisterUMDCallBack",   hle_UmdRegisterCallback);
    psp_hle_register(0xBD2BDE07, "sceUmdUser", "sceUmdUnRegisterUMDCallBack", hle_UmdUnregisterCallback);

    psp_hle_register(0x04B7766E, "scePower", "scePowerRegisterCallback",         hle_PowerRegisterCallback);
    psp_hle_register(0xFDB5BFE9, "scePower", "scePowerGetCpuClockFrequencyInt",  hle_PowerGetCpuClockFrequencyInt);
    psp_hle_register(0xBD681969, "scePower", "scePowerGetBusClockFrequencyInt",  hle_PowerGetBusClockFrequencyInt);
    psp_hle_register_unnamed(0x469989AD, "scePower", hle_PowerSetClocks);

    psp_hle_register(0xC41C2853, "sceRtc", "sceRtcGetTickResolution",         hle_RtcGetTickResolution);
    psp_hle_register(0x3F7AD767, "sceRtc", "sceRtcGetCurrentTick",            hle_RtcGetCurrentTick);
    psp_hle_register(0xF5FCC995, "sceRtc", "sceRtcGetCurrentNetworkTick",     hle_RtcGetCurrentTick);
    psp_hle_register(0xE7C27D1B, "sceRtc", "sceRtcGetCurrentClockLocalTime",  hle_RtcGetCurrentClockLocalTime);
    psp_hle_register(0x34885E0D, "sceRtc", "sceRtcConvertUtcToLocalTime",     hle_RtcConvertUtcToLocalTime);
    psp_hle_register(0x7ED29E40, "sceRtc", "sceRtcSetTick",                   hle_RtcSetTick);
    psp_hle_register(0x44F45E05, "sceRtc", "sceRtcTickAddTicks",              hle_RtcTickAddTicks);
    psp_hle_register(0xF2A4AFE5, "sceRtc", "sceRtcTickAddSeconds",            hle_RtcTickAddSeconds);
    psp_hle_register(0xE1C93E47, "sceRtc", "sceRtcGetTime64_t",               hle_RtcGetTime64_t);
    psp_hle_register(0x1909C99B, "sceRtc", "sceRtcSetTime64_t",               hle_RtcSetTime64_t);

    psp_hle_register(0x36AA6E91, "sceImpose", "sceImposeSetLanguageMode", hle_ImposeSetLanguageMode);
    psp_hle_register(0x24FD7BCF, "sceImpose", "sceImposeGetLanguageMode", hle_ImposeGetLanguageMode);

    psp_hle_register(0xA7144800, "sceCtrl", "sceCtrlSetIdleCancelThreshold", hle_CtrlSetIdleCancelThreshold);

    psp_hle_register(0x3EE30821, "UtilsForUser", "sceKernelDcacheWritebackRange",           hle_CacheRange);
    psp_hle_register(0x34B9FA9E, "UtilsForUser", "sceKernelDcacheWritebackInvalidateRange", hle_CacheRange);
    psp_hle_register(0xBFA98062, "UtilsForUser", "sceKernelDcacheInvalidateRange",          hle_CacheRange);

    psp_hle_register(0x3E0271D3, "sceSuspendForUser", "sceKernelVolatileMemLock",   hle_VolatileMemLock);
    psp_hle_register(0xA569E425, "sceSuspendForUser", "sceKernelVolatileMemUnlock", hle_VolatileMemUnlock);

    psp_hle_register(0xC69BEBCE, "sceOpenPSID", "sceOpenPSIDGetOpenPSID", hle_GetOpenPSID);
}
