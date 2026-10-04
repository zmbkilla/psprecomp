/* psprecomp — ModuleMgrForUser and sceUtility's module loader.
 *
 * A PSP game can load further code at run time: firmware modules through
 * sceUtilityLoadModule (codecs, network stack), and PRX files of its own
 * through sceKernelLoadModule. Under static recompilation there is no loader
 * that could run new code, so each request has exactly two honest answers:
 *
 *   - the module's exports are provided by this runtime's HLE (firmware
 *     modules, and Sony libraries a game ships on its disc such as
 *     libfont.prx = sceFont_Library): loading succeeds and yields a module id,
 *     and the game's import stubs for that library already resolve to HLE;
 *   - the module is game code that has not been recompiled into this binary:
 *     loading fails, and says so by path.
 *
 * Which firmware functions are actually implemented is a separate question,
 * answered call by call by psp_hle_call's "unimplemented" report.
 */

#include "psprecomp/hle.h"

#include <stdio.h>
#include <string.h>

#define MAX_MODULES 32
#define MODULE_UID_BASE 0x00050000u

#define ERR_UNKNOWN_MODULE     0x8002012Eu
#define ERR_UNSUPPORTED_PRX    0x80020148u   /* this binary cannot run it */
#define ERR_ALREADY_LOADED     0x80111102u   /* sceUtility: module already loaded */
#define ERR_NOT_LOADED         0x80111103u   /* sceUtility: module not loaded */

typedef struct {
    uint32_t uid;
    char     path[128];
    const char *provides;
    int      started;
    int      used;
} module;

static module   g_mod[MAX_MODULES];
static uint32_t g_next_uid;
static uint32_t g_utility_loaded[64];
static int      g_nutility;

/* Libraries a game may carry on its disc whose exports this runtime provides
 * itself, matched by file name. */
static const struct { const char *file; const char *library; } HLE_PRX[] = {
    { "libfont.prx", "sceLibFont" },
};

void psp_modules_reset(void) {
    memset(g_mod, 0, sizeof g_mod);
    g_next_uid = MODULE_UID_BASE;
    memset(g_utility_loaded, 0, sizeof g_utility_loaded);
    g_nutility = 0;
}

void psp_modules_init(void) { psp_modules_reset(); }

static module *find_module(uint32_t uid) {
    for (int i = 0; i < MAX_MODULES; i++)
        if (g_mod[i].used && g_mod[i].uid == uid) return &g_mod[i];
    return NULL;
}

/* (path, flags, option) */
static void hle_LoadModule(void) {
    char path[256];
    psp_str(psp_arg(0), path, sizeof path);
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    const char *provides = NULL;
    for (size_t i = 0; i < sizeof HLE_PRX / sizeof HLE_PRX[0]; i++)
        if (!strcmp(base, HLE_PRX[i].file)) provides = HLE_PRX[i].library;

    if (!provides) {
        fprintf(stderr, "psprecomp: sceKernelLoadModule(\"%s\"): game code that is not "
                        "recompiled into this binary -- refusing\n", path);
        psp_ret(ERR_UNSUPPORTED_PRX);
        return;
    }
    for (int i = 0; i < MAX_MODULES; i++) {
        if (g_mod[i].used) continue;
        memset(&g_mod[i], 0, sizeof g_mod[i]);
        g_mod[i].uid = g_next_uid++;
        snprintf(g_mod[i].path, sizeof g_mod[i].path, "%s", path);
        g_mod[i].provides = provides;
        g_mod[i].used = 1;
        fprintf(stderr, "psprecomp: sceKernelLoadModule(\"%s\") -> 0x%X (exports provided by HLE: %s)\n",
                path, g_mod[i].uid, provides);
        psp_ret(g_mod[i].uid);
        return;
    }
    psp_ret(SCE_KERNEL_ERROR_NO_MEMORY);
}

/* (uid, argsize, argp, status*, option) */
static void hle_StartModule(void) {
    module *m = find_module(psp_arg(0));
    if (!m) { psp_ret(ERR_UNKNOWN_MODULE); return; }
    m->started = 1;
    if (psp_arg(3)) psp_write32(psp_arg(3), 0);
    psp_ret(m->uid);
}

/* (uid, argsize, argp, status*, option) */
static void hle_StopModule(void) {
    module *m = find_module(psp_arg(0));
    if (!m) { psp_ret(ERR_UNKNOWN_MODULE); return; }
    m->started = 0;
    if (psp_arg(3)) psp_write32(psp_arg(3), 0);
    psp_ret(0);
}

static void hle_UnloadModule(void) {
    module *m = find_module(psp_arg(0));
    if (!m) { psp_ret(ERR_UNKNOWN_MODULE); return; }
    m->used = 0;
    psp_ret(m->uid);
}

/* sceUtilityLoadModule(id): a firmware module by number -- 0x01xx network,
 * 0x02xx USB, 0x03xx audio/video codecs, 0x04xx NP, 0x05xx MP4, 0x06xx
 * libfont... All of them are firmware this runtime stands in for, so loading
 * is bookkeeping: the NIDs they export are already registered (or reported
 * as unimplemented when called). */
static void hle_UtilityLoadModule(void) {
    uint32_t id = psp_arg(0);
    for (int i = 0; i < g_nutility; i++)
        if (g_utility_loaded[i] == id) { psp_ret(ERR_ALREADY_LOADED); return; }
    if (g_nutility < 64) g_utility_loaded[g_nutility++] = id;
    fprintf(stderr, "psprecomp: sceUtilityLoadModule(0x%04X)\n", id);
    psp_ret(0);
}

static void hle_UtilityUnloadModule(void) {
    uint32_t id = psp_arg(0);
    for (int i = 0; i < g_nutility; i++) {
        if (g_utility_loaded[i] != id) continue;
        g_utility_loaded[i] = g_utility_loaded[--g_nutility];
        psp_ret(0);
        return;
    }
    psp_ret(ERR_NOT_LOADED);
}

void psp_modules_register(void) {
    psp_hle_register(0x977DE386, "ModuleMgrForUser", "sceKernelLoadModule",   hle_LoadModule);
    psp_hle_register(0x50F0C1EC, "ModuleMgrForUser", "sceKernelStartModule",  hle_StartModule);
    psp_hle_register(0xD1FF982A, "ModuleMgrForUser", "sceKernelStopModule",   hle_StopModule);
    psp_hle_register(0x2E0911AA, "ModuleMgrForUser", "sceKernelUnloadModule", hle_UnloadModule);
    psp_hle_register(0x2A2B3DE0, "sceUtility", "sceUtilityLoadModule",   hle_UtilityLoadModule);
    psp_hle_register(0xE49BFE92, "sceUtility", "sceUtilityUnloadModule", hle_UtilityUnloadModule);
}
