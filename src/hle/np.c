/* psprecomp — PSN (NP) libraries: sceNp, sceNpService, sceNpAuth,
 * sceNpCommerce2, and PSP2i's PSN sign-in utility (sceUtilityPsn*).
 *
 * Signing in and issuing tickets are a backend's job (psp_np_set_backend):
 * the port shows its own login screen and talks to a compatible server. This
 * file only carries the firmware's side faithfully:
 *
 *   - nothing is signed in until the backend says so; without a backend (or
 *     after a failed / cancelled sign-in) the sign-in reports an error and
 *     sceNpGetNpId reports SCE_NP_MANAGER_ERROR_NOT_SIGNIN;
 *   - sceNpAuthCreateStartRequest asks the backend for a ticket for the
 *     game's service ID and returns a request ID; when the backend answers,
 *     the game's ticket callback receives (request, ticket length) -- or
 *     (request, error code) -- and sceNpAuthGetTicket copies the ticket the
 *     backend obtained. No ticket is ever made up here.
 *
 * psp_np_poll() must be called regularly (once per vblank): it is where
 * backend results reach the game. */

#include "psprecomp/hle.h"
#include "psprecomp/net.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SCE_NP_ERROR_ALREADY_INITIALIZED     0x80550001u
#define SCE_NP_ERROR_NOT_INITIALIZED         0x80550002u
#define SCE_NP_ERROR_INVALID_ARGUMENT        0x80550003u
#define SCE_NP_AUTH_ERROR_NOT_INITIALIZED    0x80550302u
#define SCE_NP_AUTH_ERROR_EBUSY              0x80550306u
#define SCE_NP_AUTH_ERROR_ESRCH              0x80550305u
#define SCE_NP_AUTH_ERROR_INVALID_ARGUMENT   0x80550311u
#define SCE_NP_AUTH_ERROR_ABORTED            0x80550307u
#define SCE_NP_MANAGER_ERROR_NOT_SIGNIN      0x8055050Bu

/* PSP2i's sceUtilityPsnGetStatus codes. */
enum { PSN_AVAILABLE = 0, PSN_BUSY = 1, PSN_WRONG_VERSION = 2, PSN_SHUTDOWN = 3, PSN_PROCESSING = 4, PSN_ERROR = 5 };

static const psp_np_backend *g_be;
void psp_np_set_backend(const psp_np_backend *be) { g_be = be; }

static void np_log(const char *fmt, ...) {
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fprintf(stderr, "np: %s\n", line);
    if (g_be && g_be->log) {
        char l2[520];
        snprintf(l2, sizeof l2, "np: %s", line);
        g_be->log(l2);
    }
}

const psp_np_backend *psp_np_backend_get(void) { return g_be; }
int psp_np_signed_in(void);

static int g_np_inited, g_service_inited, g_auth_inited, g_commerce_inited;

/* ---- sign-in state ------------------------------------------------------------------- */

static int signed_in(void) { return g_be && g_be->signin_state && g_be->signin_state() == PSP_NP_SIGNIN_OK; }
int psp_np_signed_in(void) { return signed_in(); }

/* ---- sceNp -------------------------------------------------------------------------------- */

static void hle_NpInit(void) {
    if (g_np_inited) { psp_ret(SCE_NP_ERROR_ALREADY_INITIALIZED); return; }
    g_np_inited = 1;
    psp_ret(0);
}
static void hle_NpTerm(void) { g_np_inited = 0; psp_ret(0); }

/* SceNpId: online ID (16 chars + NUL + 3 pad), opt[8], reserved[8]. */
static void hle_NpGetNpId(void) {
    const uint32_t out = psp_arg(0);
    if (!out) { psp_ret(SCE_NP_ERROR_INVALID_ARGUMENT); return; }
    if (!signed_in()) { psp_ret(SCE_NP_MANAGER_ERROR_NOT_SIGNIN); return; }
    uint8_t id[36];
    memset(id, 0, sizeof id);
    const char *name = g_be->online_id ? g_be->online_id() : "";
    strncpy((char *)id, name ? name : "", 16);
    psp_mem_write_block(out, id, sizeof id);
    psp_ret(0);
}

/* (int *is_restricted, int *age) -- from the backend's account; unrestricted
 * adult when it does not say. */
static void hle_NpGetContentRatingFlag(void) {
    if (!signed_in()) { psp_ret(SCE_NP_MANAGER_ERROR_NOT_SIGNIN); return; }
    if (psp_arg(0)) psp_write32(psp_arg(0), 0);
    if (psp_arg(1)) psp_write32(psp_arg(1), 20);
    psp_ret(0);
}
static void hle_NpGetChatRestrictionFlag(void) {
    if (!signed_in()) { psp_ret(SCE_NP_MANAGER_ERROR_NOT_SIGNIN); return; }
    if (psp_arg(0)) psp_write32(psp_arg(0), 0);
    psp_ret(0);
}

/* ---- sceNpService / sceNpCommerce2 ----------------------------------------------------------- */

static void hle_NpServiceInit(void) { g_service_inited = 1; psp_ret(0); }
static void hle_NpServiceTerm(void) { g_service_inited = 0; psp_ret(0); }
static void hle_NpCommerce2Init(void) { g_commerce_inited = 1; psp_ret(0); }
static void hle_NpCommerce2Term(void) { g_commerce_inited = 0; psp_ret(0); }

/* ---- sceUtilityPsn* (PSP2i's PSN sign-in) ------------------------------------------------- */

static int g_psn_active, g_psn_status = PSN_ERROR, g_psn_reported;

static void hle_PsnInitStart(void) {
    const uint32_t p = psp_arg(0);
    char title[32] = "";
    if (p) psp_str(psp_read32(p + 0x30 + 0x18), title, sizeof title);       /* titleIdPtr */
    np_log("PSN sign-in requested (mode %u, title \"%s\")", p ? psp_read32(p + 0x30) : 0, title);
    g_psn_reported = -1;
    if (!g_be || !g_be->signin_begin) {
        np_log("no PSN backend: sign-in fails (real PSN authentication is not implemented)");
        g_psn_status = PSN_ERROR;
        g_psn_active = 0;
        return;
    }
    g_psn_active = 1;
    g_psn_status = PSN_PROCESSING;
    g_be->signin_begin();
}

static void hle_PsnGetStatus(void) {
    if (g_psn_active && g_be && g_be->signin_state) {
        switch (g_be->signin_state()) {
        case PSP_NP_SIGNIN_OK:        g_psn_status = PSN_AVAILABLE; g_psn_active = 0; break;
        case PSP_NP_SIGNIN_FAILED:
        case PSP_NP_SIGNIN_CANCELLED: g_psn_status = PSN_ERROR;     g_psn_active = 0; break;
        default:                      g_psn_status = PSN_PROCESSING; break;
        }
    }
    if (g_psn_status != g_psn_reported) {
        static const char *const S[] = { "available (signed in)", "busy", "wrong version", "shutdown", "processing", "error (not signed in)" };
        np_log("PSN sign-in status -> %s", S[g_psn_status]);
        g_psn_reported = g_psn_status;
    }
    psp_ret((uint32_t)g_psn_status);
}

static void hle_PsnUpdate(void) { psp_ret(0); }
static void hle_PsnShutdownStart(void) {
    if (g_psn_active && g_be && g_be->signin_cancel) g_be->signin_cancel();
    g_psn_active = 0;
    psp_ret(0);
}

/* ---- sceNpAuth ----------------------------------------------------------------------------- */

#define MAX_AUTH 4
static struct {
    int used, delivered;
    uint32_t cb, cb_arg;
    uint8_t *ticket;
    uint32_t ticket_len;
    int failed;
    uint32_t error;
} g_req[MAX_AUTH];

static void hle_NpAuthInit(void) {
    g_auth_inited = 1;
    psp_ret(0);
}
static void hle_NpAuthTerm(void) {
    for (int i = 0; i < MAX_AUTH; i++) { free(g_req[i].ticket); memset(&g_req[i], 0, sizeof g_req[i]); }
    g_auth_inited = 0;
    psp_ret(0);
}

/* SceNpAuthRequestParameter: size, version{major,minor}, serviceId*, cookie*,
 * cookieSize, entitlementId*, consumedCount, ticketCb, cbArg. */
static void hle_NpAuthCreateStartRequest(void) {
    const uint32_t p = psp_arg(0);
    if (!g_auth_inited) { psp_ret(SCE_NP_AUTH_ERROR_NOT_INITIALIZED); return; }
    if (!p) { psp_ret(SCE_NP_AUTH_ERROR_INVALID_ARGUMENT); return; }
    const uint32_t size = psp_read32(p);
    char service[64] = "";
    psp_str(psp_read32(p + 8), service, sizeof service);
    const uint32_t cookie = psp_read32(p + 12), cookie_len = psp_read32(p + 16);
    const uint32_t cb = size >= 32 ? psp_read32(p + 28) : 0, cb_arg = size >= 36 ? psp_read32(p + 32) : 0;
    int id = -1;
    for (int i = 0; i < MAX_AUTH; i++) if (!g_req[i].used) { id = i; break; }
    if (id < 0) { psp_ret(SCE_NP_AUTH_ERROR_EBUSY); return; }
    memset(&g_req[id], 0, sizeof g_req[id]);
    g_req[id].used = 1;
    g_req[id].cb = cb;
    g_req[id].cb_arg = cb_arg;
    np_log("ticket request %d for service \"%s\" (ticket version %u.%u, cookie %u bytes, callback 0x%08X)",
           id + 1, service, psp_read32(p + 4) & 0xFFFF, psp_read32(p + 4) >> 16, cookie_len, cb);
    if (!signed_in() || !g_be->ticket_begin) {
        g_req[id].failed = 1;
        g_req[id].error = SCE_NP_MANAGER_ERROR_NOT_SIGNIN;
        np_log("ticket request %d: not signed in -- it will fail", id + 1);
    } else {
        uint8_t *ck = NULL;
        if (cookie && cookie_len && cookie_len < 4096) {
            ck = (uint8_t *)malloc(cookie_len);
            if (ck) psp_mem_read_block(ck, cookie, cookie_len);
        }
        g_be->ticket_begin(id, service, ck, ck ? cookie_len : 0);
        free(ck);
    }
    psp_ret((uint32_t)(id + 1));                 /* request IDs start at 1 */
}

void psp_np2_poll(void);                         /* np2.c */
void adhoc_pump(void);                           /* adhoc.c */

void psp_np_poll(void) {
    psp_np2_poll();
    adhoc_pump();
    for (int i = 0; i < MAX_AUTH; i++) {
        if (!g_req[i].used || g_req[i].delivered) continue;
        if (!g_req[i].failed && g_be && g_be->ticket_state) {
            uint32_t len = 0;
            const uint8_t *data = NULL;
            uint32_t err = 0;
            const int st = g_be->ticket_state(i, &data, &len, &err);
            if (st == 0) continue;                                     /* pending */
            if (st > 0 && data && len) {
                g_req[i].ticket = (uint8_t *)malloc(len);
                if (g_req[i].ticket) { memcpy(g_req[i].ticket, data, len); g_req[i].ticket_len = len; }
            } else {
                g_req[i].failed = 1;
                g_req[i].error = err ? err : 0x80550480u;              /* SCE_NP_AUTH_ERROR_UNKNOWN */
            }
        }
        g_req[i].delivered = 1;
        const uint32_t result = g_req[i].failed ? g_req[i].error : g_req[i].ticket_len;
        np_log("ticket request %d: %s (0x%08X) -> game callback", i + 1,
               g_req[i].failed ? "FAILED" : "ticket received", result);
        if (g_req[i].cb) psp_sched_post_call(g_req[i].cb, (uint32_t)(i + 1), result, g_req[i].cb_arg, 0, 0);
    }
}

static void hle_NpAuthGetTicket(void) {
    const uint32_t id = psp_arg(0), buf = psp_arg(1), len = psp_arg(2);
    if (id < 1 || id > MAX_AUTH || !g_req[id - 1].used) { psp_ret(SCE_NP_AUTH_ERROR_ESRCH); return; }
    if (!buf) { psp_ret(SCE_NP_AUTH_ERROR_INVALID_ARGUMENT); return; }
    if (g_req[id - 1].failed || !g_req[id - 1].ticket) { psp_ret(g_req[id - 1].failed ? g_req[id - 1].error : SCE_NP_AUTH_ERROR_EBUSY); return; }
    const uint32_t n = g_req[id - 1].ticket_len < len ? g_req[id - 1].ticket_len : len;
    psp_mem_write_block(buf, g_req[id - 1].ticket, n);
    np_log("game read ticket %u (%u of %u bytes)", id, n, g_req[id - 1].ticket_len);
    psp_ret(n);
}

static void hle_NpAuthAbortRequest(void) {
    const uint32_t id = psp_arg(0);
    if (id < 1 || id > MAX_AUTH || !g_req[id - 1].used) { psp_ret(SCE_NP_AUTH_ERROR_ESRCH); return; }
    if (g_be && g_be->ticket_cancel) g_be->ticket_cancel((int)id - 1);
    if (!g_req[id - 1].delivered) { g_req[id - 1].failed = 1; g_req[id - 1].error = SCE_NP_AUTH_ERROR_ABORTED; }
    psp_ret(0);
}

static void hle_NpAuthDestroyRequest(void) {
    const uint32_t id = psp_arg(0);
    if (id < 1 || id > MAX_AUTH || !g_req[id - 1].used) { psp_ret(SCE_NP_AUTH_ERROR_ESRCH); return; }
    if (g_be && g_be->ticket_cancel) g_be->ticket_cancel((int)id - 1);
    free(g_req[id - 1].ticket);
    memset(&g_req[id - 1], 0, sizeof g_req[id - 1]);
    psp_ret(0);
}

/* Most NP NIDs here come from newer firmware libraries whose NIDs are not
 * SHA-1 of a known name: they are registered unnamed (the toolkit's NID
 * check only accepts names that hash to the NID) and identified by their
 * behaviour, noted beside each. */
void psp_np_register(void) {
    psp_hle_register(0x857B47D3, "sceNp", NULL,                   hle_NpInit);   /* sceNpInit (behaviour; name unverified) */
    psp_hle_register(0x37E1E274, "sceNp", NULL,                   hle_NpTerm);   /* sceNpTerm (behaviour; name unverified) */
    psp_hle_register(0x633B5F71, "sceNp", NULL,                hle_NpGetNpId);   /* sceNpGetNpId (behaviour; name unverified) */
    psp_hle_register(0xBB069A87, "sceNp", NULL,   hle_NpGetContentRatingFlag);   /* sceNpGetContentRatingFlag (behaviour; name unverified) */
    psp_hle_register(0x1D60AE4B, "sceNp", NULL, hle_NpGetChatRestrictionFlag);   /* sceNpGetChatRestrictionFlag (behaviour; name unverified) */
    psp_hle_register(0x0F8F5821, "sceNpService", NULL,     hle_NpServiceInit);   /* sceNpServiceInit (behaviour; name unverified) */
    psp_hle_register(0x00ACFAC3, "sceNpService", NULL,     hle_NpServiceTerm);   /* sceNpServiceTerm (behaviour; name unverified) */
    psp_hle_register(0x0E9956E3, "sceNpCommerce2", NULL, hle_NpCommerce2Init);   /* sceNpCommerce2Init (behaviour; name unverified) */
    psp_hle_register(0xA5A34EA4, "sceNpCommerce2", NULL, hle_NpCommerce2Term);   /* sceNpCommerce2Term (behaviour; name unverified) */
    psp_hle_register(0xA1DE86F8, "sceNpAuth", NULL,               hle_NpAuthInit);   /* sceNpAuthInit (behaviour; name unverified) */
    psp_hle_register(0x4EC1F667, "sceNpAuth", NULL,               hle_NpAuthTerm);   /* sceNpAuthTerm (behaviour; name unverified) */
    psp_hle_register(0xCD86A656, "sceNpAuth", NULL, hle_NpAuthCreateStartRequest);   /* sceNpAuthCreateStartRequest (behaviour; name unverified) */
    psp_hle_register(0x3F1C1F70, "sceNpAuth", NULL,          hle_NpAuthGetTicket);   /* sceNpAuthGetTicket (behaviour; name unverified) */
    psp_hle_register(0xD99455DD, "sceNpAuth", NULL,       hle_NpAuthAbortRequest);   /* sceNpAuthAbortRequest (behaviour; name unverified) */
    psp_hle_register(0x72BB0467, "sceNpAuth", NULL,     hle_NpAuthDestroyRequest);   /* sceNpAuthDestroyRequest (behaviour; name unverified) */
    psp_hle_register(0xA7BB7C67, "sceUtility", "sceUtilityPsnInitStart",     hle_PsnInitStart);
    psp_hle_register(0x094198B8, "sceUtility", "sceUtilityPsnGetStatus",     hle_PsnGetStatus);
    psp_hle_register(0x0940A1B9, "sceUtility", "sceUtilityPsnUpdate",        hle_PsnUpdate);
    psp_hle_register(0xC130D441, "sceUtility", "sceUtilityPsnShutdownStart", hle_PsnShutdownStart);
}
