/* psprecomp — NP matching 2 (sceNpMatching2): matchmaking servers, worlds
 * and rooms for PSN games.
 *
 * The servers and worlds come from the backend (psp_np_backend.m2_*), which
 * asks a compatible matching server on the signed-in session -- nothing is
 * made up here: no backend, not signed in, or an empty answer is reported to
 * the game as the PSP firmware would report an unreachable server.
 *
 *   Init / Term, CreateContext / DestroyContext   bookkeeping; the context
 *                                       remembers the game's communication
 *                                       ID ("NPWR01446_00" for PSP2i)
 *   ContextStart                        fetches the server list (blocking,
 *                                       as the firmware caches it here)
 *   GetServerIdListLocal                that cached list
 *   GetServerInfo                       a server's status, from that list,
 *                                       through the request callback
 *   GetWorldInfoList                    the server's worlds (backend),
 *                                       through the request callback
 *   RegisterSignalingCallback, SignalingGetConnectionStatus, AbortRequest
 *   room requests (CreateJoinRoom, JoinRoom, SearchRoom, LeaveRoom, room
 *   data, room messages, kick, user info)  not yet carried to the server:
 *                                       logged with their parameters, and
 *                                       answered through the request
 *                                       callback with "service unavailable"
 *                                       so the game is never left waiting
 *
 * Request callbacks are called as the firmware calls them:
 *   cb(ctxId, reqId, event, errorCode, data, cbArg)
 * with `data` pointing to the event's response structure in guest memory
 * (valid during the callback). The layouts follow PPSSPP's sceNp2 (Komak57's
 * fork, master), which was checked against np_matching2.prx.
 *
 * NIDs: none of these hash to a known name (newer firmware library); they
 * are registered unnamed and identified by behaviour, noted beside each. */

#include "psprecomp/hle.h"
#include "psprecomp/net.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const psp_np_backend *psp_np_backend_get(void);     /* np.c */
int psp_np_signed_in(void);                          /* np.c */

#define M2_OK                               0u
#define M2_ERROR_ALREADY_INITIALIZED        0x80550C01u
#define M2_ERROR_NOT_INITIALIZED            0x80550C02u
#define M2_ERROR_CONTEXT_MAX                0x80550C05u
#define M2_ERROR_CONTEXT_NOT_FOUND          0x80550C06u
#define M2_ERROR_CONTEXT_NOT_STARTED        0x80550C08u
#define M2_ERROR_SERVER_NOT_FOUND           0x80550C09u
#define M2_ERROR_INVALID_ARGUMENT           0x80550C0Au
#define M2_ERROR_INVALID_SERVER_ID          0x80550C0Cu
#define M2_ERROR_SERVER_NOT_AVAILABLE       0x80550C2Du
#define M2_ERROR_CONTEXT_ALREADY_STARTED    0x80550CE1u
#define M2_SERVER_ERROR_SERVICE_UNAVAILABLE 0x80550D02u

/* Request events (np_matching2.prx). */
enum {
    EV_GetServerInfo = 0x0001, EV_GetWorldInfoList = 0x0002, EV_GetUserInfoList = 0x0004,
    EV_SetRoomDataExternal = 0x0006, EV_GetRoomDataExternalList = 0x0007,
    EV_CreateJoinRoom = 0x0101, EV_JoinRoom = 0x0102, EV_LeaveRoom = 0x0103, EV_KickoutRoomMember = 0x0105,
    EV_SearchRoom = 0x0106, EV_SendRoomMessage = 0x0108, EV_SetRoomDataInternal = 0x0109,
};

enum { SERVER_AVAILABLE = 1, SERVER_UNAVAILABLE = 2 };

static void m2_log(const char *fmt, ...) {
    char line[600];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fprintf(stderr, "np: m2 %s\n", line);
    const psp_np_backend *be = psp_np_backend_get();
    if (be && be->log) {
        char l2[620];
        snprintf(l2, sizeof l2, "np: m2 %s", line);
        be->log(l2);
    }
}

/* ---- state ------------------------------------------------------------------------- */

#define MAX_CTX 7
#define MAX_SERVERS 16
#define MAX_WORLDS 16

static int g_inited;
static struct {
    int used, started;
    char com_id[16];                 /* "NPWR01446_00" */
    uint32_t next_req;
    uint16_t servers[MAX_SERVERS];
    int nservers;
    uint32_t sig_cb, sig_arg;
} g_ctx[MAX_CTX + 1];                /* context IDs 1..7 */

/* Event data handed to callbacks: a few rotating blocks of guest memory. */
#define EV_SLOTS 8
#define EV_SLOT_SIZE 0x600
static uint32_t g_ev_base;
static int g_ev_next;
static uint32_t ev_block(void) {
    if (!g_ev_base) g_ev_base = psp_sysmem_alloc(EV_SLOTS * EV_SLOT_SIZE, 1);
    if (!g_ev_base) return 0;
    const uint32_t a = g_ev_base + (uint32_t)(g_ev_next++ % EV_SLOTS) * EV_SLOT_SIZE;
    for (uint32_t i = 0; i < EV_SLOT_SIZE; i += 4) psp_write32(a + i, 0);
    return a;
}

static int ctx_ok(uint32_t id) { return id >= 1 && id <= MAX_CTX && g_ctx[id].used; }

static const char *event_name(uint32_t ev) {
    switch (ev) {
    case EV_GetServerInfo: return "GetServerInfo";
    case EV_GetWorldInfoList: return "GetWorldInfoList";
    case EV_GetUserInfoList: return "GetUserInfoList";
    case EV_SetRoomDataExternal: return "SetRoomDataExternal";
    case EV_GetRoomDataExternalList: return "GetRoomDataExternalList";
    case EV_CreateJoinRoom: return "CreateJoinRoom";
    case EV_JoinRoom: return "JoinRoom";
    case EV_LeaveRoom: return "LeaveRoom";
    case EV_KickoutRoomMember: return "KickoutRoomMember";
    case EV_SearchRoom: return "SearchRoom";
    case EV_SendRoomMessage: return "SendRoomMessage";
    case EV_SetRoomDataInternal: return "SetRoomDataInternal";
    default: return "?";
    }
}

/* SceNpMatching2RequestOptParam: cbFunc, cbFuncArg, timeout, appReqId. A new
 * request ID goes to *assignedReqIdPtr; returns it. */
static uint32_t new_request(uint32_t ctx, uint32_t opt, uint32_t assigned_ptr, uint32_t *cb, uint32_t *cb_arg) {
    *cb = opt ? psp_read32(opt) : 0;
    *cb_arg = opt ? psp_read32(opt + 4) : 0;
    uint32_t id = ++g_ctx[ctx].next_req;
    if (!id) id = ++g_ctx[ctx].next_req;              /* 0 means "aborted" to the game */
    if (assigned_ptr) psp_write32(assigned_ptr, id);
    return id;
}

/* The request callback: cb(ctxId, reqId, event, errorCode, data, cbArg). */
static void deliver(uint32_t ctx, uint32_t req, uint32_t ev, uint32_t err, uint32_t data, uint32_t cb, uint32_t cb_arg) {
    m2_log("-> %s callback 0x%08X(ctx %u, req %u, event 0x%04X, error 0x%08X, data 0x%08X, arg 0x%08X)%s",
           event_name(ev), cb, ctx, req, ev, err, data, cb_arg, cb ? "" : " -- no callback, dropped");
    if (cb) psp_sched_post_call6(cb, ctx, req, ev, err, data, cb_arg);
}

/* ---- init / contexts ----------------------------------------------------------------- */

/* sceNpMatching2Init(poolSize, matchingPriority, threadStackSize, signalingPriority) */
static void hle_Init(void) {
    m2_log("Init(pool %u, priority %u, stack %u, signaling priority %u)", psp_arg(0), psp_arg(1), psp_arg(2), psp_arg(3));
    if (g_inited) { psp_ret(M2_ERROR_ALREADY_INITIALIZED); return; }
    memset(g_ctx, 0, sizeof g_ctx);
    g_inited = 1;
    psp_ret(M2_OK);
}

static void hle_Term(void) {
    m2_log("Term()");
    memset(g_ctx, 0, sizeof g_ctx);
    g_inited = 0;
    psp_ret(M2_OK);
}

/* sceNpMatching2CreateContext(SceNpCommunicationId *, passphrase *, u16 *ctxId, optionFlags)
 * SceNpCommunicationId: char data[9], term, u8 num, dummy. */
static void hle_CreateContext(void) {
    const uint32_t cid = psp_arg(0), pass = psp_arg(1), out = psp_arg(2), flags = psp_arg(3);
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!cid || !pass || !out) { psp_ret(M2_ERROR_INVALID_ARGUMENT); return; }
    char data[10];
    for (int i = 0; i < 9; i++) data[i] = (char)psp_read8(cid + (uint32_t)i);
    data[9] = '\0';
    const unsigned num = psp_read8(cid + 10);
    int id = 0;
    for (int i = 1; i <= MAX_CTX; i++) if (!g_ctx[i].used) { id = i; break; }
    if (!id) { psp_ret(M2_ERROR_CONTEXT_MAX); return; }
    memset(&g_ctx[id], 0, sizeof g_ctx[id]);
    g_ctx[id].used = 1;
    snprintf(g_ctx[id].com_id, sizeof g_ctx[id].com_id, "%.9s_%02u", data, num % 100);
    psp_write16(out, (uint16_t)id);
    m2_log("CreateContext: communication ID %s, options 0x%X -> context %d", g_ctx[id].com_id, flags, id);
    psp_ret(M2_OK);
}

static void hle_DestroyContext(void) {
    const uint32_t ctx = psp_arg(0);
    m2_log("DestroyContext(%u)", ctx);
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    memset(&g_ctx[ctx], 0, sizeof g_ctx[ctx]);
    psp_ret(M2_OK);
}

/* The firmware fetches the server list here; GetServerIdListLocal reads it. */
static void hle_ContextStart(void) {
    const uint32_t ctx = psp_arg(0);
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    if (g_ctx[ctx].started) { psp_ret(M2_ERROR_CONTEXT_ALREADY_STARTED); return; }
    const psp_np_backend *be = psp_np_backend_get();
    m2_log("ContextStart(%u): asking the matching server for the server list of %s", ctx, g_ctx[ctx].com_id);
    if (!psp_np_signed_in() || !be || !be->m2_server_list) {
        m2_log("ContextStart: not signed in (or no matching backend) -> service unavailable");
        psp_ret(M2_SERVER_ERROR_SERVICE_UNAVAILABLE);
        return;
    }
    uint32_t err = 0;
    const int n = be->m2_server_list(g_ctx[ctx].com_id, g_ctx[ctx].servers, MAX_SERVERS, &err);
    if (n < 0) {
        m2_log("ContextStart: server list request failed -> 0x%08X", err);
        psp_ret(err ? err : M2_SERVER_ERROR_SERVICE_UNAVAILABLE);
        return;
    }
    g_ctx[ctx].nservers = n;
    g_ctx[ctx].started = 1;
    char list[128] = "";
    for (int i = 0; i < n; i++) snprintf(list + strlen(list), sizeof list - strlen(list), "%s%u", i ? "," : "", g_ctx[ctx].servers[i]);
    m2_log("ContextStart: %d server(s) for %s: %s", n, g_ctx[ctx].com_id, n ? list : "(none -- the matching server has none configured for this game)");
    psp_ret(M2_OK);
}

static void hle_ContextStop(void) {
    const uint32_t ctx = psp_arg(0);
    m2_log("ContextStop(%u)", ctx);
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    if (!g_ctx[ctx].started) { psp_ret(M2_ERROR_CONTEXT_NOT_STARTED); return; }
    g_ctx[ctx].started = 0;
    psp_ret(M2_OK);
}

/* sceNpMatching2GetServerIdListLocal(ctx, u16 *ids, max) -> count */
static void hle_GetServerIdListLocal(void) {
    const uint32_t ctx = psp_arg(0), out = psp_arg(1), max = psp_arg(2);
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    if (!g_ctx[ctx].started) { psp_ret(M2_ERROR_CONTEXT_NOT_STARTED); return; }
    if (!g_ctx[ctx].nservers) { m2_log("GetServerIdListLocal(%u): no servers -> server not found", ctx); psp_ret(M2_ERROR_SERVER_NOT_FOUND); return; }
    int n = g_ctx[ctx].nservers < (int)max ? g_ctx[ctx].nservers : (int)max;
    if (out) for (int i = 0; i < n; i++) psp_write16(out + 2u * (uint32_t)i, g_ctx[ctx].servers[i]);
    else n = g_ctx[ctx].nservers;
    m2_log("GetServerIdListLocal(%u, max %u) -> %d", ctx, max, n);
    psp_ret((uint32_t)n);
}

/* sceNpMatching2GetServerInfo(ctx, {u16 serverId} *, optParam *, u32 *assignedReqId)
 * Response: {u16 id, u8 status, u8 pad}. */
static void hle_GetServerInfo(void) {
    const uint32_t ctx = psp_arg(0), req = psp_arg(1), opt = psp_arg(2), assigned = psp_arg(3);
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    if (!assigned) { psp_ret(M2_ERROR_INVALID_ARGUMENT); return; }
    uint32_t cb, arg;
    const uint32_t id = new_request(ctx, opt, assigned, &cb, &arg);
    const uint16_t server = req ? psp_read16(req) : 0;
    m2_log("GetServerInfo(ctx %u, server %u) request %u", ctx, server, id);
    if (!g_inited) { deliver(ctx, id, EV_GetServerInfo, M2_ERROR_NOT_INITIALIZED, 0, cb, arg); psp_ret(M2_OK); return; }
    if (!req) { deliver(ctx, id, EV_GetServerInfo, M2_ERROR_INVALID_SERVER_ID, 0, cb, arg); psp_ret(M2_OK); return; }
    int known = 0;
    for (int i = 0; i < g_ctx[ctx].nservers; i++) known |= g_ctx[ctx].servers[i] == server;
    const uint32_t d = ev_block();
    if (!d) { deliver(ctx, id, EV_GetServerInfo, M2_ERROR_SERVER_NOT_AVAILABLE, 0, cb, arg); psp_ret(M2_OK); return; }
    psp_write16(d, server);
    psp_write8(d + 2, known ? SERVER_AVAILABLE : SERVER_UNAVAILABLE);
    m2_log("GetServerInfo: server %u %s", server, known ? "available" : "unavailable (not in the server list)");
    deliver(ctx, id, EV_GetServerInfo, M2_OK, d, cb, arg);
    psp_ret(M2_OK);
}

/* sceNpMatching2GetWorldInfoList(ctx, {u16 serverId} *, optParam *, u32 *assignedReqId)
 * Response: {SceNpMatching2World list *, u32 count}; each list entry is 0x40
 * bytes: u32 next, then u32 worldId, numOfLobby, maxNumOfTotalLobbyMember,
 * curNumOfTotalLobbyMember, curNumOfRoom, curNumOfTotalRoomMember, u8
 * withEntitlementId, entitlementId[32], pad. */
static void hle_GetWorldInfoList(void) {
    const uint32_t ctx = psp_arg(0), req = psp_arg(1), opt = psp_arg(2), assigned = psp_arg(3);
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    if (!assigned) { psp_ret(M2_ERROR_INVALID_ARGUMENT); return; }
    uint32_t cb, arg;
    const uint32_t id = new_request(ctx, opt, assigned, &cb, &arg);
    const uint16_t server = req ? psp_read16(req) : 0;
    m2_log("GetWorldInfoList(ctx %u, server %u) request %u", ctx, server, id);
    if (!g_inited) { deliver(ctx, id, EV_GetWorldInfoList, M2_ERROR_NOT_INITIALIZED, 0, cb, arg); psp_ret(M2_OK); return; }
    int known = 0;
    for (int i = 0; i < g_ctx[ctx].nservers; i++) known |= g_ctx[ctx].servers[i] == server;
    if (!server || !known) { deliver(ctx, id, EV_GetWorldInfoList, M2_ERROR_INVALID_SERVER_ID, 0, cb, arg); psp_ret(M2_OK); return; }
    const psp_np_backend *be = psp_np_backend_get();
    if (!psp_np_signed_in() || !be || !be->m2_world_list) {
        deliver(ctx, id, EV_GetWorldInfoList, M2_SERVER_ERROR_SERVICE_UNAVAILABLE, 0, cb, arg);
        psp_ret(M2_OK);
        return;
    }
    uint32_t worlds[MAX_WORLDS], err = 0;
    const int n = be->m2_world_list(g_ctx[ctx].com_id, server, worlds, MAX_WORLDS, &err);
    if (n <= 0) {
        m2_log("GetWorldInfoList: %s -> 0x%08X", n < 0 ? "request failed" : "no worlds on this server", n < 0 ? err : M2_SERVER_ERROR_SERVICE_UNAVAILABLE);
        deliver(ctx, id, EV_GetWorldInfoList, n < 0 && err ? err : M2_SERVER_ERROR_SERVICE_UNAVAILABLE, 0, cb, arg);
        psp_ret(M2_OK);
        return;
    }
    const uint32_t d = ev_block();
    if (!d) { deliver(ctx, id, EV_GetWorldInfoList, M2_ERROR_SERVER_NOT_AVAILABLE, 0, cb, arg); psp_ret(M2_OK); return; }
    const uint32_t list = d + 0x10;
    psp_write32(d, list);
    psp_write32(d + 4, (uint32_t)n);
    char ids[160] = "";
    for (int i = 0; i < n; i++) {
        const uint32_t e = list + 0x40u * (uint32_t)i;
        psp_write32(e, i + 1 < n ? e + 0x40 : 0);
        psp_write32(e + 4, worlds[i]);
        snprintf(ids + strlen(ids), sizeof ids - strlen(ids), "%s%u", i ? "," : "", worlds[i]);
    }
    m2_log("GetWorldInfoList: %d world(s) on server %u: %s", n, server, ids);
    deliver(ctx, id, EV_GetWorldInfoList, M2_OK, d, cb, arg);
    psp_ret(M2_OK);
}

/* ---- signaling ----------------------------------------------------------------------- */

static void hle_RegisterSignalingCallback(void) {
    const uint32_t ctx = psp_arg(0), cb = psp_arg(1), arg = psp_arg(2);
    m2_log("RegisterSignalingCallback(ctx %u, callback 0x%08X, arg 0x%08X)", ctx, cb, arg);
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    g_ctx[ctx].sig_cb = cb;
    g_ctx[ctx].sig_arg = arg;
    psp_ret(M2_OK);
}

/* (ctx, self?, roomId lo, roomId hi, memberId, int *connStatus, inaddr *, u16 *port)
 * No peer connections are made yet: every peer reports inactive (0). */
static void hle_SignalingGetConnectionStatus(void) {
    const uint32_t ctx = psp_arg(0), status = psp_arg(5), ip = psp_arg(6), port = psp_arg(7);
    m2_log("SignalingGetConnectionStatus(ctx %u, room %08X%08X, member %u) -> inactive", ctx, psp_arg(3), psp_arg(2), psp_arg(4));
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    if (status) psp_write32(status, 0);
    if (ip) psp_write32(ip, 0);
    if (port) psp_write16(port, 0);
    psp_ret(M2_OK);
}

static void hle_AbortRequest(void) {
    m2_log("AbortRequest(ctx %u, request %u)", psp_arg(0), psp_arg(1));
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(psp_arg(0))) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    psp_ret(M2_OK);                     /* requests are answered as they are made */
}

/* ---- requests not yet carried to the server --------------------------------------------- */

static void log_param(const char *what, uint32_t p, uint32_t n) {
    if (!p) { m2_log("  %s: (null)", what); return; }
    char hex[16 * 3 + 1];
    for (uint32_t i = 0; i < n; i += 16) {
        for (uint32_t j = 0; j < 16; j++) snprintf(hex + 3 * j, 4, "%02x ", psp_read8(p + i + j));
        m2_log("  %s +%02X: %s", what, i, hex);
    }
}

/* Async request (ctx, reqParam *, optParam *, [roomEventCb, roomMsgCb,] u32 *assignedReqId). */
static void unimplemented_request(const char *name, uint32_t ev, int assigned_arg) {
    const uint32_t ctx = psp_arg(0), req = psp_arg(1), opt = psp_arg(2), assigned = psp_arg(assigned_arg);
    m2_log("%s(ctx %u, param 0x%08X, opt 0x%08X%s) -- not carried to the matching server yet", name, ctx, req, opt,
           assigned_arg == 5 ? ", with room callbacks" : "");
    if (assigned_arg == 5) m2_log("  room event callback 0x%08X, room message callback 0x%08X", psp_arg(3), psp_arg(4));
    log_param("param", req, 0x40);
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    if (!assigned) { psp_ret(M2_ERROR_INVALID_ARGUMENT); return; }
    uint32_t cb, arg;
    const uint32_t id = new_request(ctx, opt, assigned, &cb, &arg);
    deliver(ctx, id, ev, M2_SERVER_ERROR_SERVICE_UNAVAILABLE, 0, cb, arg);
    psp_ret(M2_OK);
}

static void hle_CreateJoinRoom(void)          { unimplemented_request("CreateJoinRoom", EV_CreateJoinRoom, 5); }
static void hle_JoinRoom(void)                { unimplemented_request("JoinRoom", EV_JoinRoom, 5); }
static void hle_LeaveRoom(void)               { unimplemented_request("LeaveRoom", EV_LeaveRoom, 3); }
static void hle_SearchRoom(void)              { unimplemented_request("SearchRoom", EV_SearchRoom, 3); }
static void hle_GetRoomDataExternalList(void) { unimplemented_request("GetRoomDataExternalList", EV_GetRoomDataExternalList, 3); }
static void hle_SetRoomDataExternal(void)     { unimplemented_request("SetRoomDataExternal", EV_SetRoomDataExternal, 3); }
static void hle_SetRoomDataInternal(void)     { unimplemented_request("SetRoomDataInternal", EV_SetRoomDataInternal, 3); }
static void hle_SendRoomMessage(void)         { unimplemented_request("SendRoomMessage", EV_SendRoomMessage, 3); }
static void hle_KickoutRoomMember(void)       { unimplemented_request("KickoutRoomMember", EV_KickoutRoomMember, 3); }
static void hle_GetUserInfoList(void)         { unimplemented_request("GetUserInfoList", EV_GetUserInfoList, 3); }

void psp_np2_register(void) {
    psp_hle_register(0x2E61F6E1, "sceNpMatching2", NULL, hle_Init);                          /* sceNpMatching2Init */
    psp_hle_register(0x8BF37D8C, "sceNpMatching2", NULL, hle_Term);                          /* sceNpMatching2Term */
    psp_hle_register(0x5030CC53, "sceNpMatching2", NULL, hle_CreateContext);                 /* sceNpMatching2CreateContext */
    psp_hle_register(0x3DE70241, "sceNpMatching2", NULL, hle_DestroyContext);                /* sceNpMatching2DestroyContext */
    psp_hle_register(0x190FF903, "sceNpMatching2", NULL, hle_ContextStart);                  /* sceNpMatching2ContextStart */
    psp_hle_register(0x2B3892FC, "sceNpMatching2", NULL, hle_ContextStop);                   /* sceNpMatching2ContextStop */
    psp_hle_register(0xF47342FC, "sceNpMatching2", NULL, hle_GetServerIdListLocal);          /* sceNpMatching2GetServerIdListLocal */
    psp_hle_register(0x4EE3A8EC, "sceNpMatching2", NULL, hle_GetServerInfo);                 /* sceNpMatching2GetServerInfo */
    psp_hle_register(0xA53E7C69, "sceNpMatching2", NULL, hle_GetWorldInfoList);              /* sceNpMatching2GetWorldInfoList */
    psp_hle_register(0xA3C298D1, "sceNpMatching2", NULL, hle_RegisterSignalingCallback);     /* sceNpMatching2RegisterSignalingCallback */
    psp_hle_register(0x6D6D0C75, "sceNpMatching2", NULL, hle_SignalingGetConnectionStatus);  /* sceNpMatching2SignalingGetConnectionStatus */
    psp_hle_register(0xFADBA9DB, "sceNpMatching2", NULL, hle_AbortRequest);                  /* sceNpMatching2AbortRequest */
    psp_hle_register(0xAAD0946A, "sceNpMatching2", NULL, hle_CreateJoinRoom);                /* sceNpMatching2CreateJoinRoom */
    psp_hle_register(0x7BBFC427, "sceNpMatching2", NULL, hle_JoinRoom);                      /* sceNpMatching2JoinRoom */
    psp_hle_register(0xC870535A, "sceNpMatching2", NULL, hle_LeaveRoom);                     /* sceNpMatching2LeaveRoom */
    psp_hle_register(0x81C13E6D, "sceNpMatching2", NULL, hle_SearchRoom);                    /* sceNpMatching2SearchRoom */
    psp_hle_register(0x12C5A111, "sceNpMatching2", NULL, hle_GetRoomDataExternalList);       /* sceNpMatching2GetRoomDataExternalList */
    psp_hle_register(0xD7D4AEB2, "sceNpMatching2", NULL, hle_SetRoomDataExternal);           /* sceNpMatching2SetRoomDataExternal */
    psp_hle_register(0xE6C93DBD, "sceNpMatching2", NULL, hle_SetRoomDataInternal);           /* sceNpMatching2SetRoomDataInternal */
    psp_hle_register(0xF940D9AD, "sceNpMatching2", NULL, hle_SendRoomMessage);               /* sceNpMatching2SendRoomMessage */
    psp_hle_register(0x97529ECC, "sceNpMatching2", NULL, hle_KickoutRoomMember);             /* sceNpMatching2KickoutRoomMember */
    psp_hle_register(0xC8FC5D41, "sceNpMatching2", NULL, hle_GetUserInfoList);               /* sceNpMatching2GetUserInfoList */
}
