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
 *   room requests (SearchRoom, CreateJoinRoom, JoinRoom, LeaveRoom, room
 *   data, room messages)                carried by the backend
 *                                       (m2_room_request); it completes them
 *                                       with psp_np2_request_done, and turns
 *                                       server notifications into room
 *                                       events / room messages
 *   KickoutRoomMember, GetUserInfoList  the server has no such request:
 *                                       answered as PPSSPP does (kick: OK;
 *                                       user info: service unavailable)
 *
 * Room event callbacks (registered by CreateJoinRoom / JoinRoom) are called
 * as PSP2i's handlers read them (0x08CB3410, 0x08CB37B8):
 *   room event:   cb(ctxId, memberId, roomId lo, roomId hi, event, data, arg)
 *   room message: cb(ctxId, 0, roomId lo, roomId hi, memberId, event, data, arg)
 * (the 64-bit room ID in an even register pair, as the PSP EABI passes it).
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
#include "p2p.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
    uint32_t room_cb, room_arg, msg_cb, msg_arg;    /* from CreateJoinRoom / JoinRoom */
} g_ctx[MAX_CTX + 1];                /* context IDs 1..7 */

/* Requests waiting for the backend: request ID -> where the answer goes. */
#define MAX_REQS 64
static struct { int used; uint32_t id, ctx, cb, arg, ev; } g_req[MAX_REQS];

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

/* Variable-size event data (room data with its members and attributes): a
 * ring in guest memory. The game copies what it needs during the callback;
 * a block is reused only after the whole ring has been gone round. */
#define RING_SIZE (256u * 1024u)
static uint32_t g_ring, g_ring_size, g_ring_pos;
uint32_t psp_np2_alloc(uint32_t size) {
    if (!g_ring) {
        for (g_ring_size = RING_SIZE; g_ring_size >= 0x10000 && !g_ring; g_ring_size /= 2)
            g_ring = psp_sysmem_alloc(g_ring_size, 1);
        if (!g_ring) return 0;
        g_ring_size *= 2;                                  /* undo the loop's last halving */
    }
    size = (size + 7u) & ~7u;
    if (!size || size > g_ring_size) return 0;
    if (g_ring_pos + size > g_ring_size) g_ring_pos = 0;
    const uint32_t a = g_ring + g_ring_pos;
    g_ring_pos += size;
    for (uint32_t i = 0; i < size; i += 4) psp_write32(a + i, 0);
    return a;
}

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

/* The request callback: cb(ctxId, reqId, event, errorCode, data, cbArg).
 * Never during the request: the game records "query sent" after the call
 * returns, and a callback run before that (a blocking server request leaves
 * a vblank overdue, so a posted call would run at once) is overwritten by
 * it -- PSP2i then waits forever ("connecting to world"). Callbacks are
 * queued and posted from psp_np2_poll a few vblanks *and* some real time
 * later, as the firmware's matching thread answers some time after the
 * request. Vblanks alone are not enough: after a blocking request the
 * scheduler replays the missed vblanks in a burst, before the game runs
 * another instruction. */
#define CB_DELAY_POLLS 3
#define CB_DELAY_MS    100
#define MAX_PENDING 64
static struct { uint32_t cb, a[8]; unsigned due; uint64_t due_ms; } g_pending[MAX_PENDING];

static uint64_t now_ms(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
static int g_npending;
static unsigned g_polls;

static void queue_call(uint32_t cb, const uint32_t a[8]) {
    if (g_npending >= MAX_PENDING) { m2_log("callback queue full: dropped"); return; }
    g_pending[g_npending].cb = cb;
    memcpy(g_pending[g_npending].a, a, sizeof g_pending[g_npending].a);
    g_pending[g_npending].due = g_polls + CB_DELAY_POLLS;
    g_pending[g_npending].due_ms = now_ms() + CB_DELAY_MS;
    g_npending++;
}

static void deliver(uint32_t ctx, uint32_t req, uint32_t ev, uint32_t err, uint32_t data, uint32_t cb, uint32_t cb_arg) {
    m2_log("-> %s callback 0x%08X(ctx %u, req %u, event 0x%04X, error 0x%08X, data 0x%08X, arg 0x%08X)%s",
           event_name(ev), cb, ctx, req, ev, err, data, cb_arg, cb ? "" : " -- no callback, dropped");
    if (!cb) return;
    const uint32_t a[8] = { ctx, req, ev, err, data, cb_arg, 0, 0 };
    queue_call(cb, a);
}

/* Once per vblank (from psp_np_poll). */
void psp_np2_poll(void) {
    g_polls++;
    const psp_np_backend *be = psp_np_backend_get();
    if (g_inited && be && be->m2_poll) be->m2_poll();
    p2p_pump();
    int k = 0;
    for (int i = 0; i < g_npending; i++) {
        if ((int)(g_polls - g_pending[i].due) >= 0 && now_ms() >= g_pending[i].due_ms)
            psp_sched_post_call8(g_pending[i].cb, g_pending[i].a);
        else g_pending[k++] = g_pending[i];
    }
    g_npending = k;
}

/* ---- what the backend calls ----------------------------------------------------------- */

void psp_np2_request_done(uint32_t req_id, uint32_t error, uint32_t data) {
    for (int i = 0; i < MAX_REQS; i++) {
        if (!g_req[i].used || g_req[i].id != req_id) continue;
        g_req[i].used = 0;
        deliver(g_req[i].ctx, req_id, g_req[i].ev, error, data, g_req[i].cb, g_req[i].arg);
        return;
    }
    m2_log("answer for request %u, which no longer waits: dropped", req_id);
}

/* The context with room callbacks (the one that created or joined the room). */
static int room_ctx(void) {
    for (int i = 1; i <= MAX_CTX; i++) if (g_ctx[i].used && (g_ctx[i].room_cb || g_ctx[i].msg_cb)) return i;
    return 0;
}

void psp_np2_room_event(uint64_t room_id, uint16_t member_id, uint16_t event, uint32_t data) {
    const int c = room_ctx();
    m2_log("-> room event 0x%04X (room 0x%016llX, member %u, data 0x%08X) to callback 0x%08X",
           event, (unsigned long long)room_id, member_id, data, c ? g_ctx[c].room_cb : 0);
    if (!c || !g_ctx[c].room_cb) return;
    const uint32_t a[8] = { (uint32_t)c, member_id, (uint32_t)room_id, (uint32_t)(room_id >> 32), event, data, g_ctx[c].room_arg, 0 };
    queue_call(g_ctx[c].room_cb, a);
}

void psp_np2_room_message(uint64_t room_id, uint16_t member_id, uint16_t event, uint32_t data) {
    const int c = room_ctx();
    m2_log("-> room message 0x%04X (room 0x%016llX, from member %u, data 0x%08X) to callback 0x%08X",
           event, (unsigned long long)room_id, member_id, data, c ? g_ctx[c].msg_cb : 0);
    if (!c || !g_ctx[c].msg_cb) return;
    const uint32_t a[8] = { (uint32_t)c, 0, (uint32_t)room_id, (uint32_t)(room_id >> 32), member_id, event, data, g_ctx[c].msg_arg };
    queue_call(g_ctx[c].msg_cb, a);
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
    memset(g_req, 0, sizeof g_req);
    g_npending = 0;
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

/* The game's signaling callback, as np_matching2.prx calls it (PSP2i 0x08CB35FC):
 * cb(ctxId, ctx pointer, roomId lo, roomId hi, peerMemberId, event, errorCode, cbArg).
 * Events from p2p.c: Dead 0x5101, Established 0x5102, PeerActivated 0x5104,
 * PeerDeactivated 0x5105, MutualActivated 0x5106. */
void psp_np2_signaling_event(uint64_t room, uint16_t member, uint16_t event, uint32_t error) {
    int c = 0;
    for (int i = 1; i <= MAX_CTX; i++) if (g_ctx[i].used && g_ctx[i].sig_cb) { c = i; break; }
    m2_log("-> signaling event 0x%04X (room 0x%016llX, member %u, error 0x%08X) to callback 0x%08X",
           event, (unsigned long long)room, member, error, c ? g_ctx[c].sig_cb : 0);
    if (!c) return;
    const uint32_t a[8] = { (uint32_t)c, 0, (uint32_t)room, (uint32_t)(room >> 32), member, event, error, g_ctx[c].sig_arg };
    queue_call(g_ctx[c].sig_cb, a);
}

#define M2_SIGNALING_ERROR_PEER_NOT_FOUND 0x80550E19u   /* SCE_NP_MATCHING2_SIGNALING_ERROR_MATCHING2_PEER_NOT_FOUND */
#define SIGNALING_ERROR_CONN_NOT_FOUND    0x8002A80Eu   /* SCE_NP_SIGNALING_ERROR_CONN_NOT_FOUND */

/* (ctx, self, roomId lo, roomId hi, peerMemberId, int *connStatus, inaddr *, u16 *port)
 * connStatus 0 inactive, 1 pending, 2 active (then the peer's address and
 * port, network order) -- p2p.c's signaling, answered as the reference does. */
static void hle_SignalingGetConnectionStatus(void) {
    const uint32_t ctx = psp_arg(0), status = psp_arg(5), ip = psp_arg(6), port = psp_arg(7);
    const uint64_t room = (uint64_t)psp_arg(2) | (uint64_t)psp_arg(3) << 32;
    const uint16_t member = (uint16_t)psp_arg(4);
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    if (!status || !ip || !port) { psp_ret(M2_ERROR_INVALID_ARGUMENT); return; }
    psp_write32(status, 0);
    uint32_t ip_n = 0;
    uint16_t port_h = 0;
    const int st = p2p_conn_status(room, member, &ip_n, &port_h);
    if (st == -1) {
        m2_log("SignalingGetConnectionStatus(room 0x%016llX, member %u): no such member", (unsigned long long)room, member);
        psp_ret(M2_SIGNALING_ERROR_PEER_NOT_FOUND);
        return;
    }
    if (st == -2) {
        m2_log("SignalingGetConnectionStatus(room 0x%016llX, member %u): no connection", (unsigned long long)room, member);
        psp_ret(SIGNALING_ERROR_CONN_NOT_FOUND);
        return;
    }
    psp_write32(status, (uint32_t)st);
    if (st == 2) {
        psp_mem_write_block(ip, &ip_n, 4);
        psp_write8(port, (uint8_t)(port_h >> 8));       /* network order */
        psp_write8(port + 1, (uint8_t)port_h);
    }
    const uint8_t *b = (const uint8_t *)&ip_n;
    if (st == 2) m2_log("SignalingGetConnectionStatus(room 0x%016llX, member %u) -> active at %u.%u.%u.%u:%u",
                        (unsigned long long)room, member, b[0], b[1], b[2], b[3], port_h);
    else m2_log("SignalingGetConnectionStatus(room 0x%016llX, member %u) -> pending", (unsigned long long)room, member);
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

/* A room request carried by the backend: (ctx, reqParam *, optParam *,
 * [roomEventOpt *, roomMsgOpt *,] u32 *assignedReqId). The room option
 * structures are {callback, argument}. */
static void room_request(const char *name, int kind, uint32_t ev, int assigned_arg) {
    const uint32_t ctx = psp_arg(0), req = psp_arg(1), opt = psp_arg(2), assigned = psp_arg(assigned_arg);
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    if (!assigned || !req) { psp_ret(M2_ERROR_INVALID_ARGUMENT); return; }
    uint32_t cb, arg;
    uint32_t id = new_request(ctx, opt, assigned, &cb, &arg);
    if (kind == PSP_M2_SEND_ROOM_MESSAGE && !cb) { id = 0; psp_write32(assigned, 0); }   /* PSP2i: no callback, ID 0 */
    if (assigned_arg == 5) {
        const uint32_t ro = psp_arg(3), mo = psp_arg(4);
        if (ro) { g_ctx[ctx].room_cb = psp_read32(ro); g_ctx[ctx].room_arg = psp_read32(ro + 4); }
        if (mo) { g_ctx[ctx].msg_cb = psp_read32(mo); g_ctx[ctx].msg_arg = psp_read32(mo + 4); }
        m2_log("%s: room event callback 0x%08X (arg 0x%08X), room message callback 0x%08X (arg 0x%08X)", name,
               g_ctx[ctx].room_cb, g_ctx[ctx].room_arg, g_ctx[ctx].msg_cb, g_ctx[ctx].msg_arg);
    }
    m2_log("%s(ctx %u, param 0x%08X) request %u", name, ctx, req, id);
    const psp_np_backend *be = psp_np_backend_get();
    uint32_t err = M2_SERVER_ERROR_SERVICE_UNAVAILABLE;
    if (psp_np_signed_in() && be && be->m2_room_request) {
        int slot = -1;
        for (int i = 0; i < MAX_REQS; i++) if (!g_req[i].used) { slot = i; break; }
        if (slot >= 0) {
            g_req[slot].used = 1; g_req[slot].id = id; g_req[slot].ctx = ctx;
            g_req[slot].cb = cb; g_req[slot].arg = arg; g_req[slot].ev = ev;
            const int rc = be->m2_room_request(kind, g_ctx[ctx].com_id, id, req);
            if (rc == 0) { psp_ret(M2_OK); return; }
            g_req[slot].used = 0;
            err = (uint32_t)rc;
        } else m2_log("%s: too many requests in flight", name);
    } else m2_log("%s: not signed in, or no matching backend -> service unavailable", name);
    deliver(ctx, id, ev, err, 0, cb, arg);
    psp_ret(M2_OK);
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

static void hle_CreateJoinRoom(void)          { room_request("CreateJoinRoom", PSP_M2_CREATE_JOIN_ROOM, EV_CreateJoinRoom, 5); }
static void hle_JoinRoom(void)                { room_request("JoinRoom", PSP_M2_JOIN_ROOM, EV_JoinRoom, 5); }
static void hle_LeaveRoom(void)               { room_request("LeaveRoom", PSP_M2_LEAVE_ROOM, EV_LeaveRoom, 3); }
static void hle_SearchRoom(void)              { room_request("SearchRoom", PSP_M2_SEARCH_ROOM, EV_SearchRoom, 3); }
static void hle_GetRoomDataExternalList(void) { room_request("GetRoomDataExternalList", PSP_M2_GET_ROOM_DATA_EXTERNAL_LIST, EV_GetRoomDataExternalList, 3); }
static void hle_SetRoomDataExternal(void)     { room_request("SetRoomDataExternal", PSP_M2_SET_ROOM_DATA_EXTERNAL, EV_SetRoomDataExternal, 3); }
static void hle_SetRoomDataInternal(void)     { room_request("SetRoomDataInternal", PSP_M2_SET_ROOM_DATA_INTERNAL, EV_SetRoomDataInternal, 3); }
static void hle_SendRoomMessage(void)         { room_request("SendRoomMessage", PSP_M2_SEND_ROOM_MESSAGE, EV_SendRoomMessage, 3); }
static void hle_GetUserInfoList(void)         { unimplemented_request("GetUserInfoList", EV_GetUserInfoList, 3); }

/* RPCN has no kick request; answered OK, as PPSSPP does. */
static void hle_KickoutRoomMember(void) {
    const uint32_t ctx = psp_arg(0), req = psp_arg(1), opt = psp_arg(2), assigned = psp_arg(3);
    m2_log("KickoutRoomMember(ctx %u, param 0x%08X): not supported by the matching server -- answered OK", ctx, req);
    if (!g_inited) { psp_ret(M2_ERROR_NOT_INITIALIZED); return; }
    if (!ctx_ok(ctx)) { psp_ret(M2_ERROR_CONTEXT_NOT_FOUND); return; }
    if (!assigned) { psp_ret(M2_ERROR_INVALID_ARGUMENT); return; }
    uint32_t cb, arg;
    const uint32_t id = new_request(ctx, opt, assigned, &cb, &arg);
    deliver(ctx, id, EV_KickoutRoomMember, M2_OK, 0, cb, arg);
    psp_ret(M2_OK);
}

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
