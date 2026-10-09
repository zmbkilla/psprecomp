/* psprecomp â€” sceNetAdhocMatching: the PSP's lobby protocol (hosts announce
 * themselves, others ask to join, the host accepts), on PDP sockets.
 *
 * Wire-compatible with PPSSPP (Komak57/ppsspp master,
 * Core/HLE/sceNetAdhocMatching.cpp, proAdhoc.cpp), so players of either meet.
 * Packets (u8 opcode, then little-endian fields), sent to each peer at the
 * context's port (or the port the peer was last heard from):
 *   PING 0                       keep-alive, every keepalive interval
 *   HELLO 1 {s32 len, data}      a host (or P2P player) with room, every hello interval
 *   JOIN 2 {s32 len, data}       a request to join
 *   ACCEPT 3 {s32 len, s32 n, data, n MACs}   accepted; the host's other children
 *   CANCEL 4 {s32 len, data}     refused / cancelled / left
 *   BULK 5 {s32 len, data}       SendData
 *   BIRTH 7 {MAC} / DEATH 8 {MAC} a child joined / left (to the other children)
 *   BYE 9                        stopping
 * Events go to the game's handler(id, event, &mac, optlen, &opt). As in the
 * reference, events and sends are kept on stacks (newest first).
 *
 * Runs on the game thread from adhoc_pump (the reference's input and event
 * threads). */

#include "psprecomp/hle.h"
#include "psprecomp/net.h"
#include "adhoc.h"

#include <stdlib.h>
#include <string.h>

#define M_INVALID_MODE      0x80410801u
#define M_INVALID_MAXNUM    0x80410803u
#define M_RXBUF_TOO_SHORT   0x80410804u
#define M_INVALID_OPTLEN    0x80410805u
#define M_INVALID_ARG       0x80410806u
#define M_INVALID_ID        0x80410807u
#define M_NO_SPACE          0x80410809u
#define M_NOT_RUNNING       0x8041080Bu
#define M_UNKNOWN_TARGET    0x8041080Cu
#define M_TARGET_NOT_READY  0x8041080Du
#define M_EXCEED_MAXNUM     0x8041080Eu
#define M_REQUEST_IN_PROGRESS 0x8041080Fu
#define M_ALREADY_ESTABLISHED 0x80410810u
#define M_ALREADY_INITIALIZED 0x80410812u
#define M_NOT_INITIALIZED   0x80410813u
#define M_PORT_IN_USE       0x80410814u
#define M_INVALID_DATALEN   0x80410816u
#define M_NOT_ESTABLISHED   0x80410817u
#define M_DATA_BUSY         0x80410818u

enum { MODE_PARENT = 1, MODE_CHILD = 2, MODE_P2P = 3 };
enum { EV_HELLO = 1, EV_REQUEST, EV_LEAVE, EV_DENY, EV_CANCEL, EV_ACCEPT, EV_ESTABLISHED, EV_TIMEOUT, EV_ERROR,
       EV_BYE, EV_DATA, EV_DATA_ACK, EV_DATA_TIMEOUT };
enum { P_OFFER = 1, P_PARENT, P_CHILD, P_P2P, P_INCOMING, P_OUTGOING, P_CANCELLING };
enum { PK_PING = 0, PK_HELLO, PK_JOIN, PK_ACCEPT, PK_CANCEL, PK_BULK, PK_BULK_ABORT, PK_BIRTH, PK_DEATH, PK_BYE };

typedef struct mpeer { struct mpeer *next; uint8_t mac[6]; int state, sending; uint64_t lastping; } mpeer;
typedef struct mmsg { struct mmsg *next; int opcode; uint8_t mac[6]; int optlen; uint8_t opt[]; } mmsg;

#define MAX_CTX 16
#define MAX_PORTS 32
typedef struct {
    int used, id, mode, running, maxpeers, socket, rxbuflen, hellolen;
    uint8_t mac[6];
    uint16_t port;
    uint32_t hello_int, keepalive_int, resend_int, handler;
    int resendcounter;
    uint64_t timeout, lastping, lasthello;
    uint8_t *rxbuf, *hello;
    mpeer *peers;
    mmsg *events, *inputs;
    struct { uint8_t mac[6]; uint16_t port; } ports[MAX_PORTS];
    int nports;
} mctx;

static int g_inited;
static mctx g_ctx[MAX_CTX];

static mctx *ctx_get(int id) {
    for (int i = 0; i < MAX_CTX; i++) if (g_ctx[i].used && g_ctx[i].id == id) return &g_ctx[i];
    return NULL;
}

static uint16_t peer_port(mctx *c, const uint8_t mac[6]) {
    for (int i = 0; i < c->nports; i++) if (!memcmp(c->ports[i].mac, mac, 6)) return c->ports[i].port;
    return c->port;
}
static void set_peer_port(mctx *c, const uint8_t mac[6], uint16_t port) {
    for (int i = 0; i < c->nports; i++) if (!memcmp(c->ports[i].mac, mac, 6)) { c->ports[i].port = port; return; }
    if (c->nports < MAX_PORTS) { memcpy(c->ports[c->nports].mac, mac, 6); c->ports[c->nports].port = port; c->nports++; }
}

/* ---- peers ------------------------------------------------------------------------------------ */

static mpeer *find_peer(mctx *c, const uint8_t mac[6]) {
    for (mpeer *p = c->peers; p; p = p->next) if (!memcmp(p->mac, mac, 6)) return p;
    return NULL;
}
static mpeer *find_state(mctx *c, int state) {
    for (mpeer *p = c->peers; p; p = p->next) if (p->state == state) return p;
    return NULL;
}
static int count_children(mctx *c) {
    int n = 0;
    for (mpeer *p = c->peers; p; p = p->next) if (p->state == P_CHILD) n++;
    return n;
}
static int count_connected(mctx *c) {
    if (c->mode == MODE_PARENT) return count_children(c) + 1;
    if (c->mode == MODE_CHILD) return 1 + (find_state(c, P_PARENT) ? count_children(c) + 1 : 0);
    return 1 + (find_state(c, P_P2P) ? 1 : 0);
}
static mpeer *add_peer(mctx *c, const uint8_t mac[6], int state) {
    mpeer *p = (mpeer *)calloc(1, sizeof *p);
    if (!p) return NULL;
    memcpy(p->mac, mac, 6);
    p->state = state;
    p->lastping = adhoc_real_us();
    p->next = c->peers;
    c->peers = p;
    return p;
}
static void delete_peer(mctx *c, mpeer *peer) {
    for (mpeer **pp = &c->peers; *pp; pp = &(*pp)->next)
        if (*pp == peer) { *pp = peer->next; free(peer); return; }
}
static void clear_peers(mctx *c) { while (c->peers) { mpeer *n = c->peers->next; free(c->peers); c->peers = n; } }
static void clear_stack(mmsg **s) { while (*s) { mmsg *n = (*s)->next; free(*s); *s = n; } }

/* ---- stacks ------------------------------------------------------------------------------------- */

static void push(mmsg **stack, int opcode, const uint8_t mac[6], int optlen, const void *opt) {
    if (optlen < 0) optlen = 0;
    mmsg *m = (mmsg *)calloc(1, sizeof *m + (size_t)optlen + 1);
    if (!m) return;
    m->opcode = opcode;
    memcpy(m->mac, mac, 6);
    m->optlen = optlen;
    if (optlen && opt) memcpy(m->opt, opt, (size_t)optlen);
    m->next = *stack;
    *stack = m;
}
static void event(mctx *c, int ev, const uint8_t mac[6], int optlen, const void *opt) { push(&c->events, ev, mac, optlen, opt); }
static void input(mctx *c, int op, const uint8_t mac[6], int optlen, const void *opt) { push(&c->inputs, op, mac, optlen, opt); }

/* ---- sending ------------------------------------------------------------------------------------- */

static void send_to(mctx *c, const uint8_t mac[6], const void *p, int n) {
    adhoc_pdp_send_internal(c->socket, mac, peer_port(c, mac), p, n);
}

static void put_s32(uint8_t *b, int v) { memcpy(b, &v, 4); }
static int get_s32(const uint8_t *b) { int v; memcpy(&v, b, 4); return v; }

static void broadcast(mctx *c, const void *p, int n) {
    uint8_t macs[32][6];
    const int k = adhoc_active_peers(macs, 32);
    for (int i = 0; i < k; i++) send_to(c, macs[i], p, n);
}

static void send_hello(mctx *c) {
    uint8_t *b = (uint8_t *)malloc(5u + (size_t)c->hellolen);
    if (!b) return;
    b[0] = PK_HELLO;
    put_s32(b + 1, c->hellolen);
    if (c->hellolen) memcpy(b + 5, c->hello, (size_t)c->hellolen);
    broadcast(c, b, 5 + c->hellolen);
    free(b);
}

static void send_with_opt(mctx *c, int op, const uint8_t mac[6], int optlen, const void *opt) {
    uint8_t *b = (uint8_t *)malloc(5u + (size_t)optlen);
    if (!b) return;
    b[0] = (uint8_t)op;
    put_s32(b + 1, optlen);
    if (optlen) memcpy(b + 5, opt, (size_t)optlen);
    send_to(c, mac, b, 5 + optlen);
    free(b);
}

static void send_accept(mctx *c, const uint8_t mac[6], int optlen, const void *opt) {
    mpeer *peer = find_peer(c, mac);
    if (!peer || (peer->state != P_CHILD && peer->state != P_P2P)) return;
    const int siblings = c->mode == MODE_PARENT ? count_connected(c) - 2 : 0;
    const int n = siblings > 0 ? siblings : 0;
    uint8_t *b = (uint8_t *)malloc(9u + (size_t)optlen + 6u * (size_t)n);
    if (!b) return;
    b[0] = PK_ACCEPT;
    put_s32(b + 1, optlen);
    put_s32(b + 5, n);
    if (optlen) memcpy(b + 9, opt, (size_t)optlen);
    int i = 0;
    for (mpeer *p = c->peers; p && i < n; p = p->next)
        if (p != peer && p->state == P_CHILD) memcpy(b + 9 + optlen + 6 * i++, p->mac, 6);
    send_to(c, mac, b, 9 + optlen + 6 * n);
    free(b);
    event(c, EV_ESTABLISHED, mac, 0, NULL);
}

static void send_cancel(mctx *c, const uint8_t mac[6], int optlen, const void *opt) {
    send_with_opt(c, PK_CANCEL, mac, optlen, opt);
    mpeer *peer = find_peer(c, mac);
    if (!peer) return;
    if (c->mode == MODE_CHILD) clear_peers(c);
    else peer->lastping = adhoc_real_us();
}

static void send_bulk(mctx *c, const uint8_t mac[6], int len, const void *data) {
    mpeer *peer = find_peer(c, mac);
    if (!peer) return;
    send_with_opt(c, PK_BULK, mac, len, data);
    peer->sending = 0;
    event(c, EV_DATA_ACK, mac, 0, NULL);
}

static void send_birth(mctx *c, const uint8_t mac[6]) {
    mpeer *newborn = find_peer(c, mac);
    if (!newborn) return;
    uint8_t b[7];
    b[0] = PK_BIRTH;
    memcpy(b + 1, mac, 6);
    for (mpeer *p = c->peers; p; p = p->next) if (p != newborn && p->state == P_CHILD) send_to(c, p->mac, b, 7);
}

static void send_death(mctx *c, const uint8_t mac[6]) {
    mpeer *dead = find_peer(c, mac);
    if (!dead) return;
    uint8_t b[7];
    memcpy(b + 1, mac, 6);
    for (mpeer *p = c->peers; p; p = p->next) {
        if (p == dead) { b[0] = PK_BYE; send_to(c, p->mac, b, 1); }
        else if (p->state == P_CHILD) { b[0] = PK_DEATH; send_to(c, p->mac, b, 7); }
    }
    delete_peer(c, dead);
}

static void send_bye(mctx *c) {
    const uint8_t b = PK_BYE;
    for (mpeer *p = c->peers; p; p = p->next)
        if (p->state == P_PARENT || p->state == P_CHILD || p->state == P_P2P || p->state == P_CANCELLING) send_to(c, p->mac, &b, 1);
}

static void flush_inputs(mctx *c) {
    while (c->inputs) {
        mmsg *m = c->inputs;
        c->inputs = m->next;
        switch (m->opcode) {
        case PK_ACCEPT: send_accept(c, m->mac, m->optlen, m->opt); break;
        case PK_JOIN: {
            mpeer *p = find_peer(c, m->mac);
            if (p && p->state == P_OUTGOING) send_with_opt(c, PK_JOIN, m->mac, m->optlen, m->opt);
            break;
        }
        case PK_CANCEL: send_cancel(c, m->mac, m->optlen, m->opt); break;
        case PK_BULK:   send_bulk(c, m->mac, m->optlen, m->opt); break;
        case PK_BIRTH:  send_birth(c, m->mac); break;
        case PK_DEATH:  send_death(c, m->mac); break;
        default: break;
        }
        free(m);
    }
}

/* ---- receiving ----------------------------------------------------------------------------------- */

static void on_hello(mctx *c, const uint8_t mac[6], int len) {
    if (!((c->mode == MODE_CHILD && !find_state(c, P_PARENT)) || (c->mode == MODE_P2P && !find_state(c, P_P2P)))) return;
    if (len < 5) return;
    const int optlen = get_s32(c->rxbuf + 1);
    if (optlen < 0 || optlen > len - 5) return;            /* not 5 + optlen: it could overflow */
    mpeer *p = find_peer(c, mac);
    if (!p) p = add_peer(c, mac, P_OFFER);
    if (p && p->state != P_OUTGOING && p->state != P_INCOMING) event(c, EV_HELLO, mac, optlen, c->rxbuf + 5);
}

static void on_join(mctx *c, const uint8_t mac[6], int len) {
    if (c->mode == MODE_CHILD) return;
    if ((c->mode == MODE_PARENT && count_children(c) < c->maxpeers - 1) || (c->mode == MODE_P2P && !find_state(c, P_P2P))) {
        if (len >= 5) {
            const int optlen = get_s32(c->rxbuf + 1);
            if (optlen >= 0 && optlen <= len - 5) {
                mpeer *p = find_peer(c, mac);
                if (p && p->lastping && c->mode == MODE_PARENT) return;      /* a repeated request */
                if (!p) p = add_peer(c, mac, P_INCOMING);
                else { p->state = P_INCOMING; p->lastping = adhoc_real_us(); }
                if (p) { event(c, EV_REQUEST, mac, optlen, c->rxbuf + 5); return; }
            }
        }
    }
    send_cancel(c, mac, 0, NULL);                       /* no room: refuse */
}

static void on_accept(mctx *c, const uint8_t mac[6], int len) {
    if (c->mode == MODE_PARENT) return;
    if (!((c->mode == MODE_CHILD && !find_state(c, P_PARENT)) || (c->mode == MODE_P2P && !find_state(c, P_P2P)))) return;
    if (len < 9) return;
    const int optlen = get_s32(c->rxbuf + 1), n = get_s32(c->rxbuf + 5);
    if (optlen < 0 || n < 0 || (long long)len < 9LL + optlen + 6LL * n) return;
    mpeer *req = find_state(c, P_OUTGOING), *peer = find_peer(c, mac);
    if (!req || req != peer) return;
    peer->state = c->mode == MODE_CHILD ? P_PARENT : P_P2P;
    for (mpeer *p = c->peers; p;) {                     /* drop everyone not in the match */
        mpeer *next = p->next;
        if (p->state != P_CHILD && p->state != P_P2P && p->state != P_PARENT && p->state != 0) delete_peer(c, p);
        p = next;
    }
    if (c->mode == MODE_CHILD) {
        const uint8_t *sib = c->rxbuf + 9 + optlen;
        for (int i = n - 1; i >= 0; i--) {
            mpeer *s = find_peer(c, sib + 6 * i);
            if (s) { s->state = P_CHILD; s->sending = 0; s->lastping = adhoc_real_us(); }
            else add_peer(c, sib + 6 * i, P_CHILD);
        }
        mpeer *self = find_peer(c, c->mac);              /* self, as state 0 */
        if (self) { self->state = 0; self->sending = 0; self->lastping = adhoc_real_us(); }
        else add_peer(c, c->mac, 0);
    }
    event(c, EV_ESTABLISHED, mac, 0, NULL);
    event(c, EV_ACCEPT, mac, optlen, c->rxbuf + 9);     /* newest first: ACCEPT, then ESTABLISHED */
}

static void on_cancel(mctx *c, const uint8_t mac[6], int len) {
    mpeer *peer = find_peer(c, mac);
    if (!peer || len < 5) return;
    const int optlen = get_s32(c->rxbuf + 1);
    if (optlen < 0 || optlen > len - 5) return;            /* not 5 + optlen: it could overflow */
    const uint8_t *opt = c->rxbuf + 5;
    mpeer *req = find_state(c, P_OUTGOING);
    if (c->mode == MODE_CHILD) {
        mpeer *parent = find_state(c, P_PARENT);
        if (req == peer) { event(c, EV_DENY, mac, optlen, opt); peer->lastping = 0; }
        else if (parent == peer) {
            for (mpeer *p = c->peers; p; p = p->next)
                if (p->state == P_CHILD || p->state == P_PARENT) event(c, EV_LEAVE, p->mac, optlen, opt);
            clear_peers(c);
        }
    } else if (c->mode == MODE_PARENT) {
        if (peer->state == P_INCOMING) { event(c, EV_CANCEL, mac, optlen, opt); peer->lastping = 0; }
        else if (peer->state == P_CHILD) { event(c, EV_LEAVE, mac, optlen, opt); peer->lastping = 0; }
    } else {
        mpeer *p2p = find_state(c, P_P2P);
        if (req == peer) { event(c, EV_DENY, mac, optlen, opt); peer->lastping = 0; }
        else if (p2p == peer) { event(c, EV_LEAVE, mac, optlen, opt); peer->lastping = 0; }
        else if (peer->state == P_INCOMING) { event(c, EV_CANCEL, mac, optlen, opt); peer->lastping = 0; }
    }
}

static void on_bulk(mctx *c, const uint8_t mac[6], int len) {
    mpeer *p = find_peer(c, mac);
    if (!p) return;
    if (!((c->mode == MODE_PARENT && p->state == P_CHILD) || (c->mode == MODE_CHILD && (p->state == P_CHILD || p->state == P_PARENT)) ||
          (c->mode == MODE_P2P && p->state == P_P2P))) return;
    if (len <= 5) return;
    const int n = get_s32(c->rxbuf + 1);
    if (n > 0 && n <= len - 5) event(c, EV_DATA, mac, n, c->rxbuf + 5);   /* not 5 + n: it could overflow */
}

static void on_birth(mctx *c, const uint8_t mac[6], int len) {
    mpeer *p = find_peer(c, mac);
    if (!p || c->mode != MODE_CHILD || p != find_state(c, P_PARENT) || len < 7) return;
    add_peer(c, c->rxbuf + 1, P_CHILD);
}

static void on_death(mctx *c, const uint8_t mac[6], int len) {
    mpeer *p = find_peer(c, mac);
    if (!p || c->mode != MODE_CHILD || p != find_state(c, P_PARENT) || len < 7) return;
    mpeer *dead = find_peer(c, c->rxbuf + 1);
    if (!dead || dead->state != P_CHILD) return;
    event(c, EV_LEAVE, c->rxbuf + 1, 0, NULL);
    delete_peer(c, dead);
}

static void on_bye(mctx *c, const uint8_t mac[6]) {
    mpeer *p = find_peer(c, mac);
    if (!p) return;
    if ((c->mode == MODE_PARENT && p->state == P_CHILD) || (c->mode == MODE_CHILD && p->state == P_CHILD) ||
        (c->mode == MODE_P2P && (p->state == P_P2P || p->state == P_OFFER || p->state == P_INCOMING || p->state == P_OUTGOING ||
                                 p->state == P_CANCELLING))) {
        if (c->mode != MODE_CHILD) event(c, EV_BYE, mac, 0, NULL);
        delete_peer(c, p);
    } else if (c->mode == MODE_CHILD && p->state == P_PARENT) {
        event(c, EV_BYE, mac, 0, NULL);
        clear_peers(c);
    }
}

static void handle_timeouts(mctx *c) {
    const uint64_t now = adhoc_real_us();
    for (mpeer *p = c->peers; p;) {
        mpeer *next = p->next;
        if (p->state && now - p->lastping > c->timeout &&
            ((c->mode == MODE_CHILD && p->state == P_PARENT) || (c->mode == MODE_PARENT && p->state == P_CHILD) ||
             (c->mode == MODE_P2P && p->state != P_PARENT && p->state != P_CHILD))) {
            event(c, EV_TIMEOUT, p->mac, 0, NULL);
            adhoc_log("matching %d: peer timed out", c->id);
            if (c->mode == MODE_PARENT) input(c, PK_DEATH, p->mac, 0, NULL);
            else input(c, PK_CANCEL, p->mac, 0, NULL);
        }
        p = next;
    }
}

/* Hand the oldest-pushed-last events to the game: handler(id, event, &mac, optlen, &opt). */
static void deliver_events(mctx *c) {
    while (c->events) {
        mmsg *m = c->events;
        c->events = m->next;
        mpeer *p = find_peer(c, m->mac);
        if (m->opcode == EV_HELLO && p && (p->state == P_OUTGOING || p->state == P_INCOMING || p->state == P_CANCELLING)) {
            free(m);                                    /* no HELLO in the middle of a join (as the reference) */
            continue;
        }
        const uint32_t buf = adhoc_guest_alloc(8u + (uint32_t)m->optlen);
        if (buf && c->handler) {
            psp_mem_write_block(buf, m->mac, 6);
            if (m->optlen) psp_mem_write_block(buf + 8, m->opt, (uint32_t)m->optlen);
            psp_sched_post_call(c->handler, (uint32_t)c->id, (uint32_t)m->opcode, buf, (uint32_t)m->optlen, buf + 8);
        }
        free(m);
    }
}

void adhoc_matching_tick(void) {
    if (!g_inited) return;
    const uint64_t now = adhoc_real_us();
    for (int i = 0; i < MAX_CTX; i++) {
        mctx *c = &g_ctx[i];
        if (!c->used || !c->running) continue;
        if ((c->mode == MODE_PARENT && count_children(c) < c->maxpeers - 1) || (c->mode == MODE_P2P && !find_state(c, P_P2P)))
            if (c->hello_int && now - c->lasthello >= c->hello_int) { send_hello(c); c->lasthello = now; }
        if (c->keepalive_int) {
            if (now - c->lastping >= c->keepalive_int) {
                handle_timeouts(c);
                const uint8_t ping = PK_PING;
                broadcast(c, &ping, 1);
                c->lastping = now;
            }
        } else handle_timeouts(c);
        flush_inputs(c);
        for (int k = 0; k < 64; k++) {
            uint8_t mac[6];
            uint16_t port = 0;
            int len = c->rxbuflen;
            if (adhoc_pdp_recv_internal(c->socket, mac, &port, c->rxbuf, &len) != 0 || len <= 0) break;
            set_peer_port(c, mac, port);
            switch (c->rxbuf[0]) {
            case PK_PING:   { mpeer *p = find_peer(c, mac); if (p) p->lastping = adhoc_real_us(); break; }
            case PK_HELLO:  on_hello(c, mac, len); break;
            case PK_JOIN:   on_join(c, mac, len); break;
            case PK_ACCEPT: on_accept(c, mac, len); break;
            case PK_CANCEL: on_cancel(c, mac, len); break;
            case PK_BULK:   on_bulk(c, mac, len); break;
            case PK_BIRTH:  on_birth(c, mac, len); break;
            case PK_DEATH:  on_death(c, mac, len); break;
            case PK_BYE:    on_bye(c, mac); break;
            default: break;
            }
        }
        flush_inputs(c);
        deliver_events(c);
    }
}

/* ---- the calls ------------------------------------------------------------------------------------- */

static void hle_Init(void) {
    if (g_inited) { psp_ret(M_ALREADY_INITIALIZED); return; }
    g_inited = 1;
    psp_ret(0);
}

static void ctx_stop(mctx *c) {
    if (!c->running) return;
    flush_inputs(c);
    send_bye(c);
    adhoc_pdp_delete_internal(c->socket);
    clear_stack(&c->inputs);
    clear_stack(&c->events);
    clear_peers(c);
    c->running = 0;
}

static void ctx_delete(mctx *c) {
    ctx_stop(c);
    free(c->hello);
    free(c->rxbuf);
    memset(c, 0, sizeof *c);
}

void adhoc_matching_reset(void) { for (int i = 0; i < MAX_CTX; i++) if (g_ctx[i].used) ctx_delete(&g_ctx[i]); }

static void hle_Term(void) { adhoc_matching_reset(); g_inited = 0; psp_ret(0); }

/* Create(mode, maxnum, port, rxbuflen, hello_int, keepalive_int, init_count, rexmt_int, callback) */
static void hle_Create(void) {
    const int mode = (int)psp_arg(0), maxnum = (int)psp_arg(1), port = (int)psp_arg(2), rxbuflen = (int)psp_arg(3);
    const uint32_t hello_int = psp_cpu.r[PSP_REG_T0], keepalive_int = psp_cpu.r[PSP_REG_T1],
                   init_count = psp_cpu.r[PSP_REG_T2], rexmt_int = psp_cpu.r[PSP_REG_T3];
    const uint32_t callback = psp_read32(psp_cpu.r[PSP_REG_SP]);       /* ninth argument: on the stack */
    if (!g_inited) { psp_ret(M_NOT_INITIALIZED); return; }
    if (maxnum <= 1 || maxnum > 16) { psp_ret(M_INVALID_MAXNUM); return; }
    if (rxbuflen < 1) { psp_ret(M_RXBUF_TOO_SHORT); return; }
    if (mode < 1 || mode > 3) { psp_ret(M_INVALID_ARG); return; }
    for (int i = 0; i < MAX_CTX; i++) if (g_ctx[i].used && g_ctx[i].port == (uint16_t)port) { psp_ret(M_PORT_IN_USE); return; }
    mctx *c = NULL;
    int id = 1;
    for (;; id++) { if (!ctx_get(id)) break; }
    for (int i = 0; i < MAX_CTX; i++) if (!g_ctx[i].used) { c = &g_ctx[i]; break; }
    if (!c) { psp_ret(M_NO_SPACE); return; }
    memset(c, 0, sizeof *c);
    c->rxbuf = (uint8_t *)calloc(1, (size_t)rxbuflen);
    if (!c->rxbuf) { psp_ret(M_NO_SPACE); return; }
    c->used = 1; c->id = id; c->mode = mode; c->maxpeers = maxnum; c->port = (uint16_t)port; c->rxbuflen = rxbuflen;
    c->resendcounter = (int)init_count; c->resend_int = rexmt_int; c->hello_int = hello_int;
    c->keepalive_int = keepalive_int ? keepalive_int : 2000000u;
    c->timeout = ((uint64_t)keepalive_int + rexmt_int) * init_count + 500000u;   /* + 0.5 s for internet play, as the reference */
    c->handler = callback;
    adhoc_local_mac(c->mac);
    adhoc_log("matching %d: created (mode %d, %d players, port %d, callback 0x%08X)", id, mode, maxnum, port, callback);
    psp_ret((uint32_t)id);
}

/* Start(id, evthPri, evthStack, inthPri, inthStack, optLen, optData) */
static void hle_Start(void) {
    mctx *c = ctx_get((int)psp_arg(0));
    const int optlen = (int)psp_cpu.r[PSP_REG_T1];
    const uint32_t opt = psp_cpu.r[PSP_REG_T2];
    if (!c) { psp_ret(0); return; }                     /* as the reference: GTA VCS needs success */
    if (optlen > 0 && opt) {
        free(c->hello);
        c->hello = (uint8_t *)malloc((size_t)optlen);
        if (c->hello) { psp_mem_read_block(c->hello, opt, (uint32_t)optlen); c->hellolen = optlen; }
    }
    uint8_t mac[6];
    const int sock = adhoc_pdp_create_internal(mac, c->port, c->rxbuflen);
    if (sock < 1) { psp_ret(M_PORT_IN_USE); return; }
    c->socket = sock;
    c->running = 1;
    c->lastping = c->lasthello = 0;
    adhoc_log("matching %d: started (hello %d bytes)", c->id, c->hellolen);
    psp_ret(0);
}

static void hle_Stop(void) {
    mctx *c = ctx_get((int)psp_arg(0));
    if (c) ctx_stop(c);
    psp_ret(0);
}

static void hle_Delete(void) {
    mctx *c = ctx_get((int)psp_arg(0));
    if (c) ctx_delete(c);
    psp_ret(0);
}

static int read_opt(uint32_t addr, int len, uint8_t **out) {
    *out = NULL;
    if (len <= 0 || !addr) return 0;
    *out = (uint8_t *)malloc((size_t)len);
    if (!*out) return -1;
    psp_mem_read_block(*out, addr, (uint32_t)len);
    return 0;
}

static void hle_SelectTarget(void) {
    const int id = (int)psp_arg(0), optlen = (int)psp_arg(2);
    const uint32_t macp = psp_arg(1), optp = psp_arg(3);
    if (!g_inited) { psp_ret(M_NOT_INITIALIZED); return; }
    if (!macp) { psp_ret(M_INVALID_ARG); return; }
    mctx *c = ctx_get(id);
    if (!c) { psp_ret(M_INVALID_ID); return; }
    if (!c->running) { psp_ret(M_NOT_RUNNING); return; }
    uint8_t mac[6];
    psp_mem_read_block(mac, macp, 6);
    mpeer *p = find_peer(c, mac);
    if (!p) { psp_ret(M_UNKNOWN_TARGET); return; }
    if (optlen != 0 && (optlen <= 0 || !optp)) { psp_ret(M_INVALID_OPTLEN); return; }
    uint8_t *opt;
    if (read_opt(optp, optlen, &opt) != 0) { psp_ret(M_NO_SPACE); return; }
    uint32_t r = M_TARGET_NOT_READY;
    if (c->mode == MODE_PARENT) {
        if (p->state == P_CHILD) r = M_ALREADY_ESTABLISHED;
        else if (count_children(c) == c->maxpeers - 1) r = M_EXCEED_MAXNUM;
        else if (p->state == P_INCOMING) {
            p->state = P_CHILD;
            input(c, PK_BIRTH, mac, 0, NULL);
            input(c, PK_ACCEPT, mac, optlen, opt);
            r = 0;
        }
    } else {
        const int linked = c->mode == MODE_CHILD ? find_state(c, P_PARENT) != NULL : find_state(c, P_P2P) != NULL;
        if (linked) r = M_ALREADY_ESTABLISHED;
        else if (find_state(c, P_OUTGOING)) r = M_REQUEST_IN_PROGRESS;
        else if (p->state == P_OFFER) { p->state = P_OUTGOING; input(c, PK_JOIN, mac, optlen, opt); r = 0; }
        else if (c->mode == MODE_P2P && p->state == P_INCOMING) { p->state = P_P2P; input(c, PK_ACCEPT, mac, optlen, opt); r = 0; }
    }
    free(opt);
    psp_ret(r);
}

static void cancel_target(int id, uint32_t macp, int optlen, uint32_t optp) {
    if (!g_inited) { psp_ret(M_NOT_INITIALIZED); return; }
    if (!macp || (optlen != 0 && (optlen <= 0 || !optp))) { psp_ret(M_INVALID_ARG); return; }
    mctx *c = ctx_get(id);
    if (!c) { psp_ret(M_INVALID_ID); return; }
    if (!c->running) { psp_ret(M_NOT_RUNNING); return; }
    uint8_t mac[6];
    psp_mem_read_block(mac, macp, 6);
    mpeer *p = find_peer(c, mac);
    if (!p) { psp_ret(0); return; }
    if ((c->mode == MODE_CHILD && (p->state == P_PARENT || p->state == P_OUTGOING)) ||
        (c->mode == MODE_PARENT && (p->state == P_CHILD || p->state == P_INCOMING)) ||
        (c->mode == MODE_P2P && (p->state == P_P2P || p->state == P_INCOMING))) {
        uint8_t *opt;
        if (read_opt(optp, optlen, &opt) != 0) { psp_ret(M_NO_SPACE); return; }
        if (c->mode == MODE_PARENT && p->state == P_CHILD && count_connected(c) > 1) input(c, PK_DEATH, mac, 0, NULL);
        p->state = P_CANCELLING;
        input(c, PK_CANCEL, mac, optlen, opt);
        p->lastping = 0;
        free(opt);
    }
    psp_ret(0);
}

static void hle_CancelTargetWithOpt(void) { cancel_target((int)psp_arg(0), psp_arg(1), (int)psp_arg(2), psp_arg(3)); }
static void hle_CancelTarget(void) { cancel_target((int)psp_arg(0), psp_arg(1), 0, 0); }

static void hle_SetHelloOpt(void) {
    const int id = (int)psp_arg(0), optlen = (int)psp_arg(1);
    const uint32_t optp = psp_arg(2);
    if (!g_inited) { psp_ret(M_NOT_INITIALIZED); return; }
    mctx *c = ctx_get(id);
    if (!c) { psp_ret(M_INVALID_ID); return; }
    if (c->mode == MODE_CHILD) { psp_ret(M_INVALID_MODE); return; }
    if (!c->running) { psp_ret(M_NOT_RUNNING); return; }
    if (optlen != 0 && !optp) { psp_ret(M_INVALID_OPTLEN); return; }
    if (optlen > 0) {
        uint8_t *h = (uint8_t *)realloc(c->hello, (size_t)optlen);
        if (!h) { c->hellolen = 0; psp_ret(M_NO_SPACE); return; }
        psp_mem_read_block(h, optp, (uint32_t)optlen);
        c->hello = h;
        c->hellolen = optlen;
    } else c->hellolen = 0;
    psp_ret(0);
}

static void hle_GetHelloOpt(void) {
    mctx *c = ctx_get((int)psp_arg(0));
    const uint32_t lenp = psp_arg(1), data = psp_arg(2);
    if (!lenp) { psp_ret(M_INVALID_ARG); return; }
    if (c) {
        psp_write32(lenp, (uint32_t)c->hellolen);
        if (c->hellolen > 0 && data) psp_mem_write_block(data, c->hello, (uint32_t)c->hellolen);
    }
    psp_ret(0);
}

static void hle_SendData(void) {
    const int id = (int)psp_arg(0), len = (int)psp_arg(2);
    const uint32_t macp = psp_arg(1), data = psp_arg(3);
    if (!g_inited) { psp_ret(M_NOT_INITIALIZED); return; }
    if (!macp) { psp_ret(M_INVALID_ARG); return; }
    mctx *c = ctx_get(id);
    if (!c) { psp_ret(M_INVALID_ID); return; }
    if (!c->running) { psp_ret(M_NOT_RUNNING); return; }
    if (len <= 0 || !data) { psp_ret(M_INVALID_DATALEN); return; }
    uint8_t mac[6];
    psp_mem_read_block(mac, macp, 6);
    mpeer *p = find_peer(c, mac);
    if (!p) { psp_ret(M_UNKNOWN_TARGET); return; }
    if (p->state != P_PARENT && p->state != P_CHILD && p->state != P_P2P) { psp_ret(M_NOT_ESTABLISHED); return; }
    if (p->sending) { psp_ret(M_DATA_BUSY); return; }
    uint8_t *tmp = (uint8_t *)malloc((size_t)len);
    if (!tmp) { psp_ret(M_NO_SPACE); return; }
    psp_mem_read_block(tmp, data, (uint32_t)len);
    p->sending = 1;
    send_bulk(c, mac, len, tmp);
    free(tmp);
    psp_ret(0);
}

static void hle_AbortSendData(void) {
    const int id = (int)psp_arg(0);
    const uint32_t macp = psp_arg(1);
    if (!g_inited) { psp_ret(M_NOT_INITIALIZED); return; }
    if (!macp) { psp_ret(M_INVALID_ARG); return; }
    mctx *c = ctx_get(id);
    if (!c) { psp_ret(M_INVALID_ID); return; }
    if (!c->running) { psp_ret(M_NOT_RUNNING); return; }
    uint8_t mac[6];
    psp_mem_read_block(mac, macp, 6);
    mpeer *p = find_peer(c, mac);
    if (!p) { psp_ret(M_UNKNOWN_TARGET); return; }
    p->sending = 0;
    psp_ret(0);
}

void adhoc_matching_register(void) {
    psp_hle_register(0x2A2A1E07, "sceNetAdhocMatching", "sceNetAdhocMatchingInit",                hle_Init);
    psp_hle_register(0x7945ECDA, "sceNetAdhocMatching", "sceNetAdhocMatchingTerm",                hle_Term);
    psp_hle_register(0xCA5EDA6F, "sceNetAdhocMatching", "sceNetAdhocMatchingCreate",              hle_Create);
    psp_hle_register(0x93EF3843, "sceNetAdhocMatching", "sceNetAdhocMatchingStart",               hle_Start);
    psp_hle_register(0x32B156B3, "sceNetAdhocMatching", "sceNetAdhocMatchingStop",                hle_Stop);
    psp_hle_register(0xF16EAF4F, "sceNetAdhocMatching", "sceNetAdhocMatchingDelete",              hle_Delete);
    psp_hle_register(0x5E3D4B79, "sceNetAdhocMatching", "sceNetAdhocMatchingSelectTarget",        hle_SelectTarget);
    psp_hle_register(0xEA3C6108, "sceNetAdhocMatching", "sceNetAdhocMatchingCancelTarget",        hle_CancelTarget);
    psp_hle_register(0x8F58BEDF, "sceNetAdhocMatching", "sceNetAdhocMatchingCancelTargetWithOpt", hle_CancelTargetWithOpt);
    psp_hle_register(0xB5D96C2A, "sceNetAdhocMatching", "sceNetAdhocMatchingGetHelloOpt",         hle_GetHelloOpt);
    psp_hle_register(0xB58E61B7, "sceNetAdhocMatching", "sceNetAdhocMatchingSetHelloOpt",         hle_SetHelloOpt);
    psp_hle_register(0xF79472D7, "sceNetAdhocMatching", "sceNetAdhocMatchingSendData",            hle_SendData);
    psp_hle_register(0xEC19337D, "sceNetAdhocMatching", "sceNetAdhocMatchingAbortSendData",       hle_AbortSendData);
}
