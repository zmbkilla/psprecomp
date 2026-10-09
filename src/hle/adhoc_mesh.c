/* psprecomp — ad hoc: the modern connection (PSP_ADHOC_MODE_MODERN).
 *
 * Direct hosting for players behind NATs, carrier-grade NAT included, between
 * recomp players. Every player has one UDP socket (the mesh port, 27320 by
 * default) carrying all of its ad hoc traffic:
 *
 *   1. Candidates: the addresses a peer might reach us at -- the socket's local
 *      IPv4 and global IPv6 address, the public IPv4 endpoint a STUN server
 *      (RFC 5389 binding request) saw, and, for a peer, the IPv4 address the ad
 *      hoc server reported with the mesh port (most NATs keep the port).
 *   2. Signaling: candidates are swapped through the ad hoc server's relay
 *      ("aemu postoffice") as PDP frames to a mailbox port no game uses.
 *   3. Punching: both sides send PROBEs to every candidate of the other; the
 *      outgoing probes open each NAT, and the first datagram that arrives fixes
 *      the path. PINGs every 2 s keep the NAT mappings alive.
 *   4. Data: PDP datagrams go over the path as they are; PTP streams get a
 *      small reliable layer (SYN / SYNACK, byte-sequenced DATA with go-back-N
 *      retransmission, cumulative ACK, FIN / RST).
 *   Until a path exists -- or for a pair whose NATs cannot be punched (both
 *   symmetric) -- the same packets travel through the relay mailbox instead,
 *   so play still works, only slower.
 *
 * Mesh packet: {u32 'P2IM', u8 version 1, u8 type, src MAC[6]} + body, all
 * integers big-endian:
 *   CANDS {u32 nonce, u8 n, n x {u8 family 4|6, u16 port, addr[4|16]}}
 *   PROBE / PROBE_ACK {dst MAC[6], u32 nonce}     PING {}
 *   PDP {u16 sport, u16 dport, data}
 *   SYN {u32 conn, u16 sport, u16 dport}          SYNACK {u32 conn}
 *   DATA {u32 conn, u8 dir, u32 seq, data}        ACK {u32 conn, u8 dir, u32 next}
 *   FIN / RST {u32 conn, u8 dir}
 * conn is chosen by the connecting side; dir 1 = sent by the connecting side. */

#include "psprecomp/net.h"
#include "adhoc.h"
#include "adhoc_sock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MESH_MAGIC     0x5032494Du
#define MESH_VERSION   1
#define MESH_PORT_DEFAULT 27320
#define MAILBOX_RPORT  65534                     /* relay port of the mailbox (no game port + offset is this) */
#define MAX_PEERS      32
#define MAX_CANDS      8
#define MAX_STREAMS    64
#define MAX_PDPQ       32
#define MSS            1180
#define WINDOW         (48 * 1024)
#define MAX_QUEUE      (1024 * 1024)
#define PATH_TIMEOUT   10000000u
#define RELAY_FRAME_HDR 14

enum { T_CANDS = 1, T_PROBE, T_PROBE_ACK, T_PING, T_PDP = 10, T_SYN = 20, T_SYNACK, T_DATA, T_ACK, T_FIN, T_RST };
enum { S_FREE = 0, S_SYN_SENT, S_EST, S_CLOSED };

typedef struct { uint8_t fam; uint8_t ip[16]; uint16_t port; } cand;

typedef struct {
    int used;
    uint8_t mac[6];
    cand c[MAX_CANDS];
    int nc;
    uint32_t server_ip;                 /* network order, from the ad hoc server */
    int have_path, logged;
    cand path;
    uint64_t path_rx, last_tx, next_probe, next_cands, cands_sent, punch_start;
} mpeer;

typedef struct {
    int used, state, connector, pending;
    uint32_t conn;
    uint8_t mac[6];
    uint16_t lport, pport;
    buf_t in, out;
    uint32_t snd_una, snd_nxt, rcv_nxt;
    uint64_t rto, rto_at, next_syn, opened, progress;
    int fin_rcvd;
} mstream;

typedef struct { int used; uint16_t port; buf_t q; } pdpq;

static char     g_stun_cfg[256] = "stun.l.google.com:19302";
static uint16_t g_port_cfg = MESH_PORT_DEFAULT;

static int      g_started, g_v6;
static hsock    g_u = BAD_SOCK;
static uint16_t g_port;
static uint32_t g_nonce;
static cand     g_my[MAX_CANDS];
static int      g_nmy;
static uint64_t g_cands_changed;

static int      g_stun_ok, g_stun_tries;
static uint8_t  g_stun_tx[12];
static uint64_t g_stun_next;

static hsock    g_mb = BAD_SOCK;
static int      g_mb_up;
static buf_t    g_mb_in, g_mb_out;
static uint64_t g_mb_retry, g_mb_start;

static mpeer    g_peers[MAX_PEERS];
static mstream  g_st[MAX_STREAMS];
static uint16_t g_listen[MAX_STREAMS];
static int      g_nlisten;
static pdpq     g_pq[MAX_PDPQ];

void mesh_configure(const char *stun, uint16_t port) {
    snprintf(g_stun_cfg, sizeof g_stun_cfg, "%s", stun ? stun : "stun.l.google.com:19302");
    g_port_cfg = port ? port : MESH_PORT_DEFAULT;
}

/* ---- little helpers -------------------------------------------------------------------------- */

static void put16(uint8_t *b, uint16_t v) { b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)v; }
static void put32(uint8_t *b, uint32_t v) { b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v; }
static uint16_t get16(const uint8_t *b) { return (uint16_t)(b[0] << 8 | b[1]); }
static uint32_t get32(const uint8_t *b) { return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3]; }

static int cand_eq(const cand *a, const cand *b) {
    return a->fam == b->fam && a->port == b->port && !memcmp(a->ip, b->ip, a->fam == 4 ? 4 : 16);
}

/* For the log, which players share: private and loopback IPv4 in full, public
 * addresses masked (the port is what tells whether punching can work). */
static const char *cand_text(const cand *c, char *buf, size_t n) {
    const uint8_t *a = c->ip;
    const int priv = c->fam == 4 && (a[0] == 10 || a[0] == 127 || (a[0] == 172 && (a[1] & 0xF0) == 16) || (a[0] == 192 && a[1] == 168));
    if (priv) snprintf(buf, n, "%u.%u.%u.%u:%u", a[0], a[1], a[2], a[3], c->port);
    else snprintf(buf, n, "%s:%u", c->fam == 6 ? "[IPv6]" : "public IPv4", c->port);
    return buf;
}

static const char *mac_s(const uint8_t m[6], char *buf) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return buf;
}

static int sa_to_cand(const struct sockaddr *sa, cand *c) {
    memset(c, 0, sizeof *c);
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
        c->fam = 4;
        memcpy(c->ip, &s->sin_addr, 4);
        c->port = ntohs(s->sin_port);
        return 1;
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
        static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
        if (!memcmp(&s->sin6_addr, mapped, 12)) { c->fam = 4; memcpy(c->ip, (const uint8_t *)&s->sin6_addr + 12, 4); }
        else { c->fam = 6; memcpy(c->ip, &s->sin6_addr, 16); }
        c->port = ntohs(s->sin6_port);
        return 1;
    }
    return 0;
}

/* A candidate as a destination for our socket (IPv4 is v4-mapped on a dual-stack socket). */
static int cand_to_sa(const cand *c, struct sockaddr_storage *ss, socklen_t *len) {
    memset(ss, 0, sizeof *ss);
    if (g_v6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
        s->sin6_family = AF_INET6;
        s->sin6_port = htons(c->port);
        if (c->fam == 4) { uint8_t *a = (uint8_t *)&s->sin6_addr; a[10] = a[11] = 0xFF; memcpy(a + 12, c->ip, 4); }
        else memcpy(&s->sin6_addr, c->ip, 16);
        *len = sizeof *s;
        return 1;
    }
    if (c->fam != 4) return 0;
    struct sockaddr_in *s = (struct sockaddr_in *)ss;
    s->sin_family = AF_INET;
    s->sin_port = htons(c->port);
    memcpy(&s->sin_addr, c->ip, 4);
    *len = sizeof *s;
    return 1;
}

static void udp_to(const cand *c, const void *p, int n) {
    struct sockaddr_storage ss;
    socklen_t l;
    if (g_u == BAD_SOCK || !c->port || !cand_to_sa(c, &ss, &l)) return;
    sendto(g_u, (const char *)p, n, 0, (struct sockaddr *)&ss, l);
}

static int header(uint8_t *b, int type) {
    put32(b, MESH_MAGIC);
    b[4] = MESH_VERSION;
    b[5] = (uint8_t)type;
    adhoc_local_mac(b + 6);
    return 12;
}

static void add_my_cand(const cand *c) {
    for (int i = 0; i < g_nmy; i++) if (cand_eq(&g_my[i], c)) return;
    if (g_nmy < MAX_CANDS) { g_my[g_nmy++] = *c; g_cands_changed = adhoc_real_us(); }
}

/* The local address used toward the internet: a connected UDP socket's name (nothing is sent). */
static int local_addr(int family, cand *out) {
    hsock s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == BAD_SOCK) return 0;
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t l;
    if (family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET; a->sin_port = htons(53);
        inet_pton(AF_INET, "8.8.8.8", &a->sin_addr);
        l = sizeof *a;
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6; a->sin6_port = htons(53);
        inet_pton(AF_INET6, "2001:4860:4860::8888", &a->sin6_addr);
        l = sizeof *a;
    }
    int ok = 0;
    if (connect(s, (struct sockaddr *)&ss, l) == 0) {
        struct sockaddr_storage me;
        socklen_t ml = sizeof me;
        if (getsockname(s, (struct sockaddr *)&me, &ml) == 0 && sa_to_cand((struct sockaddr *)&me, out)) ok = 1;
    }
    close_sock(s);
    if (!ok) return 0;
    if (out->fam == 4 && (!out->ip[0] || out->ip[0] == 127)) return 0;
    if (out->fam == 6 && (out->ip[0] & 0xE0) != 0x20) return 0;      /* global unicast only */
    out->port = g_port;
    return 1;
}

/* ---- peers ------------------------------------------------------------------------------------- */

static mpeer *peer_find(const uint8_t mac[6]) {
    for (int i = 0; i < MAX_PEERS; i++) if (g_peers[i].used && !memcmp(g_peers[i].mac, mac, 6)) return &g_peers[i];
    return NULL;
}

static mpeer *peer_get(const uint8_t mac[6]) {
    mpeer *p = peer_find(mac);
    if (p) return p;
    for (int i = 0; i < MAX_PEERS; i++)
        if (!g_peers[i].used) {
            p = &g_peers[i];
            memset(p, 0, sizeof *p);
            p->used = 1;
            memcpy(p->mac, mac, 6);
            p->punch_start = adhoc_real_us();
            return p;
        }
    return NULL;
}

static int path_alive(const mpeer *p, uint64_t now) { return p->have_path && (now < p->path_rx || now - p->path_rx < PATH_TIMEOUT); }

static void peer_add_cand(mpeer *p, const cand *c) {
    for (int i = 0; i < p->nc; i++) if (cand_eq(&p->c[i], c)) return;
    if (p->nc < MAX_CANDS) p->c[p->nc++] = *c;
}

/* ---- the relay mailbox (signaling, and the fallback path) ----------------------------------------- */

static void mb_close(void) {
    if (g_mb != BAD_SOCK) close_sock(g_mb);
    g_mb = BAD_SOCK;
    g_mb_up = 0;
    buf_free(&g_mb_in);
    buf_free(&g_mb_out);
}

static void mb_open(void) {
    uint32_t ip;
    uint16_t port;
    mb_close();
    g_mb_retry = adhoc_real_us() + 5000000u;
    if (!adhoc_relay_addr(&ip, &port)) { g_mb_retry = 0; return; }   /* until adhocctl has resolved the server */
    g_mb = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_mb == BAD_SOCK) return;
    set_nonblocking(g_mb);
    const int one = 1;
    setsockopt(g_mb, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = ip;
    a.sin_port = htons(port);
    if (connect(g_mb, (struct sockaddr *)&a, sizeof a) != 0 && !IN_PROGRESS(last_error())) { mb_close(); return; }
    g_mb_start = adhoc_real_us();
    uint8_t init[24];                                     /* {s32 0 = PDP, src MAC[8], u16 sport, dst MAC[8], u16 dport} */
    memset(init, 0, sizeof init);
    adhoc_local_mac(init + 4);
    const uint16_t rp = MAILBOX_RPORT;
    memcpy(init + 12, &rp, 2);
    buf_add(&g_mb_out, init, sizeof init);
}

static void mb_send(const uint8_t mac[6], const void *p, int n) {
    if (g_mb == BAD_SOCK || g_mb_out.len > MAX_QUEUE) return;
    uint8_t h[RELAY_FRAME_HDR];
    memset(h, 0, sizeof h);
    memcpy(h, mac, 6);
    const uint16_t rp = MAILBOX_RPORT;
    memcpy(h + 8, &rp, 2);
    const uint32_t sz = (uint32_t)n;
    memcpy(h + 10, &sz, 4);
    buf_add(&g_mb_out, h, sizeof h);
    buf_add(&g_mb_out, p, (uint32_t)n);
}

static void handle(const uint8_t *b, int n, const cand *from);

static void mb_pump(uint64_t now) {
    if (g_mb == BAD_SOCK) { if (now >= g_mb_retry) mb_open(); return; }
    if (!g_mb_up) {
        fd_set w, x;
        FD_ZERO(&w); FD_ZERO(&x);
        FD_SET(g_mb, &w); FD_SET(g_mb, &x);
        struct timeval tv = { 0, 0 };
        if (select((int)g_mb + 1, NULL, &w, &x, &tv) > 0 && FD_ISSET(g_mb, &w)) {
            int e = 0;
            socklen_t l = sizeof e;
            getsockopt(g_mb, SOL_SOCKET, SO_ERROR, (char *)&e, &l);
            if (e) { adhoc_log("modern: the relay refused the mailbox connection"); mb_close(); return; }
            g_mb_up = 1;
            adhoc_log("modern: relay mailbox open (signaling and fallback path)");
        } else {
            if (now - g_mb_start > 8000000u) { adhoc_log("modern: no relay for the mailbox (direct paths only from guesses)"); mb_close(); }
            return;
        }
    }
    while (g_mb_out.len) {
        const int k = send(g_mb, (const char *)g_mb_out.p, (int)g_mb_out.len, 0);
        if (k > 0) { buf_drop(&g_mb_out, (uint32_t)k); continue; }
        if (k < 0 && WOULD_BLOCK(last_error())) break;
        adhoc_log("modern: lost the relay mailbox");
        mb_close();
        return;
    }
    uint8_t tmp[8192];
    for (int i = 0; i < 64; i++) {
        const int k = recv(g_mb, (char *)tmp, sizeof tmp, 0);
        if (k > 0) { buf_add(&g_mb_in, tmp, (uint32_t)k); continue; }
        if (k < 0 && WOULD_BLOCK(last_error())) break;
        adhoc_log("modern: the relay closed the mailbox");
        mb_close();
        return;
    }
    while (g_mb_in.len >= RELAY_FRAME_HDR) {           /* {src MAC[8], u16 sport, u32 size, data} */
        uint32_t sz;
        memcpy(&sz, g_mb_in.p + 10, 4);
        if (sz > 64 * 1024) { mb_close(); return; }
        if (g_mb_in.len < RELAY_FRAME_HDR + sz) break;
        if (sz >= 12 && !memcmp(g_mb_in.p + RELAY_FRAME_HDR + 6, g_mb_in.p, 6))   /* the claimed sender is the relay's */
            handle(g_mb_in.p + RELAY_FRAME_HDR, (int)sz, NULL);
        buf_drop(&g_mb_in, RELAY_FRAME_HDR + sz);
    }
}

/* To a peer: over its direct path if alive, else through the mailbox. */
static void send_peer(mpeer *p, const void *pkt, int n) {
    const uint64_t now = adhoc_real_us();
    if (path_alive(p, now)) { udp_to(&p->path, pkt, n); p->last_tx = now; return; }
    mb_send(p->mac, pkt, n);
}

/* ---- STUN (RFC 5389 binding) ------------------------------------------------------------------------ */

static cand     g_stun_server;
static int      g_stun_have;

static void stun_resolve(void) {
    g_stun_have = 0;
    if (!g_stun_cfg[0]) return;
    char host[256];
    snprintf(host, sizeof host, "%s", g_stun_cfg);
    uint16_t port = 3478;
    char *colon = strrchr(host, ':');
    if (colon && !strchr(colon + 1, ']')) { *colon = '\0'; port = (uint16_t)atoi(colon + 1); }
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host, NULL, &hints, &res) == 0 && res) {
        sa_to_cand(res->ai_addr, &g_stun_server);
        g_stun_server.port = port;
        g_stun_have = 1;
        freeaddrinfo(res);
    } else adhoc_log("modern: cannot resolve the STUN server %s", host);
}

static void stun_send(void) {
    uint8_t b[20];
    put16(b, 0x0001);
    put16(b + 2, 0);
    put32(b + 4, 0x2112A442u);
    for (int i = 0; i < 12; i++) g_stun_tx[i] = (uint8_t)(rand() ^ (int)(adhoc_real_us() >> (i & 7)));
    memcpy(b + 8, g_stun_tx, 12);
    udp_to(&g_stun_server, b, sizeof b);
}

static int stun_parse(const uint8_t *b, int n) {
    if (n < 20 || get16(b) != 0x0101 || get32(b + 4) != 0x2112A442u || memcmp(b + 8, g_stun_tx, 12)) return 0;
    int off = 20;
    const int end = 20 + get16(b + 2) < n ? 20 + get16(b + 2) : n;
    while (off + 4 <= end) {
        const uint16_t t = get16(b + off), l = get16(b + off + 2);
        const uint8_t *v = b + off + 4;
        if (off + 4 + l > end) break;
        if ((t == 0x0020 || t == 0x0001) && l >= 8 && v[1] == 1) {
            cand c;
            memset(&c, 0, sizeof c);
            c.fam = 4;
            c.port = get16(v + 2);
            memcpy(c.ip, v + 4, 4);
            if (t == 0x0020) {
                c.port ^= 0x2112;
                c.ip[0] ^= 0x21; c.ip[1] ^= 0x12; c.ip[2] ^= 0xA4; c.ip[3] ^= 0x42;
            }
            if (!g_stun_ok) {
                char s[64];
                adhoc_log("modern: STUN sees us at %s%s", cand_text(&c, s, sizeof s),
                          c.port == g_port ? "" : " (the NAT maps the port; punching still works unless that NAT is symmetric)");
            }
            g_stun_ok = 1;
            add_my_cand(&c);
            return 1;
        }
        off += 4 + ((l + 3) & ~3);
    }
    return 1;
}

/* ---- PDP queues ------------------------------------------------------------------------------------- */

static pdpq *pq_find(uint16_t port) {
    for (int i = 0; i < MAX_PDPQ; i++) if (g_pq[i].used && g_pq[i].port == port) return &g_pq[i];
    return NULL;
}

int mesh_pdp_bind(uint16_t port) {
    if (pq_find(port)) return -1;
    for (int i = 0; i < MAX_PDPQ; i++)
        if (!g_pq[i].used) { memset(&g_pq[i], 0, sizeof g_pq[i]); g_pq[i].used = 1; g_pq[i].port = port; return 0; }
    return -1;
}

void mesh_pdp_unbind(uint16_t port) {
    pdpq *q = pq_find(port);
    if (q) { buf_free(&q->q); q->used = 0; }
}

int mesh_pdp_send(const uint8_t mac[6], uint16_t sport, uint16_t dport, const void *d, int len) {
    if (!g_started || len < 0 || len > 60000) return -1;
    mpeer *p = peer_find(mac);
    if (!p && adhoc_peer_ip(mac)) p = peer_get(mac);
    if (!p) return -1;
    uint8_t *b = (uint8_t *)malloc((size_t)len + 16);
    if (!b) return -1;
    int o = header(b, T_PDP);
    put16(b + o, sport); put16(b + o + 2, dport);
    if (len) memcpy(b + o + 4, d, (size_t)len);
    send_peer(p, b, o + 4 + len);
    free(b);
    return 0;
}

/* 1 = a datagram (copied), 2 = it is larger than *len (*len = its size, the first bytes copied, kept), 0 = none. */
int mesh_pdp_recv(uint16_t port, uint8_t mac[6], uint16_t *sport, void *buf, int *len) {
    pdpq *q = pq_find(port);
    if (!q || q->q.len < 12) return 0;
    uint32_t sz;
    memcpy(&sz, q->q.p + 8, 4);
    memcpy(mac, q->q.p, 6);
    memcpy(sport, q->q.p + 6, 2);
    if ((int)sz > *len) {
        if (*len > 0) memcpy(buf, q->q.p + 12, (size_t)*len);
        *len = (int)sz;
        return 2;
    }
    memcpy(buf, q->q.p + 12, sz);
    *len = (int)sz;
    buf_drop(&q->q, 12 + sz);
    return 1;
}

uint32_t mesh_pdp_avail(uint16_t port) {
    pdpq *q = pq_find(port);
    if (!q || q->q.len < 12) return 0;
    uint32_t sz;
    memcpy(&sz, q->q.p + 8, 4);
    return sz;
}

static void pdp_deliver(const uint8_t mac[6], uint16_t sport, uint16_t dport, const uint8_t *d, int n) {
    pdpq *q = pq_find(dport);
    if (!q || q->q.len > MAX_QUEUE) return;
    uint8_t h[12];
    memcpy(h, mac, 6);
    memcpy(h + 6, &sport, 2);
    const uint32_t sz = (uint32_t)n;
    memcpy(h + 8, &sz, 4);
    buf_add(&q->q, h, 12);
    buf_add(&q->q, d, sz);
}

/* ---- PTP streams ----------------------------------------------------------------------------------- */

static mstream *st_get(int sid) { return sid >= 1 && sid <= MAX_STREAMS && g_st[sid - 1].used ? &g_st[sid - 1] : NULL; }

static mstream *st_find(const uint8_t mac[6], uint32_t conn, int connector) {
    for (int i = 0; i < MAX_STREAMS; i++) {
        mstream *s = &g_st[i];
        if (s->used && s->conn == conn && s->connector == connector && !memcmp(s->mac, mac, 6)) return s;
    }
    return NULL;
}

static mstream *st_new(void) {
    for (int i = 0; i < MAX_STREAMS; i++)
        if (!g_st[i].used) { memset(&g_st[i], 0, sizeof g_st[i]); g_st[i].used = 1; return &g_st[i]; }
    return NULL;
}

static void st_ctl(mstream *s, int type) {
    mpeer *p = peer_get(s->mac);
    if (!p) return;
    uint8_t b[32];
    int o = header(b, type);
    put32(b + o, s->conn); o += 4;
    if (type == T_SYN) { put16(b + o, s->lport); put16(b + o + 2, s->pport); o += 4; }
    else if (type != T_SYNACK) b[o++] = (uint8_t)s->connector;
    if (type == T_ACK) { put32(b + o, s->rcv_nxt); o += 4; }
    send_peer(p, b, o);
}

static uint64_t base_rto(const mstream *s) {
    const mpeer *p = peer_find(s->mac);
    return p && path_alive(p, adhoc_real_us()) ? 250000u : 1000000u;    /* the relay is TCP already: resend rarely */
}

static void st_pump(mstream *s, uint64_t now) {
    if (s->state == S_SYN_SENT) {
        if (now >= s->next_syn) { st_ctl(s, T_SYN); s->next_syn = now + 300000u; }
        if (now - s->opened > 30000000u) s->state = S_CLOSED;
        return;
    }
    if (s->state != S_EST) return;
    mpeer *p = peer_get(s->mac);
    if (!p) return;
    if (s->snd_nxt != s->snd_una && s->rto_at && now >= s->rto_at) {     /* go back */
        s->snd_nxt = s->snd_una;
        s->rto = s->rto * 2 > 2000000u ? 2000000u : s->rto * 2;
        s->rto_at = 0;
    }
    while (s->snd_nxt - s->snd_una < s->out.len && s->snd_nxt - s->snd_una < WINDOW) {
        const uint32_t off = s->snd_nxt - s->snd_una;
        const uint32_t n = s->out.len - off < MSS ? s->out.len - off : MSS;
        uint8_t b[12 + 9 + MSS];
        int o = header(b, T_DATA);
        put32(b + o, s->conn); b[o + 4] = (uint8_t)s->connector; put32(b + o + 5, s->snd_nxt);
        o += 9;
        memcpy(b + o, s->out.p + off, n);
        send_peer(p, b, o + (int)n);
        if (!s->rto_at) s->rto_at = now + (s->rto ? s->rto : (s->rto = base_rto(s)));
        s->snd_nxt += n;
    }
    if (s->out.len && now - s->progress > 30000000u) { adhoc_log("modern: stream to port %u timed out", s->pport); s->state = S_CLOSED; }
}

int mesh_stream_open(const uint8_t mac[6], uint16_t lport, uint16_t pport) {
    if (!g_started) return 0;
    mstream *s = st_new();
    if (!s) return 0;
    memcpy(s->mac, mac, 6);
    s->lport = lport; s->pport = pport;
    s->connector = 1;
    s->conn = ((uint32_t)rand() << 16) ^ (uint32_t)rand() ^ (uint32_t)adhoc_real_us();
    s->state = S_SYN_SENT;
    s->opened = s->progress = adhoc_real_us();
    st_pump(s, s->opened);
    return (int)(s - g_st) + 1;
}

int mesh_stream_state(int sid) {
    mstream *s = st_get(sid);
    if (!s || s->state == S_CLOSED) return -1;
    return s->state == S_EST ? 1 : 0;
}

int mesh_stream_send(int sid, const void *d, int len) {
    mstream *s = st_get(sid);
    if (!s || s->state == S_CLOSED || s->fin_rcvd) return -1;
    if (s->state != S_EST || s->out.len > MAX_QUEUE) return 0;
    if (!s->out.len) s->progress = adhoc_real_us();
    buf_add(&s->out, d, (uint32_t)len);
    st_pump(s, adhoc_real_us());
    return len;
}

int mesh_stream_recv(int sid, void *buf, int cap) {
    mstream *s = st_get(sid);
    if (!s) return -1;
    if (s->in.len) {
        const uint32_t n = s->in.len < (uint32_t)cap ? s->in.len : (uint32_t)cap;
        memcpy(buf, s->in.p, n);
        buf_drop(&s->in, n);
        return (int)n;
    }
    return s->state == S_CLOSED || s->fin_rcvd ? -1 : 0;
}

uint32_t mesh_stream_avail(int sid) { mstream *s = st_get(sid); return s ? s->in.len : 0; }
uint32_t mesh_stream_unsent(int sid) { mstream *s = st_get(sid); return s ? s->out.len : 0; }

void mesh_stream_close(int sid) {
    mstream *s = st_get(sid);
    if (!s) return;
    if (s->state == S_EST) { st_ctl(s, T_FIN); st_ctl(s, T_FIN); }
    buf_free(&s->in); buf_free(&s->out);
    memset(s, 0, sizeof *s);
}

int mesh_listen(uint16_t port) {
    for (int i = 0; i < g_nlisten; i++) if (g_listen[i] == port) return -1;
    if (g_nlisten >= MAX_STREAMS) return -1;
    g_listen[g_nlisten++] = port;
    return 0;
}

void mesh_unlisten(uint16_t port) {
    for (int i = 0; i < g_nlisten; i++)
        if (g_listen[i] == port) { g_listen[i] = g_listen[--g_nlisten]; break; }
    for (int i = 0; i < MAX_STREAMS; i++)                  /* never accepted: drop */
        if (g_st[i].used && g_st[i].pending && g_st[i].lport == port) mesh_stream_close(i + 1);
}

int mesh_accept(uint16_t port, uint8_t mac[6], uint16_t *pport) {
    mstream *best = NULL;
    for (int i = 0; i < MAX_STREAMS; i++) {
        mstream *s = &g_st[i];
        if (s->used && s->pending && s->lport == port && s->state == S_EST && (!best || s->opened < best->opened)) best = s;
    }
    if (!best) return 0;
    best->pending = 0;
    memcpy(mac, best->mac, 6);
    *pport = best->pport;
    return (int)(best - g_st) + 1;
}

static int listening(uint16_t port) {
    for (int i = 0; i < g_nlisten; i++) if (g_listen[i] == port) return 1;
    return 0;
}

/* ---- incoming packets ------------------------------------------------------------------------------ */

static void send_cands(mpeer *p) {
    uint8_t b[12 + 5 + MAX_CANDS * 19];
    int o = header(b, T_CANDS);
    put32(b + o, g_nonce);
    b[o + 4] = (uint8_t)g_nmy;
    o += 5;
    for (int i = 0; i < g_nmy; i++) {
        b[o] = g_my[i].fam;
        put16(b + o + 1, g_my[i].port);
        const int l = g_my[i].fam == 4 ? 4 : 16;
        memcpy(b + o + 3, g_my[i].ip, (size_t)l);
        o += 3 + l;
    }
    mb_send(p->mac, b, o);
}

static void probe(mpeer *p, const cand *to, int type) {
    uint8_t b[24];
    int o = header(b, type);
    memcpy(b + o, p->mac, 6);
    put32(b + o + 6, g_nonce);
    udp_to(to, b, o + 10);
}

static void handle(const uint8_t *b, int n, const cand *from) {
    if (n < 12 || get32(b) != MESH_MAGIC || b[4] != MESH_VERSION) return;
    const int type = b[5];
    const uint8_t *mac = b + 6;
    if (adhoc_is_local_mac(mac)) return;
    mpeer *p = peer_get(mac);
    if (!p) return;
    const uint64_t now = adhoc_real_us();
    const uint8_t *d = b + 12;
    const int dl = n - 12;
    char m[18], s[64];
    if (from) {
        if (type == T_PROBE || type == T_PROBE_ACK) {
            uint8_t me[6];
            adhoc_local_mac(me);
            if (dl < 10 || memcmp(d, me, 6)) return;           /* someone else's probe (shared address) */
        }
        if (!path_alive(p, now) || cand_eq(&p->path, from)) {
            if (!p->have_path || !cand_eq(&p->path, from) || !p->logged) {
                adhoc_log("modern: direct path to %s via %s", mac_s(mac, m), cand_text(from, s, sizeof s));
                p->logged = 1;
            }
            p->path = *from;
            p->have_path = 1;
            p->path_rx = now;
        }
        if (type == T_PROBE) probe(p, from, T_PROBE_ACK);
    }
    switch (type) {
    case T_CANDS: {
        if (dl < 5) return;
        int k = d[4], o = 5;
        for (int i = 0; i < k && o + 3 <= dl; i++) {
            cand c;
            memset(&c, 0, sizeof c);
            c.fam = d[o];
            c.port = get16(d + o + 1);
            const int l = c.fam == 4 ? 4 : c.fam == 6 ? 16 : 0;
            if (!l || o + 3 + l > dl) break;
            memcpy(c.ip, d + o + 3, (size_t)l);
            peer_add_cand(p, &c);
            o += 3 + l;
        }
        if (!path_alive(p, now)) { p->next_probe = now; if (!p->punch_start) p->punch_start = now; }
        break;
    }
    case T_PDP:
        if (dl >= 4) pdp_deliver(mac, get16(d), get16(d + 2), d + 4, dl - 4);
        break;
    case T_SYN: {
        if (dl < 8) return;
        const uint32_t conn = get32(d);
        const uint16_t sport = get16(d + 4), dport = get16(d + 6);
        mstream *st = st_find(mac, conn, 0);
        if (!st && listening(dport) && (st = st_new()) != NULL) {
            memcpy(st->mac, mac, 6);
            st->conn = conn; st->connector = 0; st->lport = dport; st->pport = sport;
            st->state = S_EST; st->pending = 1;
            st->opened = st->progress = now;
            adhoc_log("modern: connection from %s:%u to port %u", mac_s(mac, m), sport, dport);
        }
        if (st) st_ctl(st, T_SYNACK);
        else {                                               /* nobody listens: refuse */
            mstream tmp;
            memset(&tmp, 0, sizeof tmp);
            memcpy(tmp.mac, mac, 6);
            tmp.conn = conn;
            st_ctl(&tmp, T_RST);
        }
        break;
    }
    case T_SYNACK: {
        if (dl < 4) return;
        mstream *st = st_find(mac, get32(d), 1);
        if (st && st->state == S_SYN_SENT) { st->state = S_EST; st->progress = now; }
        break;
    }
    case T_DATA: case T_ACK: case T_FIN: case T_RST: {
        if (dl < 5) return;
        mstream *st = st_find(mac, get32(d), !d[4]);
        if (!st) return;
        if (type == T_RST) { st->state = S_CLOSED; break; }
        if (type == T_FIN) { st->fin_rcvd = 1; break; }
        if (type == T_ACK) {
            if (dl < 9) return;
            const uint32_t a = get32(d + 5), adv = a - st->snd_una;
            if ((int32_t)adv > 0 && adv <= st->out.len) {
                buf_drop(&st->out, adv);
                st->snd_una = a;
                if ((int32_t)(st->snd_nxt - a) < 0) st->snd_nxt = a;
                st->rto = base_rto(st);
                st->rto_at = st->snd_nxt != st->snd_una ? now + st->rto : 0;
                st->progress = now;
            }
            break;
        }
        if (dl < 9) return;
        if (st->state == S_SYN_SENT) { st->state = S_EST; st->progress = now; }   /* the SYNACK was lost */
        const uint32_t seq = get32(d + 5);
        const uint8_t *data = d + 9;
        const uint32_t len = (uint32_t)(dl - 9), skip = st->rcv_nxt - seq;
        if ((int32_t)skip >= 0 && skip < len && st->in.len < MAX_QUEUE) {
            buf_add(&st->in, data + skip, len - skip);
            st->rcv_nxt += len - skip;
        }
        st_ctl(st, T_ACK);
        break;
    }
    default: break;
    }
}

/* ---- start / stop / pump ---------------------------------------------------------------------------- */

int mesh_start(void) {
    if (g_started) return 0;
    g_v6 = 0;
    g_u = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (g_u != BAD_SOCK) {
        const int off = 0;
        setsockopt(g_u, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&off, sizeof off);
        g_v6 = 1;
    } else g_u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_u == BAD_SOCK) { adhoc_log("modern: cannot create the UDP socket"); return -1; }
    set_nonblocking(g_u);
    const int big = 1 << 20;
    setsockopt(g_u, SOL_SOCKET, SO_RCVBUF, (const char *)&big, sizeof big);
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t l;
    for (int attempt = 0; attempt < 2; attempt++) {
        const uint16_t want = attempt ? 0 : g_port_cfg;
        if (g_v6) { struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss; a->sin6_family = AF_INET6; a->sin6_port = htons(want); l = sizeof *a; }
        else { struct sockaddr_in *a = (struct sockaddr_in *)&ss; a->sin_family = AF_INET; a->sin_port = htons(want); l = sizeof *a; }
        if (bind(g_u, (struct sockaddr *)&ss, l) == 0) break;
        if (attempt) { adhoc_log("modern: cannot bind a UDP port"); close_sock(g_u); g_u = BAD_SOCK; return -1; }
        adhoc_log("modern: UDP port %u is taken; using another (peers then need the relay to find us)", g_port_cfg);
    }
    l = sizeof ss;
    getsockname(g_u, (struct sockaddr *)&ss, &l);
    cand me;
    sa_to_cand((struct sockaddr *)&ss, &me);
    g_port = me.port;
    srand((unsigned)adhoc_real_us());
    g_nonce = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
    g_nmy = 0;
    g_stun_ok = 0;
    g_stun_tries = 0;
    g_stun_next = 0;
    g_started = 1;
    cand c;
    if (local_addr(AF_INET, &c)) add_my_cand(&c);
    if (g_v6 && local_addr(AF_INET6, &c)) add_my_cand(&c);
    stun_resolve();
    char s[64], all[400] = "";
    for (int i = 0; i < g_nmy; i++) {
        if (i) strncat(all, ", ", sizeof all - strlen(all) - 1);
        strncat(all, cand_text(&g_my[i], s, sizeof s), sizeof all - strlen(all) - 1);
    }
    adhoc_log("modern: UDP port %u (%s), local %s; STUN %s", g_port, g_v6 ? "IPv4 + IPv6" : "IPv4 only",
              g_nmy ? all : "none", g_stun_have ? g_stun_cfg : "off");
    mb_open();
    return 0;
}

void mesh_stop(void) {
    if (!g_started) return;
    for (int i = 0; i < MAX_STREAMS; i++) if (g_st[i].used) mesh_stream_close(i + 1);
    for (int i = 0; i < MAX_PDPQ; i++) if (g_pq[i].used) buf_free(&g_pq[i].q);
    memset(g_pq, 0, sizeof g_pq);
    memset(g_peers, 0, sizeof g_peers);
    g_nlisten = 0;
    mb_close();
    if (g_u != BAD_SOCK) close_sock(g_u);
    g_u = BAD_SOCK;
    g_started = 0;
}

void mesh_pump(void) {
    if (!g_started) return;
    const uint64_t now = adhoc_real_us();
    static uint8_t pkt[65536];
    for (int k = 0; k < 256; k++) {
        struct sockaddr_storage from;
        socklen_t fl = sizeof from;
        const int n = recvfrom(g_u, (char *)pkt, sizeof pkt, 0, (struct sockaddr *)&from, &fl);
        if (n < 0) {
#ifdef _WIN32
            if (last_error() == WSAECONNRESET) continue;
#endif
            break;
        }
        cand c;
        if (!sa_to_cand((struct sockaddr *)&from, &c)) continue;
        if (n >= 20 && get32(pkt + 4) == 0x2112A442u) { stun_parse(pkt, n); continue; }
        handle(pkt, n, &c);
    }
    mb_pump(now);
    if (g_stun_have && !g_stun_ok && g_stun_tries < 8 && now >= g_stun_next) {
        stun_send();
        g_stun_tries++;
        g_stun_next = now + 500000u;
        if (g_stun_tries == 8) adhoc_log("modern: no STUN answer (punching relies on the local and guessed addresses)");
    }
    /* the group's players, as the ad hoc server tells them */
    uint8_t macs[MAX_PEERS][6];
    const int np = adhoc_active_peers(macs, MAX_PEERS);
    for (int i = 0; i < np; i++) {
        mpeer *p = peer_get(macs[i]);
        if (!p) continue;
        const uint32_t ip = adhoc_peer_ip(macs[i]);
        if (ip && ip != p->server_ip) {
            p->server_ip = ip;
            cand g;
            memset(&g, 0, sizeof g);
            g.fam = 4;
            memcpy(g.ip, &ip, 4);
            g.port = g_port_cfg;
            peer_add_cand(p, &g);
        }
    }
    char m[18];
    for (int i = 0; i < MAX_PEERS; i++) {
        mpeer *p = &g_peers[i];
        if (!p->used) continue;
        if (path_alive(p, now)) {
            if (now - p->last_tx >= 2000000u) {
                uint8_t b[12];
                header(b, T_PING);
                udp_to(&p->path, b, 12);
                p->last_tx = now;
            }
            continue;
        }
        if (p->have_path && p->logged) {
            adhoc_log("modern: lost the direct path to %s; relaying until it is back", mac_s(p->mac, m));
            p->logged = 0;
            p->punch_start = now;
            p->next_probe = now;
        }
        if (now >= p->next_probe) {
            for (int c = 0; c < p->nc; c++) probe(p, &p->c[c], T_PROBE);
            p->next_probe = now + (now - p->punch_start < 15000000u ? 250000u : 2000000u);
        }
        if (g_mb_up && (now >= p->next_cands || g_cands_changed > p->cands_sent)) {
            send_cands(p);
            p->cands_sent = now;
            p->next_cands = now + 3000000u;
        }
    }
    for (int i = 0; i < MAX_STREAMS; i++) if (g_st[i].used) st_pump(&g_st[i], now);
}
