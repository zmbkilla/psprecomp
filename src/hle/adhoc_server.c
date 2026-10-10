/* psprecomp — ad hoc: the built-in rendezvous server.
 *
 * Any recomp can be the server players meet on: the host program starts it
 * (psp2i: adhoc_server=host runs it inside the game and uses it; psp2i
 * --adhoc-server runs it alone, for a machine others can reach -- a PC with an
 * open port, a VPS). Players behind any NAT, carrier-grade NAT included,
 * connect out to it; the modern connection (adhoc_mesh.c) then punches direct
 * paths between them and uses this server's relay where it cannot.
 *
 * It speaks what the game's ad hoc client sends (adhoc.c, adhoc_mesh.c):
 *
 *   lobby, TCP `port`: u8 opcode packets.
 *     in:  LOGIN {MAC[6], nickname[128], product[9]}, CONNECT {group[8]},
 *          DISCONNECT, SCAN, PING
 *     out: CONNECT {nickname[128], MAC[6], IPv4} for each other member (to a
 *          joiner) and for the joiner (to the members), CONNECT_BSSID {host
 *          MAC} when joined, DISCONNECT {IPv4} when a member leaves, SCAN
 *          {group[8], host MAC} per group of the same game then SCAN_COMPLETE.
 *   relay, TCP `relay_port`: a 24-byte record {s32 0, MAC[8], u16 port,
 *     MAC[8], u16 port} registers (MAC, port); then frames {dst MAC[8], u16
 *     dport, u32 size, data} go to the connection registered as (dst, dport),
 *     arriving as {src MAC[8], u16 sport, u32 size, data}. Datagram sockets
 *     only (what the modern connection uses).
 *
 * The modern connection's own server, not a PPSSPP one: a member who leaves
 * is announced by MAC (DISCONNECT_MAC {MAC}), so players sharing a public
 * address (one carrier-grade NAT) stay apart. Both ports listen on IPv6 and
 * IPv4: over IPv6 a player behind carrier-grade NAT can often host. A member
 * reached over IPv6 has no IPv4 to report and gets a unique placeholder in
 * 240.0.0.0/8 (never routed; its real addresses travel as candidates).
 *
 * A group's host is its first member. A player whose address is this machine
 * (127.0.0.1) is reported at the machine's own network address instead, so the
 * others get something they can use. Everything runs on one host thread. */

#include "psprecomp/net.h"
#include "adhoc_sock.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <pthread.h>
#  include <time.h>
#endif

enum { OP_PING = 0, OP_LOGIN, OP_CONNECT, OP_DISCONNECT, OP_SCAN, OP_SCAN_COMPLETE, OP_CONNECT_BSSID, OP_CHAT,
       OP_DISCONNECT_MAC };

#define MAX_LOBBY  64
#define MAX_RELAY  128
#define LOGIN_LEN  (1 + 6 + 128 + 9)
#define FRAME_HDR  14
#define MAX_FRAME  (64 * 1024)
#define MAX_OUT    (2u << 20)
#define IDLE_US    20000000u          /* clients ping every 2 s */

typedef struct {
    int      used, logged, in_group;
    hsock    s;
    uint32_t ip;                       /* network order, as reported to others */
    uint8_t  mac[6];
    char     nick[128];
    uint8_t  product[9];
    uint8_t  group[8];
    uint64_t joined, rx;
    buf_t    in, out;
} lobby_client;

typedef struct {
    int      used, ready;
    hsock    s;
    uint8_t  mac[8];
    uint16_t port;
    buf_t    in, out;
} relay_client;

static lobby_client g_lc[MAX_LOBBY];
static relay_client g_rc[MAX_RELAY];
static hsock    g_lobby = BAD_SOCK, g_relay = BAD_SOCK;
static volatile int g_running;
static uint16_t g_lport, g_rport;
static uint32_t g_self_ip;             /* network order */
static uint32_t g_next_token = 1;      /* placeholders for IPv6 members: 240.0.0.n */
static void   (*g_log)(const char *line);

static void slog(const char *fmt, ...) {
    char line[400];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (g_log) g_log(line);
    else fprintf(stderr, "adhoc server: %s\n", line);
}

static uint64_t now_us(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64() * 1000u;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
#endif
}

static const char *ip_s(uint32_t ip_n, char *b) {
    const uint8_t *p = (const uint8_t *)&ip_n;
    snprintf(b, 16, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return b;
}
static const char *mac_s(const uint8_t *m, char *b) {
    snprintf(b, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return b;
}

/* This machine's address on its network (the route out; nothing is sent). */
static uint32_t self_ip(void) {
    hsock u = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (u == BAD_SOCK) return 0;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(53);
    a.sin_addr.s_addr = htonl(0x08080808u);
    uint32_t ip = 0;
    socklen_t l = sizeof a;
    if (connect(u, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(u, (struct sockaddr *)&a, &l) == 0) ip = a.sin_addr.s_addr;
    close_sock(u);
    return ip;
}

/* This machine's global IPv6 address, as text ("" if it has none). */
static void self_ip6(char *out, size_t cap) {
    out[0] = '\0';
    hsock u = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (u == BAD_SOCK) return;
    struct sockaddr_in6 a;
    memset(&a, 0, sizeof a);
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(53);
    inet_pton(AF_INET6, "2001:4860:4860::8888", &a.sin6_addr);
    socklen_t l = sizeof a;
    if (connect(u, (struct sockaddr *)&a, sizeof a) == 0 && getsockname(u, (struct sockaddr *)&a, &l) == 0)
        inet_ntop(AF_INET6, &a.sin6_addr, out, (socklen_t)cap);
    close_sock(u);
}

/* A listening socket: IPv6 accepting IPv4 too, else IPv4 only. */
static hsock listen_on(uint16_t port) {
    const int one = 1, zero = 0;
    hsock s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (s != BAD_SOCK) {
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&zero, sizeof zero);
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_any;
        a.sin6_port = htons(port);
        if (bind(s, (struct sockaddr *)&a, sizeof a) == 0 && listen(s, 16) == 0) { set_nonblocking(s); return s; }
        close_sock(s);
    }
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == BAD_SOCK) return BAD_SOCK;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 16) != 0) { close_sock(s); return BAD_SOCK; }
    set_nonblocking(s);
    return s;
}

/* The IPv4 to report for a client's address: its own, this machine's
 * network address for a local one, or a placeholder for IPv6. */
static uint32_t report_ip(const struct sockaddr_storage *ss) {
    uint32_t ip = 0;
    if (ss->ss_family == AF_INET) ip = ((const struct sockaddr_in *)ss)->sin_addr.s_addr;
    else if (ss->ss_family == AF_INET6) {
        const uint8_t *b = ((const struct sockaddr_in6 *)ss)->sin6_addr.s6_addr;
        static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
        static const uint8_t loop6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
        if (!memcmp(b, mapped, 12)) memcpy(&ip, b + 12, 4);
        else if (!memcmp(b, loop6, 16)) ip = htonl(0x7F000001u);
        else ip = htonl(0xF0000000u | (g_next_token++ & 0xFFFFFFu));
    }
    if ((ntohl(ip) >> 24) == 127 && g_self_ip) ip = g_self_ip;
    return ip;
}

static void queue(buf_t *b, const void *p, uint32_t n) { if (b->len + n <= MAX_OUT) buf_add(b, p, n); }

/* ---- lobby ------------------------------------------------------------------------------ */

static int same_group(const lobby_client *a, const lobby_client *b) {
    return a->in_group && b->in_group && !memcmp(a->group, b->group, 8) && !memcmp(a->product, b->product, 9);
}

static void send_connect(lobby_client *to, const lobby_client *who) {
    uint8_t p[1 + 128 + 6 + 4];
    p[0] = OP_CONNECT;
    memcpy(p + 1, who->nick, 128);
    memcpy(p + 129, who->mac, 6);
    memcpy(p + 135, &who->ip, 4);
    queue(&to->out, p, sizeof p);
}

static const lobby_client *group_host(const lobby_client *member) {
    const lobby_client *h = NULL;
    for (int i = 0; i < MAX_LOBBY; i++) {
        const lobby_client *c = &g_lc[i];
        if (c->used && same_group(c, member) && (!h || c->joined < h->joined)) h = c;
    }
    return h;
}

static void leave_group(lobby_client *c) {
    if (!c->in_group) return;
    uint8_t p[7];
    p[0] = OP_DISCONNECT_MAC;
    memcpy(p + 1, c->mac, 6);
    for (int i = 0; i < MAX_LOBBY; i++) {
        lobby_client *o = &g_lc[i];
        if (o != c && o->used && same_group(o, c)) queue(&o->out, p, sizeof p);
    }
    char m[18];
    slog("%s (%s) left group %.8s", c->nick, mac_s(c->mac, m), (const char *)c->group);
    c->in_group = 0;
}

static void join_group(lobby_client *c, const uint8_t name[8]) {
    leave_group(c);
    memcpy(c->group, name, 8);
    c->in_group = 1;
    c->joined = now_us();
    int n = 0;
    for (int i = 0; i < MAX_LOBBY; i++) {
        lobby_client *o = &g_lc[i];
        if (o == c || !o->used || !same_group(o, c)) continue;
        send_connect(c, o);
        send_connect(o, c);
        n++;
    }
    const lobby_client *h = group_host(c);
    uint8_t b[7];
    b[0] = OP_CONNECT_BSSID;
    memcpy(b + 1, h ? h->mac : c->mac, 6);
    queue(&c->out, b, sizeof b);
    char m[18];
    slog("%s (%s) joined group %.8s (%d other player(s))", c->nick, mac_s(c->mac, m), (const char *)name, n);
}

static void scan(lobby_client *c) {
    for (int i = 0; i < MAX_LOBBY; i++) {
        const lobby_client *o = &g_lc[i];
        if (!o->used || !o->in_group || memcmp(o->product, c->product, 9) != 0) continue;
        if (group_host(o) != o) continue;                    /* one entry per group: its host */
        uint8_t p[1 + 8 + 6];
        p[0] = OP_SCAN;
        memcpy(p + 1, o->group, 8);
        memcpy(p + 9, o->mac, 6);
        queue(&c->out, p, sizeof p);
    }
    const uint8_t done = OP_SCAN_COMPLETE;
    queue(&c->out, &done, 1);
}

static void lobby_drop(lobby_client *c, const char *why) {
    if (c->logged) { char m[18]; slog("%s (%s) disconnected: %s", c->nick, mac_s(c->mac, m), why); }
    leave_group(c);
    close_sock(c->s);
    buf_free(&c->in);
    buf_free(&c->out);
    memset(c, 0, sizeof *c);
    c->s = BAD_SOCK;
}

/* Handle every complete packet; 0, or -1 to drop the client. */
static int lobby_packets(lobby_client *c) {
    while (c->in.len) {
        const uint8_t *p = c->in.p;
        uint32_t need;
        switch (p[0]) {
        case OP_LOGIN: need = LOGIN_LEN; break;
        case OP_CONNECT: need = 9; break;
        case OP_CHAT: need = 1 + 64; break;
        case OP_PING: case OP_DISCONNECT: case OP_SCAN: need = 1; break;
        default: return -1;
        }
        if (c->in.len < need) return 0;
        if (p[0] != OP_LOGIN && p[0] != OP_PING && !c->logged) return -1;
        switch (p[0]) {
        case OP_LOGIN: {
            memcpy(c->mac, p + 1, 6);
            memcpy(c->nick, p + 7, 128);
            c->nick[127] = '\0';
            memcpy(c->product, p + 135, 9);
            for (int i = 0; i < MAX_LOBBY; i++)                /* a reconnect replaces the old session */
                if (&g_lc[i] != c && g_lc[i].used && g_lc[i].logged && !memcmp(g_lc[i].mac, c->mac, 6))
                    lobby_drop(&g_lc[i], "replaced by a new login");
            c->logged = 1;
            char m[18], ip[16];
            slog("%s (%s) logged in from %s, game %.9s", c->nick, mac_s(c->mac, m), ip_s(c->ip, ip), (const char *)c->product);
            break;
        }
        case OP_CONNECT: join_group(c, p + 1); break;
        case OP_DISCONNECT: leave_group(c); break;
        case OP_SCAN: scan(c); break;
        default: break;
        }
        buf_drop(&c->in, need);
    }
    return 0;
}

/* ---- relay ------------------------------------------------------------------------------- */

static void relay_drop(relay_client *r) {
    close_sock(r->s);
    buf_free(&r->in);
    buf_free(&r->out);
    memset(r, 0, sizeof *r);
    r->s = BAD_SOCK;
}

static int relay_packets(relay_client *r) {
    if (!r->ready) {
        if (r->in.len < 24) return 0;
        int32_t type;
        memcpy(&type, r->in.p, 4);
        if (type != 0) { slog("relay: only datagram sockets are relayed here (type %d refused)", (int)type); return -1; }
        memcpy(r->mac, r->in.p + 4, 8);
        memcpy(&r->port, r->in.p + 12, 2);
        for (int i = 0; i < MAX_RELAY; i++)                    /* a reconnect replaces the old socket */
            if (&g_rc[i] != r && g_rc[i].used && g_rc[i].ready && !memcmp(g_rc[i].mac, r->mac, 6) && g_rc[i].port == r->port)
                relay_drop(&g_rc[i]);
        r->ready = 1;
        buf_drop(&r->in, 24);
    }
    while (r->in.len >= FRAME_HDR) {
        uint32_t size;
        memcpy(&size, r->in.p + 10, 4);
        if (size > MAX_FRAME) return -1;
        if (r->in.len < FRAME_HDR + size) return 0;
        uint16_t dport;
        memcpy(&dport, r->in.p + 8, 2);
        for (int i = 0; i < MAX_RELAY; i++) {
            relay_client *d = &g_rc[i];
            if (!d->used || !d->ready || d->port != dport || memcmp(d->mac, r->in.p, 6) != 0) continue;
            uint8_t h[FRAME_HDR];
            memcpy(h, r->mac, 8);
            memcpy(h + 8, &r->port, 2);
            memcpy(h + 10, &size, 4);
            if (d->out.len + FRAME_HDR + size <= MAX_OUT) {
                buf_add(&d->out, h, FRAME_HDR);
                buf_add(&d->out, r->in.p + FRAME_HDR, size);
            }
            break;
        }
        buf_drop(&r->in, FRAME_HDR + size);
    }
    return 0;
}

/* ---- the loop ----------------------------------------------------------------------------- */

/* Read what is there and send what is queued; -1 when the connection is gone. */
static int io(hsock s, buf_t *in, buf_t *out, int readable, int writable, uint64_t *rx) {
    if (readable) {
        uint8_t tmp[16384];
        for (int k = 0; k < 16; k++) {
            const int n = recv(s, (char *)tmp, sizeof tmp, 0);
            if (n > 0) { buf_add(in, tmp, (uint32_t)n); if (rx) *rx = now_us(); continue; }
            if (n < 0 && WOULD_BLOCK(last_error())) break;
            return -1;
        }
    }
    if (writable && out->len) {
        const int n = send(s, (const char *)out->p, (int)out->len, 0);
        if (n > 0) buf_drop(out, (uint32_t)n);
        else if (n < 0 && !WOULD_BLOCK(last_error())) return -1;
    }
    return 0;
}

static void accept_lobby(void) {
    for (;;) {
        struct sockaddr_storage a;
        socklen_t l = sizeof a;
        hsock s = accept(g_lobby, (struct sockaddr *)&a, &l);
        if (s == BAD_SOCK) return;
        set_nonblocking(s);
        const int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
        int i = 0;
        while (i < MAX_LOBBY && g_lc[i].used) i++;
        if (i == MAX_LOBBY) { close_sock(s); continue; }
        lobby_client *c = &g_lc[i];
        memset(c, 0, sizeof *c);
        c->used = 1;
        c->s = s;
        c->ip = report_ip(&a);
        c->rx = now_us();
    }
}

static void accept_relay(void) {
    for (;;) {
        hsock s = accept(g_relay, NULL, NULL);
        if (s == BAD_SOCK) return;
        set_nonblocking(s);
        const int one = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
        int i = 0;
        while (i < MAX_RELAY && g_rc[i].used) i++;
        if (i == MAX_RELAY) { close_sock(s); continue; }
        memset(&g_rc[i], 0, sizeof g_rc[i]);
        g_rc[i].used = 1;
        g_rc[i].s = s;
    }
}

static void loop_once(void) {
    fd_set r, w;
    FD_ZERO(&r); FD_ZERO(&w);
    hsock top = g_lobby > g_relay ? g_lobby : g_relay;
    FD_SET(g_lobby, &r);
    FD_SET(g_relay, &r);
    for (int i = 0; i < MAX_LOBBY; i++) if (g_lc[i].used) {
        FD_SET(g_lc[i].s, &r);
        if (g_lc[i].out.len) FD_SET(g_lc[i].s, &w);
        if (g_lc[i].s > top) top = g_lc[i].s;
    }
    for (int i = 0; i < MAX_RELAY; i++) if (g_rc[i].used) {
        FD_SET(g_rc[i].s, &r);
        if (g_rc[i].out.len) FD_SET(g_rc[i].s, &w);
        if (g_rc[i].s > top) top = g_rc[i].s;
    }
    struct timeval tv = { 0, 50000 };
    if (select((int)top + 1, &r, &w, NULL, &tv) < 0) return;
    if (FD_ISSET(g_lobby, &r)) accept_lobby();
    if (FD_ISSET(g_relay, &r)) accept_relay();
    const uint64_t now = now_us();
    for (int i = 0; i < MAX_LOBBY; i++) {
        lobby_client *c = &g_lc[i];
        if (!c->used) continue;
        if (io(c->s, &c->in, &c->out, FD_ISSET(c->s, &r), FD_ISSET(c->s, &w), &c->rx) != 0) { lobby_drop(c, "connection closed"); continue; }
        if (lobby_packets(c) != 0) { lobby_drop(c, "bad packet"); continue; }
        if (now - c->rx > IDLE_US) lobby_drop(c, "silent for 20 s");
        else if (c->out.len) io(c->s, &c->in, &c->out, 0, 1, NULL);   /* answers go out without waiting a round */
    }
    for (int i = 0; i < MAX_RELAY; i++) {
        relay_client *rc = &g_rc[i];
        if (!rc->used) continue;
        if (io(rc->s, &rc->in, &rc->out, FD_ISSET(rc->s, &r), FD_ISSET(rc->s, &w), NULL) != 0 || relay_packets(rc) != 0) relay_drop(rc);
    }
    for (int i = 0; i < MAX_RELAY; i++)                       /* forwarded frames go out at once */
        if (g_rc[i].used && g_rc[i].out.len && io(g_rc[i].s, &g_rc[i].in, &g_rc[i].out, 0, 1, NULL) != 0) relay_drop(&g_rc[i]);
}

#ifdef _WIN32
static DWORD WINAPI server_main(LPVOID unused) { (void)unused; while (g_running) loop_once(); return 0; }
#else
static void *server_main(void *unused) { (void)unused; while (g_running) loop_once(); return NULL; }
#endif

int psp_adhoc_server_start(uint16_t port, uint16_t relay_port, void (*log)(const char *line)) {
    if (g_running) return 0;
    g_log = log;
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    for (int i = 0; i < MAX_LOBBY; i++) g_lc[i].s = BAD_SOCK;
    for (int i = 0; i < MAX_RELAY; i++) g_rc[i].s = BAD_SOCK;
    g_lport = port;
    g_rport = relay_port;
    g_lobby = listen_on(port);
    g_relay = listen_on(relay_port);
    if (g_lobby == BAD_SOCK || g_relay == BAD_SOCK) {
        slog("cannot listen on TCP ports %u and %u (in use, or not allowed)", port, relay_port);
        if (g_lobby != BAD_SOCK) close_sock(g_lobby);
        if (g_relay != BAD_SOCK) close_sock(g_relay);
        g_lobby = g_relay = BAD_SOCK;
        return -1;
    }
    g_self_ip = self_ip();
    g_running = 1;
#ifdef _WIN32
    HANDLE t = CreateThread(NULL, 0, server_main, NULL, 0, NULL);
    if (!t) { g_running = 0; return -1; }
    CloseHandle(t);
#else
    pthread_t t;
    if (pthread_create(&t, NULL, server_main, NULL) != 0) { g_running = 0; return -1; }
    pthread_detach(t);
#endif
    /* Public addresses stay out of the log (players share their logs); the
     * host program shows them on screen (psp_adhoc_host_addresses). */
    char ip[16];
    slog("hosting on TCP %u and %u (on this network: %s; players elsewhere need these ports reachable)",
         port, relay_port, ip_s(g_self_ip, ip));
    return 0;
}

int psp_adhoc_server_running(void) { return g_running; }

void psp_adhoc_host_addresses(char *v4, size_t v4cap, char *v6, size_t v6cap) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    char ip[16];
    const uint32_t a = self_ip();
    snprintf(v4, v4cap, "%s", a ? ip_s(a, ip) : "");
    self_ip6(v6, v6cap);
}

int psp_adhoc_server_players(void) {
    int n = 0;
    for (int i = 0; i < MAX_LOBBY; i++) n += g_lc[i].used && g_lc[i].logged;
    return n;
}
