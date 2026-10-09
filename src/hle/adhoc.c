/* psprecomp â€” ad hoc multiplayer (sceNetAdhoc, sceNetAdhocctl,
 * sceNetAdhocDiscover) over the internet.
 *
 * A PSP plays ad hoc over its own WLAN radio. Here, as in PPSSPP (whose
 * protocols are kept, so players of either meet -- Komak57/ppsspp master,
 * Core/HLE/sceNetAdhoc.cpp and proAdhoc.cpp):
 *
 *   - Adhocctl talks to an ad hoc server ("pro adhoc server", TCP, port 27312
 *     by default; host and port are the host program's setting): u8 opcode
 *     packets -- LOGIN {MAC, nickname[128], product code[9]}, CONNECT {group
 *     name[8]}, DISCONNECT, SCAN, PING every 2 s; the server answers CONNECT
 *     {nickname, MAC, IPv4} per member of the group, DISCONNECT {IPv4}, SCAN
 *     {group, host MAC} ... SCAN_COMPLETE, CONNECT_BSSID {MAC} (joined).
 *   - Game data (PDP datagrams, PTP streams) travels one of three ways, the
 *     host program's choice (psprecomp/net.h):
 *       PPSSPP direct: UDP / TCP between the players' addresses, every port
 *         shifted by the port offset (10000 by default) -- needs reachable ports;
 *       PPSSPP relay ("aemu postoffice", TCP port 27313 of the same server):
 *         every socket is a TCP connection to the server, which forwards the
 *         data -- works behind any NAT. Init record (24 bytes) {s32 type 0 PDP /
 *         1 PTP listen / 2 PTP connect / 3 PTP accept, src MAC[8], u16 sport,
 *         dst MAC[8], u16 dport}; PDP frames {MAC[8], u16 port, u32 size, data};
 *         PTP: a 10-byte {MAC[8], u16 port} connect notice / ack, then frames
 *         {u32 size, data}. Ports carry the port offset too;
 *       modern: direct hosting through NAT traversal (adhoc_mesh.c).
 *
 * Everything runs on the game thread: adhoc_pump from the vblank poll and from
 * the calls themselves; blocking calls park only the calling PSP thread. */

#include "psprecomp/hle.h"
#include "psprecomp/net.h"
#include "adhoc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "adhoc_sock.h"

void psp_net_log_line(const char *fmt, ...);      /* net.c */

/* ---- error codes ---------------------------------------------------------------------- */

#define ADHOC_INVALID_SOCKET_ID   0x80410701u
#define ADHOC_INVALID_ADDR        0x80410702u
#define ADHOC_INVALID_PORT        0x80410703u
#define ADHOC_INVALID_DATALEN     0x80410705u
#define ADHOC_NOT_ENOUGH_SPACE    0x80400706u
#define ADHOC_SOCKET_ALERTED      0x80410708u
#define ADHOC_WOULD_BLOCK         0x80410709u
#define ADHOC_PORT_IN_USE         0x8041070Au
#define ADHOC_NOT_CONNECTED       0x8041070Bu
#define ADHOC_DISCONNECTED        0x8041070Cu
#define ADHOC_NOT_OPENED          0x8040070Du
#define ADHOC_NOT_LISTENED        0x8040070Eu
#define ADHOC_SOCKET_ID_NOT_AVAIL 0x8041070Fu
#define ADHOC_PORT_NOT_AVAIL      0x80410710u
#define ADHOC_INVALID_ARG         0x80410711u
#define ADHOC_NOT_INITIALIZED     0x80410712u
#define ADHOC_ALREADY_INITIALIZED 0x80410713u
#define ADHOC_TIMEOUT             0x80410715u
#define ADHOC_NO_ENTRY            0x80410716u
#define ADHOC_CONNECTION_REFUSED  0x80410718u
#define NET_NO_SPACE              0x80410001u
#define CTL_ALREADY_CONNECTED     0x80410B02u
#define CTL_INVALID_ARG           0x80410B04u
#define CTL_ALREADY_INITIALIZED   0x80410B07u
#define CTL_NOT_INITIALIZED       0x80410B08u
#define CTL_BUSY                  0x80410B10u
#define CTL_TOO_MANY_HANDLERS     0x80410B12u

enum { OP_PING = 0, OP_LOGIN, OP_CONNECT, OP_DISCONNECT, OP_SCAN, OP_SCAN_COMPLETE, OP_CONNECT_BSSID, OP_CHAT };
enum { EV_ERROR = 0, EV_CONNECT = 1, EV_DISCONNECT = 2, EV_SCAN = 3 };
enum { ST_DISCONNECTED = 0, ST_CONNECTED = 1, ST_SCANNING = 2 };
enum { CONN_CONNECT = 0, CONN_CREATE = 1, CONN_JOIN = 2 };
enum { PTP_CLOSED = 0, PTP_LISTEN = 1, PTP_SYN_SENT = 2, PTP_SYN_RCVD = 3, PTP_ESTABLISHED = 4 };
enum { F_NONBLOCK = 1, F_ALERTSEND = 0x10, F_ALERTRECV = 0x20, F_ALERTCONNECT = 0x80, F_ALERTACCEPT = 0x100,
       F_ALERTFLUSH = 0x200, F_ALERTALL = 0x3F0 };
enum { SOCK_PDP = 1, SOCK_PTP = 2 };
enum { RELAY_PDP = 0, RELAY_PTP_LISTEN = 1, RELAY_PTP_CONNECT = 2, RELAY_PTP_ACCEPT = 3 };

#define RELAY_PORT_DEFAULT 27313
#define SERVER_PORT_DEFAULT 27312
#define MAX_SOCK 255
#define MAX_FRIENDS 32
#define MAX_GROUPS 32
#define MAX_HANDLERS 32
#define CHANNEL 11

/* ---- configuration (psprecomp/net.h) ----------------------------------------------------- */

static char     g_server[256] = "socom.cc";
static uint16_t g_server_port = SERVER_PORT_DEFAULT;
static uint16_t g_relay_port = RELAY_PORT_DEFAULT;
static int      g_mode;                         /* PSP_ADHOC_MODE_* */
static uint16_t g_offset = 10000;
static char     g_nick[128] = "PSP2i";

void psp_adhoc_configure(const psp_adhoc_config *c) {
    if (!c) return;
    if (c->server && c->server[0]) snprintf(g_server, sizeof g_server, "%s", c->server);
    g_server_port = c->server_port ? c->server_port : SERVER_PORT_DEFAULT;
    g_relay_port = c->relay_port ? c->relay_port : RELAY_PORT_DEFAULT;
    g_mode = c->mode;
    g_offset = (uint16_t)c->port_offset;
    if (c->nickname && c->nickname[0]) snprintf(g_nick, sizeof g_nick, "%s", c->nickname);
    mesh_configure(c->stun_server, c->mesh_port);
}

/* ---- little helpers ------------------------------------------------------------------------ */

void adhoc_log(const char *fmt, ...) {
    char line[600];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    psp_net_log_line("adhoc: %s", line);
}

uint64_t adhoc_real_us(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}
/* Never 0: a friend's last_recv doubles as its "active" flag. */
uint64_t adhoc_guest_us(void) { const uint64_t t = psp_sched_now_us(); return t ? t : 1; }

static void nap(void) { psp_sched_sleep_until(psp_sched_now_us() + 1000); }

/* The ad hoc MAC: the install's address with the two low bits of the first
 * byte clear (some games reject others, as PPSSPP notes). */
void adhoc_local_mac(uint8_t mac[6]) { psp_net_ether_addr(mac); mac[0] &= 0xFC; }
int adhoc_is_local_mac(const uint8_t mac[6]) { uint8_t m[6]; adhoc_local_mac(m); return !memcmp(m, mac, 6); }
static int is_broadcast(const uint8_t m[6]) { static const uint8_t b[6] = { 255, 255, 255, 255, 255, 255 }; return !memcmp(m, b, 6); }
static int is_zero(const uint8_t m[6]) { static const uint8_t z[6] = { 0 }; return !memcmp(m, z, 6); }
static const char *mac_text(const uint8_t m[6], char *buf) {
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
    return buf;
}
static const char *ip_text(uint32_t ip_n, char *buf) {
    const uint8_t *b = (const uint8_t *)&ip_n;
    snprintf(buf, 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}
static uint32_t local_ip_n(void) {
    psp_net_host h;
    return psp_net_host_info(&h) && h.ipv4 ? htonl(h.ipv4) : htonl(INADDR_LOOPBACK);
}

static int sock_ready(hsock s, int write) {
    fd_set f, x;
    FD_ZERO(&f); FD_ZERO(&x);
    FD_SET(s, &f); FD_SET(s, &x);
    struct timeval tv = { 0, 0 };
    return select((int)s + 1, write ? NULL : &f, write ? &f : NULL, &x, &tv) > 0 && FD_ISSET(s, &f);
}

static int sock_error(hsock s) {
    int e = 0;
    socklen_t l = sizeof e;
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&e, &l);
    return e;
}

static uint32_t g_server_ip;                    /* network order; 0 = unresolved */

static void resolve_server(void) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    g_server_ip = 0;
    if (getaddrinfo(g_server, NULL, &hints, &res) == 0 && res) {
        g_server_ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(res);
    }
    char ip[16];
    if (g_server_ip) adhoc_log("server %s -> %s (port %u, relay %u)", g_server, ip_text(g_server_ip, ip), g_server_port, g_relay_port);
    else adhoc_log("cannot resolve the ad hoc server %s", g_server);
}

/* A non-blocking TCP connection to the server's port. */
static hsock tcp_connect_server(uint16_t port) {
    if (!g_server_ip) return BAD_SOCK;
    hsock s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == BAD_SOCK) return BAD_SOCK;
    set_nonblocking(s);
    const int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = g_server_ip;
    a.sin_port = htons(port);
    if (connect(s, (struct sockaddr *)&a, sizeof a) != 0 && !IN_PROGRESS(last_error())) { close_sock(s); return BAD_SOCK; }
    return s;
}

/* ---- the server connection ------------------------------------------------------------------- */

static int      g_ctl_inited, g_adhoc_inited, g_relay, g_mesh;
static hsock    g_meta = BAD_SOCK;
static int      g_meta_up;                      /* TCP connected, login queued */
static buf_t    g_meta_in, g_meta_out;
static uint64_t g_last_ping, g_meta_retry, g_meta_rx;
static int      g_in_group;                     /* a CONNECT {group} stands: re-sent after a reconnect */
static int      g_srv_group;                    /* the server has us in a group (this connection) */
static int      g_rejoining;                    /* reconnected; the next CONNECT_BSSID is not a new event */
static uint64_t g_meta_lost_at;                 /* the connection dropped (0 = fine) */

/* The server drops a client it has not heard from for 15 s (PPSSPP's and aemu's
 * servers). Pings normally go out from adhoc_pump on the game thread, which can
 * stall for longer during loading; a small host thread sends them meanwhile.
 * g_meta_mx guards the connection between the two. */
#ifdef _WIN32
static CRITICAL_SECTION g_meta_mx;
static void mx_init(void) { InitializeCriticalSection(&g_meta_mx); }
#  define META_LOCK()   EnterCriticalSection(&g_meta_mx)
#  define META_UNLOCK() LeaveCriticalSection(&g_meta_mx)
#else
#  include <pthread.h>
static pthread_mutex_t g_meta_mx;
static void mx_init(void) {
    pthread_mutexattr_t a;
    pthread_mutexattr_init(&a);
    pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&g_meta_mx, &a);
}
#  define META_LOCK()   pthread_mutex_lock(&g_meta_mx)
#  define META_UNLOCK() pthread_mutex_unlock(&g_meta_mx)
#endif
static uint8_t  g_product[16];                  /* SceNetAdhocctlAdhocId {s32 type, char data[9], pad[3]} */
static int      g_state = ST_DISCONNECTED, g_busy, g_cur_mode = -1, g_conn_type;
static uint8_t  g_group[8], g_bssid[6];
static uint64_t g_ctl_start;

static struct { int used; uint8_t mac[6]; char nick[128]; uint32_t ip; uint64_t last_recv; } g_friends[MAX_FRIENDS];
static struct { uint8_t name[8], mac[6]; } g_groups[MAX_GROUPS], g_new_groups[MAX_GROUPS];
static int g_ngroups, g_nnew_groups;
static struct { int used; uint32_t func, arg; } g_handlers[MAX_HANDLERS];
static struct { uint32_t flag, error; } g_events[32];
static int g_nevents;

static void notify(uint32_t flag, uint32_t error) {
    if (g_nevents < 32) { g_events[g_nevents].flag = flag; g_events[g_nevents].error = error; g_nevents++; }
}

static void meta_send(const void *p, uint32_t n) { META_LOCK(); buf_add(&g_meta_out, p, n); META_UNLOCK(); }

static void meta_close(void) {
    META_LOCK();
    if (g_meta != BAD_SOCK) close_sock(g_meta);
    g_meta = BAD_SOCK;
    g_meta_up = 0;
    buf_free(&g_meta_in);
    buf_free(&g_meta_out);
    META_UNLOCK();
}

static void keepalive_tick(void) {
    META_LOCK();
    const uint64_t now = adhoc_real_us();
    if (g_ctl_inited && g_meta != BAD_SOCK && g_meta_up && !g_meta_out.len && now - g_last_ping >= 2000000u) {
        const uint8_t ping = OP_PING;
        if (send(g_meta, (const char *)&ping, 1, 0) == 1) g_last_ping = now;
    }
    META_UNLOCK();
}

#ifdef _WIN32
static DWORD WINAPI keepalive_main(LPVOID unused) { (void)unused; for (;;) { Sleep(500); keepalive_tick(); } }
#else
static void *keepalive_main(void *unused) { (void)unused; for (;;) { usleep(500000); keepalive_tick(); } return NULL; }
#endif

static void keepalive_start(void) {
    static int started;
    if (started) return;
    started = 1;
    mx_init();
#ifdef _WIN32
    HANDLE h = CreateThread(NULL, 64 * 1024, keepalive_main, NULL, 0, NULL);
    if (h) CloseHandle(h);
#else
    pthread_t t;
    if (pthread_create(&t, NULL, keepalive_main, NULL) == 0) pthread_detach(t);
#endif
}

static void meta_open(void) {
    META_LOCK();
    meta_close();
    if (!g_server_ip) resolve_server();
    g_meta = tcp_connect_server(g_server_port);
    g_meta_retry = adhoc_real_us() + 5000000u;
    if (g_meta == BAD_SOCK) { adhoc_log("cannot connect to the ad hoc server"); META_UNLOCK(); return; }
    /* login: opcode, MAC, nickname[128], product code[9] */
    uint8_t p[1 + 6 + 128 + 9];
    memset(p, 0, sizeof p);
    g_srv_group = 0;                                    /* a fresh login is in no group */
    p[0] = OP_LOGIN;
    adhoc_local_mac(p + 1);
    memcpy(p + 7, g_nick, strlen(g_nick) < 127 ? strlen(g_nick) : 127);
    memcpy(p + 135, g_product + 4, 9);
    meta_send(p, sizeof p);
    char m[18];
    adhoc_log("connecting to %s:%u as %s (%s), game %.9s", g_server, g_server_port, g_nick, mac_text(p + 1, m), (const char *)g_product + 4);
    if (g_in_group) {                                   /* (re)join the group we are in */
        uint8_t c[9];
        c[0] = OP_CONNECT;
        memcpy(c + 1, g_group, 8);
        meta_send(c, sizeof c);
        g_srv_group = 1;
        if (g_meta_lost_at) { g_rejoining = 1; adhoc_log("rejoining group %.8s after the reconnect", (const char *)g_group); }
    }
    META_UNLOCK();
}

/* Group packets, sent the way the server accepts them. PPSSPP's server logs a
 * player out for DISCONNECT outside a group and for SCAN inside one; and
 * meta_open empties the send queue, so it must come before what is queued. */
static void srv_disconnect(void) {
    if (g_srv_group && g_meta != BAD_SOCK) { const uint8_t op = OP_DISCONNECT; meta_send(&op, 1); }
    g_srv_group = 0;
}
static void srv_connect(const uint8_t name[8]) {
    if (g_meta == BAD_SOCK) { meta_open(); return; }    /* sends the CONNECT after the login (g_in_group) */
    uint8_t p[9];
    p[0] = OP_CONNECT;
    memcpy(p + 1, name, 8);
    meta_send(p, sizeof p);
    g_srv_group = 1;
}
static void srv_scan(void) {
    if (g_meta == BAD_SOCK) meta_open();
    else srv_disconnect();
    const uint8_t op = OP_SCAN;
    meta_send(&op, 1);
}

static int friend_find(const uint8_t mac[6]) {
    for (int i = 0; i < MAX_FRIENDS; i++) if (g_friends[i].used && !memcmp(g_friends[i].mac, mac, 6)) return i;
    return -1;
}

int adhoc_active_peers(uint8_t (*macs)[6], int max) {
    int n = 0;
    for (int i = 0; i < MAX_FRIENDS && n < max; i++)
        if (g_friends[i].used && g_friends[i].last_recv) memcpy(macs[n++], g_friends[i].mac, 6);
    return n;
}

void adhoc_peer_seen(const uint8_t mac[6]) {
    const int f = friend_find(mac);
    if (f >= 0 && g_friends[f].last_recv) g_friends[f].last_recv = adhoc_guest_us();
}

uint32_t adhoc_peer_ip(const uint8_t mac[6]) {
    const int f = friend_find(mac);
    return f >= 0 && g_friends[f].last_recv ? g_friends[f].ip : 0;
}

int adhoc_relay_addr(uint32_t *ip_n, uint16_t *port) {
    *ip_n = g_server_ip;
    *port = g_relay_port;
    return g_server_ip != 0;
}

/* MAC -> IPv4 (network order); 0 if unknown. */
static uint32_t resolve_mac(const uint8_t mac[6]) {
    if (adhoc_is_local_mac(mac)) return local_ip_n();
    const int f = friend_find(mac);
    return f >= 0 ? g_friends[f].ip : 0;
}
static int resolve_ip(uint32_t ip, uint8_t mac[6]) {
    if (ip == local_ip_n() || ip == htonl(INADDR_LOOPBACK)) { adhoc_local_mac(mac); return 1; }
    for (int i = 0; i < MAX_FRIENDS; i++)
        if (g_friends[i].used && g_friends[i].ip == ip) { memcpy(mac, g_friends[i].mac, 6); return 1; }
    return 0;
}

static void meta_packets(void) {
    char m[18], ip[16];
    for (;;) {
        if (!g_meta_in.len) return;
        const uint8_t *p = g_meta_in.p;
        uint32_t need;
        switch (p[0]) {
        case OP_CONNECT_BSSID: need = 7; break;
        case OP_CHAT:          need = 1 + 64 + 128; break;
        case OP_CONNECT:       need = 1 + 128 + 6 + 4; break;
        case OP_DISCONNECT:    need = 5; break;
        case OP_SCAN:          need = 1 + 8 + 6; break;
        case OP_SCAN_COMPLETE: need = 1; break;
        case OP_PING:          need = 1; break;
        default:
            adhoc_log("unknown server packet 0x%02X: resynchronising", p[0]);
            buf_drop(&g_meta_in, 1);
            continue;
        }
        if (g_meta_in.len < need) return;
        switch (p[0]) {
        case OP_CONNECT_BSSID:
            memcpy(g_bssid, p + 1, 6);
            if (g_rejoining) {                          /* the game never left: no new event */
                g_rejoining = 0;
                g_meta_lost_at = 0;
                adhoc_log("rejoined group %.8s (host %s)", (const char *)g_group, mac_text(g_bssid, m));
                break;
            }
            g_meta_lost_at = 0;
            adhoc_log("joined group %.8s (host %s)", (const char *)g_group, mac_text(g_bssid, m));
            notify(EV_CONNECT, 0);
            break;
        case OP_CONNECT: {
            uint32_t a;
            memcpy(&a, p + 135, 4);
            if (adhoc_is_local_mac(p + 129)) {
                /* Ourselves: after a reconnect the server still has our old
                 * session in the group until it times out (observed 6 s), and
                 * reports it as another player. Never a peer. */
                adhoc_log("ignoring the server's stale entry for ourselves");
                break;
            }
            int f = friend_find(p + 129);
            if (f < 0) for (int i = 0; i < MAX_FRIENDS; i++) if (!g_friends[i].used) { f = i; break; }
            if (f >= 0) {
                g_friends[f].used = 1;
                memcpy(g_friends[f].mac, p + 129, 6);
                memcpy(g_friends[f].nick, p + 1, 128);
                g_friends[f].nick[127] = '\0';
                g_friends[f].ip = a;
                g_friends[f].last_recv = adhoc_guest_us();
                adhoc_log("player %s (%s) at %s", g_friends[f].nick, mac_text(g_friends[f].mac, m), ip_text(a, ip));
            }
            break;
        }
        case OP_DISCONNECT: {
            uint32_t a;
            memcpy(&a, p + 1, 4);
            for (int i = 0; i < MAX_FRIENDS; i++)
                if (g_friends[i].used && g_friends[i].ip == a) {
                    adhoc_log("player %s left", g_friends[i].nick);
                    g_friends[i].used = 0;
                }
            break;
        }
        case OP_SCAN:
            if (g_nnew_groups < MAX_GROUPS) {
                memcpy(g_new_groups[g_nnew_groups].name, p + 1, 8);
                memcpy(g_new_groups[g_nnew_groups].mac, p + 9, 6);
                g_nnew_groups++;
            }
            break;
        case OP_SCAN_COMPLETE:
            memcpy(g_groups, g_new_groups, sizeof g_groups);
            g_ngroups = g_nnew_groups;
            g_nnew_groups = 0;
            adhoc_log("scan: %d group(s)", g_ngroups);
            notify(EV_SCAN, 0);
            break;
        case OP_CHAT:
            adhoc_log("chat: %.64s", (const char *)p + 1);
            break;
        default: break;
        }
        buf_drop(&g_meta_in, need);
    }
}

/* The connection dropped: say why, reconnect soon, and keep the players for a
 * while -- dropping them at once makes the game think everyone left (observed:
 * stuck loading). The reconnect re-joins the group. */
static void meta_lost(const char *why) {
    const uint64_t now = adhoc_real_us();
    adhoc_log("%s (last ping sent %.1f s ago, last server data %.1f s ago)", why,
              (double)(now - g_last_ping) / 1e6, g_meta_rx ? (double)(now - g_meta_rx) / 1e6 : -1.0);
    meta_close();
    g_meta_retry = now + 1000000u;
    if (!g_meta_lost_at) g_meta_lost_at = now;
}

static void meta_pump_locked(void);
static void meta_pump(void) {
    if (!g_ctl_inited) return;
    META_LOCK();
    meta_pump_locked();
    META_UNLOCK();
}

static void meta_pump_locked(void) {
    const uint64_t now = adhoc_real_us();
    if (g_meta_lost_at && now - g_meta_lost_at > 20000000u) {
        adhoc_log("no server for 20 s: the other players are gone");
        for (int i = 0; i < MAX_FRIENDS; i++) g_friends[i].last_recv = 0;
        g_meta_lost_at = 0;
        g_rejoining = 0;
    }
    if (g_meta == BAD_SOCK) {
        if (now >= g_meta_retry) meta_open();
        return;
    }
    if (!g_meta_up) {
        if (sock_ready(g_meta, 1)) {
            if (sock_error(g_meta)) { adhoc_log("the ad hoc server refused the connection"); meta_close(); return; }
            g_meta_up = 1;
            g_last_ping = g_meta_rx = now;
            adhoc_log("connected to the ad hoc server");
        } else {
            if (now >= g_meta_retry) { adhoc_log("no answer from the ad hoc server"); meta_close(); }
            return;
        }
    }
    if (now - g_last_ping >= 2000000u) { const uint8_t ping = OP_PING; meta_send(&ping, 1); g_last_ping = now; }
    while (g_meta_out.len) {
        const int n = send(g_meta, (const char *)g_meta_out.p, (int)g_meta_out.len, 0);
        if (n > 0) { buf_drop(&g_meta_out, (uint32_t)n); continue; }
        if (n < 0 && WOULD_BLOCK(last_error())) break;
        char why[80];
        snprintf(why, sizeof why, "lost the ad hoc server connection (send error %d)", last_error());
        meta_lost(why);
        return;
    }
    uint8_t tmp[2048];
    for (;;) {
        const int n = recv(g_meta, (char *)tmp, sizeof tmp, 0);
        if (n > 0) { buf_add(&g_meta_in, tmp, (uint32_t)n); g_meta_rx = now; continue; }
        if (n < 0 && WOULD_BLOCK(last_error())) break;
        char why[80];
        if (n == 0) snprintf(why, sizeof why, "the ad hoc server closed the connection");
        else snprintf(why, sizeof why, "the ad hoc server connection failed (error %d)", last_error());
        meta_lost(why);
        return;
    }
    meta_packets();
}

/* Deliver one adhocctl event: the new state, then the game's handlers
 * handler(event, error, arg). A join waits for the host's details first. */
static void events_pump(void) {
    if (!g_nevents) return;
    const uint32_t flag = g_events[0].flag, err = g_events[0].error;
    if (flag == EV_CONNECT && g_conn_type == CONN_JOIN && adhoc_real_us() - g_ctl_start < 5000000u) {
        uint8_t one[1][6];
        if (!adhoc_active_peers(one, 1)) return;
    }
    memmove(g_events, g_events + 1, sizeof g_events[0] * (size_t)(g_nevents - 1));
    g_nevents--;
    switch (flag) {
    case EV_CONNECT: g_state = ST_CONNECTED; break;
    case EV_SCAN: case EV_DISCONNECT: g_state = ST_DISCONNECTED; break;
    default: break;
    }
    g_busy = 0;
    adhoc_log("event %u (error 0x%08X): state %d", flag, err, g_state);
    for (int i = 0; i < MAX_HANDLERS; i++)
        if (g_handlers[i].used) psp_sched_post_call(g_handlers[i].func, flag, err, g_handlers[i].arg, 0, 0);
}

/* ---- sockets --------------------------------------------------------------------------------- */

typedef struct {
    int used, type, flags, alerted, nonblock;
    uint32_t bufsize;
    uint8_t laddr[6], paddr[6];
    uint16_t lport, pport;               /* game ports */
    int state, retry_int, retry_cnt, attempts;
    hsock s;
    /* relay */
    int relay, rconnecting, rdead, await_ack;
    uint16_t rport;                      /* the port registered with the relay */
    buf_t rin, rout, stream;
    uint32_t frame_left;
    uint64_t rstart;
    /* modern (adhoc_mesh.c) */
    int mesh, sid;
    uint64_t tx, rx;                     /* game bytes, for the log */
    /* relay: a connect the game gave up on, kept for its retry (see hle_PtpClose) */
    int parked;
    uint64_t parked_at;
    /* relay / modern: a connection to ourselves, paired in-process (see local_connect) */
    int local, lpeer, lwant;
} asock;

static asock g_s[MAX_SOCK];

static asock *sock_get(uint32_t id, int type) {
    if (id < 1 || id > MAX_SOCK || !g_s[id - 1].used || g_s[id - 1].parked) return NULL;
    if (type && g_s[id - 1].type != type) return NULL;
    return &g_s[id - 1];
}

static int sock_new(void) {
    for (int i = 0; i < MAX_SOCK; i++) if (!g_s[i].used) { memset(&g_s[i], 0, sizeof g_s[i]); g_s[i].s = BAD_SOCK; return i + 1; }
    return 0;
}

static void sock_free(asock *a) {
    if (a->mesh) {
        if (a->type == SOCK_PDP) mesh_pdp_unbind(a->lport);
        else if (a->state == PTP_LISTEN) mesh_unlisten(a->lport);
        else if (a->sid) mesh_stream_close(a->sid);
    }
    if (a->s != BAD_SOCK) close_sock(a->s);
    buf_free(&a->rin); buf_free(&a->rout); buf_free(&a->stream);
    memset(a, 0, sizeof *a);
    a->s = BAD_SOCK;
}

static uint16_t offset_port(uint16_t p) {          /* as the reference's offset_port_simple */
    if (!p) return 0;
    p = (uint16_t)(p + g_offset);
    return p ? p : 65535;
}

/* Relay: open a TCP connection and queue the init record. */
static int relay_open(asock *a, int type, const uint8_t src[6], uint16_t sport, const uint8_t dst[6], uint16_t dport) {
    a->s = tcp_connect_server(g_relay_port);
    if (a->s == BAD_SOCK) return -1;
    a->relay = 1;
    a->rconnecting = 1;
    a->rdead = 0;
    a->rstart = adhoc_real_us();
    uint8_t init[24];
    memset(init, 0, sizeof init);
    init[0] = (uint8_t)type;
    if (src) memcpy(init + 4, src, 6);
    memcpy(init + 12, &sport, 2);
    if (dst) memcpy(init + 14, dst, 6);
    memcpy(init + 22, &dport, 2);
    buf_add(&a->rout, init, sizeof init);
    return 0;
}

/* Move relay bytes; 0 ok, -1 the connection is gone. */
static int relay_io(asock *a) {
    if (!a->relay || a->s == BAD_SOCK) return 0;       /* not opened yet */
    if (a->rdead) return -1;
    if (a->rconnecting) {
        /* The relay can be slow to accept: socom.cc's 27313 took 2-15 s per TCP
         * connect from the user's network (its 27312 ~0.2 s, ping 200 ms). */
        if (!sock_ready(a->s, 1)) {
            if (adhoc_real_us() - a->rstart > 20000000u) { adhoc_log("relay: no TCP connection after 20 s"); a->rdead = 1; return -1; }
            return 0;
        }
        if (sock_error(a->s)) { a->rdead = 1; return -1; }
        a->rconnecting = 0;
        const double took = (double)(adhoc_real_us() - a->rstart) / 1e6;
        if (took > 1.0) adhoc_log("relay: socket %d took %.1f s to reach the relay (a slow relay; a nearer server helps)", (int)(a - g_s) + 1, took);
    }
    while (a->rout.len) {
        const int n = send(a->s, (const char *)a->rout.p, (int)a->rout.len, 0);
        if (n > 0) { buf_drop(&a->rout, (uint32_t)n); continue; }
        if (n < 0 && WOULD_BLOCK(last_error())) break;
        a->rdead = 1;
        return -1;
    }
    uint8_t tmp[8192];
    for (int k = 0; k < 64; k++) {
        const int n = recv(a->s, (char *)tmp, sizeof tmp, 0);
        if (n > 0) { buf_add(&a->rin, tmp, (uint32_t)n); continue; }
        if (n < 0 && WOULD_BLOCK(last_error())) break;
        a->rdead = 1;
        return -1;
    }
    /* PTP data: the ack first (connect/accept), then u32-size frames into the stream */
    if (a->type == SOCK_PTP && a->state != PTP_LISTEN) {
        if (a->await_ack) {
            if (a->rin.len < 10) return 0;
            buf_drop(&a->rin, 10);
            a->await_ack = 0;
            if (a->state == PTP_SYN_SENT) { a->state = PTP_ESTABLISHED; adhoc_log("ptp %d: connected through the relay", (int)(a - g_s) + 1); }
        }
        while (a->rin.len) {
            if (!a->frame_left) {
                if (a->rin.len < 4) break;
                memcpy(&a->frame_left, a->rin.p, 4);
                buf_drop(&a->rin, 4);
                if (a->frame_left > 50 * 1024) { a->rdead = 1; return -1; }
                continue;
            }
            const uint32_t take = a->rin.len < a->frame_left ? a->rin.len : a->frame_left;
            buf_add(&a->stream, a->rin.p, take);
            buf_drop(&a->rin, take);
            a->frame_left -= take;
        }
    }
    return 0;
}

static void sockets_pump(void) {
    const uint64_t now = adhoc_real_us();
    for (int i = 0; i < MAX_SOCK; i++) {
        asock *a = &g_s[i];
        if (!a->used || !a->relay) continue;
        relay_io(a);
        /* a kept connect nobody came back for */
        if (a->parked && (a->rdead || now - a->parked_at > (a->state == PTP_ESTABLISHED ? 10000000u : 30000000u))) {
            adhoc_log("ptp %d: dropping the kept relay connect (%s)", i + 1, a->rdead ? "the relay closed it" : "not retried");
            if (a->s != BAD_SOCK) close_sock(a->s);
            buf_free(&a->rin); buf_free(&a->rout); buf_free(&a->stream);
            memset(a, 0, sizeof *a);
            a->s = BAD_SOCK;
        }
    }
}

/* ---- connections to ourselves ------------------------------------------------------------------
 * PSP2i's host connects to its own listening ports (13009, 12000). Through the
 * relay that is a round trip to the server per connection -- observed taking up
 * to 13 s before the room was ready. In relay and modern modes a connection to
 * our own MAC is paired in-process instead: data goes straight into the other
 * socket's stream. (Direct mode uses a real TCP connection to our address.) */

static asock *local_peer(asock *a) {
    if (!a->local || a->lpeer < 1 || a->lpeer > MAX_SOCK) return NULL;
    asock *p = &g_s[a->lpeer - 1];
    return p->used && !p->parked && p->local && p->lpeer == (int)(a - g_s) + 1 ? p : NULL;
}

/* 0 = connected, 1 = waiting for an accept, else an error. */
static uint32_t local_connect(asock *a) {
    if (a->local) return local_peer(a) ? 0 : ADHOC_CONNECTION_REFUSED;
    for (int i = 0; i < MAX_SOCK; i++) {
        const asock *l = &g_s[i];
        if (l->used && !l->parked && l->type == SOCK_PTP && l->state == PTP_LISTEN && l->lport == a->pport) {
            a->lwant = i + 1;                      /* the listener's accept completes it */
            a->state = PTP_SYN_SENT;
            return 1;
        }
    }
    a->lwant = 0;
    return 1;                                       /* nobody listens there yet: the game retries */
}

/* A waiting connect to listener l: the accepted socket's id, or 0. */
static int local_accept(asock *l, uint8_t mac[6], uint16_t *port) {
    const int lid = (int)(l - g_s) + 1;
    for (int i = 0; i < MAX_SOCK; i++) {
        asock *c = &g_s[i];
        if (!c->used || c->parked || c->lwant != lid || c->local) continue;
        const int id = sock_new();
        if (!id) return (int)NET_NO_SPACE;
        asock *a = &g_s[id - 1];
        a->used = 1; a->type = SOCK_PTP; a->nonblock = l->nonblock; a->bufsize = l->bufsize;
        a->retry_int = l->retry_int; a->retry_cnt = l->retry_cnt;
        memcpy(a->laddr, l->laddr, 6);
        a->lport = l->lport;
        memcpy(a->paddr, c->laddr, 6);
        a->pport = c->lport;
        a->state = PTP_ESTABLISHED;
        a->local = 1; a->lpeer = i + 1;
        c->local = 1; c->lpeer = id; c->lwant = 0;
        c->state = PTP_ESTABLISHED;
        memcpy(mac, a->paddr, 6);
        *port = a->pport;
        adhoc_log("ptp %d: accepted our own connection from port %u as %d (in-process)", lid, a->pport, id);
        return id;
    }
    return 0;
}

/* ---- the pump --------------------------------------------------------------------------------- */

static void netconf_pump(void);

void adhoc_pump(void) {
    meta_pump();
    events_pump();
    sockets_pump();
    if (g_mesh) mesh_pump();
    netconf_pump();
    adhoc_matching_tick();
}

/* Guest scratch ring for callback data. */
uint32_t adhoc_guest_alloc(uint32_t size) {
    static uint32_t ring, pos;
    const uint32_t RING = 64 * 1024;
    if (!ring) ring = psp_sysmem_alloc(RING, 1);
    if (!ring) return 0;
    size = (size + 15u) & ~15u;
    if (size > RING) return 0;
    if (pos + size > RING) pos = 0;
    const uint32_t a = ring + pos;
    pos += size;
    for (uint32_t i = 0; i < size; i += 4) psp_write32(a + i, 0);
    return a;
}

/* ---- sceNetAdhoc: init ------------------------------------------------------------------------ */

static void hle_AdhocInit(void) {
    if (g_adhoc_inited) { psp_ret(ADHOC_ALREADY_INITIALIZED); return; }
    g_adhoc_inited = 1;
    {   /* random ports differ per run (an unseeded rand() repeated them run after run) */
        uint8_t m[6];
        adhoc_local_mac(m);
        srand((unsigned)(adhoc_real_us() ^ ((uint32_t)m[3] << 16 | (uint32_t)m[4] << 8 | m[5])));
    }
    g_relay = g_mode == PSP_ADHOC_MODE_PPSSPP_RELAY;
    g_mesh = g_mode == PSP_ADHOC_MODE_MODERN;
    adhoc_log("sceNetAdhocInit: %s, server %s:%u, port offset %u",
              g_mesh ? "modern connection (direct hosting through NAT traversal; recomp players only)"
              : g_relay ? "PPSSPP-style relay (all data through the server's relay; works behind any NAT)"
                        : "PPSSPP-style direct (straight to other players; their ports must be reachable)",
              g_server, g_server_port, g_offset);
    if (g_relay || g_mesh) adhoc_log("relay port %u", g_relay_port);
    if (g_mesh && mesh_start() != 0) adhoc_log("modern: could not start; nothing will connect");
    psp_ret(0);
}

static void close_all_sockets(void) { for (int i = 0; i < MAX_SOCK; i++) if (g_s[i].used) sock_free(&g_s[i]); }

static void ctl_term(void);

static void hle_AdhocTerm(void) {
    ctl_term();
    if (g_adhoc_inited) close_all_sockets();
    mesh_stop();
    g_adhoc_inited = 0;
    psp_ret(0);
}

/* ---- sceNetAdhocctl ------------------------------------------------------------------------- */

static void hle_CtlInit(void) {
    const uint32_t product = psp_arg(2);
    if (g_ctl_inited) { psp_ret(CTL_ALREADY_INITIALIZED); return; }
    memset(g_product, 0, sizeof g_product);
    if (product) psp_mem_read_block(g_product, product, 16);
    keepalive_start();
    g_ctl_inited = 1;
    g_state = ST_DISCONNECTED;
    g_busy = 0;
    g_nevents = 0;
    g_in_group = 0;
    g_rejoining = 0;
    g_meta_lost_at = 0;
    resolve_server();
    meta_open();
    /* wait (up to 3 s) for the server, as the reference does before returning */
    const uint64_t end = adhoc_real_us() + 3000000u;
    while (g_meta != BAD_SOCK && !g_meta_up && adhoc_real_us() < end) { meta_pump(); nap(); }
    psp_ret(0);
}

static void ctl_disconnect(void) {
    g_in_group = 0;
    g_rejoining = 0;
    srv_disconnect();
    memset(g_group, 0, sizeof g_group);
    for (int i = 0; i < MAX_FRIENDS; i++) g_friends[i].last_recv = 0;
    g_cur_mode = -1;
    notify(EV_DISCONNECT, 0);
}

static void ctl_term(void) {
    if (!g_ctl_inited) return;
    if (g_state != ST_DISCONNECTED) { ctl_disconnect(); meta_pump(); }
    meta_close();
    memset(g_friends, 0, sizeof g_friends);
    memset(g_handlers, 0, sizeof g_handlers);
    g_nevents = 0;
    g_cur_mode = -1;
    g_busy = 0;
    g_state = ST_DISCONNECTED;
    g_ctl_inited = 0;
}

static void hle_CtlTerm(void) { ctl_term(); psp_ret(0); }

static void hle_CtlAddHandler(void) {
    const uint32_t func = psp_arg(0), arg = psp_arg(1);
    for (int i = 0; i < MAX_HANDLERS; i++) if (g_handlers[i].used && g_handlers[i].func == func) { psp_ret(0); return; }
    for (int i = 0; i < MAX_HANDLERS; i++)
        if (!g_handlers[i].used) { g_handlers[i].used = 1; g_handlers[i].func = func; g_handlers[i].arg = arg; psp_ret((uint32_t)i); return; }
    psp_ret(CTL_TOO_MANY_HANDLERS);
}

static void hle_CtlDelHandler(void) {
    const uint32_t id = psp_arg(0);
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    if (id < MAX_HANDLERS) g_handlers[id].used = 0;
    psp_ret(0);
}

static int valid_group_name(const uint8_t *n) {
    for (int i = 0; i < 8 && n[i]; i++)
        if (!((n[i] >= '0' && n[i] <= '9') || (n[i] >= 'A' && n[i] <= 'Z') || (n[i] >= 'a' && n[i] <= 'z'))) return 0;
    return 1;
}

/* Create / connect / join: ask the server for the group; CONNECT_BSSID ends it. */
static uint32_t ctl_create(const uint8_t name[8], int type) {
    if (!g_ctl_inited) return CTL_NOT_INITIALIZED;
    if (!valid_group_name(name)) return ADHOC_INVALID_ARG;
    if (g_state == ST_CONNECTED) { notify(EV_ERROR, CTL_ALREADY_CONNECTED); return 0; }
    if (g_state != ST_DISCONNECTED || g_busy) return CTL_BUSY;
    g_busy = 1;
    g_cur_mode = 0;
    g_conn_type = type;
    g_ctl_start = adhoc_real_us();
    memcpy(g_group, name, 8);
    g_in_group = 1;
    srv_connect(name);
    adhoc_log("%s group %.8s", type == CONN_JOIN ? "joining" : type == CONN_CREATE ? "creating" : "connecting to", (const char *)name);
    meta_pump();
    return 0;
}

static void read_group(uint32_t a, uint8_t name[8]) {
    memset(name, 0, 8);
    if (!a) return;
    for (int i = 0; i < 8; i++) { name[i] = psp_read8(a + (uint32_t)i); if (!name[i]) break; }
}

static void hle_CtlCreate(void)  { uint8_t n[8]; read_group(psp_arg(0), n); psp_ret(ctl_create(n, CONN_CREATE)); }
static void hle_CtlConnect(void) { uint8_t n[8]; read_group(psp_arg(0), n); psp_ret(ctl_create(n, CONN_CONNECT)); }
static void hle_CtlJoin(void) {
    const uint32_t si = psp_arg(0);
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    if (!si) { psp_ret(CTL_INVALID_ARG); return; }
    uint8_t n[8];
    psp_mem_read_block(n, si + 8, 8);              /* SceNetAdhocctlScanInfo.group_name */
    psp_ret(ctl_create(n, CONN_JOIN));
}

static void hle_CtlScan(void) {
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    if (g_state == ST_CONNECTED) { notify(EV_ERROR, CTL_ALREADY_CONNECTED); psp_ret(0); return; }
    if (g_state != ST_DISCONNECTED || g_busy) { psp_ret(CTL_BUSY); return; }
    g_busy = 1;
    g_state = ST_SCANNING;
    g_cur_mode = 0;
    g_nnew_groups = 0;
    srv_scan();
    psp_ret(0);
}

static void hle_CtlDisconnect(void) {
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    ctl_disconnect();
    psp_ret(0);
}

static void hle_CtlGetState(void) {
    const uint32_t out = psp_arg(0);
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    if (!out) { psp_ret(CTL_INVALID_ARG); return; }
    psp_write32(out, (uint32_t)g_state);
    psp_ret(0);
}

/* SceNetAdhocctlParameter {s32 channel, group[8], nickname[128], bssid[8]} */
static void hle_CtlGetParameter(void) {
    const uint32_t out = psp_arg(0);
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    if (!out) { psp_ret(CTL_INVALID_ARG); return; }
    uint8_t p[148];
    memset(p, 0, sizeof p);
    const uint32_t ch = CHANNEL;
    memcpy(p, &ch, 4);
    memcpy(p + 4, g_group, 8);
    memcpy(p + 12, g_nick, strlen(g_nick) < 127 ? strlen(g_nick) : 127);
    memcpy(p + 140, g_bssid, 6);
    psp_mem_write_block(out, p, sizeof p);
    psp_ret(0);
}

static void hle_CtlGetAdhocId(void) {
    const uint32_t out = psp_arg(0);
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    if (!out) { psp_ret(CTL_INVALID_ARG); return; }
    psp_mem_write_block(out, g_product, 16);
    psp_ret(0);
}

/* SceNetAdhocctlScanInfo {next, s32 channel, group[8], bssid[8], s32 mode}: 28 bytes */
static void hle_CtlGetScanInfo(void) {
    const uint32_t lenp = psp_arg(0), buf = psp_arg(1);
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    if (!lenp) { psp_ret(CTL_INVALID_ARG); return; }
    if (g_state == ST_CONNECTED) { psp_write32(lenp, 0); psp_ret(0); return; }
    if (!buf) { psp_write32(lenp, 28u * (uint32_t)g_ngroups); psp_ret(0); return; }
    const int req = (int)(psp_read32(lenp) / 28u);
    int n = 0;
    for (; n < g_ngroups && n < req; n++) {
        const uint32_t e = buf + 28u * (uint32_t)n;
        psp_write32(e, n + 1 < g_ngroups && n + 1 < req ? e + 28 : 0);
        psp_write32(e + 4, CHANNEL);
        psp_mem_write_block(e + 8, g_groups[n].name, 8);
        psp_mem_write_block(e + 16, g_groups[n].mac, 6);
        psp_write16(e + 22, 0);
        psp_write32(e + 24, 0);
    }
    psp_write32(lenp, 28u * (uint32_t)n);
    psp_ret(0);
}

/* SceNetAdhocctlPeerInfo {next, nickname[128], mac[6], pad, u32 flags, u64 last_recv}: 152 bytes */
static void write_peer(uint32_t e, const char *nick, const uint8_t mac[6], uint64_t last) {
    for (uint32_t i = 0; i < 152; i += 4) psp_write32(e + i, 0);
    psp_mem_write_block(e + 4, nick, (uint32_t)(strlen(nick) < 127 ? strlen(nick) : 127));
    psp_mem_write_block(e + 132, mac, 6);
    psp_write32(e + 140, 0x0400);
    psp_write32(e + 144, (uint32_t)last);
    psp_write32(e + 148, (uint32_t)(last >> 32));
}

static void hle_CtlGetPeerList(void) {
    const uint32_t lenp = psp_arg(0), buf = psp_arg(1);
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    if (!lenp) { psp_ret(CTL_INVALID_ARG); return; }
    adhoc_pump();
    int active = 0;
    for (int i = 0; i < MAX_FRIENDS; i++) if (g_friends[i].used && g_friends[i].last_recv) active++;
    if (!buf) { psp_write32(lenp, 152u * (uint32_t)active); psp_ret(0); return; }
    const int req = (int)(psp_read32(lenp) / 152u);
    int n = 0;
    const uint64_t now = adhoc_guest_us();
    for (int i = 0; i < MAX_FRIENDS && n < req; i++) {
        if (!g_friends[i].used || !g_friends[i].last_recv) continue;
        if (now > 1000000u && g_friends[i].last_recv < now - 1000000u) g_friends[i].last_recv = now - 1000000u;  /* keep it "fresh" */
        const uint32_t e = buf + 152u * (uint32_t)n;
        write_peer(e, g_friends[i].nick, g_friends[i].mac, g_friends[i].last_recv);
        if (n) psp_write32(e - 152, e);
        n++;
    }
    psp_write32(lenp, 152u * (uint32_t)n);
    psp_ret(0);
}

static void hle_CtlGetPeerInfo(void) {
    const uint32_t mac = psp_arg(0), size = psp_arg(1), out = psp_arg(2);
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    if (size < 152 || !out || !mac) { psp_ret(CTL_INVALID_ARG); return; }
    uint8_t m[6];
    psp_mem_read_block(m, mac, 6);
    const uint64_t now = adhoc_guest_us();
    if (adhoc_is_local_mac(m)) { write_peer(out, g_nick, m, now > 1000000u ? now - 1000000u : 0); psp_ret(0); return; }
    const int f = friend_find(m);
    if (f < 0 || !g_friends[f].last_recv) { psp_ret(ADHOC_NO_ENTRY); return; }
    write_peer(out, g_friends[f].nick, m, g_friends[f].last_recv);
    psp_ret(0);
}

static void hle_CtlGetNameByAddr(void) {
    const uint32_t mac = psp_arg(0), out = psp_arg(1);
    if (!g_ctl_inited) { psp_ret(CTL_NOT_INITIALIZED); return; }
    if (!mac || !out) { psp_ret(CTL_INVALID_ARG); return; }
    uint8_t m[6], name[128];
    psp_mem_read_block(m, mac, 6);
    memset(name, 0, sizeof name);
    if (adhoc_is_local_mac(m)) memcpy(name, g_nick, strlen(g_nick) < 127 ? strlen(g_nick) : 127);
    else {
        const int f = friend_find(m);
        if (f < 0 || !g_friends[f].last_recv) { psp_ret(ADHOC_NO_ENTRY); return; }
        memcpy(name, g_friends[f].nick, 128);
    }
    psp_mem_write_block(out, name, 128);
    psp_ret(0);
}

/* ---- PDP -------------------------------------------------------------------------------------- */

static int pdp_port_in_use(uint16_t port) {
    for (int i = 0; i < MAX_SOCK; i++) if (g_s[i].used && g_s[i].type == SOCK_PDP && g_s[i].lport == port) return 1;
    return 0;
}

static int pdp_create(uint8_t mac[6], int port, int bufsize, int flag) {
    if (!g_adhoc_inited) return (int)ADHOC_NOT_INITIALIZED;
    if (bufsize <= 0) return (int)ADHOC_INVALID_ARG;
    if (pdp_port_in_use((uint16_t)port)) return (int)ADHOC_PORT_IN_USE;
    if (g_mesh && port == 0) { do port = rand() % 60000 + 1024; while (pdp_port_in_use((uint16_t)port)); }
    if (port == 0) port = -(int)g_offset;              /* port 0 stays "any" after the offset (PSP2i uses it) */
    adhoc_local_mac(mac);
    if (g_cur_mode < 0) return (int)ADHOC_INVALID_ADDR;
    const int id = sock_new();
    if (!id) return (int)NET_NO_SPACE;
    asock *a = &g_s[id - 1];
    a->used = 1; a->type = SOCK_PDP; a->nonblock = flag; a->bufsize = (uint32_t)bufsize;
    memcpy(a->laddr, mac, 6);
    a->lport = (uint16_t)port;
    if (g_mesh) {
        if (mesh_pdp_bind(a->lport) != 0) { memset(a, 0, sizeof *a); a->s = BAD_SOCK; return (int)ADHOC_PORT_IN_USE; }
        a->mesh = 1;
        adhoc_log("pdp %d: port %u (modern)", id, a->lport);
        return id;
    }
    if (g_relay) {
        a->rport = offset_port(a->lport);
        if (relay_open(a, RELAY_PDP, mac, a->rport, NULL, 0) != 0) { sock_free(a); return (int)NET_NO_SPACE; }
        adhoc_log("pdp %d: port %u (relay)", id, a->lport);
        return id;
    }
    a->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (a->s == BAD_SOCK) { sock_free(a); return (int)NET_NO_SPACE; }
    const int one = 1;
    setsockopt(a->s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    const int rb = bufsize * 10, sb = bufsize * 5;
    setsockopt(a->s, SOL_SOCKET, SO_RCVBUF, (const char *)&rb, sizeof rb);
    setsockopt(a->s, SOL_SOCKET, SO_SNDBUF, (const char *)&sb, sizeof sb);
    set_nonblocking(a->s);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    uint16_t want = (uint16_t)(port + g_offset);
    if (!want && port > 0) want = 65535;
    addr.sin_port = htons(want);
    if (bind(a->s, (struct sockaddr *)&addr, sizeof addr) != 0) {
        adhoc_log("pdp: cannot bind port %u (port %d + offset %u) -- change the port offset", want, port, g_offset);
        sock_free(a);
        return (int)ADHOC_PORT_NOT_AVAIL;
    }
    socklen_t l = sizeof addr;
    if (getsockname(a->s, (struct sockaddr *)&addr, &l) == 0) a->lport = (uint16_t)(ntohs(addr.sin_port) - g_offset);
    adhoc_log("pdp %d: port %u (UDP %u)", id, a->lport, ntohs(addr.sin_port));
    return id;
}

int adhoc_pdp_create_internal(uint8_t mac[6], int port, int bufsize) { return pdp_create(mac, port, bufsize, F_NONBLOCK); }

static void hle_PdpCreate(void) {
    const uint32_t mac = psp_arg(0);
    uint8_t m[6] = { 0 };
    const int r = pdp_create(m, (int)psp_arg(1), (int)psp_arg(2), (int)psp_arg(3));
    if (mac && r > 0) psp_mem_write_block(mac, m, 6);
    psp_ret((uint32_t)r);
}

/* One datagram to one peer. 0 sent, 1 would block, -1 failed. */
static int pdp_send_one(asock *a, const uint8_t mac[6], uint16_t port, const void *data, int len) {
    if (a->mesh) { mesh_pdp_send(mac, a->lport, port, data, len); return 0; }   /* unknown peer: success, as below */
    if (a->relay) {
        if (a->rdead) return -1;
        if (a->rout.len > 512 * 1024) return 1;
        uint8_t h[14];
        memset(h, 0, sizeof h);
        memcpy(h, mac, 6);
        const uint16_t p = offset_port(port);
        memcpy(h + 8, &p, 2);
        const uint32_t n = (uint32_t)len;
        memcpy(h + 10, &n, 4);
        buf_add(&a->rout, h, 14);
        buf_add(&a->rout, data, (uint32_t)len);
        relay_io(a);
        return 0;
    }
    const uint32_t ip = resolve_mac(mac);
    if (!ip) return 0;                                    /* unknown peer: faking success, as the reference */
    struct sockaddr_in t;
    memset(&t, 0, sizeof t);
    t.sin_family = AF_INET;
    t.sin_addr.s_addr = ip;
    t.sin_port = htons((uint16_t)(port + g_offset));
    const int n = sendto(a->s, (const char *)data, len, 0, (struct sockaddr *)&t, sizeof t);
    if (n >= 0) return 0;
    return WOULD_BLOCK(last_error()) ? 1 : -1;
}

static uint32_t pdp_send(uint32_t id, const uint8_t mac[6], uint16_t port, const void *data, int len, int flag) {
    if (!g_adhoc_inited) return ADHOC_NOT_INITIALIZED;
    if (!port) return ADHOC_INVALID_PORT;
    if (len < 0) return ADHOC_INVALID_DATALEN;
    asock *a = sock_get(id, SOCK_PDP);
    if (!a) return ADHOC_INVALID_SOCKET_ID;
    if (!data && len) return ADHOC_INVALID_ARG;
    if (is_zero(mac)) return ADHOC_INVALID_ADDR;
    if (a->flags & F_ALERTSEND) { a->alerted |= F_ALERTSEND; return ADHOC_SOCKET_ALERTED; }
    if (is_broadcast(mac)) {
        for (int i = 0; i < MAX_FRIENDS; i++)
            if (g_friends[i].used && g_friends[i].last_recv) pdp_send_one(a, g_friends[i].mac, port, data, len);
        return 0;
    }
    for (;;) {
        const int r = pdp_send_one(a, mac, port, data, len);
        if (r == 0) return 0;
        if (r < 0) return flag ? ADHOC_WOULD_BLOCK : ADHOC_TIMEOUT;
        if (flag) return ADHOC_WOULD_BLOCK;
        adhoc_pump();
        nap();
    }
}

int adhoc_pdp_send_internal(int id, const uint8_t mac[6], uint16_t port, const void *data, int len) {
    return (int)pdp_send((uint32_t)id, mac, port, data, len, 1);
}

static void hle_PdpSend(void) {
    const uint32_t id = psp_arg(0), mac = psp_arg(1), port = psp_arg(2), data = psp_arg(3), len = psp_arg(4), flag = psp_cpu.r[PSP_REG_T2];
    uint8_t m[6] = { 0 };
    if (mac) psp_mem_read_block(m, mac, 6);
    if ((int)len < 0) { psp_ret(ADHOC_INVALID_DATALEN); return; }
    uint8_t stackbuf[2048], *tmp = len <= sizeof stackbuf ? stackbuf : (uint8_t *)malloc(len ? len : 1);
    if (!tmp) { psp_ret(NET_NO_SPACE); return; }
    if (len && data) psp_mem_read_block(tmp, data, len);
    psp_ret(pdp_send(id, m, (uint16_t)port, data ? tmp : NULL, (int)len, (int)flag));
    if (tmp != stackbuf) free(tmp);
}

/* 0 = got a datagram (copied, or *len set and NOT_ENOUGH_SPACE), else WOULD_BLOCK / error. */
static uint32_t pdp_recv_try(asock *a, uint8_t mac[6], uint16_t *port, uint8_t *buf, int *len) {
    if (a->mesh) {
        mesh_pump();
        const int r = mesh_pdp_recv(a->lport, mac, port, buf, len);
        if (r == 1) { adhoc_peer_seen(mac); return 0; }
        return r == 2 ? ADHOC_NOT_ENOUGH_SPACE : ADHOC_WOULD_BLOCK;
    }
    if (a->relay) {
        if (relay_io(a) != 0 && !a->rin.len) return ADHOC_WOULD_BLOCK;
        if (a->rin.len < 14) return ADHOC_WOULD_BLOCK;
        uint32_t size;
        memcpy(&size, a->rin.p + 10, 4);
        if (a->rin.len < 14 + size) return ADHOC_WOULD_BLOCK;
        if ((int)size > *len) { *len = (int)size; return ADHOC_NOT_ENOUGH_SPACE; }
        memcpy(mac, a->rin.p, 6);
        uint16_t p;
        memcpy(&p, a->rin.p + 8, 2);
        *port = (uint16_t)(p - g_offset);
        memcpy(buf, a->rin.p + 14, size);
        *len = (int)size;
        buf_drop(&a->rin, 14 + size);
        adhoc_peer_seen(mac);
        return 0;
    }
    static uint8_t peek[65536];
    for (int k = 0; k < 16; k++) {
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        memset(&from, 0, sizeof from);
        const int n = recvfrom(a->s, (char *)peek, sizeof peek, MSG_PEEK, (struct sockaddr *)&from, &fl);
        if (n < 0) {
            const int e = last_error();
#ifdef _WIN32
            if (e == WSAECONNRESET) { recvfrom(a->s, (char *)peek, sizeof peek, 0, NULL, NULL); continue; }
#endif
            return WOULD_BLOCK(e) ? ADHOC_WOULD_BLOCK : ADHOC_TIMEOUT;
        }
        if (!resolve_ip(from.sin_addr.s_addr, mac)) {          /* not a player of this group: drop */
            recvfrom(a->s, (char *)peek, sizeof peek, 0, NULL, NULL);
            continue;
        }
        *port = (uint16_t)(ntohs(from.sin_port) - g_offset);
        if (n > *len) {
            if (*len > 0) memcpy(buf, peek, (size_t)*len);
            *len = n;
            return ADHOC_NOT_ENOUGH_SPACE;
        }
        const int got = recvfrom(a->s, (char *)buf, *len, 0, NULL, NULL);
        *len = got < 0 ? 0 : got;
        adhoc_peer_seen(mac);
        return 0;
    }
    return ADHOC_WOULD_BLOCK;
}

int adhoc_pdp_recv_internal(int id, uint8_t mac[6], uint16_t *port, void *buf, int *len) {
    asock *a = sock_get((uint32_t)id, SOCK_PDP);
    if (!a) return (int)ADHOC_INVALID_SOCKET_ID;
    if (a->flags & F_ALERTRECV) { a->alerted |= F_ALERTRECV; return (int)ADHOC_SOCKET_ALERTED; }
    return (int)pdp_recv_try(a, mac, port, (uint8_t *)buf, len);
}

static void hle_PdpRecv(void) {
    const uint32_t id = psp_arg(0), macp = psp_arg(1), portp = psp_arg(2), buf = psp_arg(3), lenp = psp_arg(4),
                   timeout = psp_cpu.r[PSP_REG_T1], flag = psp_cpu.r[PSP_REG_T2];
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    asock *a = sock_get(id, SOCK_PDP);
    if (!a) { psp_ret(ADHOC_INVALID_SOCKET_ID); return; }
    if (!macp || !portp || !buf || !lenp) { psp_ret(ADHOC_INVALID_ARG); return; }
    const uint64_t end = timeout ? adhoc_real_us() + timeout : 0;
    int cap = (int)psp_read32(lenp);
    if (cap < 0) cap = 0;
    uint8_t *tmp = (uint8_t *)malloc((size_t)cap + 1);
    if (!tmp) { psp_ret(NET_NO_SPACE); return; }
    uint32_t r;
    for (;;) {
        if (a->flags & F_ALERTRECV) { a->alerted |= F_ALERTRECV; r = ADHOC_SOCKET_ALERTED; break; }
        uint8_t mac[6];
        uint16_t port = 0;
        int len = cap;
        r = pdp_recv_try(a, mac, &port, tmp, &len);
        if (r == 0 || r == ADHOC_NOT_ENOUGH_SPACE) {
            if (len > 0 && r == 0) psp_mem_write_block(buf, tmp, (uint32_t)len);
            else if (r == ADHOC_NOT_ENOUGH_SPACE && cap > 0) psp_mem_write_block(buf, tmp, (uint32_t)cap);
            psp_mem_write_block(macp, mac, 6);
            psp_write16(portp, port);
            psp_write32(lenp, (uint32_t)len);
            break;
        }
        if (r != ADHOC_WOULD_BLOCK || flag) break;
        if (end && adhoc_real_us() >= end) { r = ADHOC_TIMEOUT; break; }
        adhoc_pump();
        nap();
        a = sock_get(id, SOCK_PDP);
        if (!a) { r = ADHOC_INVALID_SOCKET_ID; break; }
    }
    free(tmp);
    psp_ret(r);
}

void adhoc_pdp_delete_internal(int id) { asock *a = sock_get((uint32_t)id, SOCK_PDP); if (a) sock_free(a); }

static void hle_PdpDelete(void) {
    const uint32_t id = psp_arg(0);
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    asock *a = sock_get(id, SOCK_PDP);
    if (!a) { psp_ret(ADHOC_INVALID_SOCKET_ID); return; }
    sock_free(a);
    psp_ret(0);
}

static uint32_t avail_to_recv(asock *a) {
    if (a->local) return a->stream.len;
    if (a->mesh) {
        if (a->type == SOCK_PDP) return mesh_pdp_avail(a->lport);
        return a->sid ? mesh_stream_avail(a->sid) : 0;
    }
    if (a->relay) {
        relay_io(a);
        return a->type == SOCK_PTP ? a->stream.len : a->rin.len;
    }
    if (a->s == BAD_SOCK) return 0;
#ifdef _WIN32
    u_long n = 0;
    ioctlsocket(a->s, FIONREAD, &n);
#else
    int n = 0;
    ioctl(a->s, FIONREAD, &n);
#endif
    return (uint32_t)n < a->bufsize || !a->bufsize ? (uint32_t)n : a->bufsize;
}

/* SceNetAdhocPdpStat {next, s32 id, laddr[6], u16 lport, u32 rcv_sb_cc}: 20 bytes */
static void hle_GetPdpStat(void) {
    const uint32_t lenp = psp_arg(0), buf = psp_arg(1);
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    if (!lenp) { psp_ret(ADHOC_INVALID_ARG); return; }
    int count = 0;
    for (int i = 0; i < MAX_SOCK; i++) if (g_s[i].used && g_s[i].type == SOCK_PDP) count++;
    if (!buf) { psp_write32(lenp, 20u * (uint32_t)count); psp_ret(0); return; }
    const int req = (int)(psp_read32(lenp) / 20u);
    int n = 0;
    for (int i = 0; i < MAX_SOCK && n < req; i++) {
        if (!g_s[i].used || g_s[i].type != SOCK_PDP) continue;
        const uint32_t e = buf + 20u * (uint32_t)n;
        psp_write32(e, 0);
        if (n) psp_write32(e - 20, e);
        psp_write32(e + 4, (uint32_t)i + 1);
        psp_mem_write_block(e + 8, g_s[i].laddr, 6);
        psp_write16(e + 14, g_s[i].lport);
        psp_write32(e + 16, avail_to_recv(&g_s[i]));
        n++;
    }
    psp_write32(lenp, 20u * (uint32_t)n);
    psp_ret(0);
}

void adhoc_set_socket_alert(int id, int flags) {
    asock *a = sock_get((uint32_t)id, 0);
    if (a) { a->flags = flags & F_ALERTALL; a->alerted = 0; }
}

static void hle_SetSocketAlert(void) {
    asock *a = sock_get(psp_arg(0), 0);
    if (!a) { psp_ret(ADHOC_INVALID_SOCKET_ID); return; }
    a->flags = (int)psp_arg(1) & F_ALERTALL;
    a->alerted = 0;
    psp_ret(0);
}

/* ---- PTP -------------------------------------------------------------------------------------- */

static int ptp_port_in_use(uint16_t port, int listen, const uint8_t *dmac, uint16_t dport) {
    for (int i = 0; i < MAX_SOCK; i++) {
        const asock *a = &g_s[i];
        if (!a->used || a->parked || a->type != SOCK_PTP || a->lport != port) continue;
        if (listen && a->state == PTP_LISTEN) return 1;
        if (!listen && a->state != PTP_LISTEN && dmac && !memcmp(a->paddr, dmac, 6) && a->pport == dport) return 1;
    }
    return 0;
}

/* A non-blocking connect attempt. 0 = established, 1 = in progress, else an error. */
static uint32_t ptp_connect_try(asock *a) {
    if (a->state == PTP_ESTABLISHED) return 0;
    if ((g_relay || g_mesh) && adhoc_is_local_mac(a->paddr)) return local_connect(a);
    if (a->mesh) {
        if (!a->sid) {
            a->sid = mesh_stream_open(a->paddr, a->lport, a->pport);
            if (!a->sid) return ADHOC_SOCKET_ID_NOT_AVAIL;
            a->state = PTP_SYN_SENT;
        }
        mesh_pump();
        const int st = mesh_stream_state(a->sid);
        if (st > 0) { a->state = PTP_ESTABLISHED; return 0; }
        if (st < 0) { mesh_stream_close(a->sid); a->sid = 0; a->state = PTP_CLOSED; return ADHOC_CONNECTION_REFUSED; }
        return 1;
    }
    if (a->relay) {
        if (a->s == BAD_SOCK) {
            const uint8_t *src = a->laddr;
            if (relay_open(a, RELAY_PTP_CONNECT, src, offset_port(a->lport), a->paddr, offset_port(a->pport)) != 0) return ADHOC_CONNECTION_REFUSED;
            a->await_ack = 1;
            a->state = PTP_SYN_SENT;
        }
        if (relay_io(a) != 0) {
            char m[18];
            adhoc_log("ptp %d: the relay closed the connect to %s:%u after %.1f s (nobody accepting there yet?)",
                      (int)(a - g_s) + 1, mac_text(a->paddr, m), a->pport, (double)(adhoc_real_us() - a->rstart) / 1e6);
            close_sock(a->s); a->s = BAD_SOCK;
            buf_free(&a->rin); buf_free(&a->rout);
            a->state = PTP_CLOSED;
            return ADHOC_CONNECTION_REFUSED;
        }
        return a->state == PTP_ESTABLISHED ? 0 : 1;
    }
    const uint32_t ip = resolve_mac(a->paddr);
    if (!ip) return ADHOC_INVALID_ADDR;
    if (a->state == PTP_SYN_SENT) {
        if (!sock_ready(a->s, 1)) return 1;
        const int e = sock_error(a->s);
        struct sockaddr_in pn;
        socklen_t pl = sizeof pn;
        if (!e && getpeername(a->s, (struct sockaddr *)&pn, &pl) == 0) { a->state = PTP_ESTABLISHED; return 0; }
        a->state = PTP_CLOSED;                         /* refused: recreate and retry */
    }
    if (a->state == PTP_CLOSED) {
        if (a->attempts++) {                           /* a failed socket cannot connect again everywhere */
            close_sock(a->s);
            a->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (a->s == BAD_SOCK) return ADHOC_SOCKET_ID_NOT_AVAIL;
            const int one = 1;
            setsockopt(a->s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
            setsockopt(a->s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
            set_nonblocking(a->s);
            struct sockaddr_in b;
            memset(&b, 0, sizeof b);
            b.sin_family = AF_INET;
            b.sin_port = htons((uint16_t)(a->lport + g_offset));
            bind(a->s, (struct sockaddr *)&b, sizeof b);
        }
        struct sockaddr_in t;
        memset(&t, 0, sizeof t);
        t.sin_family = AF_INET;
        t.sin_addr.s_addr = ip;
        t.sin_port = htons((uint16_t)(a->pport + g_offset));
        if (connect(a->s, (struct sockaddr *)&t, sizeof t) == 0) { a->state = PTP_ESTABLISHED; return 0; }
        const int e = last_error();
        if (!IN_PROGRESS(e)) return ADHOC_CONNECTION_REFUSED;
        a->state = PTP_SYN_SENT;
    }
    return 1;
}

static uint32_t ptp_connect(uint32_t id, uint32_t timeout, int flag) {
    if (!g_adhoc_inited) return ADHOC_NOT_INITIALIZED;
    asock *a = sock_get(id, SOCK_PTP);
    if (!a) return ADHOC_INVALID_SOCKET_ID;
    if (a->flags & F_ALERTCONNECT) { a->alerted |= F_ALERTCONNECT; return ADHOC_SOCKET_ALERTED; }
    if (a->state == PTP_ESTABLISHED) return 0;         /* PSP2i connects again after success */
    if (a->state != PTP_CLOSED && a->state != PTP_SYN_SENT) return ADHOC_NOT_OPENED;
    const uint64_t end = timeout ? adhoc_real_us() + timeout : 0;
    for (;;) {
        const uint32_t r = ptp_connect_try(a);
        if (r == 0) { char m[18]; adhoc_log("ptp %u: connected to %s:%u", id, mac_text(a->paddr, m), a->pport); return 0; }
        if (r != 1 && r != ADHOC_CONNECTION_REFUSED) return r;
        if (flag) return ADHOC_WOULD_BLOCK;
        if (end && adhoc_real_us() >= end) return ADHOC_TIMEOUT;
        adhoc_pump();
        nap();
        a = sock_get(id, SOCK_PTP);
        if (!a) return ADHOC_INVALID_SOCKET_ID;
    }
}

static uint16_t random_port(void) {
    for (;;) {
        const uint16_t p = (uint16_t)(rand() % 65534 + 1);
        int used = 0;
        for (int i = 0; i < MAX_SOCK; i++) if (g_s[i].used && g_s[i].type == SOCK_PTP && g_s[i].lport == p) used = 1;
        if (!used) return p;
    }
}

static void hle_PtpOpen(void) {
    const uint32_t srcmac = psp_arg(0), dstmac = psp_arg(2);
    int sport = (int)psp_arg(1);
    const int dport = (int)psp_arg(3), bufsize = (int)psp_cpu.r[PSP_REG_T0], rexmt_int = (int)psp_cpu.r[PSP_REG_T1],
              rexmt_cnt = (int)psp_cpu.r[PSP_REG_T2], flag = (int)psp_cpu.r[PSP_REG_T3];
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    uint8_t src[6], dst[6] = { 0 };
    adhoc_local_mac(src);
    if (srcmac) psp_mem_write_block(srcmac, src, 6);
    if (dstmac) psp_mem_read_block(dst, dstmac, 6);
    if (g_cur_mode < 0 || !srcmac || !dstmac || is_broadcast(dst) || is_zero(dst)) { psp_ret(ADHOC_INVALID_ADDR); return; }
    if (ptp_port_in_use((uint16_t)sport, 0, dst, (uint16_t)dport)) { psp_ret(ADHOC_PORT_IN_USE); return; }
    if (bufsize <= 0 || rexmt_int <= 0 || rexmt_cnt <= 0) { psp_ret(ADHOC_INVALID_ARG); return; }
    if (g_relay) {                                      /* the retry of a connect kept by hle_PtpClose */
        for (int i = 0; i < MAX_SOCK; i++) {
            asock *k = &g_s[i];
            if (!k->used || !k->parked || memcmp(k->paddr, dst, 6) || k->pport != (uint16_t)dport) continue;
            if (sport && k->lport != (uint16_t)sport) continue;
            k->parked = 0;
            k->nonblock = flag; k->bufsize = (uint32_t)bufsize; k->retry_int = rexmt_int; k->retry_cnt = rexmt_cnt;
            k->tx = k->rx = 0;
            char m[18];
            adhoc_log("ptp %d: open port %u -> %s:%u (relay), continuing the kept connect (%.1f s so far%s)", i + 1, k->lport,
                      mac_text(dst, m), k->pport, (double)(adhoc_real_us() - k->rstart) / 1e6,
                      k->state == PTP_ESTABLISHED ? ", already connected" : "");
            psp_ret((uint32_t)(i + 1));
            return;
        }
    }
    const int id = sock_new();
    if (!id) { psp_ret(NET_NO_SPACE); return; }
    asock *a = &g_s[id - 1];
    a->used = 1; a->type = SOCK_PTP; a->nonblock = flag; a->bufsize = (uint32_t)bufsize;
    a->retry_int = rexmt_int; a->retry_cnt = rexmt_cnt;
    memcpy(a->laddr, src, 6);
    memcpy(a->paddr, dst, 6);
    a->pport = (uint16_t)dport;
    a->state = PTP_CLOSED;
    if (g_mesh) {
        a->lport = sport ? (uint16_t)sport : random_port();
        a->mesh = 1;                                    /* the stream opens on connect */
    } else if (g_relay) {
        a->lport = sport ? (uint16_t)sport : random_port();
        a->relay = 1;                                   /* the relay session opens on connect */
    } else {
        if (!sport) sport = -(int)g_offset;
        a->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (a->s == BAD_SOCK) { sock_free(a); psp_ret(NET_NO_SPACE); return; }
        const int one = 1;
        setsockopt(a->s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
        setsockopt(a->s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
        set_nonblocking(a->s);
        struct sockaddr_in b;
        memset(&b, 0, sizeof b);
        b.sin_family = AF_INET;
        uint16_t want = (uint16_t)(sport + g_offset);
        if (!want && sport > 0) want = 65535;
        b.sin_port = htons(want);
        if (bind(a->s, (struct sockaddr *)&b, sizeof b) != 0) {
            adhoc_log("ptp: cannot bind port %u -- change the port offset", want);
            sock_free(a);
            psp_ret(ADHOC_PORT_NOT_AVAIL);
            return;
        }
        socklen_t l = sizeof b;
        getsockname(a->s, (struct sockaddr *)&b, &l);
        a->lport = (uint16_t)(ntohs(b.sin_port) - g_offset);
    }
    char m[18];
    adhoc_log("ptp %d: open port %u -> %s:%u%s", id, a->lport, mac_text(dst, m), a->pport, g_mesh ? " (modern)" : g_relay ? " (relay)" : "");
    ptp_connect_try(a);                                 /* games may send right after opening */
    psp_ret((uint32_t)id);
}

static void hle_PtpListen(void) {
    const uint32_t srcmac = psp_arg(0);
    int sport = (int)psp_arg(1);
    const int bufsize = (int)psp_arg(2), rexmt_int = (int)psp_arg(3), rexmt_cnt = (int)psp_cpu.r[PSP_REG_T0],
              backlog = (int)psp_cpu.r[PSP_REG_T1], flag = (int)psp_cpu.r[PSP_REG_T2];
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    uint8_t src[6];
    adhoc_local_mac(src);
    if (srcmac) psp_mem_write_block(srcmac, src, 6);
    if (g_cur_mode < 0 || !srcmac) { psp_ret(ADHOC_INVALID_ADDR); return; }
    if (ptp_port_in_use((uint16_t)sport, 1, NULL, 0)) { psp_ret(ADHOC_PORT_IN_USE); return; }
    if (bufsize <= 0 || rexmt_int <= 0 || rexmt_cnt <= 0 || backlog <= 0) { psp_ret(ADHOC_INVALID_ARG); return; }
    if (!sport) sport = g_mesh ? random_port() : -(int)g_offset;
    const int id = sock_new();
    if (!id) { psp_ret(NET_NO_SPACE); return; }
    asock *a = &g_s[id - 1];
    a->used = 1; a->type = SOCK_PTP; a->nonblock = flag; a->bufsize = (uint32_t)bufsize;
    a->retry_int = rexmt_int; a->retry_cnt = rexmt_cnt;
    memcpy(a->laddr, src, 6);
    a->state = PTP_LISTEN;
    a->lport = (uint16_t)sport;
    if (g_mesh) {
        if (mesh_listen(a->lport) != 0) { memset(a, 0, sizeof *a); a->s = BAD_SOCK; psp_ret(ADHOC_PORT_IN_USE); return; }
        a->mesh = 1;
        adhoc_log("ptp %d: listening on port %u (modern)", id, a->lport);
        psp_ret((uint32_t)id);
        return;
    }
    if (g_relay) {
        a->rport = (uint16_t)(a->lport + g_offset);
        if (relay_open(a, RELAY_PTP_LISTEN, src, a->rport, NULL, 0) != 0) { sock_free(a); psp_ret(NET_NO_SPACE); return; }
        adhoc_log("ptp %d: listening on port %u (relay)", id, a->lport);
        psp_ret((uint32_t)id);
        return;
    }
    a->s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (a->s == BAD_SOCK) { sock_free(a); psp_ret(NET_NO_SPACE); return; }
    const int one = 1;
    setsockopt(a->s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    set_nonblocking(a->s);
    struct sockaddr_in b;
    memset(&b, 0, sizeof b);
    b.sin_family = AF_INET;
    uint16_t want = (uint16_t)(sport + g_offset);
    if (!want && sport > 0) want = 65535;
    b.sin_port = htons(want);
    if (bind(a->s, (struct sockaddr *)&b, sizeof b) != 0 || listen(a->s, backlog) != 0) {
        adhoc_log("ptp: cannot listen on port %u -- change the port offset", want);
        sock_free(a);
        psp_ret(ADHOC_PORT_NOT_AVAIL);
        return;
    }
    socklen_t l = sizeof b;
    getsockname(a->s, (struct sockaddr *)&b, &l);
    a->lport = (uint16_t)(ntohs(b.sin_port) - g_offset);
    adhoc_log("ptp %d: listening on port %u (TCP %u)", id, a->lport, ntohs(b.sin_port));
    psp_ret((uint32_t)id);
}

/* One accepted connection, or 0 (none yet), or an error. */
static int ptp_accept_try(asock *l, uint8_t mac[6], uint16_t *port) {
    const int lid = (int)(l - g_s) + 1;
    {
        const int r = local_accept(l, mac, port);
        if (r) return r;
    }
    if (l->mesh) {
        mesh_pump();
        uint8_t cmac[6];
        uint16_t cport = 0;
        const int sid = mesh_accept(l->lport, cmac, &cport);
        if (!sid) return 0;
        const int id = sock_new();
        if (!id) { mesh_stream_close(sid); return (int)NET_NO_SPACE; }
        asock *a = &g_s[id - 1];
        a->used = 1; a->type = SOCK_PTP; a->nonblock = l->nonblock; a->bufsize = l->bufsize;
        a->retry_int = l->retry_int; a->retry_cnt = l->retry_cnt;
        memcpy(a->laddr, l->laddr, 6);
        a->lport = l->lport;
        memcpy(a->paddr, cmac, 6);
        a->pport = cport;
        a->state = PTP_ESTABLISHED;
        a->mesh = 1;
        a->sid = sid;
        memcpy(mac, cmac, 6);
        *port = cport;
        char m[18];
        adhoc_log("ptp %d: accepted %s:%u as %d (modern)", lid, mac_text(cmac, m), cport, id);
        return id;
    }
    if (l->relay) {
        if (relay_io(l) != 0) {                        /* the listen registration died: renew it */
            close_sock(l->s); l->s = BAD_SOCK;
            buf_free(&l->rin); buf_free(&l->rout);
            relay_open(l, RELAY_PTP_LISTEN, l->laddr, l->rport, NULL, 0);
            return 0;
        }
        if (l->rin.len < 10) return 0;
        uint8_t cmac[6];
        uint16_t cport;
        memcpy(cmac, l->rin.p, 6);
        memcpy(&cport, l->rin.p + 8, 2);
        buf_drop(&l->rin, 10);
        const int id = sock_new();
        if (!id) return (int)NET_NO_SPACE;
        asock *a = &g_s[id - 1];
        a->used = 1; a->type = SOCK_PTP; a->nonblock = l->nonblock; a->bufsize = l->bufsize;
        a->retry_int = l->retry_int; a->retry_cnt = l->retry_cnt;
        memcpy(a->laddr, l->laddr, 6);
        a->lport = l->lport;
        memcpy(a->paddr, cmac, 6);
        a->pport = (uint16_t)(cport - g_offset);
        a->state = PTP_ESTABLISHED;
        if (relay_open(a, RELAY_PTP_ACCEPT, l->laddr, l->rport, cmac, cport) != 0) { sock_free(a); return 0; }
        a->await_ack = 1;
        memcpy(mac, cmac, 6);
        *port = (uint16_t)(cport - g_offset);
        char m[18];
        adhoc_log("ptp %d: accepted %s:%u as %d (relay)", lid, mac_text(cmac, m), *port, id);
        return id;
    }
    struct sockaddr_in peer;
    socklen_t pl = sizeof peer;
    const hsock s = accept(l->s, (struct sockaddr *)&peer, &pl);
    if (s == BAD_SOCK) return 0;
    uint8_t pm[6];
    if (!resolve_ip(peer.sin_addr.s_addr, pm)) { close_sock(s); return 0; }
    const int id = sock_new();
    if (!id) { close_sock(s); return (int)NET_NO_SPACE; }
    asock *a = &g_s[id - 1];
    a->used = 1; a->type = SOCK_PTP; a->nonblock = l->nonblock; a->bufsize = l->bufsize;
    a->retry_int = l->retry_int; a->retry_cnt = l->retry_cnt;
    a->s = s;
    set_nonblocking(s);
    const int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof one);
    struct sockaddr_in loc;
    socklen_t ll = sizeof loc;
    getsockname(s, (struct sockaddr *)&loc, &ll);
    adhoc_local_mac(a->laddr);
    a->lport = (uint16_t)(ntohs(loc.sin_port) - g_offset);
    memcpy(a->paddr, pm, 6);
    a->pport = (uint16_t)(ntohs(peer.sin_port) - g_offset);
    a->state = PTP_ESTABLISHED;
    a->attempts = 1;
    memcpy(mac, pm, 6);
    *port = a->pport;
    char m[18];
    adhoc_log("ptp %d: accepted %s:%u as %d", lid, mac_text(pm, m), a->pport, id);
    return id;
}

static void hle_PtpAccept(void) {
    const uint32_t id = psp_arg(0), macp = psp_arg(1), portp = psp_arg(2), timeout = psp_arg(3), flag = psp_cpu.r[PSP_REG_T0];
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    const uint64_t end = timeout ? adhoc_real_us() + timeout : 0;
    for (;;) {
        asock *l = sock_get(id, SOCK_PTP);
        if (!l) { psp_ret(ADHOC_INVALID_SOCKET_ID); return; }
        if (l->flags & F_ALERTACCEPT) { l->alerted |= F_ALERTACCEPT; psp_ret(ADHOC_SOCKET_ALERTED); return; }
        if (l->state != PTP_LISTEN) { psp_ret(ADHOC_NOT_LISTENED); return; }
        uint8_t mac[6];
        uint16_t port = 0;
        const int r = ptp_accept_try(l, mac, &port);
        if (r > 0) {
            if (macp) psp_mem_write_block(macp, mac, 6);
            if (portp) psp_write16(portp, port);
            psp_ret((uint32_t)r);
            return;
        }
        if (r < 0) { psp_ret((uint32_t)r); return; }
        if (flag) { psp_ret(ADHOC_WOULD_BLOCK); return; }
        if (end && adhoc_real_us() >= end) { psp_ret(ADHOC_TIMEOUT); return; }
        adhoc_pump();
        nap();
    }
}

static void hle_PtpConnect(void) { psp_ret(ptp_connect(psp_arg(0), psp_arg(1), (int)psp_arg(2))); }

static void hle_PtpSend(void) {
    const uint32_t id = psp_arg(0), data = psp_arg(1), lenp = psp_arg(2), timeout = psp_arg(3), flag = psp_cpu.r[PSP_REG_T0];
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    const uint64_t end = timeout ? adhoc_real_us() + timeout : 0;
    for (;;) {
        asock *a = sock_get(id, SOCK_PTP);
        if (!a) { psp_ret(ADHOC_INVALID_SOCKET_ID); return; }
        if (a->state == PTP_SYN_SENT) ptp_connect_try(a);
        if (a->state != PTP_ESTABLISHED && a->state != PTP_SYN_SENT) { psp_ret(ADHOC_NOT_CONNECTED); return; }
        if (!data || !lenp || (int)psp_read32(lenp) <= 0) { psp_ret(ADHOC_INVALID_ARG); return; }
        if (a->flags & F_ALERTSEND) { a->alerted |= F_ALERTSEND; psp_ret(ADHOC_SOCKET_ALERTED); return; }
        uint32_t len = psp_read32(lenp);
        if (a->state == PTP_ESTABLISHED && a->local) {
            asock *p = local_peer(a);
            if (!p) { a->state = PTP_CLOSED; psp_ret(ADHOC_DISCONNECTED); return; }
            if (p->stream.len < 1024 * 1024) {
                uint8_t *tmp = (uint8_t *)malloc(len);
                if (!tmp) { psp_ret(NET_NO_SPACE); return; }
                psp_mem_read_block(tmp, data, len);
                buf_add(&p->stream, tmp, len);
                free(tmp);
                a->tx += len;
                psp_write32(lenp, len);
                psp_ret(0);
                return;
            }
        } else if (a->state == PTP_ESTABLISHED) {
            if (a->mesh) {
                uint8_t *tmp = (uint8_t *)malloc(len);
                if (!tmp) { psp_ret(NET_NO_SPACE); return; }
                psp_mem_read_block(tmp, data, len);
                const int n = mesh_stream_send(a->sid, tmp, (int)len);
                free(tmp);
                if (n > 0) { a->tx += (uint32_t)n; psp_write32(lenp, (uint32_t)n); psp_ret(0); return; }
                if (n < 0) { a->state = PTP_CLOSED; psp_ret(ADHOC_DISCONNECTED); return; }
            } else if (a->relay) {
                if (a->rdead) { a->state = PTP_CLOSED; psp_ret(ADHOC_DISCONNECTED); return; }
                if (len > 50 * 1024) len = 50 * 1024;
                if (a->rout.len < 1024 * 1024) {
                    uint8_t *tmp = (uint8_t *)malloc(len);
                    if (!tmp) { psp_ret(NET_NO_SPACE); return; }
                    psp_mem_read_block(tmp, data, len);
                    buf_add(&a->rout, &len, 4);
                    buf_add(&a->rout, tmp, len);
                    free(tmp);
                    relay_io(a);
                    a->tx += len; psp_write32(lenp, len);
                    psp_ret(0);
                    return;
                }
            } else {
                uint8_t *tmp = (uint8_t *)malloc(len);
                if (!tmp) { psp_ret(NET_NO_SPACE); return; }
                psp_mem_read_block(tmp, data, len);
                const int n = send(a->s, (const char *)tmp, (int)len, 0);
                const int e = n < 0 ? last_error() : 0;
                free(tmp);
                if (n > 0) { a->tx += (uint32_t)n; psp_write32(lenp, (uint32_t)n); psp_ret(0); return; }
                if (!WOULD_BLOCK(e)) { a->state = PTP_CLOSED; psp_ret(ADHOC_DISCONNECTED); return; }
            }
        }
        if (flag) { psp_ret(ADHOC_WOULD_BLOCK); return; }
        if (end && adhoc_real_us() >= end) { psp_ret(ADHOC_TIMEOUT); return; }
        adhoc_pump();
        nap();
    }
}

static void hle_PtpRecv(void) {
    const uint32_t id = psp_arg(0), buf = psp_arg(1), lenp = psp_arg(2), timeout = psp_arg(3), flag = psp_cpu.r[PSP_REG_T0];
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    if (!buf || !lenp || (int)psp_read32(lenp) <= 0) { psp_ret(ADHOC_INVALID_ARG); return; }
    const uint64_t end = timeout ? adhoc_real_us() + timeout : 0;
    const uint32_t cap = psp_read32(lenp);
    for (;;) {
        asock *a = sock_get(id, SOCK_PTP);
        if (!a) { psp_ret(ADHOC_INVALID_SOCKET_ID); return; }
        if (a->state == PTP_SYN_SENT) ptp_connect_try(a);
        if (a->state != PTP_ESTABLISHED && a->state != PTP_SYN_SENT) { psp_ret(ADHOC_NOT_CONNECTED); return; }
        if (a->flags & F_ALERTRECV) { a->alerted |= F_ALERTRECV; psp_ret(ADHOC_SOCKET_ALERTED); return; }
        if (a->state == PTP_ESTABLISHED && a->local) {
            if (a->stream.len) {
                const uint32_t n = a->stream.len < cap ? a->stream.len : cap;
                psp_mem_write_block(buf, a->stream.p, n);
                buf_drop(&a->stream, n);
                a->rx += n;
                psp_write32(lenp, n);
                psp_ret(0);
                return;
            }
            if (!local_peer(a)) { a->state = PTP_CLOSED; psp_ret(ADHOC_DISCONNECTED); return; }
        } else if (a->state == PTP_ESTABLISHED) {
            if (a->mesh) {
                mesh_pump();
                uint8_t *tmp = (uint8_t *)malloc(cap);
                if (!tmp) { psp_ret(NET_NO_SPACE); return; }
                const int n = mesh_stream_recv(a->sid, tmp, (int)cap);
                if (n > 0) psp_mem_write_block(buf, tmp, (uint32_t)n);
                free(tmp);
                if (n > 0) { a->rx += (uint32_t)n; psp_write32(lenp, (uint32_t)n); adhoc_peer_seen(a->paddr); psp_ret(0); return; }
                if (n < 0) { a->state = PTP_CLOSED; psp_ret(ADHOC_DISCONNECTED); return; }
            } else if (a->relay) {
                relay_io(a);
                if (a->stream.len) {
                    const uint32_t n = a->stream.len < cap ? a->stream.len : cap;
                    psp_mem_write_block(buf, a->stream.p, n);
                    buf_drop(&a->stream, n);
                    a->rx += n; psp_write32(lenp, n);
                    adhoc_peer_seen(a->paddr);
                    psp_ret(0);
                    return;
                }
                if (a->rdead) { a->state = PTP_CLOSED; psp_ret(ADHOC_DISCONNECTED); return; }
            } else {
                uint8_t *tmp = (uint8_t *)malloc(cap);
                if (!tmp) { psp_ret(NET_NO_SPACE); return; }
                const int n = recv(a->s, (char *)tmp, (int)cap, 0);
                const int e = n < 0 ? last_error() : 0;
                if (n > 0) psp_mem_write_block(buf, tmp, (uint32_t)n);
                free(tmp);
                if (n > 0) { a->rx += (uint32_t)n; psp_write32(lenp, (uint32_t)n); adhoc_peer_seen(a->paddr); psp_ret(0); return; }
                if (n == 0 || !WOULD_BLOCK(e)) { a->state = PTP_CLOSED; psp_ret(ADHOC_DISCONNECTED); return; }
            }
        }
        if (flag) { psp_ret(ADHOC_WOULD_BLOCK); return; }
        if (end && adhoc_real_us() >= end) { psp_ret(ADHOC_TIMEOUT); return; }
        adhoc_pump();
        nap();
    }
}

static void hle_PtpFlush(void) {
    asock *a = sock_get(psp_arg(0), SOCK_PTP);
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    if (!a) { psp_ret(ADHOC_INVALID_SOCKET_ID); return; }
    if (a->flags & F_ALERTFLUSH) { a->alerted |= F_ALERTFLUSH; psp_ret(ADHOC_SOCKET_ALERTED); return; }
    if (a->relay) relay_io(a);
    psp_ret(0);
}

static void hle_PtpClose(void) {
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    asock *a = sock_get(psp_arg(0), SOCK_PTP);
    if (!a) { psp_ret(ADHOC_INVALID_SOCKET_ID); return; }
    if (a->relay && a->state == PTP_SYN_SENT && a->await_ack && a->s != BAD_SOCK && !a->rdead) {
        /* The game's connect timeout (~2 s, made for a LAN) ran out while the
         * relay was still setting the connection up. Keep it: the game opens a
         * new socket to the same port right away, and hle_PtpOpen hands it this
         * one, so the wait carries on instead of starting over. */
        a->parked = 1;
        a->parked_at = adhoc_real_us();
        char m[18];
        adhoc_log("ptp %u: closed while the relay was still connecting it to %s:%u (%.1f s); kept for the retry",
                  psp_arg(0), mac_text(a->paddr, m), a->pport, (double)(a->parked_at - a->rstart) / 1e6);
        psp_ret(0);
        return;
    }
    if (a->relay && a->rout.len) relay_io(a);           /* last data out */
    adhoc_log("ptp %u: closed (port %u -> %u; sent %llu, received %llu bytes)", psp_arg(0), a->lport, a->pport, (unsigned long long)a->tx, (unsigned long long)a->rx);
    sock_free(a);
    psp_ret(0);
}

/* SceNetAdhocPtpStat {next, s32 id, laddr[6], paddr[6], u16 lport, u16 pport,
 * u32 snd_sb_cc, u32 rcv_sb_cc, s32 state}: 36 bytes */
static void hle_GetPtpStat(void) {
    const uint32_t lenp = psp_arg(0), buf = psp_arg(1);
    if (!g_adhoc_inited) { psp_ret(ADHOC_NOT_INITIALIZED); return; }
    if (!lenp) { psp_ret(ADHOC_INVALID_ARG); return; }
    int count = 0;
    for (int i = 0; i < MAX_SOCK; i++) if (g_s[i].used && !g_s[i].parked && g_s[i].type == SOCK_PTP) count++;
    if (!buf) { psp_write32(lenp, 36u * (uint32_t)count); psp_ret(0); return; }
    const int req = (int)(psp_read32(lenp) / 36u);
    int n = 0;
    for (int i = 0; i < MAX_SOCK && n < req; i++) {
        asock *a = &g_s[i];
        if (!a->used || a->parked || a->type != SOCK_PTP) continue;
        if (a->state == PTP_SYN_SENT) ptp_connect_try(a);
        const uint32_t e = buf + 36u * (uint32_t)n;
        psp_write32(e, 0);
        if (n) psp_write32(e - 36, e);
        psp_write32(e + 4, (uint32_t)i + 1);
        psp_mem_write_block(e + 8, a->laddr, 6);
        psp_mem_write_block(e + 14, a->paddr, 6);
        psp_write16(e + 20, a->lport);
        psp_write16(e + 22, a->pport);
        psp_write32(e + 24, a->local ? 0 : a->mesh && a->sid ? mesh_stream_unsent(a->sid) : a->relay ? a->rout.len : 0);
        psp_write32(e + 28, a->state == PTP_LISTEN ? 0 : avail_to_recv(a));
        psp_write32(e + 32, (uint32_t)a->state);
        n++;
    }
    psp_write32(lenp, 36u * (uint32_t)n);
    psp_ret(0);
}

/* ---- sceNetAdhocDiscover (as the reference: completes when stopped) ------------------------ */

static int g_disc_status, g_disc_stopping;
static uint32_t g_disc_param;

static void hle_DiscoverInitStart(void) {
    g_disc_param = psp_arg(0);
    g_disc_stopping = 0;
    g_disc_status = 1;
    if (g_disc_param) psp_write32(g_disc_param + 16, 0);   /* result: no peer found (yet) */
    psp_ret(0);
}
static void hle_DiscoverUpdate(void) {
    if (g_disc_status == 1 && g_disc_stopping) {
        g_disc_status = 2;
        if (g_disc_param) psp_write32(g_disc_param + 16, 1);   /* canceled */
    }
    psp_ret(0);
}
static void hle_DiscoverGetStatus(void) { psp_ret((uint32_t)g_disc_status); }
static void hle_DiscoverStop(void) { g_disc_stopping = 1; psp_ret(0); }
static void hle_DiscoverTerm(void) { g_disc_status = 0; g_disc_stopping = 0; psp_ret(0); }
static void hle_DiscoverRequestSuspend(void) { g_disc_stopping = 1; psp_ret(0); }

/* ---- the network dialog's ad hoc actions ---------------------------------------------------------- */

static int g_nc_action, g_nc_step, g_nc_active;
static uint8_t g_nc_group[8];
static uint64_t g_nc_start;

void adhoc_netconf_start(int action, const char group[8]) {
    g_nc_action = action;
    memcpy(g_nc_group, group, 8);
    g_nc_step = 0;
    g_nc_active = 1;
    g_nc_start = adhoc_real_us();
    adhoc_log("network dialog: %s group %.8s", action == 5 ? "join" : action == 4 ? "create" : "connect to", group);
}
void adhoc_netconf_cancel(void) { g_nc_active = 0; }

static void netconf_pump(void) {
    if (!g_nc_active || !g_ctl_inited || g_state != ST_DISCONNECTED || g_busy) return;
    if (g_nc_action == 5) {                             /* join: scan until the group is there */
        if (g_nc_step == 0) {
            g_busy = 1; g_state = ST_SCANNING; g_cur_mode = 0; g_nnew_groups = 0;
            srv_scan();
            g_nc_step = 1;
            return;
        }
        for (int i = 0; i < g_ngroups; i++)
            if (!memcmp(g_groups[i].name, g_nc_group, 8)) { ctl_create(g_nc_group, CONN_JOIN); g_nc_step = 2; return; }
        g_nc_step = 0;                                  /* not found yet */
        return;
    }
    if (g_nc_step == 0) { ctl_create(g_nc_group, g_nc_action == 4 ? CONN_CREATE : CONN_CONNECT); g_nc_step = 2; }
}

int adhoc_netconf_poll(void) {
    adhoc_pump();
    if (g_state == ST_CONNECTED) { g_nc_active = 0; return 1; }
    if (adhoc_real_us() - g_nc_start > 30000000u && g_state == ST_DISCONNECTED) { g_nc_active = 0; return -1; }
    return 0;
}

/* ---- registration --------------------------------------------------------------------------------- */

void psp_adhoc_register(void) {
    psp_hle_register(0xE1D621D7, "sceNetAdhoc", "sceNetAdhocInit",        hle_AdhocInit);
    psp_hle_register(0xA62C6F57, "sceNetAdhoc", "sceNetAdhocTerm",        hle_AdhocTerm);
    psp_hle_register(0x6F92741B, "sceNetAdhoc", "sceNetAdhocPdpCreate",   hle_PdpCreate);
    psp_hle_register(0xABED3790, "sceNetAdhoc", "sceNetAdhocPdpSend",     hle_PdpSend);
    psp_hle_register(0xDFE53E03, "sceNetAdhoc", "sceNetAdhocPdpRecv",     hle_PdpRecv);
    psp_hle_register(0x7F27BB5E, "sceNetAdhoc", "sceNetAdhocPdpDelete",   hle_PdpDelete);
    psp_hle_register(0xC7C1FC57, "sceNetAdhoc", "sceNetAdhocGetPdpStat",  hle_GetPdpStat);
    psp_hle_register(0x877F6D66, "sceNetAdhoc", "sceNetAdhocPtpOpen",     hle_PtpOpen);
    psp_hle_register(0xE08BDAC1, "sceNetAdhoc", "sceNetAdhocPtpListen",   hle_PtpListen);
    psp_hle_register(0x9DF81198, "sceNetAdhoc", "sceNetAdhocPtpAccept",   hle_PtpAccept);
    psp_hle_register(0xFC6FC07B, "sceNetAdhoc", "sceNetAdhocPtpConnect",  hle_PtpConnect);
    psp_hle_register(0x4DA4C788, "sceNetAdhoc", "sceNetAdhocPtpSend",     hle_PtpSend);
    psp_hle_register(0x8BEA2B3E, "sceNetAdhoc", "sceNetAdhocPtpRecv",     hle_PtpRecv);
    psp_hle_register(0x9AC2EEAC, "sceNetAdhoc", "sceNetAdhocPtpFlush",    hle_PtpFlush);
    psp_hle_register(0x157E6225, "sceNetAdhoc", "sceNetAdhocPtpClose",    hle_PtpClose);
    psp_hle_register(0xB9685118, "sceNetAdhoc", "sceNetAdhocGetPtpStat",  hle_GetPtpStat);
    psp_hle_register(0x73BFD52D, "sceNetAdhoc", "sceNetAdhocSetSocketAlert", hle_SetSocketAlert);

    psp_hle_register(0xE26F226E, "sceNetAdhocctl", "sceNetAdhocctlInit",          hle_CtlInit);
    psp_hle_register(0x9D689E13, "sceNetAdhocctl", "sceNetAdhocctlTerm",          hle_CtlTerm);
    psp_hle_register(0x20B317A0, "sceNetAdhocctl", "sceNetAdhocctlAddHandler",    hle_CtlAddHandler);
    psp_hle_register(0x6402490B, "sceNetAdhocctl", "sceNetAdhocctlDelHandler",    hle_CtlDelHandler);
    psp_hle_register(0x34401D65, "sceNetAdhocctl", "sceNetAdhocctlDisconnect",    hle_CtlDisconnect);
    psp_hle_register(0x0AD043ED, "sceNetAdhocctl", "sceNetAdhocctlConnect",       hle_CtlConnect);
    psp_hle_register(0xEC0635C1, "sceNetAdhocctl", "sceNetAdhocctlCreate",        hle_CtlCreate);
    psp_hle_register(0x5E7F79C9, "sceNetAdhocctl", "sceNetAdhocctlJoin",          hle_CtlJoin);
    psp_hle_register(0x08FFF7A0, "sceNetAdhocctl", "sceNetAdhocctlScan",          hle_CtlScan);
    psp_hle_register(0x75ECD386, "sceNetAdhocctl", "sceNetAdhocctlGetState",      hle_CtlGetState);
    psp_hle_register(0xDED9D28E, "sceNetAdhocctl", "sceNetAdhocctlGetParameter",  hle_CtlGetParameter);
    psp_hle_register(0x362CBE8F, "sceNetAdhocctl", "sceNetAdhocctlGetAdhocId",    hle_CtlGetAdhocId);
    psp_hle_register(0x81AEE1BE, "sceNetAdhocctl", "sceNetAdhocctlGetScanInfo",   hle_CtlGetScanInfo);
    psp_hle_register(0xE162CB14, "sceNetAdhocctl", "sceNetAdhocctlGetPeerList",   hle_CtlGetPeerList);
    psp_hle_register(0x8DB83FDC, "sceNetAdhocctl", "sceNetAdhocctlGetPeerInfo",   hle_CtlGetPeerInfo);
    psp_hle_register(0x8916C003, "sceNetAdhocctl", "sceNetAdhocctlGetNameByAddr", hle_CtlGetNameByAddr);

    psp_hle_register(0x941B3877, "sceNetAdhocDiscover", "sceNetAdhocDiscoverInitStart",      hle_DiscoverInitStart);
    psp_hle_register(0x52DE1B97, "sceNetAdhocDiscover", "sceNetAdhocDiscoverUpdate",         hle_DiscoverUpdate);
    psp_hle_register(0x944DDBC6, "sceNetAdhocDiscover", "sceNetAdhocDiscoverGetStatus",      hle_DiscoverGetStatus);
    psp_hle_register(0xA2246614, "sceNetAdhocDiscover", "sceNetAdhocDiscoverTerm",           hle_DiscoverTerm);
    psp_hle_register(0xF7D13214, "sceNetAdhocDiscover", "sceNetAdhocDiscoverStop",           hle_DiscoverStop);
    psp_hle_register(0xA423A21B, "sceNetAdhocDiscover", "sceNetAdhocDiscoverRequestSuspend", hle_DiscoverRequestSuspend);

    adhoc_matching_register();
}
