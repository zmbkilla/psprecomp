/* psprecomp — player-to-player traffic: the shared UDP port 3658, NP
 * signaling between room members, and the matching server's address check.
 *
 * On a PSP the firmware routes every player-to-player packet through UDP
 * port 3658, and NP signaling (np_matching2.prx) handshakes with each room
 * member before the game talks to them. Here, wire-compatible with the
 * RPCN-based PPSSPP fork that runs PSP2i online (Komak57/ppsspp master,
 * Core/Net/SIGAgents/RPCNSigAgent.cpp and Core/HLE/SocketManager.cpp), so
 * players of either can meet:
 *
 *   - One host UDP socket bound to port 3658 carries everything. Each
 *     datagram starts with a 3-byte header: u16 destination (0 = system),
 *     u8 flags. System datagrams: flags 0 = the matching server's address
 *     check, 1 = signaling. Game datagrams (destination = the game port)
 *     carry an 11-byte extension and go to net_sock.c (net_sock_p2p_input).
 *   - Address check: every 5 s (every 0.5 s until answered) 13 bytes go to
 *     the matching server's UDP port 3657: u8 1, s64 user ID, u32 local IPv4.
 *     It answers with the address and port it saw -- what other members are
 *     told to connect to (RPCN puts it in the room's signaling data).
 *   - Signaling packets (72 bytes): 'SIGN' (big-endian), u32 version 4, u64
 *     sender and receiver timestamps (us), u32 command, u32 the address and
 *     u16 the port the packet was sent to, SceNpId (36 bytes), 2 bytes
 *     padding. Commands: PING 0x23, PONG 0x24, CONNECT 0x25, CONNECT_ACK 0x26,
 *     CONFIRM 0x27, FINISHED 0x28, FINISHED_ACK 0x29, INFO 0x2A.
 *     CONNECT -> CONNECT_ACK -> CONFIRM makes a connection active
 *     (Established, 0x5102, to the game's signaling callback); the CONFIRM
 *     tells the other side we are active (PeerActivated 0x5104 /
 *     MutualActivated 0x5106). PINGs keep it alive; 60 s of silence or a
 *     FINISHED ends it (Dead, 0x5101).
 *   - The reference sends an all-zero SceNpId (it never sets its own), so
 *     peers are found by NpId when one is given, else by source address.
 *
 * Single-threaded: everything runs on the game thread (p2p_pump from the
 * vblank poll and from socket calls). */

#include "psprecomp/hle.h"
#include "psprecomp/net.h"
#include "p2p.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
typedef SOCKET hsock;
#  define BAD_SOCK INVALID_SOCKET
#  define close_sock closesocket
#else
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
typedef int hsock;
#  define BAD_SOCK (-1)
#  define close_sock close
#endif

void psp_net_log_line(const char *fmt, ...);      /* net.c */
#define LOG(...) psp_net_log_line("p2p: " __VA_ARGS__)

enum { CMD_PING = 0x23, CMD_PONG = 0x24, CMD_CONNECT = 0x25, CMD_CONNECT_ACK = 0x26, CMD_CONFIRM = 0x27,
       CMD_FINISHED = 0x28, CMD_FINISHED_ACK = 0x29, CMD_INFO = 0x2A };
enum { ST_INACTIVE = 0, ST_PENDING = 1, ST_ACTIVE = 2 };
enum { EV_DEAD = 0x5101, EV_ESTABLISHED = 0x5102, EV_PEER_ACTIVATED = 0x5104, EV_PEER_DEACTIVATED = 0x5105,
       EV_MUTUAL_ACTIVATED = 0x5106 };
#define ERR_TIMEOUT              0x8002A811u    /* SCE_NP_SIGNALING_ERROR_TIMEOUT */
#define ERR_TERMINATED_BY_PEER   0x8002A810u
#define ERR_TERMINATED_BY_MYSELF 0x8002A818u
#define ERR_M2_TERMINATED_BY_PEER 0x80550E10u   /* SCE_NP_MATCHING2_SIGNALING_ERROR_TERMINATED_BY_PEER */

#define SIG_SIZE 72                 /* sizeof(SignalingPacket) in the reference */
#define HDR_SIZE 3
#define EXT_SIZE 11

static hsock    g_sock = BAD_SOCK;
static int      g_open;
static uint32_t g_server_ip_n;      /* the matching server's UDP address check */
static uint16_t g_server_port_n;
static int64_t  g_user_id;
static char     g_npid[17];
static uint32_t g_local_ip_n;
static uint32_t g_public_ip_n;      /* as the matching server saw us */
static uint16_t g_public_port;
static uint64_t g_ping_ms, g_pong_ms;

static uint64_t now_ms(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
static uint64_t now_us(void) {
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static const char *ip_text(uint32_t ip_n, char *buf) {
    const uint8_t *b = (const uint8_t *)&ip_n;
    snprintf(buf, 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

/* ---- room members (from the matching backend) -------------------------------------------- */

#define MAX_MEMBERS 64
static struct { int used; uint64_t room; uint16_t member; char npid[17]; } g_members[MAX_MEMBERS];

static int member_find(uint64_t room, uint16_t member) {
    for (int i = 0; i < MAX_MEMBERS; i++)
        if (g_members[i].used && g_members[i].room == room && g_members[i].member == member) return i;
    return -1;
}

/* ---- signaling peers -------------------------------------------------------------------- */

enum { Q_CONNECT, Q_CONNECT_ACK, Q_PING, Q_FINISHED, Q_INFO, Q_N };
static const uint32_t Q_CMD[Q_N] = { CMD_CONNECT, CMD_CONNECT_ACK, CMD_PING, CMD_FINISHED, CMD_INFO };

typedef struct {
    int used;
    char npid[17];                  /* "" until known */
    uint64_t room;
    uint16_t member;
    uint32_t addr;                  /* where to send (network order) */
    uint16_t port;                  /* host order */
    uint32_t mapped_addr;           /* how the peer addressed us */
    uint16_t mapped_port;
    int status, op_activated;
    uint64_t last_recv_ms;
    struct { int on; uint64_t due_ms, ts_sender, ts_receiver; } q[Q_N];
    int info_counter;
    uint64_t rtts[6];
    unsigned rtt_n;
    uint32_t rtt;
} sig_peer;

#define MAX_PEERS 32
static sig_peer g_peers[MAX_PEERS];

/* ---- connected peers: where game traffic takes the P2P route ---------------------------------- */

int p2p_is_peer(uint32_t ip_n) {
    if (!ip_n || ip_n == g_local_ip_n || ip_n == htonl(INADDR_LOOPBACK)) return 0;
    for (int i = 0; i < MAX_PEERS; i++)
        if (g_peers[i].used && g_peers[i].status == ST_ACTIVE && g_peers[i].addr == ip_n) return 1;
    return 0;
}

static sig_peer *peer_by_npid(const char *npid) {
    if (!npid || !npid[0]) return NULL;
    for (int i = 0; i < MAX_PEERS; i++)
        if (g_peers[i].used && !strcmp(g_peers[i].npid, npid)) return &g_peers[i];
    return NULL;
}

static sig_peer *peer_by_addr(uint32_t ip_n, uint16_t port_h) {
    for (int i = 0; i < MAX_PEERS; i++)
        if (g_peers[i].used && g_peers[i].addr == ip_n && g_peers[i].port == port_h) return &g_peers[i];
    sig_peer *one = NULL;                       /* a NAT may change the port: the only peer at that address */
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!g_peers[i].used || g_peers[i].addr != ip_n) continue;
        if (one) return NULL;
        one = &g_peers[i];
    }
    return one;
}

static sig_peer *peer_new(const char *npid, uint32_t ip_n, uint16_t port_h) {
    for (int i = 0; i < MAX_PEERS; i++) {
        if (g_peers[i].used) continue;
        sig_peer *p = &g_peers[i];
        memset(p, 0, sizeof *p);
        p->used = 1;
        snprintf(p->npid, sizeof p->npid, "%s", npid ? npid : "");
        p->addr = ip_n;
        p->port = port_h;
        p->info_counter = 10;
        p->last_recv_ms = now_ms();
        return p;
    }
    LOG("too many signaling peers; ignoring %s", npid && npid[0] ? npid : "an unknown peer");
    return NULL;
}

static const char *peer_name(const sig_peer *p) { return p->npid[0] ? p->npid : "(no NpId)"; }

/* ---- sending -------------------------------------------------------------------------------- */

int p2p_send_raw(uint32_t ip_n, uint16_t port_n, const uint8_t *p, uint32_t n) {
    if (!g_open) return -1;
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = ip_n;
    to.sin_port = port_n;
    return sendto(g_sock, (const char *)p, (int)n, 0, (const struct sockaddr *)&to, sizeof to) == (int)n ? 0 : -1;
}

static void put32le(uint8_t *b, uint32_t v) { for (int i = 0; i < 4; i++) b[i] = (uint8_t)(v >> (8 * i)); }
static void put64le(uint8_t *b, uint64_t v) { for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * i)); }
static uint32_t get32le(const uint8_t *b) { return (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24; }
static uint64_t get64le(const uint8_t *b) { return (uint64_t)get32le(b) | (uint64_t)get32le(b + 4) << 32; }

static const char *cmd_name(uint32_t c) {
    switch (c) {
    case CMD_PING: return "PING"; case CMD_PONG: return "PONG"; case CMD_CONNECT: return "CONNECT";
    case CMD_CONNECT_ACK: return "CONNECT_ACK"; case CMD_CONFIRM: return "CONFIRM"; case CMD_FINISHED: return "FINISHED";
    case CMD_FINISHED_ACK: return "FINISHED_ACK"; case CMD_INFO: return "INFO"; default: return "?";
    }
}

/* A signaling packet to addr:port (port host order). */
static void sig_send(uint32_t cmd, uint64_t ts_sender, uint64_t ts_receiver, uint32_t ip_n, uint16_t port_h) {
    uint8_t b[HDR_SIZE + SIG_SIZE];
    memset(b, 0, sizeof b);
    b[2] = 1;                                           /* system destination, signaling */
    uint8_t *s = b + HDR_SIZE;
    s[0] = 'S'; s[1] = 'I'; s[2] = 'G'; s[3] = 'N';
    put32le(s + 4, 4);
    put64le(s + 8, ts_sender);
    put64le(s + 16, ts_receiver);
    put32le(s + 24, cmd);
    memcpy(s + 28, &ip_n, 4);                           /* sent_addr, network order */
    s[32] = (uint8_t)port_h; s[33] = (uint8_t)(port_h >> 8);   /* sent_port, host order */
    memcpy(s + 34, g_npid, strlen(g_npid));             /* SceNpId: handle.data */
    p2p_send_raw(ip_n, htons(port_h), b, sizeof b);
}

static void queue(sig_peer *p, int slot, uint64_t delay_ms, uint64_t ts_sender, uint64_t ts_receiver) {
    p->q[slot].on = 1;
    p->q[slot].due_ms = now_ms() + delay_ms;
    p->q[slot].ts_sender = ts_sender;
    p->q[slot].ts_receiver = ts_receiver;
}
static void retire(sig_peer *p, int slot) { p->q[slot].on = 0; }
static void retire_all(sig_peer *p) { for (int i = 0; i < Q_N; i++) p->q[i].on = 0; }

/* ---- state changes --------------------------------------------------------------------------- */

static void set_status(sig_peer *p, int st, uint32_t err) {
    char ip[16];
    if (p->status == ST_PENDING && st == ST_ACTIVE) {
        p->status = ST_ACTIVE;
        LOG("connection to %s (member %u) active: %s:%u", peer_name(p), p->member, ip_text(p->addr, ip), p->port);
        psp_np2_signaling_event(p->room, p->member, EV_ESTABLISHED, err);
    } else if ((p->status == ST_PENDING || p->status == ST_ACTIVE) && st == ST_INACTIVE) {
        p->status = ST_INACTIVE;
        LOG("connection to %s (member %u) ended (0x%08X)", peer_name(p), p->member, err);
        psp_np2_signaling_event(p->room, p->member, EV_DEAD, err);
        retire_all(p);
    }
}

static void set_op_activated(sig_peer *p, int on) {
    if (on && !p->op_activated) {
        p->op_activated = 1;
        psp_np2_signaling_event(p->room, p->member, p->status == ST_ACTIVE ? EV_MUTUAL_ACTIVATED : EV_PEER_ACTIVATED, 0);
    } else if (!on && p->op_activated) {
        p->op_activated = 0;
        psp_np2_signaling_event(p->room, p->member, EV_PEER_DEACTIVATED, 0);
    }
}

static void set_addr(sig_peer *p, uint32_t ip_n, uint16_t port_h) {
    if (p->addr == ip_n && p->port == port_h) return;
    char a[16], b[16];
    LOG("%s now at %s:%u (was %s:%u)", peer_name(p), ip_text(ip_n, a), port_h, ip_text(p->addr, b), p->port);
    p->addr = ip_n;
    p->port = port_h;
}

static void send_ping_once(sig_peer *p) {
    if (p->q[Q_PING].on) return;
    const uint64_t t = now_us();
    sig_send(CMD_PING, t, 0, p->addr, p->port);
    queue(p, Q_PING, 500, t, 0);
}

/* Start (or re-announce) a connection: CONNECT every 200 ms until answered. */
static void sig_connect(sig_peer *p, uint32_t ip_n, uint16_t port_h) {
    p->status = p->status == ST_ACTIVE ? ST_ACTIVE : ST_PENDING;
    p->last_recv_ms = now_ms();
    if (!p->addr || !p->port) { p->addr = ip_n; p->port = port_h; }
    char ip[16];
    LOG("connecting to %s (member %u) at %s:%u", peer_name(p), p->member, ip_text(p->addr, ip), p->port);
    const uint64_t t = now_us();
    sig_send(CMD_CONNECT, t, 0, p->addr, p->port);
    queue(p, Q_CONNECT, 200, t, 0);
}

static void sig_finish(sig_peer *p) {
    retire_all(p);
    if (p->status == ST_INACTIVE) return;
    sig_send(CMD_FINISHED, 0, 0, p->addr, p->port);
    queue(p, Q_FINISHED, 500, 0, 0);
}

/* ---- receiving -------------------------------------------------------------------------------- */

static void sig_input(const uint8_t *s, uint32_t n, uint32_t from_ip, uint16_t from_port_h) {
    char ip[16];
    if (n != SIG_SIZE) { LOG("malformed signaling packet (%u bytes) from %s:%u", n, ip_text(from_ip, ip), from_port_h); return; }
    const uint64_t ts_sender = get64le(s + 8), ts_receiver = get64le(s + 16);
    const uint32_t cmd = get32le(s + 24);
    uint32_t sent_addr;
    memcpy(&sent_addr, s + 28, 4);
    const uint16_t sent_port = (uint16_t)(s[32] | s[33] << 8);
    char npid[17];
    memcpy(npid, s + 34, 16);
    npid[16] = '\0';

    sig_peer *p = peer_by_npid(npid);
    if (!p) p = peer_by_addr(from_ip, from_port_h);
    if (!p && (cmd == CMD_CONNECT || cmd == CMD_INFO)) p = peer_new(npid, from_ip, from_port_h);
    if (p && !p->npid[0] && npid[0]) snprintf(p->npid, sizeof p->npid, "%s", npid);
    LOG("%s from %s:%u (%s)", cmd_name(cmd), ip_text(from_ip, ip), from_port_h, p ? peer_name(p) : "unknown peer");
    if (!p) return;
    if (cmd == CMD_FINISHED) {
        sig_send(CMD_FINISHED_ACK, 0, 0, from_ip, from_port_h);
        set_op_activated(p, 0);
        set_status(p, ST_INACTIVE, ERR_TERMINATED_BY_PEER);
        return;
    }
    p->last_recv_ms = now_ms();
    switch (cmd) {
    case CMD_PING:
        sig_send(CMD_PONG, ts_sender, 0, from_ip, from_port_h);
        break;
    case CMD_PONG: {
        const uint64_t t = now_us();
        p->rtts[p->rtt_n % 6] = t - ts_sender;
        p->rtt_n++;
        uint64_t sum = 0;
        const unsigned k = p->rtt_n < 6 ? p->rtt_n : 6;
        for (unsigned i = 0; i < k; i++) sum += p->rtts[i];
        p->rtt = (uint32_t)(sum / k);
        if (p->q[Q_PING].on) p->q[Q_PING].due_ms = now_ms() + 10000;
        break;
    }
    case CMD_CONNECT: {
        const uint64_t t = now_us();
        set_addr(p, from_ip, from_port_h);
        sig_send(CMD_CONNECT_ACK, ts_sender, t, from_ip, from_port_h);
        queue(p, Q_CONNECT_ACK, 200, ts_sender, t);
        break;
    }
    case CMD_CONNECT_ACK:
        send_ping_once(p);
        retire(p, Q_CONNECT);
        set_addr(p, from_ip, from_port_h);
        p->mapped_addr = sent_addr;
        p->mapped_port = sent_port;
        sig_send(CMD_CONFIRM, 0, ts_receiver, from_ip, from_port_h);
        set_status(p, ST_ACTIVE, 0);
        break;
    case CMD_CONFIRM:
        send_ping_once(p);
        retire(p, Q_CONNECT_ACK);
        set_addr(p, from_ip, from_port_h);
        p->mapped_addr = sent_addr;
        p->mapped_port = sent_port;
        set_op_activated(p, 1);
        break;
    case CMD_FINISHED_ACK:
        set_status(p, ST_INACTIVE, ERR_TERMINATED_BY_MYSELF);
        retire(p, Q_FINISHED);
        break;
    case CMD_INFO:
        break;                                      /* opens the NAT path; nothing to answer */
    default:
        LOG("unknown signaling command 0x%X", cmd);
        break;
    }
}

/* The matching server's answer: the address and port it saw us at. */
static void server_answer(const uint8_t *m, uint32_t n) {
    if (n != 6) return;
    uint32_t ip_n;
    memcpy(&ip_n, m, 4);
    const uint16_t port = (uint16_t)(m[4] << 8 | m[5]);
    g_pong_ms = now_ms();
    if (ip_n != g_public_ip_n || port != g_public_port) {
        char ip[16];
        g_public_ip_n = ip_n;
        g_public_port = port;
        LOG("the matching server sees this host at %s:%u%s", ip_text(ip_n, ip), port,
            ip_n == g_local_ip_n ? " (direct)" : port == P2P_PORT ? " (behind NAT, port kept)" : " (behind NAT, port changed)");
    }
}

static void input(const uint8_t *b, int n, const struct sockaddr_in *from) {
    if (from->sin_addr.s_addr == g_server_ip_n && from->sin_port == g_server_port_n && n == 6) { server_answer(b, 6); return; }
    if (n < HDR_SIZE) return;
    uint16_t dst;
    memcpy(&dst, b, 2);
    if (dst == 0) {
        if (b[2] == 1) sig_input(b + HDR_SIZE, (uint32_t)n - HDR_SIZE, from->sin_addr.s_addr, ntohs(from->sin_port));
        else if (b[2] == 0) server_answer(b + HDR_SIZE, (uint32_t)n - HDR_SIZE);
        return;
    }
    if (n < HDR_SIZE + EXT_SIZE) return;
    p2p_packet pk;
    pk.src_ip_n = from->sin_addr.s_addr;
    pk.src_udp_port_n = from->sin_port;
    pk.dst_port_n = dst;
    pk.flags = b[2];
    memcpy(&pk.dst_vport_n, b + 3, 2);
    memcpy(&pk.src_port_n, b + 5, 2);
    memcpy(&pk.src_vport_n, b + 7, 2);
    pk.sock_type = b[9];
    pk.seq = (uint32_t)b[10] << 24 | (uint32_t)b[11] << 16 | (uint32_t)b[12] << 8 | b[13];
    pk.data = b + HDR_SIZE + EXT_SIZE;
    pk.len = (uint32_t)n - HDR_SIZE - EXT_SIZE;
    net_sock_p2p_input(&pk);
}

/* ---- timers ------------------------------------------------------------------------------------ */

static void timers(void) {
    const uint64_t t = now_ms();
    for (int i = 0; i < MAX_PEERS; i++) {
        sig_peer *p = &g_peers[i];
        if (!p->used) continue;
        for (int s = 0; s < Q_N && p->used; s++) {
            if (!p->q[s].on || p->q[s].due_ms > t) continue;
            if (Q_CMD[s] != CMD_INFO && p->last_recv_ms + 60000 < t) {
                LOG("no answer from %s for 60 s", peer_name(p));
                set_status(p, ST_INACTIVE, ERR_TIMEOUT);
                retire_all(p);
                break;
            }
            if (Q_CMD[s] == CMD_CONNECT || Q_CMD[s] == CMD_PING) p->q[s].ts_sender = now_us();
            if (Q_CMD[s] == CMD_CONNECT_ACK) p->q[s].ts_receiver = now_us();
            sig_send(Q_CMD[s], p->q[s].ts_sender, p->q[s].ts_receiver, p->addr, p->port);
            uint64_t delay = 500;
            if (s == Q_CONNECT || s == Q_CONNECT_ACK) delay = 200;
            if (s == Q_INFO) {
                if (p->info_counter <= 0) { p->q[s].on = 0; continue; }
                p->info_counter--;
                delay = 200;
            }
            p->q[s].due_ms = t + delay;
        }
    }
    /* the matching server's address check: every 5 s, every 0.5 s until answered */
    if (g_server_ip_n && t - g_pong_ms >= 5000 && t - g_ping_ms > 500) {
        uint8_t ping[13];
        ping[0] = 1;
        put64le(ping + 1, (uint64_t)g_user_id);
        memcpy(ping + 9, &g_local_ip_n, 4);
        p2p_send_raw(g_server_ip_n, g_server_port_n, ping, sizeof ping);
        g_ping_ms = t;
    }
}

void p2p_pump(void) {
    if (!g_open) return;
    uint8_t buf[0x3000];
    for (int k = 0; k < 256; k++) {
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        const int n = recvfrom(g_sock, (char *)buf, (int)sizeof buf, 0, (struct sockaddr *)&from, &fl);
        if (n < 0) break;
        input(buf, n, &from);
    }
    timers();
    net_sock_p2p_tick(now_ms());
}

int p2p_active(void) { return g_open; }
uint32_t p2p_local_ip(void) { return g_local_ip_n; }
uint16_t p2p_default_vport_n(void) { return htons((uint16_t)g_user_id); }

int p2p_conn_status(uint64_t room, uint16_t member, uint32_t *ip_n, uint16_t *port_h) {
    const int m = member_find(room, member);
    if (m < 0) return -1;
    const sig_peer *p = peer_by_npid(g_members[m].npid);
    if (!p) return -2;
    if (p->status != ST_ACTIVE) return 1;          /* as the reference: pending unless active */
    if (ip_n) *ip_n = p->addr;
    if (port_h) *port_h = p->port;
    return 2;
}

/* ---- the matching backend's side (psprecomp/net.h) ------------------------------------------------- */

void psp_p2p_start(uint32_t server_ipv4, uint16_t server_udp_port, int64_t user_id, const char *npid) {
    g_server_ip_n = htonl(server_ipv4);
    g_server_port_n = htons(server_udp_port);
    g_user_id = user_id;
    snprintf(g_npid, sizeof g_npid, "%s", npid ? npid : "");
    psp_net_host h;
    g_local_ip_n = psp_net_host_info(&h) && h.ipv4 ? htonl(h.ipv4) : 0;
    g_pong_ms = g_ping_ms = 0;
    if (g_open) return;
#ifdef _WIN32
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
#endif
    g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_sock == BAD_SOCK) { LOG("cannot create the P2P socket"); return; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(P2P_PORT);
    if (bind(g_sock, (struct sockaddr *)&a, sizeof a) != 0) {
        LOG("cannot use UDP port %u (another program -- or a second copy of the game -- has it); "
            "other players will not reach this one", P2P_PORT);
        close_sock(g_sock);
        g_sock = BAD_SOCK;
        return;
    }
#ifdef _WIN32
    u_long one = 1;
    ioctlsocket(g_sock, FIONBIO, &one);
    BOOL off = FALSE;                                  /* no WSAECONNRESET after an ICMP "port unreachable" */
    DWORD got = 0;
    WSAIoctl(g_sock, _WSAIOW(IOC_VENDOR, 12), &off, sizeof off, NULL, 0, &got, NULL, NULL);
#else
    fcntl(g_sock, F_SETFL, fcntl(g_sock, F_GETFL, 0) | O_NONBLOCK);
#endif
    g_open = 1;
    char ip[16], sip[16];
    LOG("UDP port %u open for player-to-player traffic (local address %s, matching server %s:%u, user %lld)",
        P2P_PORT, ip_text(g_local_ip_n, ip), ip_text(g_server_ip_n, sip), server_udp_port, (long long)user_id);
}

void psp_p2p_stop(void) {
    for (int i = 0; i < MAX_PEERS; i++) if (g_peers[i].used) sig_finish(&g_peers[i]);
    if (g_open) close_sock(g_sock);
    g_sock = BAD_SOCK;
    g_open = 0;
    memset(g_peers, 0, sizeof g_peers);
    memset(g_members, 0, sizeof g_members);
}

void psp_p2p_room_member(uint64_t room, uint16_t member, const char *npid) {
    if (!npid || !npid[0] || !strcmp(npid, g_npid)) return;
    int m = member_find(room, member);
    if (m < 0) for (int i = 0; i < MAX_MEMBERS; i++) if (!g_members[i].used) { m = i; break; }
    if (m < 0) return;
    g_members[m].used = 1;
    g_members[m].room = room;
    g_members[m].member = member;
    snprintf(g_members[m].npid, sizeof g_members[m].npid, "%s", npid);
}

void psp_p2p_connect(uint64_t room, uint16_t member, uint32_t ipv4, uint16_t port) {
    if (!g_open) return;
    const int m = member_find(room, member);
    const char *npid = m >= 0 ? g_members[m].npid : "";
    const uint32_t ip_n = htonl(ipv4);
    sig_peer *p = peer_by_npid(npid);
    if (!p) p = peer_by_addr(ip_n, port);
    if (!p) p = peer_new(npid, ip_n, port);
    if (!p) return;
    if (!p->npid[0] && npid[0]) snprintf(p->npid, sizeof p->npid, "%s", npid);
    p->room = room;
    p->member = member;
    sig_connect(p, ip_n, port);
}

void psp_p2p_info(const char *npid, uint32_t ipv4, uint16_t port) {
    if (!g_open) return;
    const uint32_t ip_n = htonl(ipv4);
    sig_peer *p = peer_by_npid(npid);
    if (!p) p = peer_new(npid, ip_n, port);
    if (!p) return;
    p->addr = ip_n;
    p->port = port;
    p->info_counter = 10;
    sig_send(CMD_INFO, 0, 0, ip_n, port);
    queue(p, Q_INFO, 200, 0, 0);
}

void psp_p2p_member_left(uint64_t room, uint16_t member) {
    const int m = member_find(room, member);
    if (m < 0) return;
    sig_peer *p = peer_by_npid(g_members[m].npid);
    if (p) set_status(p, ST_INACTIVE, ERR_M2_TERMINATED_BY_PEER);
    g_members[m].used = 0;
}

void psp_p2p_room_closed(uint64_t room) {
    for (int i = 0; i < MAX_PEERS; i++) if (g_peers[i].used && g_peers[i].room == room) sig_finish(&g_peers[i]);
    for (int i = 0; i < MAX_MEMBERS; i++) if (g_members[i].used && g_members[i].room == room) g_members[i].used = 0;
}
