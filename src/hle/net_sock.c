/* psprecomp — sceNetInet sockets over the host's sockets.
 *
 * The PSP's BSD-style socket API, carried by the host network stack:
 *
 *   - Guest descriptors (1..255) map to host sockets. Host sockets are
 *     always non-blocking; a guest socket in blocking mode (the default)
 *     makes a call that would block park only the calling PSP thread
 *     (psp_sched_sleep_until) and try again, so the game's other threads
 *     keep running -- never the whole game waiting in the host.
 *   - Errors return -1 and set errno to the PSP's values (newlib: EAGAIN 11,
 *     EINPROGRESS 119, ECONNREFUSED 111, ...); sceNetInetGetPspError returns
 *     0x80010000 | errno, 0 after a success.
 *   - PSP structures: sockaddr_in {u8 len, u8 family, u16 port (network
 *     order), u32 addr (network order), u16 vport, zero[6]}; fd_set is 256
 *     bits (8 u32); timeval {u32 sec, u32 usec}.
 *   - Options: SOL_SOCKET is 0xFFFF and the BSD option numbers match the
 *     host's; SO_NBIO (0x1009) / SO_BIO (0x100A) switch the guest's blocking
 *     mode, SO_RCVTIMEO / SO_SNDTIMEO (0x1006 / 0x1005) are kept here and
 *     applied to the emulated blocking. PSP2i's socket crypto options
 *     (0x1000 / 0x2000, and the MSG_CRYPT send flags) are accepted; the
 *     traffic stays plain (both ends are emulators), but a socket with them is
 *     a player-to-player socket.
 *   - connect() to 0.0.0.0 goes to this host's own address, as on the PSP's BSD
 *     stack (Windows refuses it): a room owner connecting to its own room.
 *
 * Player-to-player sockets. The PSP types 6 (connection-oriented datagram),
 * 7 (DCCP) and 10 (packet: a TCP-like stream) talk to other players through
 * the firmware's shared UDP port 3658, after NP signaling (p2p.c). Here, as
 * in the reference emulator (Komak57/ppsspp master, SocketManager.cpp), whose
 * wire format is kept so players of either meet:
 *   - a stream (types 1, 10) whose destination is a connected signaling peer
 *     is virtual: a TCP-like exchange carried in UDP datagrams through the
 *     shared socket to the peer's address : the address's vport (3658);
 *     flags FIN 1, SYN 2, PSH 8, ACK 0x10, TCP 0x80. connect sends SYN|TCP
 *     (seq 1, 2-byte payload: the vport), the listener answers SYN|ACK|TCP,
 *     the connector ACK|TCP; data is PSH|TCP with a sequence number, each
 *     acknowledged by PSH|ACK|TCP with the same number, resent after 1 s;
 *   - a datagram socket bound to port 3658 is virtual: what it sends to a
 *     peer (or to port 3658, or with the crypto options) and everything it
 *     receives goes through the shared socket;
 *   - everything else (the game reaching its own server, the SEGA server,
 *     HTTP) stays on ordinary host sockets.
 * Wire: u16 destination port, u8 flags, then u16 destination vport, u16
 * source port, u16 source vport, u8 socket type, u32 sequence (big-endian),
 * payload. Ports and vports are carried as the game wrote them (network order).
 *
 * Constants follow PPSSPP's NetInetConstants.h (Komak57/ppsspp master). */

#include "psprecomp/hle.h"
#include "psprecomp/net.h"
#include "p2p.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
typedef SOCKET hsock;
#  define BAD_SOCK INVALID_SOCKET
#  define last_error() WSAGetLastError()
#  define close_sock closesocket
#else
#  include <errno.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
typedef int hsock;
#  define BAD_SOCK (-1)
#  define last_error() errno
#  define close_sock close
#endif

void psp_net_log_line(const char *fmt, ...);      /* net.c */

/* PSP errno */
enum { P_EINTR = 4, P_EBADF = 9, P_EAGAIN = 11, P_EFAULT = 14, P_EINVAL = 22, P_EPIPE = 32,
       P_EOPNOTSUPP = 95, P_ECONNRESET = 104, P_ENOBUFS = 105, P_EAFNOSUPPORT = 106, P_ENOTSOCK = 108,
       P_ENOPROTOOPT = 109, P_ESHUTDOWN = 110, P_ECONNREFUSED = 111, P_EADDRINUSE = 112, P_ECONNABORTED = 113,
       P_ENETUNREACH = 114, P_ENETDOWN = 115, P_ETIMEDOUT = 116, P_EHOSTDOWN = 117, P_EHOSTUNREACH = 118,
       P_EINPROGRESS = 119, P_EALREADY = 120, P_EMSGSIZE = 122, P_EADDRNOTAVAIL = 125, P_EISCONN = 127,
       P_ENOTCONN = 128 };

enum { SOL_SOCKET_P = 0xFFFF, SO_SNDTIMEO_P = 0x1005, SO_RCVTIMEO_P = 0x1006, SO_ERROR_P = 0x1007,
       SO_TYPE_P = 0x1008, SO_NBIO_P = 0x1009, SO_BIO_P = 0x100A, SO_USECRYPTO_RX_P = 0x1000,
       SO_USECRYPTO_TX_P = 0x2000 };
enum { MSG_OOB_P = 0x1, MSG_PEEK_P = 0x2, MSG_DONTROUTE_P = 0x4, MSG_WAITALL_P = 0x40, MSG_DONTWAIT_P = 0x80 };
enum { SOCK_STREAM_P = 1, SOCK_DGRAM_P = 2, SOCK_CONN_DGRAM_P = 6, SOCK_DCCP_P = 7, SOCK_PACKET_P = 10,
       SOCK_NONBLOCK_P = 0x20000000 };

/* ---- player-to-player (virtual) socket state ----------------------------------------------- */

enum { F_FIN = 0x01, F_SYN = 0x02, F_PSH = 0x08, F_ACK = 0x10, F_TCP = 0x80 };
enum { VS_CLOSED = 0, VS_LISTEN, VS_SYN_SENT, VS_SYN_RCVD, VS_ESTABLISHED, VS_CLOSE_WAIT };
#define VPORT_ANY 0xFFFFu
#define RETRY_MS 1000u
#define MAX_CONTROL_RETRIES 9            /* about 10 s for a handshake */

typedef struct vpkt {
    struct vpkt *next;
    uint32_t seq, len, off;
    uint8_t  flags;
    uint32_t src_ip_n;
    uint16_t src_port_n, src_vport_n;
    uint64_t sent_ms;
    int      sent_count;
    uint8_t  data[];
} vpkt;

typedef struct vsock {
    int state;
    uint32_t ip_n;                       /* our end, as bound (game space) */
    uint16_t port_n, vport_n;
    uint32_t peer_ip_n;                  /* the other end */
    uint16_t peer_port_n, peer_vport_n;
    uint32_t rx_seq, tx_seq;
    vpkt *rx;                            /* streams: by sequence; datagrams: arrival order */
    vpkt *tx;                            /* sent, not yet acknowledged */
    struct vsock *pending, *next;        /* a listener's half-open / unaccepted connections */
    int backlog;
    uint32_t error;                      /* PSP errno of a failed handshake */
} vsock;

#define MAX_FD 256
static struct {
    int used, type, nonblock, aborted;
    hsock s;                             /* BAD_SOCK for a virtual connection */
    uint64_t rcvtimeo_us, sndtimeo_us;   /* 0 = no timeout */
    uint32_t sends, recvs;
    int crypto;                          /* SO_USECRYPTO_RX/TX set */
    int bound;
    int virt;                            /* stream: data goes through the shared P2P socket */
    int virt_dgram;                      /* datagram socket bound to port 3658 */
    vsock v;
} g_fd[MAX_FD];

static uint32_t g_errno;
static int g_ws_up;

static uint32_t fail(uint32_t e) { g_errno = e; return 0xFFFFFFFFu; }
static uint32_t ok(uint32_t v) { g_errno = 0; return v; }

static void wsa_up(void) {
#ifdef _WIN32
    if (!g_ws_up) { WSADATA w; if (WSAStartup(MAKEWORD(2, 2), &w) == 0) g_ws_up = 1; }
#else
    g_ws_up = 1;
#endif
}

static uint32_t map_err(int e) {
#ifdef _WIN32
    switch (e) {
    case WSAEWOULDBLOCK: return P_EAGAIN;
    case WSAEINPROGRESS: return P_EINPROGRESS;
    case WSAEALREADY: return P_EALREADY;
    case WSAEISCONN: return P_EISCONN;
    case WSAENOTCONN: return P_ENOTCONN;
    case WSAECONNREFUSED: return P_ECONNREFUSED;
    case WSAETIMEDOUT: return P_ETIMEDOUT;
    case WSAECONNRESET: return P_ECONNRESET;
    case WSAECONNABORTED: return P_ECONNABORTED;
    case WSAEADDRINUSE: return P_EADDRINUSE;
    case WSAEADDRNOTAVAIL: return P_EADDRNOTAVAIL;
    case WSAENETUNREACH: return P_ENETUNREACH;
    case WSAEHOSTUNREACH: return P_EHOSTUNREACH;
    case WSAEHOSTDOWN: return P_EHOSTDOWN;
    case WSAENETDOWN: return P_ENETDOWN;
    case WSAEMSGSIZE: return P_EMSGSIZE;
    case WSAENOTSOCK: return P_ENOTSOCK;
    case WSAESHUTDOWN: return P_ESHUTDOWN;
    case WSAENOBUFS: return P_ENOBUFS;
    case WSAEAFNOSUPPORT: return P_EAFNOSUPPORT;
    case WSAENOPROTOOPT: return P_ENOPROTOOPT;
    case WSAEOPNOTSUPP: return P_EOPNOTSUPP;
    case WSAEFAULT: return P_EFAULT;
    default: return P_EINVAL;
    }
#else
    switch (e) {
    case EAGAIN: return P_EAGAIN;
    case EINPROGRESS: return P_EINPROGRESS;
    case EALREADY: return P_EALREADY;
    case EISCONN: return P_EISCONN;
    case ENOTCONN: return P_ENOTCONN;
    case ECONNREFUSED: return P_ECONNREFUSED;
    case ETIMEDOUT: return P_ETIMEDOUT;
    case ECONNRESET: return P_ECONNRESET;
    case ECONNABORTED: return P_ECONNABORTED;
    case EADDRINUSE: return P_EADDRINUSE;
    case EADDRNOTAVAIL: return P_EADDRNOTAVAIL;
    case ENETUNREACH: return P_ENETUNREACH;
    case EHOSTUNREACH: return P_EHOSTUNREACH;
    case ENETDOWN: return P_ENETDOWN;
    case EMSGSIZE: return P_EMSGSIZE;
    case EPIPE: return P_EPIPE;
    default: return P_EINVAL;
    }
#endif
}

static int would_block(int e) {
#ifdef _WIN32
    return e == WSAEWOULDBLOCK;
#else
    return e == EAGAIN || e == EWOULDBLOCK;
#endif
}

static void set_host_nonblocking(hsock s) {
#ifdef _WIN32
    u_long one = 1;
    ioctlsocket(s, FIONBIO, &one);
#else
    fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
#endif
}

static int fd_ok(uint32_t fd) { return fd > 0 && fd < MAX_FD && g_fd[fd].used; }

static uint32_t bad_fd(uint32_t fd, const char *fn) {
    static int logged;
    if (logged++ < 20) psp_net_log_line("%s: socket %u is not open (EBADF)", fn + 4, fd);
    return fail(P_EBADF);
}

/* Park the calling PSP thread for a moment (other PSP threads run). */
static void nap(void) { psp_sched_sleep_until(psp_sched_now_us() + 1000); }

/* PSP sockaddr_in at guest address a -> host sockaddr_in (and the vport, as
 * written: network order). */
static int read_addr_v(uint32_t a, uint32_t len, struct sockaddr_in *out, uint16_t *vport_n) {
    memset(out, 0, sizeof *out);
    if (vport_n) *vport_n = 0;
    if (!a || len < 8) return -1;
    out->sin_family = AF_INET;
    uint8_t b[10];
    memset(b, 0, sizeof b);
    psp_mem_read_block(b, a, len >= 10 ? 10 : 8);
    memcpy(&out->sin_port, b + 2, 2);           /* both already in network order */
    memcpy(&out->sin_addr, b + 4, 4);
    if (vport_n) memcpy(vport_n, b + 8, 2);
    return 0;
}
static int read_addr(uint32_t a, uint32_t len, struct sockaddr_in *out) { return read_addr_v(a, len, out, NULL); }

static void write_addr_v(uint32_t a, uint32_t lenp, uint32_t ip_n, uint16_t port_n, uint16_t vport_n) {
    if (!a) return;
    uint8_t b[16];
    memset(b, 0, sizeof b);
    b[0] = 16;
    b[1] = 2;                                    /* AF_INET */
    memcpy(b + 2, &port_n, 2);
    memcpy(b + 4, &ip_n, 4);
    memcpy(b + 8, &vport_n, 2);
    const uint32_t cap = lenp ? psp_read32(lenp) : 16;
    psp_mem_write_block(a, b, cap < 16 ? cap : 16);
    if (lenp) psp_write32(lenp, 16);
}
static void write_addr(uint32_t a, uint32_t lenp, const struct sockaddr_in *in) {
    write_addr_v(a, lenp, in->sin_addr.s_addr, in->sin_port, 0);
}

static const char *ipport_text(uint32_t ip_n, uint16_t port_n, char *buf, size_t cap) {
    const uint8_t *b = (const uint8_t *)&ip_n;
    snprintf(buf, cap, "%u.%u.%u.%u:%u", b[0], b[1], b[2], b[3], ntohs(port_n));
    return buf;
}
static const char *addr_text(const struct sockaddr_in *a, char *buf, size_t cap) {
    return ipport_text(a->sin_addr.s_addr, a->sin_port, buf, cap);
}

static int is_stream(int t) { return t == SOCK_STREAM_P || t == SOCK_PACKET_P; }

/* Wait for a host socket condition (read/write/except) up to timeout_us
 * (0 = forever), napping the PSP thread. 1 ready, 0 timed out, -1 aborted. */
static int wait_sock(uint32_t fd, int want_write, uint64_t timeout_us) {
    const uint64_t end = timeout_us ? psp_sched_now_us() + timeout_us : 0;
    for (;;) {
        if (g_fd[fd].aborted) return -1;
        fd_set r, w, x;
        FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&x);
        if (want_write) { FD_SET(g_fd[fd].s, &w); FD_SET(g_fd[fd].s, &x); }
        else FD_SET(g_fd[fd].s, &r);
        struct timeval tv = { 0, 0 };
        if (select((int)g_fd[fd].s + 1, &r, &w, &x, &tv) > 0) return 1;
        if (end && psp_sched_now_us() >= end) return 0;
        nap();
    }
}

/* ---- virtual sockets: packets ------------------------------------------------------------------ */

static void free_list(vpkt **l) { while (*l) { vpkt *n = (*l)->next; free(*l); *l = n; } }

static void vs_clear(vsock *v) {
    free_list(&v->rx);
    free_list(&v->tx);
    while (v->pending) { vsock *n = v->pending->next; vs_clear(v->pending); free(v->pending); v->pending = n; }
}

static vpkt *pkt_new(const uint8_t *data, uint32_t len) {
    vpkt *p = (vpkt *)calloc(1, sizeof *p + (len ? len : 1));
    if (p && len) memcpy(p->data, data, len);
    if (p) p->len = len;
    return p;
}

/* The wire form of a game packet, sent from the shared socket to ip:phys_port. */
static int wire_send(uint32_t ip_n, uint16_t phys_port_n, uint16_t dst_port_n, uint16_t dst_vport_n, uint8_t flags,
                     uint16_t src_port_n, uint16_t src_vport_n, uint8_t type, uint32_t seq, const uint8_t *data, uint32_t len) {
    uint8_t stackbuf[2048], *b = len + 14 <= sizeof stackbuf ? stackbuf : (uint8_t *)malloc(len + 14);
    if (!b) return -1;
    memcpy(b, &dst_port_n, 2);
    b[2] = flags;
    memcpy(b + 3, &dst_vport_n, 2);
    memcpy(b + 5, &src_port_n, 2);
    memcpy(b + 7, &src_vport_n, 2);
    b[9] = type;
    b[10] = (uint8_t)(seq >> 24); b[11] = (uint8_t)(seq >> 16); b[12] = (uint8_t)(seq >> 8); b[13] = (uint8_t)seq;
    if (len) memcpy(b + 14, data, len);
    const int rc = p2p_send_raw(ip_n, phys_port_n, b, len + 14);
    if (b != stackbuf) free(b);
    return rc;
}

static uint64_t ms_now(void) { return psp_sched_now_us() / 1000u; }

/* A reliable packet: numbered, kept until acknowledged, sent to the peer's
 * address : its vport (its shared P2P port). */
static int vs_send(vsock *v, int type, uint8_t flags, const uint8_t *data, uint32_t len) {
    vpkt *p = pkt_new(data, len);
    if (!p) return -1;
    p->seq = v->tx_seq + 1;
    p->flags = flags;
    p->sent_ms = ms_now();
    vpkt **t = &v->tx;
    while (*t) t = &(*t)->next;
    *t = p;
    v->tx_seq++;
    return wire_send(v->peer_ip_n, v->peer_vport_n, v->peer_port_n, v->peer_vport_n, flags, v->port_n, v->vport_n,
                     (uint8_t)type, p->seq, data, len);
}

static void vs_ack(vsock *v, uint32_t seq) {
    for (vpkt **t = &v->tx; *t; t = &(*t)->next)
        if ((*t)->seq == seq) { vpkt *d = *t; *t = d->next; free(d); return; }
}

/* In-order bytes ready for recv (or the end of the stream). */
static int vs_readable(const vsock *v) {
    if (v->state == VS_CLOSE_WAIT) return 1;
    for (const vpkt *p = v->rx; p; p = p->next) if (p->seq == v->rx_seq + 1) return 1;
    return 0;
}

static int vs_has_accept(const vsock *v) {
    for (const vsock *c = v->pending; c; c = c->next) if (c->state == VS_ESTABLISHED) return 1;
    return 0;
}

/* ---- virtual sockets: input from the shared socket ------------------------------------------------ */

/* A stream packet for socket v (type `type`): as the reference's Process_Reliable. */
static int vs_input_stream(uint32_t fd, vsock *v, int type, const p2p_packet *pk) {
    if (v->port_n != pk->dst_port_n || v->vport_n != pk->dst_vport_n) return 0;
    if (v->ip_n && v->ip_n != p2p_local_ip()) return 0;
    if (pk->sock_type != type) return 0;
    char t[32];
    if (v->state == VS_LISTEN) {
        if (pk->flags != (F_SYN | F_TCP) && pk->flags != (F_SYN | F_ACK | F_TCP) && pk->flags != (F_ACK | F_TCP)) return 0;
    } else {
        if (v->peer_ip_n && v->peer_ip_n != pk->src_ip_n) return 0;
        if (v->peer_port_n != pk->src_port_n || v->peer_vport_n != pk->src_vport_n) return 0;
    }
    switch (pk->flags) {
    case F_PSH | F_ACK | F_TCP:
        if (v->state != VS_LISTEN) vs_ack(v, pk->seq);
        break;
    case F_PSH | F_TCP:
        if (v->state == VS_LISTEN) break;
        if (pk->seq > v->rx_seq) {
            int dup = 0;
            vpkt **at = &v->rx;
            for (vpkt *p = v->rx; p; p = p->next) if (p->seq == pk->seq) dup = 1;
            if (!dup) {
                vpkt *p = pkt_new(pk->data, pk->len);
                if (p) {
                    p->seq = pk->seq;
                    while (*at && (*at)->seq < p->seq) at = &(*at)->next;
                    p->next = *at;
                    *at = p;
                }
            }
        }
        /* acknowledge with the received number (also for a resend) */
        wire_send(v->peer_ip_n, v->peer_vport_n, v->peer_port_n, v->peer_vport_n, F_PSH | F_ACK | F_TCP,
                  v->port_n, v->vport_n, (uint8_t)type, pk->seq, NULL, 0);
        break;
    case F_SYN | F_TCP: {
        if (v->state != VS_LISTEN) break;
        int n = 0;
        for (vsock *c = v->pending; c; c = c->next) {
            n++;
            if (c->peer_ip_n == pk->src_ip_n && c->peer_port_n == pk->src_port_n && c->peer_vport_n == pk->src_vport_n) {
                /* the connector resent its SYN: our SYN|ACK went missing -- resent by the timer */
                return 1;
            }
        }
        if (n >= (v->backlog > 0 ? v->backlog : 1)) {
            psp_net_log_line("socket %u: backlog full, dropping a connection from %s", fd, ipport_text(pk->src_ip_n, pk->src_port_n, t, sizeof t));
            break;
        }
        vsock *c = (vsock *)calloc(1, sizeof *c);
        if (!c) break;
        c->ip_n = v->ip_n; c->port_n = v->port_n; c->vport_n = v->vport_n;
        c->peer_ip_n = pk->src_ip_n; c->peer_port_n = pk->src_port_n; c->peer_vport_n = pk->src_vport_n;
        c->state = VS_SYN_RCVD;
        c->rx_seq = 1;
        c->next = v->pending;
        v->pending = c;
        psp_net_log_line("socket %u: player-to-player connection request from %s (vport %u)", fd,
                         ipport_text(pk->src_ip_n, pk->src_port_n, t, sizeof t), ntohs(pk->src_vport_n));
        vs_send(c, type, F_SYN | F_ACK | F_TCP, NULL, 0);
        break;
    }
    case F_SYN | F_ACK | F_TCP:
        if (v->state != VS_SYN_SENT) break;
        v->peer_ip_n = pk->src_ip_n;
        vs_ack(v, 1);
        v->state = VS_ESTABLISHED;
        v->rx_seq++;
        psp_net_log_line("socket %u: player-to-player connection to %s established", fd,
                         ipport_text(v->peer_ip_n, v->peer_port_n, t, sizeof t));
        vs_send(v, type, F_ACK | F_TCP, NULL, 0);
        break;
    case F_ACK | F_TCP:
        if (v->state != VS_LISTEN) break;
        for (vsock *c = v->pending; c; c = c->next) {
            if (c->peer_ip_n != pk->src_ip_n || c->peer_port_n != pk->src_port_n) continue;
            if (pk->src_vport_n && c->peer_vport_n != pk->src_vport_n) continue;
            if (c->state != VS_SYN_RCVD) continue;
            c->state = VS_ESTABLISHED;
            vs_ack(c, 1);
            c->rx_seq++;
            psp_net_log_line("socket %u: player-to-player connection from %s ready to accept", fd,
                             ipport_text(c->peer_ip_n, c->peer_port_n, t, sizeof t));
            break;
        }
        break;
    case F_FIN | F_TCP:
        if (v->state == VS_LISTEN) break;
        v->state = VS_CLOSE_WAIT;
        v->rx_seq++;
        psp_net_log_line("socket %u: the peer closed the connection", fd);
        break;
    default:
        break;
    }
    return 1;
}

/* A datagram for a socket bound to the shared port: as Process_Unreliable. */
static int vs_input_dgram(uint32_t fd, const p2p_packet *pk) {
    vsock *v = &g_fd[fd].v;
    if (pk->sock_type != g_fd[fd].type) return 0;
    if (v->ip_n && v->ip_n != p2p_local_ip()) return 0;
    if (v->port_n != pk->dst_port_n) return 0;
    if (pk->dst_vport_n == VPORT_ANY) { if (!v->port_n) return 0; }
    else if (v->vport_n != pk->dst_vport_n) return 0;
    int n = 0;
    vpkt **t = &v->rx;
    while (*t) { t = &(*t)->next; n++; }
    if (n >= 512) return 1;                          /* the game is not reading: drop */
    vpkt *p = pkt_new(pk->data, pk->len);
    if (!p) return 1;
    p->src_ip_n = pk->src_ip_n;
    p->src_port_n = pk->src_port_n;
    p->src_vport_n = pk->src_vport_n;
    *t = p;
    return 1;
}

void net_sock_p2p_input(const p2p_packet *pk) {
    int delivered = 0;
    for (uint32_t fd = 1; fd < MAX_FD; fd++) {
        if (!g_fd[fd].used) continue;
        if (g_fd[fd].virt_dgram) delivered |= vs_input_dgram(fd, pk);
        else if (is_stream(g_fd[fd].type) && g_fd[fd].v.state != VS_CLOSED) delivered |= vs_input_stream(fd, &g_fd[fd].v, g_fd[fd].type, pk);
    }
    if (!delivered) {
        static int logged;
        char t[32];
        if (logged++ < 50)
            psp_net_log_line("p2p: no socket for a packet from %s to port %u vport %u (flags 0x%02X, type %u, %u bytes)",
                             ipport_text(pk->src_ip_n, pk->src_port_n, t, sizeof t), ntohs(pk->dst_port_n),
                             ntohs(pk->dst_vport_n), pk->flags, pk->sock_type, pk->len);
    }
}

/* Resend what was not acknowledged. Returns 1 if a handshake gave up. */
static int vs_retransmit(vsock *v, int type, uint64_t now) {
    uint8_t expect = 0;
    if (v->state == VS_SYN_SENT) expect = F_SYN | F_TCP;
    else if (v->state == VS_SYN_RCVD) expect = F_SYN | F_ACK | F_TCP;
    for (vpkt **t = &v->tx; *t;) {
        vpkt *p = *t;
        if (expect && p->flags != expect) { t = &p->next; continue; }
        if (now - p->sent_ms < RETRY_MS) { t = &p->next; continue; }
        const int data = (p->flags & F_PSH) != 0;
        if (!data && p->sent_count >= MAX_CONTROL_RETRIES) {
            if (expect) return 1;
            *t = p->next;                                /* a plain ACK: nobody acknowledges it */
            free(p);
            continue;
        }
        wire_send(v->peer_ip_n, v->peer_vport_n, v->peer_port_n, v->peer_vport_n, p->flags, v->port_n, v->vport_n,
                  (uint8_t)type, p->seq, p->data, p->len);
        p->sent_ms = now;
        p->sent_count++;
        t = &p->next;
    }
    return 0;
}

void net_sock_p2p_tick(uint64_t now_ms_real) {
    (void)now_ms_real;
    const uint64_t now = ms_now();
    for (uint32_t fd = 1; fd < MAX_FD; fd++) {
        if (!g_fd[fd].used || !is_stream(g_fd[fd].type)) continue;
        vsock *v = &g_fd[fd].v;
        if (v->state != VS_CLOSED && v->state != VS_LISTEN && vs_retransmit(v, g_fd[fd].type, now)) {
            psp_net_log_line("socket %u: no answer from the peer: connection failed", fd);
            v->state = VS_CLOSED;
            v->error = P_ETIMEDOUT;
        }
        for (vsock **c = &v->pending; *c;) {
            if (vs_retransmit(*c, g_fd[fd].type, now)) {
                vsock *d = *c;
                *c = d->next;
                vs_clear(d);
                free(d);
            } else c = &(*c)->next;
        }
    }
}

/* ---- the calls ------------------------------------------------------------------------- */

static uint32_t new_fd(void) {
    for (uint32_t i = 1; i < MAX_FD; i++) if (!g_fd[i].used) return i;
    return 0;
}

/* socket(domain, type, protocol) */
static void hle_Socket(void) {
    const uint32_t domain = psp_arg(0), type = psp_arg(1), proto = psp_arg(2);
    wsa_up();
    if (domain != 2) { psp_net_log_line("socket(domain %u, type 0x%X, protocol %u): unsupported domain", domain, type, proto); psp_ret(fail(P_EAFNOSUPPORT)); return; }
    const uint32_t t = type & 0xF;
    int htype;
    switch (t) {
    case SOCK_STREAM_P: case SOCK_PACKET_P: htype = SOCK_STREAM; break;
    case SOCK_DGRAM_P: case SOCK_CONN_DGRAM_P: case SOCK_DCCP_P: htype = SOCK_DGRAM; break;
    default:
        psp_net_log_line("socket(domain %u, type 0x%X, protocol %u): unsupported type", domain, type, proto);
        psp_ret(fail(P_EOPNOTSUPP));
        return;
    }
    const uint32_t fd = new_fd();
    if (!fd) { psp_net_log_line("socket: no free descriptor"); psp_ret(fail(P_ENOBUFS)); return; }
    const hsock s = socket(AF_INET, htype, htype == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
    if (s == BAD_SOCK) {
        const uint32_t e = map_err(last_error());
        psp_net_log_line("socket(type 0x%X): host socket failed (errno %u)", type, e);
        psp_ret(fail(e));
        return;
    }
    set_host_nonblocking(s);
    if (htype == SOCK_DGRAM) { const int one = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one); }
    memset(&g_fd[fd], 0, sizeof g_fd[fd]);
    g_fd[fd].used = 1;
    g_fd[fd].s = s;
    g_fd[fd].type = (int)t;
    g_fd[fd].nonblock = (type & SOCK_NONBLOCK_P) != 0;
    static const char *const TN[] = { "?", "TCP", "UDP", "?", "?", "?", "P2P datagram (UDP)", "P2P master (UDP)", "?", "?", "P2P stream (TCP)" };
    psp_net_log_line("socket %u: %s%s", fd, TN[t <= 10 ? t : 0], g_fd[fd].nonblock ? " (non-blocking)" : "");
    psp_ret(ok(fd));
}

static void hle_Bind(void) {
    const uint32_t fd = psp_arg(0), a = psp_arg(1), len = psp_arg(2);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    struct sockaddr_in sa;
    uint16_t vport_n;
    if (read_addr_v(a, len, &sa, &vport_n)) { psp_ret(fail(P_EINVAL)); return; }
    char t[32];
    vsock *v = &g_fd[fd].v;
    v->ip_n = sa.sin_addr.s_addr;
    v->port_n = sa.sin_port;
    v->vport_n = vport_n ? vport_n : p2p_default_vport_n();
    g_fd[fd].bound = 1;
    /* The shared P2P port: the datagram socket's traffic goes through p2p.c;
     * the host socket takes any free port (3658 is the shared socket's). */
    const int shared = !is_stream(g_fd[fd].type) && ntohs(sa.sin_port) == P2P_PORT && p2p_active();
    if (shared) sa.sin_port = 0;
    if (bind(g_fd[fd].s, (struct sockaddr *)&sa, sizeof sa) != 0) {
        const uint32_t e = map_err(last_error());
        psp_net_log_line("socket %u: bind %s failed (errno %u)", fd, addr_text(&sa, t, sizeof t), e);
        psp_ret(fail(e));
        return;
    }
    g_fd[fd].virt_dgram = shared;
    psp_net_log_line("socket %u: bound to %s vport %u%s", fd, ipport_text(v->ip_n, v->port_n, t, sizeof t), ntohs(vport_n),
                     shared ? " (player-to-player, through the shared port)" : "");
    psp_ret(ok(0));
}

static void hle_Listen(void) {
    const uint32_t fd = psp_arg(0), backlog = psp_arg(1);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    if (listen(g_fd[fd].s, (int)(backlog ? backlog : 1)) != 0) {
        const uint32_t e = map_err(last_error());
        psp_net_log_line("socket %u: listen failed (errno %u)", fd, e);
        psp_ret(fail(e));
        return;
    }
    if (is_stream(g_fd[fd].type)) {                  /* also takes player-to-player connections */
        g_fd[fd].v.state = VS_LISTEN;
        g_fd[fd].v.backlog = backlog > 0 && backlog < 128 ? (int)backlog : 16;
        if (!g_fd[fd].bound) g_fd[fd].v.vport_n = p2p_default_vport_n();
    }
    psp_net_log_line("socket %u: listening (backlog %u)", fd, backlog);
    psp_ret(ok(0));
}

/* A player-to-player connection that finished its handshake becomes a new socket. */
static int accept_virtual(uint32_t fd, uint32_t a, uint32_t lenp) {
    vsock *v = &g_fd[fd].v;
    for (vsock **c = &v->pending; *c; c = &(*c)->next) {
        if ((*c)->state != VS_ESTABLISHED) continue;
        const uint32_t nfd = new_fd();
        if (!nfd) return -(int)P_ENOBUFS;
        vsock *conn = *c;
        *c = conn->next;
        memset(&g_fd[nfd], 0, sizeof g_fd[nfd]);
        g_fd[nfd].used = 1;
        g_fd[nfd].s = BAD_SOCK;
        g_fd[nfd].type = g_fd[fd].type;
        g_fd[nfd].nonblock = g_fd[fd].nonblock;
        g_fd[nfd].crypto = g_fd[fd].crypto;
        g_fd[nfd].bound = 1;
        g_fd[nfd].virt = 1;
        g_fd[nfd].v = *conn;
        g_fd[nfd].v.next = NULL;
        g_fd[nfd].v.pending = NULL;
        free(conn);
        write_addr_v(a, lenp, g_fd[nfd].v.peer_ip_n, g_fd[nfd].v.peer_port_n, g_fd[nfd].v.peer_vport_n);
        char t[32];
        psp_net_log_line("socket %u: accepted player-to-player %s as socket %u", fd,
                         ipport_text(g_fd[nfd].v.peer_ip_n, g_fd[nfd].v.peer_port_n, t, sizeof t), nfd);
        return (int)nfd;
    }
    return 0;
}

static void hle_Accept(void) {
    const uint32_t fd = psp_arg(0), a = psp_arg(1), lenp = psp_arg(2);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    for (;;) {
        p2p_pump();
        if (vs_has_accept(&g_fd[fd].v)) {
            const int r = accept_virtual(fd, a, lenp);
            if (r > 0) { psp_ret(ok((uint32_t)r)); return; }
            if (r < 0) { psp_ret(fail((uint32_t)-r)); return; }
        }
        struct sockaddr_in peer;
        socklen_t pl = sizeof peer;
        const hsock s = g_fd[fd].s == BAD_SOCK ? BAD_SOCK : accept(g_fd[fd].s, (struct sockaddr *)&peer, &pl);
        if (s != BAD_SOCK) {
            const uint32_t nfd = new_fd();
            if (!nfd) { close_sock(s); psp_ret(fail(P_ENOBUFS)); return; }
            set_host_nonblocking(s);
            memset(&g_fd[nfd], 0, sizeof g_fd[nfd]);
            g_fd[nfd].used = 1;
            g_fd[nfd].s = s;
            g_fd[nfd].type = g_fd[fd].type;
            g_fd[nfd].nonblock = g_fd[fd].nonblock;
            write_addr(a, lenp, &peer);
            char t[32];
            psp_net_log_line("socket %u: accepted %s as socket %u", fd, addr_text(&peer, t, sizeof t), nfd);
            psp_ret(ok(nfd));
            return;
        }
        const int e = g_fd[fd].s == BAD_SOCK ? 0 : last_error();
        if ((g_fd[fd].s != BAD_SOCK && !would_block(e)) || g_fd[fd].nonblock) { psp_ret(fail(g_fd[fd].s == BAD_SOCK ? P_EAGAIN : map_err(e))); return; }
        if (g_fd[fd].aborted) { psp_ret(fail(P_EINTR)); return; }
        nap();
    }
}

/* The PSP's BSD stack sends a connection to 0.0.0.0 to this host's own
 * address -- the IP the game was given (sceNetApctlGetInfo), not loopback.
 * It matters: a game server running on this PSP sees its own player arrive
 * from the PSP's address (PSP2i hosted sessions). Loopback if unknown. */
static uint32_t this_host_addr(void) {
    psp_net_host h;
    if (psp_net_host_info(&h) && h.ipv4) return htonl(h.ipv4);
    return htonl(INADDR_LOOPBACK);
}

/* A stream to a connected signaling peer: the handshake through the shared socket. */
static uint32_t connect_virtual(uint32_t fd, const struct sockaddr_in *sa, uint16_t vport_n) {
    vsock *v = &g_fd[fd].v;
    char t[32];
    if (v->state == VS_ESTABLISHED || v->state == VS_CLOSE_WAIT) return fail(P_EISCONN);
    if (v->state == VS_SYN_SENT) return fail(P_EALREADY);
    static uint16_t next_port = 49152;
    vs_clear(v);
    v->peer_ip_n = sa->sin_addr.s_addr;
    v->peer_port_n = sa->sin_port;
    v->peer_vport_n = vport_n;
    v->ip_n = 0;
    v->port_n = htons(next_port);
    next_port = next_port >= 65000 ? 49152 : next_port + 1;
    v->vport_n = vport_n;
    v->rx_seq = v->tx_seq = 0;
    v->error = 0;
    v->state = VS_SYN_SENT;
    g_fd[fd].virt = 1;
    psp_net_log_line("socket %u: connecting to player %s vport %u (through the shared port)", fd,
                     addr_text(sa, t, sizeof t), ntohs(vport_n));
    if (!vport_n) psp_net_log_line("socket %u: no vport in the address: the peer's port is unknown", fd);
    vs_send(v, g_fd[fd].type, F_SYN | F_TCP, (const uint8_t *)&v->vport_n, 2);
    if (g_fd[fd].nonblock) return fail(P_EINPROGRESS);
    const uint64_t end = psp_sched_now_us() + (g_fd[fd].sndtimeo_us ? g_fd[fd].sndtimeo_us : 30000000u);
    for (;;) {
        p2p_pump();
        if (v->state == VS_ESTABLISHED) return ok(0);
        if (v->state == VS_CLOSED) return fail(v->error ? v->error : P_ECONNREFUSED);
        if (g_fd[fd].aborted) return fail(P_EINTR);
        if (psp_sched_now_us() >= end) return fail(P_ETIMEDOUT);
        nap();
    }
}

static void hle_Connect(void) {
    const uint32_t fd = psp_arg(0), a = psp_arg(1), len = psp_arg(2);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    struct sockaddr_in sa;
    uint16_t vport_n;
    if (read_addr_v(a, len, &sa, &vport_n)) { psp_ret(fail(P_EINVAL)); return; }
    char t[32];
    if (is_stream(g_fd[fd].type) && (g_fd[fd].virt || p2p_is_peer(sa.sin_addr.s_addr))) {
        psp_ret(connect_virtual(fd, &sa, vport_n));
        return;
    }
    const int any = sa.sin_addr.s_addr == htonl(INADDR_ANY);
    if (any) sa.sin_addr.s_addr = this_host_addr();                /* BSD: 0.0.0.0 is this host */
    if (connect(g_fd[fd].s, (struct sockaddr *)&sa, sizeof sa) == 0) {
        psp_net_log_line("socket %u: connected to %s%s", fd, addr_text(&sa, t, sizeof t), any ? " (0.0.0.0 = this host)" : "");
        psp_ret(ok(0));
        return;
    }
    const int e = last_error();
#ifdef _WIN32
    const int pending = e == WSAEWOULDBLOCK;
#else
    const int pending = e == EINPROGRESS;
#endif
    if (!pending) {
        const uint32_t pe = map_err(e);
        psp_net_log_line("socket %u: connect to %s failed (errno %u)", fd, addr_text(&sa, t, sizeof t), pe);
        psp_ret(fail(pe));
        return;
    }
    if (g_fd[fd].nonblock) {
        psp_net_log_line("socket %u: connecting to %s%s (in progress)", fd, addr_text(&sa, t, sizeof t), any ? " (0.0.0.0 = this host)" : "");
        psp_ret(fail(P_EINPROGRESS));
        return;
    }
    const int w = wait_sock(fd, 1, g_fd[fd].sndtimeo_us ? g_fd[fd].sndtimeo_us : 30000000u);
    if (w < 0) { psp_ret(fail(P_EINTR)); return; }
    if (w == 0) { psp_net_log_line("socket %u: connect to %s timed out", fd, addr_text(&sa, t, sizeof t)); psp_ret(fail(P_ETIMEDOUT)); return; }
    int soerr = 0;
    socklen_t sl = sizeof soerr;
    getsockopt(g_fd[fd].s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl);
    if (soerr) {
        const uint32_t pe = map_err(soerr);
        psp_net_log_line("socket %u: connect to %s failed (errno %u)", fd, addr_text(&sa, t, sizeof t), pe);
        psp_ret(fail(pe));
        return;
    }
    psp_net_log_line("socket %u: connected to %s%s", fd, addr_text(&sa, t, sizeof t), any ? " (0.0.0.0 = this host)" : "");
    psp_ret(ok(0));
}

static int host_flags(uint32_t f) {
    int h = 0;
    if (f & MSG_OOB_P) h |= MSG_OOB;
    if (f & MSG_PEEK_P) h |= MSG_PEEK;
    if (f & MSG_DONTROUTE_P) h |= MSG_DONTROUTE;
    return h;                                    /* DONTWAIT is handled here; CRYPT flags: plain traffic */
}

/* The first bytes of each message on a socket, for following a game's own
 * protocol (PSP2i's session server). The first 400 messages per socket. */
static void log_data(uint32_t fd, const char *dir, const uint8_t *p, int n) {
    if (n <= 0 || g_fd[fd].sends + g_fd[fd].recvs > 400) return;
    char hex[3 * 48 + 1];
    const int k = n < 48 ? n : 48;
    for (int i = 0; i < k; i++) snprintf(hex + 3 * i, 4, "%02x ", p[i]);
    hex[3 * k] = '\0';
    psp_net_log_line("socket %u: %s %d bytes: %s%s", fd, dir, n, hex, n > k ? "..." : "");
    /* PSP2I_NET_DUMP=1: every sent message in full (both ends are usually this
     * runtime, so sends alone cover the traffic), 64 bytes a line, up to 8 MB. */
    static int dump = -1;
    static size_t dumped;
    if (dump < 0) { const char *e = getenv("PSP2I_NET_DUMP"); dump = e && *e == '1'; }
    if (!dump || dir[0] != 's' || n <= k || dumped > (8u << 20)) return;
    dumped += (size_t)n;
    for (int o = 0; o < n; o += 64) {
        char line[3 * 64 + 1];
        const int m = n - o < 64 ? n - o : 64;
        for (int i = 0; i < m; i++) snprintf(line + 3 * i, 4, "%02x ", p[o + i]);
        line[3 * m] = '\0';
        psp_net_log_line("socket %u:   +%04X %s", fd, o, line);
    }
}

/* send on a player-to-player stream */
static uint32_t send_virtual(uint32_t fd, const uint8_t *data, uint32_t len) {
    vsock *v = &g_fd[fd].v;
    if (v->state != VS_ESTABLISHED && v->state != VS_CLOSE_WAIT) return fail(v->state == VS_SYN_SENT ? P_EAGAIN : P_ENOTCONN);
    if (vs_send(v, g_fd[fd].type, F_PSH | F_TCP, data, len) != 0) return fail(P_ENETUNREACH);
    log_data(fd, "sent (p2p)", data, (int)len);
    g_fd[fd].sends++;
    return ok(len);
}

/* sendto from a socket on the shared port: to a peer through p2p.c */
static uint32_t sendto_virtual(uint32_t fd, const uint8_t *data, uint32_t len, const struct sockaddr_in *to, uint16_t vport_n) {
    vsock *v = &g_fd[fd].v;
    const uint16_t dvport = vport_n ? vport_n : (uint16_t)VPORT_ANY;
    if (wire_send(to->sin_addr.s_addr, to->sin_port, to->sin_port, dvport, F_PSH, v->port_n, v->vport_n,
                  (uint8_t)g_fd[fd].type, v->tx_seq + 1, data, len) != 0)
        return fail(P_ENETUNREACH);
    v->tx_seq++;
    log_data(fd, "sent (p2p)", data, (int)len);
    g_fd[fd].sends++;
    return ok(len);
}

/* send / sendto */
static uint32_t do_send(uint32_t fd, uint32_t buf, uint32_t len, uint32_t flags, const struct sockaddr_in *to, uint16_t to_vport_n) {
    if (!fd_ok(fd)) return bad_fd(fd, __func__);
    if (len > 0x100000) return fail(P_EMSGSIZE);
    uint8_t stackbuf[2048], *tmp = len <= sizeof stackbuf ? stackbuf : (uint8_t *)malloc(len ? len : 1);
    if (!tmp) return fail(P_ENOBUFS);
    if (len) psp_mem_read_block(tmp, buf, len);
    uint32_t r;
    if (g_fd[fd].virt) {
        r = send_virtual(fd, tmp, len);
        p2p_pump();
        if (tmp != stackbuf) free(tmp);
        return r;
    }
    if (to && !is_stream(g_fd[fd].type) && p2p_active() &&
        (g_fd[fd].virt_dgram || g_fd[fd].crypto || p2p_is_peer(to->sin_addr.s_addr) || ntohs(to->sin_port) == P2P_PORT)) {
        r = sendto_virtual(fd, tmp, len, to, to_vport_n);
        p2p_pump();
        if (tmp != stackbuf) free(tmp);
        return r;
    }
    const int nb = g_fd[fd].nonblock || (flags & MSG_DONTWAIT_P);
    const uint64_t end = g_fd[fd].sndtimeo_us ? psp_sched_now_us() + g_fd[fd].sndtimeo_us : 0;
    for (;;) {
        const int n = to ? sendto(g_fd[fd].s, (const char *)tmp, (int)len, host_flags(flags), (const struct sockaddr *)to, sizeof *to)
                         : send(g_fd[fd].s, (const char *)tmp, (int)len, host_flags(flags));
        if (n >= 0) { log_data(fd, "sent", tmp, n); r = ok((uint32_t)n); g_fd[fd].sends++; break; }
        const int e = last_error();
        if (!would_block(e) || nb) { r = fail(map_err(e)); break; }
        if (end && psp_sched_now_us() >= end) { r = fail(P_EAGAIN); break; }
        if (wait_sock(fd, 1, 1000) < 0) { r = fail(P_EINTR); break; }
    }
    if (tmp != stackbuf) free(tmp);
    return r;
}

/* recv on a player-to-player stream: the bytes in order, across packets */
static uint32_t recv_virtual(uint32_t fd, uint32_t buf, uint32_t len, uint32_t flags) {
    vsock *v = &g_fd[fd].v;
    const int nb = g_fd[fd].nonblock || (flags & MSG_DONTWAIT_P);
    const uint64_t end = g_fd[fd].rcvtimeo_us ? psp_sched_now_us() + g_fd[fd].rcvtimeo_us : 0;
    for (;;) {
        p2p_pump();
        if (v->state == VS_SYN_SENT || v->state == VS_SYN_RCVD) { if (nb) return fail(P_EAGAIN); }
        else if (v->state != VS_ESTABLISHED && v->state != VS_CLOSE_WAIT) return fail(P_ENOTCONN);
        else if (vs_readable(v)) break;
        if (nb) return fail(P_EAGAIN);
        if (g_fd[fd].aborted) return fail(P_EINTR);
        if (end && psp_sched_now_us() >= end) return fail(P_EAGAIN);
        nap();
    }
    uint32_t got = 0;
    uint8_t first[48];
    uint32_t nfirst = 0;
    while (got < len) {
        vpkt **at = &v->rx;
        while (*at && (*at)->seq != v->rx_seq + 1) at = &(*at)->next;
        vpkt *p = *at;
        if (!p) break;
        const uint32_t avail = p->len - p->off, take = avail < len - got ? avail : len - got;
        if (take) psp_mem_write_block(buf + got, p->data + p->off, take);
        for (uint32_t i = 0; i < take && nfirst < sizeof first; i++) first[nfirst++] = p->data[p->off + i];
        got += take;
        if (take < avail) { p->off += take; break; }
        *at = p->next;
        free(p);
        v->rx_seq++;
    }
    if (got) log_data(fd, "received (p2p)", first, (int)got < (int)sizeof first ? (int)got : (int)sizeof first);
    else log_data(fd, "received end of stream (p2p)", first, 1);
    g_fd[fd].recvs++;
    return ok(got);
}

/* recvfrom on a socket on the shared port */
static uint32_t recvfrom_virtual(uint32_t fd, uint32_t buf, uint32_t len, uint32_t flags, uint32_t from, uint32_t fromlen) {
    vsock *v = &g_fd[fd].v;
    const int nb = g_fd[fd].nonblock || (flags & MSG_DONTWAIT_P);
    const uint64_t end = g_fd[fd].rcvtimeo_us ? psp_sched_now_us() + g_fd[fd].rcvtimeo_us : 0;
    for (;;) {
        p2p_pump();
        if (v->rx) break;
        if (nb) return fail(P_EAGAIN);
        if (g_fd[fd].aborted) return fail(P_EINTR);
        if (end && psp_sched_now_us() >= end) return fail(P_EAGAIN);
        nap();
    }
    vpkt *p = v->rx;
    if (!(flags & MSG_PEEK_P)) v->rx = p->next;
    const uint32_t n = p->len < len ? p->len : len;        /* datagram semantics: the rest is lost */
    if (n) psp_mem_write_block(buf, p->data, n);
    if (from) write_addr_v(from, fromlen, p->src_ip_n, p->src_port_n, p->src_vport_n);
    log_data(fd, "received (p2p)", p->data, (int)n);
    if (!(flags & MSG_PEEK_P)) free(p);
    g_fd[fd].recvs++;
    return ok(n);
}

/* recv / recvfrom */
static uint32_t do_recv(uint32_t fd, uint32_t buf, uint32_t len, uint32_t flags, uint32_t from, uint32_t fromlen) {
    if (!fd_ok(fd)) return bad_fd(fd, __func__);
    if (len > 0x100000) len = 0x100000;
    if (g_fd[fd].virt) return recv_virtual(fd, buf, len, flags);
    if (g_fd[fd].virt_dgram) return recvfrom_virtual(fd, buf, len, flags, from, fromlen);
    uint8_t stackbuf[2048], *tmp = len <= sizeof stackbuf ? stackbuf : (uint8_t *)malloc(len ? len : 1);
    if (!tmp) return fail(P_ENOBUFS);
    const int nb = g_fd[fd].nonblock || (flags & MSG_DONTWAIT_P);
    const uint64_t timeout = g_fd[fd].rcvtimeo_us;
    uint32_t r;
    for (;;) {
        struct sockaddr_in peer;
        socklen_t pl = sizeof peer;
        memset(&peer, 0, sizeof peer);
        const int n = from ? recvfrom(g_fd[fd].s, (char *)tmp, (int)len, host_flags(flags), (struct sockaddr *)&peer, &pl)
                           : recv(g_fd[fd].s, (char *)tmp, (int)len, host_flags(flags));
        if (n >= 0) {
            if (n) psp_mem_write_block(buf, tmp, (uint32_t)n);
            log_data(fd, n ? "received" : "received end of stream", tmp, n ? n : 1);
            if (from) write_addr(from, fromlen, &peer);
            g_fd[fd].recvs++;
            r = ok((uint32_t)n);
            break;
        }
        const int e = last_error();
#ifdef _WIN32
        if (e == WSAEMSGSIZE && from) {          /* datagram larger than the buffer: BSD truncates */
            psp_mem_write_block(buf, tmp, len);
            write_addr(from, fromlen, &peer);
            r = ok(len);
            break;
        }
#endif
        if (!would_block(e) || nb) { r = fail(map_err(e)); break; }
        const int w = wait_sock(fd, 0, timeout);
        if (w < 0) { r = fail(P_EINTR); break; }
        if (w == 0) { r = fail(P_EAGAIN); break; }
    }
    if (tmp != stackbuf) free(tmp);
    return r;
}

static void hle_Send(void) {
    const uint32_t fd = psp_arg(0), buf = psp_arg(1), len = psp_arg(2), flags = psp_arg(3);
    psp_ret(do_send(fd, buf, len, flags, NULL, 0));
}

static void hle_Sendto(void) {
    const uint32_t fd = psp_arg(0), buf = psp_arg(1), len = psp_arg(2), flags = psp_arg(3), to = psp_arg(4), tolen = psp_arg(5);
    struct sockaddr_in sa;
    uint16_t vport_n = 0;
    if (to && read_addr_v(to, tolen, &sa, &vport_n)) { psp_ret(fail(P_EINVAL)); return; }
    if (to && sa.sin_addr.s_addr == htonl(INADDR_ANY)) sa.sin_addr.s_addr = this_host_addr();
    psp_ret(do_send(fd, buf, len, flags, to ? &sa : NULL, vport_n));
}

static void hle_Recv(void) {
    const uint32_t fd = psp_arg(0), buf = psp_arg(1), len = psp_arg(2), flags = psp_arg(3);
    psp_ret(do_recv(fd, buf, len, flags, 0, 0));
}

static void hle_Recvfrom(void) {
    const uint32_t fd = psp_arg(0), buf = psp_arg(1), len = psp_arg(2), flags = psp_arg(3), from = psp_arg(4), fromlen = psp_arg(5);
    psp_ret(do_recv(fd, buf, len, flags, from, fromlen));
}

static void fd_free(uint32_t fd) {
    if (g_fd[fd].s != BAD_SOCK) close_sock(g_fd[fd].s);
    vs_clear(&g_fd[fd].v);
    memset(&g_fd[fd], 0, sizeof g_fd[fd]);
}

static void hle_Close(void) {
    const uint32_t fd = psp_arg(0);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    psp_net_log_line("socket %u: closed (%u sends, %u receives)", fd, g_fd[fd].sends, g_fd[fd].recvs);
    fd_free(fd);
    psp_ret(ok(0));
}

static uint64_t timeo_from_guest(uint32_t v, uint32_t len) {
    if (!v) return 0;
    if (len >= 8) return (uint64_t)psp_read32(v) * 1000000u + psp_read32(v + 4);   /* timeval */
    return psp_read32(v);                                                          /* microseconds */
}

static void hle_Setsockopt(void) {
    const uint32_t fd = psp_arg(0), level = psp_arg(1), name = psp_arg(2), val = psp_arg(3), len = psp_arg(4);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    const uint32_t iv = val && len >= 4 ? psp_read32(val) : (val && len ? psp_read8(val) : 0);
    const hsock s = g_fd[fd].s;
    if (level == SOL_SOCKET_P) {
        switch (name) {
        case SO_NBIO_P: g_fd[fd].nonblock = iv != 0; psp_ret(ok(0)); return;
        case SO_BIO_P:  g_fd[fd].nonblock = 0; psp_ret(ok(0)); return;
        case SO_RCVTIMEO_P: g_fd[fd].rcvtimeo_us = timeo_from_guest(val, len); psp_ret(ok(0)); return;
        case SO_SNDTIMEO_P: g_fd[fd].sndtimeo_us = timeo_from_guest(val, len); psp_ret(ok(0)); return;
        case SO_USECRYPTO_RX_P: case SO_USECRYPTO_TX_P:
            if (iv) g_fd[fd].crypto = 1;
            psp_net_log_line("socket %u: crypto option 0x%X = %u (a player-to-player socket; traffic stays plain)", fd, name, iv);
            psp_ret(ok(0));
            return;
        case 0x0004: case 0x0008: case 0x0020: case 0x0100: case 0x1001: case 0x1002: {   /* REUSEADDR KEEPALIVE BROADCAST OOBINLINE SNDBUF RCVBUF */
            const int v = (int)iv;
            if (s != BAD_SOCK) setsockopt(s, SOL_SOCKET, (int)name, (const char *)&v, sizeof v);
            psp_ret(ok(0));
            return;
        }
        case 0x0080: {                           /* SO_LINGER {int onoff, int linger} */
            struct linger l;
            l.l_onoff = (unsigned short)(val ? psp_read32(val) : 0);
            l.l_linger = (unsigned short)(val && len >= 8 ? psp_read32(val + 4) : 0);
            if (s != BAD_SOCK) setsockopt(s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l);
            psp_ret(ok(0));
            return;
        }
        default: break;
        }
    } else if (level == 6 && name == 1) {        /* IPPROTO_TCP, TCP_NODELAY */
        const int v = (int)iv;
        if (s != BAD_SOCK) setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char *)&v, sizeof v);
        psp_ret(ok(0));
        return;
    } else if (level == 0 && (name == 3 || name == 4)) {   /* IP_TOS, IP_TTL */
        const int v = (int)iv;
        if (s != BAD_SOCK) setsockopt(s, IPPROTO_IP, name == 3 ? IP_TOS : IP_TTL, (const char *)&v, sizeof v);
        psp_ret(ok(0));
        return;
    }
    psp_net_log_line("socket %u: option level 0x%X name 0x%X = %u accepted, not applied", fd, level, name, iv);
    psp_ret(ok(0));
}

static void hle_Getsockopt(void) {
    const uint32_t fd = psp_arg(0), level = psp_arg(1), name = psp_arg(2), val = psp_arg(3), lenp = psp_arg(4);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    const hsock s = g_fd[fd].s;
    int v = 0;
    if (level == SOL_SOCKET_P && name == SO_ERROR_P) {
        if (g_fd[fd].virt) {
            v = (int)g_fd[fd].v.error;
            g_fd[fd].v.error = 0;
        } else {
            socklen_t sl = sizeof v;
            getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&v, &sl);
            v = v ? (int)map_err(v) : 0;
        }
    } else if (level == SOL_SOCKET_P && name == SO_NBIO_P) v = g_fd[fd].nonblock;
    else if (level == SOL_SOCKET_P && name == SO_TYPE_P) v = g_fd[fd].type;
    else if (level == SOL_SOCKET_P && (name == 0x1001 || name == 0x1002 || name == 0x0004 || name == 0x0008 || name == 0x0020)) {
        socklen_t sl = sizeof v;
        if (s != BAD_SOCK) getsockopt(s, SOL_SOCKET, (int)name, (char *)&v, &sl);
    } else if (level == SOL_SOCKET_P && (name == SO_RCVTIMEO_P || name == SO_SNDTIMEO_P)) {
        const uint64_t us = name == SO_RCVTIMEO_P ? g_fd[fd].rcvtimeo_us : g_fd[fd].sndtimeo_us;
        if (val && lenp && psp_read32(lenp) >= 8) {
            psp_write32(val, (uint32_t)(us / 1000000u)); psp_write32(val + 4, (uint32_t)(us % 1000000u)); psp_write32(lenp, 8);
            psp_ret(ok(0));
            return;
        }
        v = (int)us;
    }
    if (val) psp_write32(val, (uint32_t)v);
    if (lenp) psp_write32(lenp, 4);
    psp_ret(ok(0));
}

static void hle_Shutdown(void) {
    const uint32_t fd = psp_arg(0), how = psp_arg(1);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    if (g_fd[fd].virt) {
        /* As the reference: a player-to-player stream ends without a FIN; the
         * peer learns of it from signaling (the member leaves). */
        psp_net_log_line("socket %u: shutdown (player-to-player)", fd);
        psp_ret(ok(0));
        return;
    }
    if (shutdown(g_fd[fd].s, (int)how) != 0) { psp_ret(fail(map_err(last_error()))); return; }
    psp_ret(ok(0));
}

/* Readiness of the player-to-player side of a socket. */
static void virtual_ready(uint32_t fd, int *r, int *w, int *x) {
    const vsock *v = &g_fd[fd].v;
    *r = *w = *x = 0;
    if (g_fd[fd].virt) {
        *r = vs_readable(v) || v->state == VS_CLOSED;
        *w = v->state == VS_ESTABLISHED || v->state == VS_CLOSED;
        *x = v->state == VS_CLOSED && v->error;
    } else if (g_fd[fd].virt_dgram) {
        *r = v->rx != NULL;
        *w = 1;
    } else if (v->state == VS_LISTEN) {
        *r = vs_has_accept(v);
    }
}

/* select(nfds, readfds, writefds, exceptfds, timeout): PSP fd_sets are 8 u32. */
static void hle_Select(void) {
    const uint32_t nfds = psp_arg(0), rp = psp_arg(1), wp = psp_arg(2), xp = psp_arg(3), tp = psp_arg(4);
    uint32_t rin[8] = { 0 }, win[8] = { 0 }, xin[8] = { 0 };
    for (int i = 0; i < 8; i++) {
        if (rp) rin[i] = psp_read32(rp + 4u * (uint32_t)i);
        if (wp) win[i] = psp_read32(wp + 4u * (uint32_t)i);
        if (xp) xin[i] = psp_read32(xp + 4u * (uint32_t)i);
    }
    const uint64_t timeout = tp ? (uint64_t)psp_read32(tp) * 1000000u + psp_read32(tp + 4) : 0;
    const uint64_t end = psp_sched_now_us() + timeout;
    const uint32_t n = nfds < MAX_FD ? nfds : MAX_FD;
    for (;;) {
        p2p_pump();
        uint32_t rout[8] = { 0 }, wout[8] = { 0 }, xout[8] = { 0 };
        int count = 0;
        fd_set r, w, x;
        FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&x);
        int any = 0, maxs = 0;
        for (uint32_t fd = 1; fd < n; fd++) {
            const uint32_t bit = 1u << (fd & 31), k = fd >> 5;
            if (!((rin[k] | win[k] | xin[k]) & bit)) continue;
            if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
            int vr, vw, vx;
            virtual_ready(fd, &vr, &vw, &vx);
            if ((rin[k] & bit) && vr) { rout[k] |= bit; count++; }
            if ((win[k] & bit) && vw) { wout[k] |= bit; count++; }
            if ((xin[k] & bit) && vx) { xout[k] |= bit; count++; }
            if (g_fd[fd].virt || g_fd[fd].virt_dgram || g_fd[fd].s == BAD_SOCK) continue;   /* the host socket is idle */
            if (rin[k] & bit) FD_SET(g_fd[fd].s, &r);
            if (win[k] & bit) FD_SET(g_fd[fd].s, &w);
            if (xin[k] & bit) FD_SET(g_fd[fd].s, &x);
            if ((int)g_fd[fd].s > maxs) maxs = (int)g_fd[fd].s;
            any = 1;
        }
        if (any) {
            struct timeval tv = { 0, 0 };
            if (select(maxs + 1, &r, &w, &x, &tv) < 0) { psp_ret(fail(map_err(last_error()))); return; }
            for (uint32_t fd = 1; fd < n; fd++) {
                if (!fd_ok(fd) || g_fd[fd].virt || g_fd[fd].virt_dgram || g_fd[fd].s == BAD_SOCK) continue;
                const uint32_t bit = 1u << (fd & 31), k = fd >> 5;
                if ((rin[k] & bit) && !(rout[k] & bit) && FD_ISSET(g_fd[fd].s, &r)) { rout[k] |= bit; count++; }
                if ((win[k] & bit) && !(wout[k] & bit) && FD_ISSET(g_fd[fd].s, &w)) { wout[k] |= bit; count++; }
                if ((xin[k] & bit) && !(xout[k] & bit) && FD_ISSET(g_fd[fd].s, &x)) { xout[k] |= bit; count++; }
            }
        }
        if (count || (tp && psp_sched_now_us() >= end)) {
            for (int i = 0; i < 8; i++) {
                if (rp) psp_write32(rp + 4u * (uint32_t)i, rout[i]);
                if (wp) psp_write32(wp + 4u * (uint32_t)i, wout[i]);
                if (xp) psp_write32(xp + 4u * (uint32_t)i, xout[i]);
            }
            psp_ret(ok((uint32_t)count));
            return;
        }
        nap();
    }
}

/* Abort: a call blocked on the socket returns with EINTR. */
static void hle_SocketAbort(void) {
    const uint32_t fd = psp_arg(0);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    g_fd[fd].aborted = 1;
    psp_net_log_line("socket %u: aborted", fd);
    psp_ret(ok(0));
}

static void hle_GetPspError(void) { psp_ret(g_errno ? 0x80010000u | (g_errno & 0xFFFF) : 0); }
static void hle_GetErrno(void) { psp_ret(g_errno); }

void psp_net_sock_close_all(void) {
    for (int i = 1; i < MAX_FD; i++) if (g_fd[i].used) fd_free((uint32_t)i);
}

void psp_net_sock_register(void) {
    psp_hle_register(0x8B7B220F, "sceNetInet", "sceNetInetSocket",      hle_Socket);
    psp_hle_register(0x1A33F9AE, "sceNetInet", "sceNetInetBind",        hle_Bind);
    psp_hle_register(0xD10A1A7A, "sceNetInet", "sceNetInetListen",      hle_Listen);
    psp_hle_register(0xDB094E1B, "sceNetInet", "sceNetInetAccept",      hle_Accept);
    psp_hle_register(0x410B34AA, "sceNetInet", "sceNetInetConnect",     hle_Connect);
    psp_hle_register(0x7AA671BC, "sceNetInet", "sceNetInetSend",        hle_Send);
    psp_hle_register(0x05038FC7, "sceNetInet", "sceNetInetSendto",      hle_Sendto);
    psp_hle_register(0xCDA85C99, "sceNetInet", "sceNetInetRecv",        hle_Recv);
    psp_hle_register(0xC91142E4, "sceNetInet", "sceNetInetRecvfrom",    hle_Recvfrom);
    psp_hle_register(0x8D7284EA, "sceNetInet", "sceNetInetClose",       hle_Close);
    psp_hle_register(0x2FE71FE7, "sceNetInet", "sceNetInetSetsockopt",  hle_Setsockopt);
    psp_hle_register(0x4A114C7C, "sceNetInet", "sceNetInetGetsockopt",  hle_Getsockopt);
    psp_hle_register(0x4CFE4E56, "sceNetInet", "sceNetInetShutdown",    hle_Shutdown);
    psp_hle_register(0x5BE8D595, "sceNetInet", "sceNetInetSelect",      hle_Select);
    psp_hle_register(0x80A21ABD, "sceNetInet", "sceNetInetSocketAbort", hle_SocketAbort);
    psp_hle_register(0x8CA3A97E, "sceNetInet", "sceNetInetGetPspError", hle_GetPspError);
    psp_hle_register(0xFBABE411, "sceNetInet", "sceNetInetGetErrno",    hle_GetErrno);
}
