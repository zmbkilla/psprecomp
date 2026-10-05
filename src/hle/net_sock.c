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
 *     (0x1000 / 0x2000, and the MSG_CRYPT send flags) are accepted and
 *     ignored: both ends are this runtime, and the traffic is plain.
 *   - connect() to 0.0.0.0 goes to this host's own address, as on the PSP's BSD
 *     stack (Windows refuses it): a room owner connecting to its own room.
 *   - The PSP's player-to-player socket types -- 6 (connection-oriented
 *     datagram), 7 (DCCP, the P2P "master") and 10 (packet: a TCP-like
 *     stream) -- take the local route PPSSPP uses for destinations that are
 *     not remote peers: 10 on a host TCP socket, 6 and 7 on host UDP. The
 *     address's virtual port (sin_vport) is ignored on this route. Traffic
 *     to remote players needs the virtual-port protocol over UDP 3658 and
 *     signaling (not yet).
 *
 * Constants follow PPSSPP's NetInetConstants.h (Komak57/ppsspp master). */

#include "psprecomp/hle.h"
#include "psprecomp/net.h"

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

#define MAX_FD 256
static struct {
    int used, type, nonblock, aborted;
    hsock s;
    uint64_t rcvtimeo_us, sndtimeo_us;      /* 0 = no timeout */
    uint32_t sends, recvs;
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

/* PSP sockaddr_in at guest address a -> host sockaddr_in. */
static int read_addr(uint32_t a, uint32_t len, struct sockaddr_in *out) {
    memset(out, 0, sizeof *out);
    if (!a || len < 8) return -1;
    out->sin_family = AF_INET;
    uint8_t b[8];
    psp_mem_read_block(b, a, 8);
    memcpy(&out->sin_port, b + 2, 2);           /* both already in network order */
    memcpy(&out->sin_addr, b + 4, 4);
    return 0;
}

static void write_addr(uint32_t a, uint32_t lenp, const struct sockaddr_in *in) {
    if (!a) return;
    uint8_t b[16];
    memset(b, 0, sizeof b);
    b[0] = 16;
    b[1] = 2;                                    /* AF_INET */
    memcpy(b + 2, &in->sin_port, 2);
    memcpy(b + 4, &in->sin_addr, 4);
    const uint32_t cap = lenp ? psp_read32(lenp) : 16;
    psp_mem_write_block(a, b, cap < 16 ? cap : 16);
    if (lenp) psp_write32(lenp, 16);
}

static const char *addr_text(const struct sockaddr_in *a, char *buf, size_t cap) {
    const uint8_t *b = (const uint8_t *)&a->sin_addr;
    snprintf(buf, cap, "%u.%u.%u.%u:%u", b[0], b[1], b[2], b[3], ntohs(a->sin_port));
    return buf;
}

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

/* ---- the calls ------------------------------------------------------------------------- */

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
    uint32_t fd = 0;
    for (uint32_t i = 1; i < MAX_FD; i++) if (!g_fd[i].used) { fd = i; break; }
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
    if (read_addr(a, len, &sa)) { psp_ret(fail(P_EINVAL)); return; }
    char t[32];
    if (bind(g_fd[fd].s, (struct sockaddr *)&sa, sizeof sa) != 0) {
        const uint32_t e = map_err(last_error());
        psp_net_log_line("socket %u: bind %s failed (errno %u)", fd, addr_text(&sa, t, sizeof t), e);
        psp_ret(fail(e));
        return;
    }
    psp_net_log_line("socket %u: bound to %s", fd, addr_text(&sa, t, sizeof t));
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
    psp_net_log_line("socket %u: listening (backlog %u)", fd, backlog);
    psp_ret(ok(0));
}

static void hle_Accept(void) {
    const uint32_t fd = psp_arg(0), a = psp_arg(1), lenp = psp_arg(2);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    for (;;) {
        struct sockaddr_in peer;
        socklen_t pl = sizeof peer;
        const hsock s = accept(g_fd[fd].s, (struct sockaddr *)&peer, &pl);
        if (s != BAD_SOCK) {
            uint32_t nfd = 0;
            for (uint32_t i = 1; i < MAX_FD; i++) if (!g_fd[i].used) { nfd = i; break; }
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
        const int e = last_error();
        if (!would_block(e) || g_fd[fd].nonblock) { psp_ret(fail(map_err(e))); return; }
        if (wait_sock(fd, 0, 0) < 0) { psp_ret(fail(P_EINTR)); return; }
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

static void hle_Connect(void) {
    const uint32_t fd = psp_arg(0), a = psp_arg(1), len = psp_arg(2);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    struct sockaddr_in sa;
    if (read_addr(a, len, &sa)) { psp_ret(fail(P_EINVAL)); return; }
    char t[32];
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
}

/* send / sendto */
static uint32_t do_send(uint32_t fd, uint32_t buf, uint32_t len, uint32_t flags, const struct sockaddr_in *to) {
    if (!fd_ok(fd)) return bad_fd(fd, __func__);
    if (len > 0x100000) return fail(P_EMSGSIZE);
    uint8_t stackbuf[2048], *tmp = len <= sizeof stackbuf ? stackbuf : (uint8_t *)malloc(len ? len : 1);
    if (!tmp) return fail(P_ENOBUFS);
    if (len) psp_mem_read_block(tmp, buf, len);
    const int nb = g_fd[fd].nonblock || (flags & MSG_DONTWAIT_P);
    const uint64_t end = g_fd[fd].sndtimeo_us ? psp_sched_now_us() + g_fd[fd].sndtimeo_us : 0;
    uint32_t r;
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

/* recv / recvfrom */
static uint32_t do_recv(uint32_t fd, uint32_t buf, uint32_t len, uint32_t flags, uint32_t from, uint32_t fromlen) {
    if (!fd_ok(fd)) return bad_fd(fd, __func__);
    if (len > 0x100000) len = 0x100000;
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
    psp_ret(do_send(fd, buf, len, flags, NULL));
}

static void hle_Sendto(void) {
    const uint32_t fd = psp_arg(0), buf = psp_arg(1), len = psp_arg(2), flags = psp_arg(3), to = psp_arg(4), tolen = psp_arg(5);
    struct sockaddr_in sa;
    if (to && read_addr(to, tolen, &sa)) { psp_ret(fail(P_EINVAL)); return; }
    if (to && sa.sin_addr.s_addr == htonl(INADDR_ANY)) sa.sin_addr.s_addr = this_host_addr();
    psp_ret(do_send(fd, buf, len, flags, to ? &sa : NULL));
}

static void hle_Recv(void) {
    const uint32_t fd = psp_arg(0), buf = psp_arg(1), len = psp_arg(2), flags = psp_arg(3);
    psp_ret(do_recv(fd, buf, len, flags, 0, 0));
}

static void hle_Recvfrom(void) {
    const uint32_t fd = psp_arg(0), buf = psp_arg(1), len = psp_arg(2), flags = psp_arg(3), from = psp_arg(4), fromlen = psp_arg(5);
    psp_ret(do_recv(fd, buf, len, flags, from, fromlen));
}

static void hle_Close(void) {
    const uint32_t fd = psp_arg(0);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    close_sock(g_fd[fd].s);
    psp_net_log_line("socket %u: closed (%u sends, %u receives)", fd, g_fd[fd].sends, g_fd[fd].recvs);
    memset(&g_fd[fd], 0, sizeof g_fd[fd]);
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
    if (level == SOL_SOCKET_P) {
        switch (name) {
        case SO_NBIO_P: g_fd[fd].nonblock = iv != 0; psp_ret(ok(0)); return;
        case SO_BIO_P:  g_fd[fd].nonblock = 0; psp_ret(ok(0)); return;
        case SO_RCVTIMEO_P: g_fd[fd].rcvtimeo_us = timeo_from_guest(val, len); psp_ret(ok(0)); return;
        case SO_SNDTIMEO_P: g_fd[fd].sndtimeo_us = timeo_from_guest(val, len); psp_ret(ok(0)); return;
        case SO_USECRYPTO_RX_P: case SO_USECRYPTO_TX_P:
            psp_net_log_line("socket %u: crypto option 0x%X = %u accepted (traffic stays plain)", fd, name, iv);
            psp_ret(ok(0));
            return;
        case 0x0004: case 0x0008: case 0x0020: case 0x0100: case 0x1001: case 0x1002: {   /* REUSEADDR KEEPALIVE BROADCAST OOBINLINE SNDBUF RCVBUF */
            const int v = (int)iv;
            setsockopt(g_fd[fd].s, SOL_SOCKET, (int)name, (const char *)&v, sizeof v);
            psp_ret(ok(0));
            return;
        }
        case 0x0080: {                           /* SO_LINGER {int onoff, int linger} */
            struct linger l;
            l.l_onoff = (unsigned short)(val ? psp_read32(val) : 0);
            l.l_linger = (unsigned short)(val && len >= 8 ? psp_read32(val + 4) : 0);
            setsockopt(g_fd[fd].s, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l);
            psp_ret(ok(0));
            return;
        }
        default: break;
        }
    } else if (level == 6 && name == 1) {        /* IPPROTO_TCP, TCP_NODELAY */
        const int v = (int)iv;
        setsockopt(g_fd[fd].s, IPPROTO_TCP, TCP_NODELAY, (const char *)&v, sizeof v);
        psp_ret(ok(0));
        return;
    } else if (level == 0 && (name == 3 || name == 4)) {   /* IP_TOS, IP_TTL */
        const int v = (int)iv;
        setsockopt(g_fd[fd].s, IPPROTO_IP, name == 3 ? IP_TOS : IP_TTL, (const char *)&v, sizeof v);
        psp_ret(ok(0));
        return;
    }
    psp_net_log_line("socket %u: option level 0x%X name 0x%X = %u accepted, not applied", fd, level, name, iv);
    psp_ret(ok(0));
}

static void hle_Getsockopt(void) {
    const uint32_t fd = psp_arg(0), level = psp_arg(1), name = psp_arg(2), val = psp_arg(3), lenp = psp_arg(4);
    if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
    int v = 0;
    if (level == SOL_SOCKET_P && name == SO_ERROR_P) {
        socklen_t sl = sizeof v;
        getsockopt(g_fd[fd].s, SOL_SOCKET, SO_ERROR, (char *)&v, &sl);
        v = v ? (int)map_err(v) : 0;
    } else if (level == SOL_SOCKET_P && name == SO_NBIO_P) v = g_fd[fd].nonblock;
    else if (level == SOL_SOCKET_P && name == SO_TYPE_P) v = g_fd[fd].type;
    else if (level == SOL_SOCKET_P && (name == 0x1001 || name == 0x1002 || name == 0x0004 || name == 0x0008 || name == 0x0020)) {
        socklen_t sl = sizeof v;
        getsockopt(g_fd[fd].s, SOL_SOCKET, (int)name, (char *)&v, &sl);
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
    if (shutdown(g_fd[fd].s, (int)how) != 0) { psp_ret(fail(map_err(last_error()))); return; }
    psp_ret(ok(0));
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
        uint32_t rout[8] = { 0 }, wout[8] = { 0 }, xout[8] = { 0 };
        int count = 0;
        fd_set r, w, x;
        FD_ZERO(&r); FD_ZERO(&w); FD_ZERO(&x);
        int any = 0, maxs = 0;
        for (uint32_t fd = 1; fd < n; fd++) {
            const uint32_t bit = 1u << (fd & 31), k = fd >> 5;
            if (!((rin[k] | win[k] | xin[k]) & bit)) continue;
            if (!fd_ok(fd)) { psp_ret(bad_fd(fd, __func__)); return; }
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
                if (!fd_ok(fd)) continue;
                const uint32_t bit = 1u << (fd & 31), k = fd >> 5;
                if ((rin[k] & bit) && FD_ISSET(g_fd[fd].s, &r)) { rout[k] |= bit; count++; }
                if ((win[k] & bit) && FD_ISSET(g_fd[fd].s, &w)) { wout[k] |= bit; count++; }
                if ((xin[k] & bit) && FD_ISSET(g_fd[fd].s, &x)) { xout[k] |= bit; count++; }
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
    for (int i = 1; i < MAX_FD; i++) if (g_fd[i].used) { close_sock(g_fd[i].s); memset(&g_fd[i], 0, sizeof g_fd[i]); }
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
