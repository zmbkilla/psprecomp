/* Player-to-player tests: p2p.c (signaling, the matching server's address
 * check) and net_sock.c's virtual sockets, against a fake peer that speaks
 * the reference emulator's wire format (Komak57/ppsspp master,
 * RPCNSigAgent.cpp / SocketManager.cpp) from 127.0.0.2, and a fake matching
 * server on 127.0.0.1. Every byte the peer checks is the reference's layout.
 *
 * Needs UDP port 3658 free (the shared P2P port); skipped if it is taken. */

#include "psprecomp/hle.h"
#include "psprecomp/dispatch.h"
#include "psprecomp/net.h"
#include "crypto/sha1.h"
#include "p2p.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
typedef SOCKET hsock;
#  define close_sock closesocket
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
typedef int hsock;
#  define close_sock close
#endif

static int failures;
#define CHECK(cond, ...)                                       \
    do {                                                       \
        if (!(cond)) {                                         \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);        \
            printf(__VA_ARGS__);                               \
            printf("\n");                                      \
            failures++;                                        \
        }                                                      \
    } while (0)

static uint32_t call(const char *name, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t a4, uint32_t a5) {
    psp_cpu.r[PSP_REG_A0] = a0; psp_cpu.r[PSP_REG_A1] = a1; psp_cpu.r[PSP_REG_A2] = a2; psp_cpu.r[PSP_REG_A3] = a3;
    psp_cpu.r[PSP_REG_T0] = a4; psp_cpu.r[PSP_REG_T1] = a5;
    psp_hle_call(psp_nid(name));
    return psp_cpu.r[PSP_REG_V0];
}
static uint32_t inet_errno(void) { return call("sceNetInetGetErrno", 0, 0, 0, 0, 0, 0); }

#define PEER_IP   0x7F000002u      /* 127.0.0.2 */
#define PEER_PORT 4000
#define SERVER_PORT 13657
#define G 0x08900000u              /* guest scratch */

static hsock g_peer, g_server;

static hsock udp_at(uint32_t ip, uint16_t port) {
    hsock s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(ip);
    a.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { close_sock(s); return (hsock)-1; }
    return s;
}

/* One datagram within 1 s; its length, or -1. */
static int recv_from(hsock s, uint8_t *b, int cap, struct sockaddr_in *from) {
    fd_set r;
    FD_ZERO(&r);
    FD_SET(s, &r);
    struct timeval tv = { 1, 0 };
    if (select((int)s + 1, &r, NULL, NULL, &tv) <= 0) return -1;
    socklen_t fl = sizeof *from;
    return recvfrom(s, (char *)b, cap, 0, (struct sockaddr *)from, &fl);
}

/* Peer -> us (127.0.0.1:3658). */
static void peer_send(const uint8_t *b, int n) {
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = htonl(0x7F000001u);
    to.sin_port = htons(3658);
    sendto(g_peer, (const char *)b, n, 0, (struct sockaddr *)&to, sizeof to);
}

/* A signaling packet as the reference builds it (its own SceNpId left zero). */
static void peer_sig(uint32_t cmd, uint64_t ts_s, uint64_t ts_r) {
    uint8_t b[75];
    memset(b, 0, sizeof b);
    b[2] = 1;
    memcpy(b + 3, "SIGN", 4);
    b[7] = 4;
    for (int i = 0; i < 8; i++) { b[11 + i] = (uint8_t)(ts_s >> (8 * i)); b[19 + i] = (uint8_t)(ts_r >> (8 * i)); }
    b[27] = (uint8_t)cmd;
    b[31] = 127; b[34] = 1;                    /* sent_addr 127.0.0.1 (network order) */
    b[35] = 3658 & 255; b[36] = 3658 >> 8;     /* sent_port, host order, little-endian */
    peer_send(b, sizeof b);
}

/* Receive signaling packets until one with command `cmd` (others skipped). */
static int peer_expect_sig(uint32_t cmd, uint8_t *out) {
    for (int k = 0; k < 8; k++) {
        struct sockaddr_in from;
        const int n = recv_from(g_peer, out, 2048, &from);
        if (n < 0) return -1;
        if (n == 75 && out[0] == 0 && out[1] == 0 && out[2] == 1 && out[27] == cmd) return n;
    }
    return -1;
}

/* A game packet as SocketManager packs it. Ports and vports in host order here. */
static void peer_game(uint16_t dst_port, uint8_t flags, uint16_t dst_vport, uint16_t src_port, uint16_t src_vport,
                      uint8_t type, uint32_t seq, const void *data, int len) {
    uint8_t b[256];
    b[0] = (uint8_t)(dst_port >> 8); b[1] = (uint8_t)dst_port; b[2] = flags;
    b[3] = (uint8_t)(dst_vport >> 8); b[4] = (uint8_t)dst_vport;
    b[5] = (uint8_t)(src_port >> 8); b[6] = (uint8_t)src_port;
    b[7] = (uint8_t)(src_vport >> 8); b[8] = (uint8_t)src_vport;
    b[9] = type;
    b[10] = (uint8_t)(seq >> 24); b[11] = (uint8_t)(seq >> 16); b[12] = (uint8_t)(seq >> 8); b[13] = (uint8_t)seq;
    if (len) memcpy(b + 14, data, (size_t)len);
    peer_send(b, 14 + len);
}

typedef struct { uint16_t dst_port, dst_vport, src_port, src_vport; uint8_t flags, type; uint32_t seq; int len; uint8_t data[2048]; } gpkt;

/* The next game packet (signaling skipped). */
static int peer_expect_game(gpkt *g) {
    uint8_t b[2100];
    for (int k = 0; k < 16; k++) {
        struct sockaddr_in from;
        const int n = recv_from(g_peer, b, sizeof b, &from);
        if (n < 0) return -1;
        if (n < 14 || (b[0] == 0 && b[1] == 0)) continue;
        g->dst_port = (uint16_t)(b[0] << 8 | b[1]); g->flags = b[2];
        g->dst_vport = (uint16_t)(b[3] << 8 | b[4]); g->src_port = (uint16_t)(b[5] << 8 | b[6]);
        g->src_vport = (uint16_t)(b[7] << 8 | b[8]); g->type = b[9];
        g->seq = (uint32_t)b[10] << 24 | (uint32_t)b[11] << 16 | (uint32_t)b[12] << 8 | b[13];
        g->len = n - 14;
        memcpy(g->data, b + 14, (size_t)g->len);
        return 0;
    }
    return -1;
}

/* PSP sockaddr_in at a: port, IPv4 (host order), vport. */
static void put_addr(uint32_t a, uint16_t port, uint32_t ip, uint16_t vport) {
    uint8_t b[16];
    memset(b, 0, sizeof b);
    b[0] = 16; b[1] = 2;
    b[2] = (uint8_t)(port >> 8); b[3] = (uint8_t)port;
    b[4] = (uint8_t)(ip >> 24); b[5] = (uint8_t)(ip >> 16); b[6] = (uint8_t)(ip >> 8); b[7] = (uint8_t)ip;
    b[8] = (uint8_t)(vport >> 8); b[9] = (uint8_t)vport;
    psp_mem_write_block(a, b, 16);
}

static void set_nbio(uint32_t fd) {
    psp_write32(G + 0x100, 1);
    call("sceNetInetSetsockopt", fd, 0xFFFF, 0x1009, G + 0x100, 4, 0);
}

static void test_server_check(void) {
    psp_p2p_start(0x7F000001u, SERVER_PORT, 0x1234, "alice");
    CHECK(p2p_active(), "the shared port is open");
    p2p_pump();
    uint8_t b[64];
    struct sockaddr_in from;
    const int n = recv_from(g_server, b, sizeof b, &from);
    CHECK(n == 13 && b[0] == 1 && b[1] == 0x34 && b[2] == 0x12 && b[3] == 0, "address check: 13 bytes, 1, user ID (got %d)", n);
    CHECK(ntohs(from.sin_port) == 3658, "address check sent from port 3658 (got %u)", ntohs(from.sin_port));
    /* the server's answer: [0 0 0] ip port(BE) */
    const uint8_t ans[9] = { 0, 0, 0, 203, 0, 113, 7, 0x0E, 0x4A };
    sendto(g_server, (const char *)ans, 9, 0, (struct sockaddr *)&from, sizeof from);
    p2p_pump();
}

static void test_signaling(void) {
    uint8_t b[2048];
    psp_p2p_room_member(5, 2, "bob");
    psp_p2p_connect(5, 2, PEER_IP, PEER_PORT);
    CHECK(peer_expect_sig(0x25, b) == 75, "CONNECT reaches the peer");
    CHECK(!memcmp(b + 3, "SIGN", 4) && b[7] == 4, "signature 'SIGN', version 4");
    CHECK(b[31] == 127 && b[32] == 0 && b[33] == 0 && b[34] == 2, "sent_addr = the peer's address, network order");
    CHECK((b[35] | b[36] << 8) == PEER_PORT, "sent_port = the peer's port, little-endian host order");
    CHECK(!memcmp(b + 37, "alice", 6), "our NpId at offset 34");
    uint32_t ip = 0; uint16_t port = 0;
    CHECK(p2p_conn_status(5, 2, &ip, &port) == 1, "pending until answered");
    const uint64_t ts = (uint64_t)b[11] | (uint64_t)b[12] << 8 | (uint64_t)b[13] << 16 | (uint64_t)b[14] << 24;
    peer_sig(0x26, ts, 777);                           /* CONNECT_ACK, from an all-zero NpId */
    p2p_pump();
    CHECK(p2p_conn_status(5, 2, &ip, &port) == 2, "active after CONNECT_ACK");
    CHECK(ip == htonl(PEER_IP) && port == PEER_PORT, "the peer's address and port");
    CHECK(p2p_is_peer(htonl(PEER_IP)), "traffic to the peer takes the P2P route");
    CHECK(peer_expect_sig(0x27, b) == 75, "CONFIRM after CONNECT_ACK");
    CHECK((b[19] | b[20] << 8) == 777, "CONFIRM echoes the receiver timestamp");
    /* the peer's own handshake */
    peer_sig(0x25, 4242, 0);
    p2p_pump();
    CHECK(peer_expect_sig(0x26, b) == 75, "CONNECT_ACK to the peer's CONNECT");
    CHECK((b[11] | b[12] << 8) == 4242, "CONNECT_ACK echoes the sender timestamp");
    peer_sig(0x27, 0, 0);
    peer_sig(0x23, 99, 0);                             /* PING */
    p2p_pump();
    CHECK(peer_expect_sig(0x24, b) == 75 && b[11] == 99, "PONG echoes the PING's timestamp");
}

static void test_stream_connect(void) {
    gpkt g;
    const uint32_t fd = call("sceNetInetSocket", 2, 10, 0, 0, 0, 0);
    CHECK((int)fd > 0, "type 10 socket");
    set_nbio(fd);
    put_addr(G, 12000, PEER_IP, PEER_PORT);
    CHECK(call("sceNetInetConnect", fd, G, 16, 0, 0, 0) == 0xFFFFFFFFu && inet_errno() == 119, "non-blocking connect: EINPROGRESS");
    CHECK(peer_expect_game(&g) == 0, "SYN reaches the peer at the address's vport");
    CHECK(g.dst_port == 12000 && g.flags == 0x82 && g.dst_vport == PEER_PORT && g.type == 10 && g.seq == 1,
          "SYN|TCP to port 12000, vport %u, seq 1 (got port %u flags 0x%02X vport %u type %u seq %u)", PEER_PORT,
          g.dst_port, g.flags, g.dst_vport, g.type, g.seq);
    CHECK(g.src_vport == PEER_PORT && g.len == 2 && g.data[0] == (PEER_PORT >> 8) && g.data[1] == (PEER_PORT & 255),
          "SYN payload: the vport");
    const uint16_t eph = g.src_port;
    peer_game(eph, 0x92, PEER_PORT, 12000, PEER_PORT, 10, 1, NULL, 0);       /* SYN|ACK */
    p2p_pump();
    CHECK(peer_expect_game(&g) == 0 && g.flags == 0x90 && g.seq == 2 && g.dst_port == 12000 && g.src_port == eph,
          "ACK|TCP seq 2 completes the handshake (got flags 0x%02X seq %u port %u)", g.flags, g.seq, g.dst_port);
    /* select: writable now */
    for (int i = 0; i < 8; i++) psp_write32(G + 0x40 + 4u * (uint32_t)i, 0);
    psp_write32(G + 0x40 + 4 * (fd >> 5), 1u << (fd & 31));
    psp_write32(G + 0x80, 0); psp_write32(G + 0x84, 0);
    CHECK(call("sceNetInetSelect", fd + 1, 0, G + 0x40, 0, G + 0x80, 0) == 1, "select: writable when established");
    psp_mem_write_block(G + 0x200, "hello", 5);
    CHECK(call("sceNetInetSend", fd, G + 0x200, 5, 0, 0, 0) == 5, "send");
    CHECK(peer_expect_game(&g) == 0 && g.flags == 0x88 && g.seq == 3 && g.len == 5 && !memcmp(g.data, "hello", 5), "PSH|TCP seq 3 'hello'");
    peer_game(eph, 0x98, PEER_PORT, 12000, PEER_PORT, 10, 3, NULL, 0);       /* its acknowledgement */
    peer_game(eph, 0x88, PEER_PORT, 12000, PEER_PORT, 10, 3, "rld!", 4);    /* out of order */
    peer_game(eph, 0x88, PEER_PORT, 12000, PEER_PORT, 10, 2, "wo", 2);
    p2p_pump();
    char got[16] = "";
    const uint32_t n = call("sceNetInetRecv", fd, G + 0x300, 16, 0, 0, 0);
    psp_mem_read_block(got, G + 0x300, n < 16 ? n : 15);
    CHECK(n == 6 && !memcmp(got, "world!", 6), "recv joins the stream in order (got %d)", (int)n);
    CHECK(peer_expect_game(&g) == 0 && g.flags == 0x98 && g.seq == 3, "PSH|ACK echoes the received number");
    CHECK(peer_expect_game(&g) == 0 && g.flags == 0x98 && g.seq == 2, "... for each packet");
    call("sceNetInetClose", fd, 0, 0, 0, 0, 0);
}

static void test_stream_accept(void) {
    gpkt g;
    const uint32_t fd = call("sceNetInetSocket", 2, 10, 0, 0, 0, 0);
    set_nbio(fd);
    put_addr(G, 12039, 0, PEER_PORT);
    CHECK(call("sceNetInetBind", fd, G, 16, 0, 0, 0) == 0, "bind 12039");
    CHECK(call("sceNetInetListen", fd, 8, 0, 0, 0, 0) == 0, "listen");
    CHECK(call("sceNetInetAccept", fd, G + 0x20, G + 0x30, 0, 0, 0) == 0xFFFFFFFFu && inet_errno() == 11, "nothing to accept yet");
    const uint8_t vp[2] = { PEER_PORT >> 8, PEER_PORT & 255 };
    peer_game(12039, 0x82, PEER_PORT, 50000, PEER_PORT, 10, 1, vp, 2);       /* SYN */
    p2p_pump();
    CHECK(peer_expect_game(&g) == 0 && g.flags == 0x92 && g.dst_port == 50000 && g.src_port == 12039 && g.seq == 1,
          "SYN|ACK from the listener's port to the connector's");
    peer_game(12039, 0x90, PEER_PORT, 50000, PEER_PORT, 10, 2, NULL, 0);     /* ACK */
    p2p_pump();
    psp_write32(G + 0x30, 16);
    const uint32_t c = call("sceNetInetAccept", fd, G + 0x20, G + 0x30, 0, 0, 0);
    CHECK((int)c > 0 && c != 0xFFFFFFFFu, "accept the player-to-player connection");
    CHECK(psp_read8(G + 0x22) == 50000 >> 8 && psp_read8(G + 0x23) == (50000 & 255) && psp_read8(G + 0x24) == 127 &&
          psp_read8(G + 0x27) == 2 && psp_read8(G + 0x28) == (PEER_PORT >> 8), "accept: the peer's address, port and vport");
    peer_game(12039, 0x88, PEER_PORT, 50000, PEER_PORT, 10, 3, "ping", 4);
    p2p_pump();
    char got[8] = "";
    CHECK(call("sceNetInetRecv", c, G + 0x300, 8, 0x80, 0, 0) == 4, "recv on the accepted socket");
    psp_mem_read_block(got, G + 0x300, 4);
    CHECK(!memcmp(got, "ping", 4), "'ping'");
    CHECK(peer_expect_game(&g) == 0 && g.flags == 0x98 && g.seq == 3, "acknowledged");
    psp_mem_write_block(G + 0x200, "pong", 4);
    CHECK(call("sceNetInetSend", c, G + 0x200, 4, 0, 0, 0) == 4, "send on the accepted socket");
    CHECK(peer_expect_game(&g) == 0 && g.flags == 0x88 && g.seq == 2 && g.dst_port == 50000 && !memcmp(g.data, "pong", 4),
          "PSH|TCP seq 2 after the SYN|ACK");
    call("sceNetInetClose", c, 0, 0, 0, 0, 0);
    call("sceNetInetClose", fd, 0, 0, 0, 0, 0);
}

static void test_datagram(void) {
    gpkt g;
    const uint32_t fd = call("sceNetInetSocket", 2, 6, 0, 0, 0, 0);
    set_nbio(fd);
    psp_write32(G + 0x100, 1);
    call("sceNetInetSetsockopt", fd, 0xFFFF, 0x1000, G + 0x100, 4, 0);
    put_addr(G, 3658, 0, 0x0102);
    CHECK(call("sceNetInetBind", fd, G, 16, 0, 0, 0) == 0, "bind the shared port 3658 (virtual)");
    put_addr(G + 0x20, PEER_PORT, PEER_IP, 0x0304);
    psp_mem_write_block(G + 0x200, "dgram", 5);
    CHECK(call("sceNetInetSendto", fd, G + 0x200, 5, 0, G + 0x20, 16) == 5, "sendto the peer");
    CHECK(peer_expect_game(&g) == 0 && g.dst_port == PEER_PORT && g.flags == 0x08 && g.dst_vport == 0x0304 &&
          g.src_port == 3658 && g.src_vport == 0x0102 && g.type == 6 && g.seq == 1 && !memcmp(g.data, "dgram", 5),
          "PSH datagram with both vports (got port %u flags 0x%02X dvport %04X sport %u svport %04X type %u seq %u)",
          g.dst_port, g.flags, g.dst_vport, g.src_port, g.src_vport, g.type, g.seq);
    peer_game(3658, 0x08, 0x0102, PEER_PORT, 0x0304, 6, 1, "back", 4);
    peer_game(3658, 0x08, 0xFFFF, PEER_PORT, 0x0304, 6, 2, "any", 3);         /* to every socket of the port */
    peer_game(3658, 0x08, 0x0102, PEER_PORT, 0x0304, 2, 3, "other", 5);       /* another socket type: not ours */
    p2p_pump();
    psp_write32(G + 0x30, 16);
    CHECK(call("sceNetInetRecvfrom", fd, G + 0x300, 64, 0, G + 0x20, G + 0x30) == 4, "recvfrom");
    CHECK(psp_read8(G + 0x24) == 127 && psp_read8(G + 0x27) == 2 && psp_read8(G + 0x22) == (PEER_PORT >> 8) &&
          psp_read8(G + 0x28) == 0x03 && psp_read8(G + 0x29) == 0x04, "from: the peer's address, port and vport");
    CHECK(call("sceNetInetRecvfrom", fd, G + 0x300, 64, 0, 0, 0) == 3, "a datagram for any vport");
    CHECK(call("sceNetInetRecvfrom", fd, G + 0x300, 64, 0, 0, 0) == 0xFFFFFFFFu && inet_errno() == 11, "nothing for another type");
    call("sceNetInetClose", fd, 0, 0, 0, 0, 0);
}

static void test_finished(void) {
    uint8_t b[2048];
    peer_sig(0x28, 0, 0);                              /* FINISHED */
    p2p_pump();
    CHECK(peer_expect_sig(0x29, b) == 75, "FINISHED_ACK");
    uint32_t ip; uint16_t port;
    CHECK(p2p_conn_status(5, 2, &ip, &port) == 1 && !p2p_is_peer(htonl(PEER_IP)), "connection ended by the peer");
}

int main(void) {
#ifdef _WIN32
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);
#endif
    CHECK(psp_mem_init() == 0, "memory init");
    psp_cpu_reset();
    psp_cpu.r[PSP_REG_SP] = 0x08810000u;
    psp_hle_init();
    g_peer = udp_at(PEER_IP, PEER_PORT);
    g_server = udp_at(0x7F000001u, SERVER_PORT);
    hsock probe = udp_at(0, 3658);
    if (g_peer == (hsock)-1 || g_server == (hsock)-1 || probe == (hsock)-1) {
        printf("SKIP: UDP port 3658, %u or 127.0.0.2:%u is in use\n", SERVER_PORT, PEER_PORT);
        return 0;
    }
    close_sock(probe);

    test_server_check();
    test_signaling();
    test_stream_connect();
    test_stream_accept();
    test_datagram();
    test_finished();
    psp_p2p_stop();
    psp_mem_free();

    if (failures) { printf("\n%d check(s) failed\n", failures); return 1; }
    printf("all player-to-player checks passed\n");
    return 0;
}
