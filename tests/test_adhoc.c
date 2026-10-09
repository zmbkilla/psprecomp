/* Ad hoc tests: adhoc.c and adhoc_matching.c against a fake ad hoc server
 * (127.0.0.1:47312), a fake relay (127.0.0.1:47313) and a fake player "bob"
 * at 127.0.0.2, all speaking PPSSPP's formats (Komak57/ppsspp master,
 * proAdhoc.h, sceNetAdhoc*.cpp; aemu_postoffice_packets.h). Covers both
 * connection options: PPSSPP style direct (port offset 10000) and relayed,
 * and modern (adhoc_mesh.c: STUN, candidates through the relay mailbox, hole
 * punching, PDP and reliable PTP over UDP). Skipped if the ports are taken. */

#include "psprecomp/hle.h"
#include "psprecomp/dispatch.h"
#include "psprecomp/net.h"
#include "crypto/sha1.h"
#include "adhoc.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
typedef SOCKET hsock;
#  define close_sock closesocket
#  define nap5() Sleep(5)
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
typedef int hsock;
#  define close_sock close
#  define nap5() usleep(5000)
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

static uint32_t call(const char *name, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3, uint32_t t0, uint32_t t1, uint32_t t2, uint32_t t3) {
    psp_cpu.r[PSP_REG_A0] = a0; psp_cpu.r[PSP_REG_A1] = a1; psp_cpu.r[PSP_REG_A2] = a2; psp_cpu.r[PSP_REG_A3] = a3;
    psp_cpu.r[PSP_REG_T0] = t0; psp_cpu.r[PSP_REG_T1] = t1; psp_cpu.r[PSP_REG_T2] = t2; psp_cpu.r[PSP_REG_T3] = t3;
    psp_hle_call(psp_nid(name));
    return psp_cpu.r[PSP_REG_V0];
}
#define C0(n) call(n, 0, 0, 0, 0, 0, 0, 0, 0)

#define G 0x08900000u
#define BOB_IP 0x7F000002u
static const uint8_t BOB[6] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t HOSTMAC[6] = { 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE };
#define WRONG_PORT_NEVER 0

static hsock tcp_listen(uint32_t ip, uint16_t port) {
    hsock s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(ip); a.sin_port = htons(port);
    const int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 8) != 0) { close_sock(s); return (hsock)-1; }
    return s;
}
static hsock udp_at(uint32_t ip, uint16_t port) {
    hsock s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(ip); a.sin_port = htons(port);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) { close_sock(s); return (hsock)-1; }
    return s;
}
static int readable(hsock s, int ms) {
    fd_set r;
    FD_ZERO(&r); FD_SET(s, &r);
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    return select((int)s + 1, &r, NULL, NULL, &tv) > 0;
}
static hsock accept_one(hsock l) {
    for (int i = 0; i < 100; i++) { adhoc_pump(); if (readable(l, 20)) return accept(l, NULL, NULL); }
    return (hsock)-1;
}
/* Read exactly n bytes (pumping the library meanwhile); n on success. */
static int read_n(hsock s, uint8_t *b, int n) {
    int got = 0;
    for (int i = 0; i < 200 && got < n; i++) {
        adhoc_pump();
        if (!readable(s, 10)) continue;
        const int k = recv(s, (char *)b + got, n - got, 0);
        if (k <= 0) break;
        got += k;
    }
    return got;
}
/* Real sleeps: select() with no sockets fails at once on Windows. */
static void pump_ms(int ms) { for (int i = 0; i < ms / 5; i++) { adhoc_pump(); nap5(); } }

/* Server side: answer a group join with bob's details and the BSSID. */
static void server_join(hsock srv) {
    uint8_t p[139];
    memset(p, 0, sizeof p);
    p[0] = 2;                                          /* CONNECT {nickname[128], mac, ip} */
    memcpy(p + 1, "bob", 3);
    memcpy(p + 129, BOB, 6);
    const uint32_t ip = htonl(BOB_IP);
    memcpy(p + 135, &ip, 4);
    send(srv, (const char *)p, sizeof p, 0);
    uint8_t b[7] = { 6 };                              /* CONNECT_BSSID */
    memcpy(b + 1, HOSTMAC, 6);
    send(srv, (const char *)b, 7, 0);
}

/* AdhocInit, AdhocctlInit (login) and Create(group): the session for one mode. */
static hsock start_session(hsock ls, const char *mode) {
    CHECK(C0("sceNetAdhocInit") == 0, "%s: AdhocInit", mode);
    psp_write32(G + 0x100, 0);
    psp_mem_write_block(G + 0x104, "NPJH50332", 9);
    CHECK(call("sceNetAdhocctlInit", 0x2000, 0x30, G + 0x100, 0, 0, 0, 0, 0) == 0, "%s: AdhocctlInit", mode);
    hsock srv = accept_one(ls);
    CHECK(srv != (hsock)-1, "%s: the library connects to the server", mode);
    uint8_t login[144];
    CHECK(read_n(srv, login, 144) == 144 && login[0] == 1, "%s: LOGIN, 144 bytes", mode);
    uint8_t mac[6];
    adhoc_local_mac(mac);
    CHECK(!memcmp(login + 1, mac, 6) && (mac[0] & 3) == 0, "%s: our MAC, low bits of byte 0 clear", mode);
    CHECK(!memcmp(login + 7, "alice", 6), "%s: nickname at 7", mode);
    CHECK(!memcmp(login + 135, "NPJH50332", 9), "%s: product code at 135", mode);
    psp_mem_write_block(G + 0x120, "PSP2i001", 8);
    CHECK(call("sceNetAdhocctlCreate", G + 0x120, 0, 0, 0, 0, 0, 0, 0) == 0, "%s: Create", mode);
    uint8_t conn[9];
    CHECK(read_n(srv, conn, 9) == 9 && conn[0] == 2 && !memcmp(conn + 1, "PSP2i001", 8), "%s: CONNECT with the group name", mode);
    server_join(srv);
    for (int i = 0; i < 50; i++) {
        pump_ms(10);
        psp_write32(G + 0x130, 9);
        call("sceNetAdhocctlGetState", G + 0x130, 0, 0, 0, 0, 0, 0, 0);
        if (psp_read32(G + 0x130) == 1) break;
    }
    CHECK(psp_read32(G + 0x130) == 1, "%s: connected to the group", mode);
    psp_write32(G + 0x140, 152 * 4);
    CHECK(call("sceNetAdhocctlGetPeerList", G + 0x140, G + 0x200, 0, 0, 0, 0, 0, 0) == 0 && psp_read32(G + 0x140) == 152,
          "%s: one peer", mode);
    uint8_t pm[6];
    psp_mem_read_block(pm, G + 0x200 + 132, 6);
    char nick[8];
    psp_mem_read_block(nick, G + 0x200 + 4, 4);
    CHECK(!memcmp(pm, BOB, 6) && !memcmp(nick, "bob", 4), "%s: bob, with his MAC", mode);
    return srv;
}

static void test_direct(hsock ls) {
    hsock srv = start_session(ls, "direct");
    /* PDP: port 3000 -> UDP 13000 */
    const uint32_t pdp = call("sceNetAdhocPdpCreate", G + 0x300, 3000, 2048, 0, 0, 0, 0, 0);
    CHECK((int)pdp > 0, "pdp create");
    hsock bobu = udp_at(BOB_IP, 13001);
    struct sockaddr_in to;
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET; to.sin_addr.s_addr = htonl(0x7F000001u); to.sin_port = htons(13000);
    sendto(bobu, "hello", 5, 0, (struct sockaddr *)&to, sizeof to);
    pump_ms(100);
    psp_write32(G + 0x310, 64);
    const uint32_t r = call("sceNetAdhocPdpRecv", pdp, G + 0x320, G + 0x330, G + 0x340, G + 0x310, 0, 1, 0);
    uint8_t m[6];
    psp_mem_read_block(m, G + 0x320, 6);
    CHECK(r == 0 && psp_read32(G + 0x310) == 5 && !memcmp(m, BOB, 6) && psp_read16(G + 0x330) == 3001,
          "pdp recv: bob's MAC, his port minus the offset (r 0x%08X len %u port %u)", r, psp_read32(G + 0x310), psp_read16(G + 0x330));
    psp_mem_write_block(G + 0x350, BOB, 6);
    psp_mem_write_block(G + 0x360, "pong", 4);
    CHECK(call("sceNetAdhocPdpSend", pdp, G + 0x350, 3001, G + 0x360, 4, 0, 1, 0) == 0, "pdp send");
    uint8_t b[64];
    struct sockaddr_in from;
    socklen_t fl = sizeof from;
    CHECK(readable(bobu, 500) && recvfrom(bobu, (char *)b, 64, 0, (struct sockaddr *)&from, &fl) == 4 && !memcmp(b, "pong", 4) &&
          ntohs(from.sin_port) == 13000, "pdp: raw datagram to bob's port + offset, from ours");
    /* PTP open/connect: bob listens on 4000 + offset */
    hsock bobl = tcp_listen(BOB_IP, 14000);
    psp_mem_write_block(G + 0x370, BOB, 6);
    const uint32_t ptp = call("sceNetAdhocPtpOpen", G + 0x380, 0, G + 0x370, 4000, 8192, 200000, 5, 0);
    CHECK((int)ptp > 0, "ptp open");
    hsock bobc = accept_one(bobl);
    CHECK(bobc != (hsock)-1, "ptp: TCP to bob's port + offset");
    uint32_t cr = 0;
    for (int i = 0; i < 50 && (cr = call("sceNetAdhocPtpConnect", ptp, 0, 1, 0, 0, 0, 0, 0)) != 0; i++) pump_ms(10);
    CHECK(cr == 0, "ptp connect (0x%08X)", cr);
    psp_mem_write_block(G + 0x390, "abc", 3);
    psp_write32(G + 0x394, 3);
    CHECK(call("sceNetAdhocPtpSend", ptp, G + 0x390, G + 0x394, 0, 1, 0, 0, 0) == 0, "ptp send");
    CHECK(read_n(bobc, b, 3) == 3 && !memcmp(b, "abc", 3), "ptp: plain stream bytes");
    send(bobc, "xy", 2, 0);
    pump_ms(20);
    psp_write32(G + 0x3A0, 16);
    CHECK(call("sceNetAdhocPtpRecv", ptp, G + 0x3B0, G + 0x3A0, 0, 1, 0, 0, 0) == 0 && psp_read32(G + 0x3A0) == 2, "ptp recv");
    /* PTP listen/accept: port 5000 -> TCP 15000, bob connects from 127.0.0.2 */
    const uint32_t lid = call("sceNetAdhocPtpListen", G + 0x3C0, 5000, 8192, 200000, 5, 2, 0, 0);
    CHECK((int)lid > 0, "ptp listen");
    hsock bobo = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in ba;
    memset(&ba, 0, sizeof ba);
    ba.sin_family = AF_INET; ba.sin_addr.s_addr = htonl(BOB_IP); ba.sin_port = htons(16001);
    bind(bobo, (struct sockaddr *)&ba, sizeof ba);
    to.sin_port = htons(15000);
    CHECK(connect(bobo, (struct sockaddr *)&to, sizeof to) == 0, "bob connects to port 5000 + offset");
    uint32_t aid = 0;
    for (int i = 0; i < 50; i++) { aid = call("sceNetAdhocPtpAccept", lid, G + 0x3D0, G + 0x3E0, 0, 1, 0, 0, 0); if ((int)aid > 0) break; pump_ms(10); }
    psp_mem_read_block(m, G + 0x3D0, 6);
    CHECK((int)aid > 0 && !memcmp(m, BOB, 6) && psp_read16(G + 0x3E0) == 6001, "ptp accept: bob, port minus offset (%u)", psp_read16(G + 0x3E0));

    /* Matching (parent): hello to bob, his JOIN, our accept. */
    CHECK(C0("sceNetAdhocMatchingInit") == 0, "matching init");
    psp_write32(psp_cpu.r[PSP_REG_SP], 0x08801000u);   /* ninth argument: the callback */
    const uint32_t mid = call("sceNetAdhocMatchingCreate", 1, 4, 6000, 2048, 200000, 200000, 3, 50000);
    CHECK((int)mid > 0, "matching create");
    /* Both "players" share this host, so bob uses another port (26000); the
     * library answers wherever a peer was last heard from, as the reference. */
    hsock bobm = udp_at(BOB_IP, 26000);
    psp_mem_write_block(G + 0x400, "ROOM", 4);
    CHECK(call("sceNetAdhocMatchingStart", mid, 0x30, 0x2000, 0x30, 0x2000, 4, G + 0x400, 0) == 0, "matching start");
    to.sin_port = htons(16000);
    const uint8_t ping = 0;
    sendto(bobm, (const char *)&ping, 1, 0, (struct sockaddr *)&to, sizeof to);
    int n = 0, hello = 0;
    for (int i = 0; i < 20 && !hello; i++) {
        pump_ms(50);
        while (readable(bobm, 0)) {
            n = recvfrom(bobm, (char *)b, 64, 0, (struct sockaddr *)&from, &fl);
            if (n == 9 && b[0] == 1 && b[1] == 4 && !memcmp(b + 5, "ROOM", 4) && ntohs(from.sin_port) == 16000) hello = 1;
        }
    }
    CHECK(hello, "HELLO {1, s32 4, ROOM} from port 6000 + offset");
    const uint8_t join[5] = { 2, 0, 0, 0, 0 };
    sendto(bobm, (const char *)join, 5, 0, (struct sockaddr *)&to, sizeof to);
    pump_ms(50);
    psp_mem_write_block(G + 0x410, BOB, 6);
    CHECK(call("sceNetAdhocMatchingSelectTarget", mid, G + 0x410, 0, 0, 0, 0, 0, 0) == 0, "accept bob's request");
    pump_ms(50);
    int got_accept = 0;
    for (int i = 0; i < 10 && readable(bobm, 100); i++) {
        n = recvfrom(bobm, (char *)b, 64, 0, NULL, NULL);
        if (n == 9 && b[0] == 3 && !b[1] && !b[5]) got_accept = 1;
    }
    CHECK(got_accept, "ACCEPT {3, optlen 0, siblings 0}");
    C0("sceNetAdhocMatchingTerm");
    C0("sceNetAdhocTerm");
    close_sock(srv); close_sock(bobu); close_sock(bobl); close_sock(bobc); close_sock(bobo); close_sock(bobm);
}

static void test_relay(hsock ls, hsock rl) {
    hsock srv = start_session(ls, "relay");
    const uint32_t pdp = call("sceNetAdhocPdpCreate", G + 0x300, 3000, 2048, 0, 0, 0, 0, 0);
    CHECK((int)pdp > 0, "relay: pdp create");
    hsock r1 = accept_one(rl);
    uint8_t init[24], b[64];
    CHECK(r1 != (hsock)-1 && read_n(r1, init, 24) == 24, "relay: a TCP session with a 24-byte init");
    uint8_t mac[6];
    adhoc_local_mac(mac);
    CHECK(init[0] == 0 && !memcmp(init + 4, mac, 6) && (init[12] | init[13] << 8) == 13000, "relay: PDP init {0, our MAC, port 13000}");
    psp_mem_write_block(G + 0x350, BOB, 6);
    psp_mem_write_block(G + 0x360, "ping!", 5);
    CHECK(call("sceNetAdhocPdpSend", pdp, G + 0x350, 3001, G + 0x360, 5, 0, 1, 0) == 0, "relay: pdp send");
    CHECK(read_n(r1, b, 19) == 19 && !memcmp(b, BOB, 6) && (b[8] | b[9] << 8) == 13001 && b[10] == 5 && !memcmp(b + 14, "ping!", 5),
          "relay: PDP frame {bob, 13001, 5, data}");
    uint8_t fr[18];
    memset(fr, 0, sizeof fr);
    memcpy(fr, BOB, 6);
    fr[8] = 13001 & 255; fr[9] = 13001 >> 8; fr[10] = 4;
    memcpy(fr + 14, "pong", 4);
    send(r1, (const char *)fr, 18, 0);
    pump_ms(100);
    psp_write32(G + 0x310, 64);
    const uint32_t r = call("sceNetAdhocPdpRecv", pdp, G + 0x320, G + 0x330, G + 0x340, G + 0x310, 0, 1, 0);
    uint8_t m[6];
    psp_mem_read_block(m, G + 0x320, 6);
    CHECK(r == 0 && psp_read32(G + 0x310) == 4 && !memcmp(m, BOB, 6) && psp_read16(G + 0x330) == 3001, "relay: pdp recv (0x%08X)", r);
    /* PTP connect through the relay */
    psp_mem_write_block(G + 0x370, BOB, 6);
    const uint32_t ptp = call("sceNetAdhocPtpOpen", G + 0x380, 0, G + 0x370, 4000, 8192, 200000, 5, 0);
    hsock r2 = accept_one(rl);
    CHECK(r2 != (hsock)-1 && read_n(r2, init, 24) == 24 && init[0] == 2 && !memcmp(init + 14, BOB, 6) &&
          (init[22] | init[23] << 8) == 14000, "relay: PTP connect init {2, ..., bob, 14000}");
    uint8_t ack[10];
    memset(ack, 0, sizeof ack);
    memcpy(ack, BOB, 6);
    ack[8] = 14000 & 255; ack[9] = 14000 >> 8;
    send(r2, (const char *)ack, 10, 0);
    uint32_t cr = 0;
    for (int i = 0; i < 50 && (cr = call("sceNetAdhocPtpConnect", ptp, 0, 1, 0, 0, 0, 0, 0)) != 0; i++) pump_ms(10);
    CHECK(cr == 0, "relay: connected after the ack (0x%08X)", cr);
    psp_mem_write_block(G + 0x390, "xyz", 3);
    psp_write32(G + 0x394, 3);
    CHECK(call("sceNetAdhocPtpSend", ptp, G + 0x390, G + 0x394, 0, 1, 0, 0, 0) == 0, "relay: ptp send");
    CHECK(read_n(r2, b, 7) == 7 && b[0] == 3 && !b[1] && !memcmp(b + 4, "xyz", 3), "relay: PTP frame {u32 3, xyz}");
    const uint8_t f2[6] = { 2, 0, 0, 0, 'o', 'k' };
    send(r2, (const char *)f2, 6, 0);
    pump_ms(100);
    psp_write32(G + 0x3A0, 16);
    CHECK(call("sceNetAdhocPtpRecv", ptp, G + 0x3B0, G + 0x3A0, 0, 1, 0, 0, 0) == 0 && psp_read32(G + 0x3A0) == 2, "relay: ptp recv");
    C0("sceNetAdhocTerm");
    close_sock(srv); close_sock(r1); close_sock(r2);
}

/* ---- modern: bob speaks the mesh protocol by hand (adhoc_mesh.c) ---- */

#define BOB_MESH_PORT 47321
static struct sockaddr_in g_alice;                     /* where alice's mesh packets come from */
static int g_have_alice;

static int mhdr(uint8_t *b, int type) {
    b[0] = 'P'; b[1] = '2'; b[2] = 'I'; b[3] = 'M'; b[4] = 1; b[5] = (uint8_t)type;
    memcpy(b + 6, BOB, 6);
    return 12;
}
static void be32(uint8_t *b, uint32_t v) { b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v; }
static uint32_t rd32(const uint8_t *b) { return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3]; }
static void bob_udp(hsock bu, const uint8_t *p, int n) { sendto(bu, (const char *)p, n, 0, (struct sockaddr *)&g_alice, sizeof g_alice); }

/* Bob's next mesh packet of `type` over UDP (answering probes, skipping pings); its length or 0. */
static int bob_recv(hsock bu, int type, uint8_t *b, int cap, int ms) {
    for (int i = 0; i < ms / 5; i++) {
        adhoc_pump();
        while (readable(bu, 0)) {
            struct sockaddr_in from;
            socklen_t fl = sizeof from;
            const int n = recvfrom(bu, (char *)b, cap, 0, (struct sockaddr *)&from, &fl);
            if (n < 12 || memcmp(b, "P2IM", 4)) continue;
            g_alice = from;
            g_have_alice = 1;
            if (b[5] == 2) {                                /* PROBE {dst MAC, nonce}: PROBE_ACK */
                uint8_t a[24];
                int o = mhdr(a, 3);
                memcpy(a + o, b + 6, 6);
                memcpy(a + o + 6, b + 18, 4);
                bob_udp(bu, a, o + 10);
                if (type == 2) return n;
                continue;
            }
            if (b[5] == type) return n;
        }
        nap5();
    }
    return 0;
}

/* The next relay frame to bob's mailbox carrying a mesh packet of `type`; its payload length or 0. */
static int mailbox_recv(hsock r, int type, uint8_t *b, int cap) {
    for (int k = 0; k < 40; k++) {
        uint8_t h[14];
        if (read_n(r, h, 14) != 14) return 0;
        uint32_t sz;
        memcpy(&sz, h + 10, 4);
        if (sz > (uint32_t)cap || read_n(r, b, (int)sz) != (int)sz) return 0;
        if (memcmp(h, BOB, 6) || (h[8] | h[9] << 8) != 65534) continue;
        if (sz >= 12 && b[5] == type) return (int)sz;
    }
    return 0;
}

static void test_modern(hsock ls, hsock rl) {
    hsock stun = udp_at(0x7F000001u, 47314), bu = udp_at(BOB_IP, BOB_MESH_PORT);
    if (stun == (hsock)-1 || bu == (hsock)-1) { printf("SKIP modern: test ports in use\n"); return; }
    hsock srv = start_session(ls, "modern");
    uint8_t mac[6], b[2048], init[24];
    adhoc_local_mac(mac);
    hsock mb = accept_one(rl);
    CHECK(mb != (hsock)-1 && read_n(mb, init, 24) == 24 && init[0] == 0 && !memcmp(init + 4, mac, 6) && (init[12] | init[13] << 8) == 65534,
          "modern: a relay mailbox {PDP, our MAC, port 65534}");
    /* STUN: answer the binding request with XOR-MAPPED-ADDRESS 203.0.113.7:40000 */
    int got_stun = 0;
    for (int i = 0; i < 200 && !got_stun; i++) {
        adhoc_pump();
        if (!readable(stun, 5)) continue;
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        const int n = recvfrom(stun, (char *)b, sizeof b, 0, (struct sockaddr *)&from, &fl);
        if (n != 20 || b[0] != 0 || b[1] != 1 || rd32(b + 4) != 0x2112A442u) continue;
        uint8_t r[32];
        r[0] = 1; r[1] = 1; r[2] = 0; r[3] = 12;
        memcpy(r + 4, b + 4, 16);
        r[20] = 0; r[21] = 0x20; r[22] = 0; r[23] = 8;
        r[24] = 0; r[25] = 1;
        r[26] = (uint8_t)((40000 ^ 0x2112) >> 8); r[27] = (uint8_t)((40000 ^ 0x2112) & 255);
        r[28] = 203 ^ 0x21; r[29] = 0 ^ 0x12; r[30] = 113 ^ 0xA4; r[31] = 7 ^ 0x42;
        sendto(stun, (const char *)r, 32, 0, (struct sockaddr *)&from, fl);
        got_stun = 1;
    }
    CHECK(got_stun, "modern: a STUN binding request");
    /* alice's candidates reach bob's mailbox, the STUN one among them */
    int srflx = 0;
    for (int k = 0; k < 10 && !srflx; k++) {
        const int n = mailbox_recv(mb, 1, b, sizeof b);
        if (!n) break;
        CHECK(!memcmp(b + 6, mac, 6), "modern: CANDS from alice's MAC");
        for (int o = 17, i = 0; i < b[16] && o < n; i++) {
            if (b[o] == 4 && b[o + 1] == (40000 >> 8) && b[o + 2] == (40000 & 255) && b[o + 3] == 203 && b[o + 6] == 7) srflx = 1;
            o += 3 + (b[o] == 4 ? 4 : 16);
        }
    }
    CHECK(srflx, "modern: CANDS through the mailbox carry the STUN address 203.0.113.7:40000");
    /* before any direct path, PDP goes through the mailbox */
    const uint32_t pdp = call("sceNetAdhocPdpCreate", G + 0x300, 3000, 2048, 0, 0, 0, 0, 0);
    CHECK((int)pdp > 0, "modern: pdp create");
    psp_mem_write_block(G + 0x350, BOB, 6);
    psp_mem_write_block(G + 0x360, "early", 5);
    CHECK(call("sceNetAdhocPdpSend", pdp, G + 0x350, 3001, G + 0x360, 5, 0, 1, 0) == 0, "modern: pdp send");
    int n = mailbox_recv(mb, 10, b, sizeof b);
    CHECK(n == 21 && b[12] == 3000 >> 8 && b[13] == (3000 & 255) && b[14] == 3001 >> 8 && !memcmp(b + 16, "early", 5),
          "modern: no path yet -> PDP {3000, 3001, data} tunnelled through the relay");
    /* bob's candidates through the relay -> alice probes him -> direct path */
    uint8_t f[14 + 32];
    memset(f, 0, sizeof f);
    memcpy(f, BOB, 6);
    f[8] = 65534 & 255; f[9] = 65534 >> 8;
    uint8_t *c = f + 14;
    int o = mhdr(c, 1);
    be32(c + o, 0x1234); c[o + 4] = 1; o += 5;
    c[o] = 4; c[o + 1] = BOB_MESH_PORT >> 8; c[o + 2] = BOB_MESH_PORT & 255;
    c[o + 3] = 127; c[o + 4] = 0; c[o + 5] = 0; c[o + 6] = 2; o += 7;
    const uint32_t sz = (uint32_t)o;
    memcpy(f + 10, &sz, 4);
    send(mb, (const char *)f, 14 + o, 0);
    CHECK(bob_recv(bu, 2, b, sizeof b, 2000) && !memcmp(b + 12, BOB, 6), "modern: alice probes bob's candidate {dst = bob}");
    pump_ms(50);                                       /* alice takes bob's PROBE_ACK */
    /* PDP over the direct path */
    uint8_t p[64];
    o = mhdr(p, 10);
    p[o] = 3001 >> 8; p[o + 1] = 3001 & 255; p[o + 2] = 3000 >> 8; p[o + 3] = 3000 & 255;
    memcpy(p + o + 4, "hi", 2);
    bob_udp(bu, p, o + 6);
    pump_ms(50);
    psp_write32(G + 0x310, 64);
    uint32_t r = call("sceNetAdhocPdpRecv", pdp, G + 0x320, G + 0x330, G + 0x340, G + 0x310, 0, 1, 0);
    uint8_t m[6];
    psp_mem_read_block(m, G + 0x320, 6);
    CHECK(r == 0 && psp_read32(G + 0x310) == 2 && !memcmp(m, BOB, 6) && psp_read16(G + 0x330) == 3001, "modern: pdp recv from bob's port 3001 (0x%08X)", r);
    psp_mem_write_block(G + 0x360, "yo", 2);
    call("sceNetAdhocPdpSend", pdp, G + 0x350, 3001, G + 0x360, 2, 0, 1, 0);
    n = bob_recv(bu, 10, b, sizeof b, 500);
    CHECK(n == 18 && !memcmp(b + 16, "yo", 2), "modern: with a path, PDP goes straight to bob over UDP");
    /* PTP connect: SYN / SYNACK, DATA / ACK, retransmission */
    psp_mem_write_block(G + 0x370, BOB, 6);
    const uint32_t ptp = call("sceNetAdhocPtpOpen", G + 0x380, 0, G + 0x370, 4000, 8192, 200000, 5, 0);
    CHECK((int)ptp > 0, "modern: ptp open");
    n = bob_recv(bu, 20, b, sizeof b, 1000);
    CHECK(n == 20 && b[18] == 4000 >> 8 && b[19] == (4000 & 255), "modern: SYN to port 4000");
    const uint32_t conn = rd32(b + 12);
    o = mhdr(p, 21);
    be32(p + o, conn);
    bob_udp(bu, p, o + 4);
    uint32_t cr = 1;
    for (int i = 0; i < 50 && (cr = call("sceNetAdhocPtpConnect", ptp, 0, 1, 0, 0, 0, 0, 0)) != 0; i++) pump_ms(10);
    CHECK(cr == 0, "modern: connected after the SYNACK (0x%08X)", cr);
    psp_mem_write_block(G + 0x390, "abc", 3);
    psp_write32(G + 0x394, 3);
    CHECK(call("sceNetAdhocPtpSend", ptp, G + 0x390, G + 0x394, 0, 1, 0, 0, 0) == 0, "modern: ptp send");
    n = bob_recv(bu, 22, b, sizeof b, 500);
    CHECK(n == 24 && rd32(b + 12) == conn && b[16] == 1 && rd32(b + 17) == 0 && !memcmp(b + 21, "abc", 3), "modern: DATA {conn, dir 1, seq 0, abc}");
    n = bob_recv(bu, 22, b, sizeof b, 1500);
    CHECK(n == 24 && rd32(b + 17) == 0, "modern: unacknowledged DATA is sent again");
    o = mhdr(p, 23);
    be32(p + o, conn); p[o + 4] = 0; be32(p + o + 5, 3);
    bob_udp(bu, p, o + 9);
    o = mhdr(p, 22);
    be32(p + o, conn); p[o + 4] = 0; be32(p + o + 5, 0);
    memcpy(p + o + 9, "xy", 2);
    bob_udp(bu, p, o + 11);
    n = bob_recv(bu, 23, b, sizeof b, 500);
    CHECK(n == 21 && rd32(b + 12) == conn && b[16] == 1 && rd32(b + 17) == 2, "modern: ACK {conn, dir 1, next 2}");
    psp_write32(G + 0x3A0, 16);
    CHECK(call("sceNetAdhocPtpRecv", ptp, G + 0x3B0, G + 0x3A0, 0, 1, 0, 0, 0) == 0 && psp_read32(G + 0x3A0) == 2, "modern: ptp recv");
    n = bob_recv(bu, 22, b, sizeof b, 600);
    CHECK(!n, "modern: no resend once acknowledged");
    /* PTP listen / accept; a SYN to a port nobody listens on is refused */
    const uint32_t lid = call("sceNetAdhocPtpListen", G + 0x3C0, 5000, 8192, 200000, 5, 2, 0, 0);
    CHECK((int)lid > 0, "modern: ptp listen");
    o = mhdr(p, 20);
    be32(p + o, 77); p[o + 4] = 6001 >> 8; p[o + 5] = 6001 & 255; p[o + 6] = 5000 >> 8; p[o + 7] = 5000 & 255;
    bob_udp(bu, p, o + 8);
    n = bob_recv(bu, 21, b, sizeof b, 500);
    CHECK(n == 16 && rd32(b + 12) == 77, "modern: SYNACK to bob's SYN");
    uint32_t aid = 0;
    for (int i = 0; i < 50; i++) { aid = call("sceNetAdhocPtpAccept", lid, G + 0x3D0, G + 0x3E0, 0, 1, 0, 0, 0); if ((int)aid > 0) break; pump_ms(10); }
    psp_mem_read_block(m, G + 0x3D0, 6);
    CHECK((int)aid > 0 && !memcmp(m, BOB, 6) && psp_read16(G + 0x3E0) == 6001, "modern: ptp accept: bob, port 6001");
    p[o + 7] = 5999 & 255; p[o + 6] = 5999 >> 8; be32(p + o, 78);
    bob_udp(bu, p, o + 8);
    n = bob_recv(bu, 25, b, sizeof b, 500);
    CHECK(n == 17 && rd32(b + 12) == 78, "modern: RST for a port nobody listens on");
    C0("sceNetAdhocTerm");
    close_sock(srv); close_sock(mb); close_sock(stun); close_sock(bu);
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
    hsock ls = tcp_listen(0x7F000001u, 47312), rl = tcp_listen(0x7F000001u, 47313);
    if (ls == (hsock)-1 || rl == (hsock)-1) { printf("SKIP: test ports in use\n"); return 0; }
    psp_adhoc_config c;
    memset(&c, 0, sizeof c);
    c.server = "127.0.0.1"; c.server_port = 47312; c.relay_port = 47313;
    c.mode = PSP_ADHOC_MODE_PPSSPP_DIRECT; c.port_offset = 10000; c.nickname = "alice";
    psp_adhoc_configure(&c);
    test_direct(ls);
    c.mode = PSP_ADHOC_MODE_PPSSPP_RELAY;
    psp_adhoc_configure(&c);
    test_relay(ls, rl);
    c.mode = PSP_ADHOC_MODE_MODERN; c.stun_server = "127.0.0.1:47314"; c.mesh_port = 47320;
    psp_adhoc_configure(&c);
    test_modern(ls, rl);
    psp_mem_free();
    if (failures) { printf("\n%d check(s) failed\n", failures); return 1; }
    printf("all ad hoc checks passed\n");
    return 0;
}
