/* psprecomp — networking: WLAN driver, sceNet core, Apctl (access point
 * control), Resolver (DNS), Inet (address helpers; sockets not yet), UPnP and
 * the network-configuration dialog (sceUtilityNetconf).
 *
 * The PSP's network stack is not reproduced. Each firmware call is answered
 * from the host's own networking (the adapter list and DNS on Windows,
 * getifaddrs/getaddrinfo elsewhere):
 *
 *   - the WLAN "switch" is on when the host has a usable connection (an
 *     interface that is up, not loopback, with an IPv4 address and a default
 *     gateway) and off otherwise -- never a hard-coded success;
 *   - the Netconf dialog "connects" by checking that connection: success puts
 *     Apctl in GOT_IP (with the host's address, mask and gateway) and tells
 *     the game's Apctl handlers, failure ends the dialog with an error;
 *   - the resolver resolves names with the host's DNS (and logs them: the
 *     names a game looks up are how its servers are found).
 *
 * PSPRECOMP_NET=off makes the host look disconnected, for testing a game's
 * error paths. Status and error codes are the firmware's, so the game's own
 * error handling sees what a PSP would report. HTTP is in http.c. */

#include "psprecomp/hle.h"
#include "psprecomp/net.h"
#include "adhoc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <iphlpapi.h>
#else
#  include <ifaddrs.h>
#  include <net/if.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <sys/socket.h>
#endif

/* Firmware status codes used here. */
#define SCE_NET_APCTL_ERROR_ALREADY_INITIALIZED 0x80410A01u
#define SCE_NET_APCTL_ERROR_INVALID_CODE        0x80410A02u
#define SCE_NET_APCTL_ERROR_NOT_IN_BSS          0x80410A05u
#define SCE_NET_APCTL_ERROR_WLAN_SWITCH_OFF     0x80410A06u
#define SCE_NET_APCTL_ERROR_INVALID_ID          0x80410A09u
#define SCE_NET_INET_ERROR_ALREADY_INITIALIZED  0x80410201u
#define SCE_NET_RESOLVER_ERROR_INVALID_PTR      0x80410403u
#define SCE_NET_RESOLVER_ERROR_INVALID_ID       0x80410405u
#define SCE_NET_RESOLVER_ERROR_ID_MAX           0x80410406u
#define SCE_NET_RESOLVER_ERROR_NO_RECORD        0x80410411u
#define SCE_NET_RESOLVER_ERROR_INVALID_HOST     0x80410414u

enum { APCTL_DISCONNECTED = 0, APCTL_SCANNING, APCTL_JOINING, APCTL_GETTING_IP, APCTL_GOT_IP };
enum { APCTL_EV_CONNECT_REQUEST = 0, APCTL_EV_ESTABLISHED = 3, APCTL_EV_GET_IP = 4,
       APCTL_EV_DISCONNECT_REQUEST = 5, APCTL_EV_ERROR = 6 };

static void net_log(const char *fmt, ...);
void psp_net_sock_register(void);          /* net_sock.c */
void psp_net_sock_close_all(void);

/* ---- the host connection ---------------------------------------------------- */

static int g_forced_off = -1;

static void sockets_up(void) {
#ifdef _WIN32
    static int up;
    if (!up) { WSADATA w; up = WSAStartup(MAKEWORD(2, 2), &w) == 0; }
#endif
}

int psp_net_host_info(psp_net_host *out) {
    psp_net_host h;
    memset(&h, 0, sizeof h);
    if (g_forced_off < 0) {
        const char *e = getenv("PSPRECOMP_NET");
        g_forced_off = e && (!strcmp(e, "off") || !strcmp(e, "0"));
    }
    if (!g_forced_off) {
#ifdef _WIN32
        ULONG len = 16384;
        IP_ADAPTER_ADDRESSES *list = NULL;
        for (int tries = 0; tries < 3; tries++) {
            list = (IP_ADAPTER_ADDRESSES *)malloc(len);
            if (!list) break;
            ULONG r = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST |
                                           GAA_FLAG_SKIP_ANYCAST, NULL, list, &len);
            if (r == ERROR_SUCCESS) break;
            free(list); list = NULL;
            if (r != ERROR_BUFFER_OVERFLOW) break;
        }
        for (IP_ADAPTER_ADDRESSES *a = list; a && !h.connected; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            if (!a->FirstGatewayAddress || !a->FirstUnicastAddress) continue;
            const struct sockaddr_in *ip = (const struct sockaddr_in *)a->FirstUnicastAddress->Address.lpSockaddr;
            const struct sockaddr_in *gw = (const struct sockaddr_in *)a->FirstGatewayAddress->Address.lpSockaddr;
            if (ip->sin_family != AF_INET) continue;
            h.connected = 1;
            h.ipv4 = ntohl(ip->sin_addr.s_addr);
            h.gateway = gw->sin_family == AF_INET ? ntohl(gw->sin_addr.s_addr) : 0;
            const ULONG plen = a->FirstUnicastAddress->OnLinkPrefixLength;
            h.netmask = plen ? 0xFFFFFFFFu << (32 - (plen > 32 ? 32 : plen)) : 0;
            h.wireless = a->IfType == IF_TYPE_IEEE80211;
            if (a->FirstDnsServerAddress) {
                const struct sockaddr_in *d = (const struct sockaddr_in *)a->FirstDnsServerAddress->Address.lpSockaddr;
                if (d->sin_family == AF_INET) h.dns1 = ntohl(d->sin_addr.s_addr);
                if (a->FirstDnsServerAddress->Next) {
                    d = (const struct sockaddr_in *)a->FirstDnsServerAddress->Next->Address.lpSockaddr;
                    if (d->sin_family == AF_INET) h.dns2 = ntohl(d->sin_addr.s_addr);
                }
            }
        }
        free(list);
#else
        struct ifaddrs *ifs = NULL;
        if (getifaddrs(&ifs) == 0) {
            for (struct ifaddrs *i = ifs; i && !h.connected; i = i->ifa_next) {
                if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET) continue;
                if (!(i->ifa_flags & IFF_UP) || (i->ifa_flags & IFF_LOOPBACK)) continue;
                h.connected = 1;
                h.ipv4 = ntohl(((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr);
                if (i->ifa_netmask) h.netmask = ntohl(((struct sockaddr_in *)i->ifa_netmask)->sin_addr.s_addr);
            }
            freeifaddrs(ifs);
        }
#endif
    }
    if (out) *out = h;
    return h.connected;
}

/* A stable, locally administered MAC address for this install: games show and
 * exchange it, so it must not change between runs; it is not the host's
 * hardware address. */
void psp_net_ether_addr(uint8_t mac[6]) {
    static uint8_t m[6];
    static int ready;
    if (!ready) {
        uint32_t h = 0x811C9DC5u;
        char name[256] = "";
#ifdef _WIN32
        DWORD n = sizeof name;
        GetComputerNameA(name, &n);
#else
        const char *e = getenv("HOSTNAME");
        if (e) snprintf(name, sizeof name, "%s", e);
#endif
        for (const char *p = name; *p; p++) h = (h ^ (uint8_t)*p) * 0x01000193u;
        m[0] = 0x00;                          /* the two low bits clear: ad hoc games reject others */
        m[1] = 0x50;
        m[2] = (uint8_t)(h >> 24); m[3] = (uint8_t)(h >> 16); m[4] = (uint8_t)(h >> 8); m[5] = (uint8_t)h;
        ready = 1;
    }
    memcpy(mac, m, 6);
}

static void ip_str(uint32_t ip, char out[16]) {
    snprintf(out, 16, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
}

/* ---- logging ---------------------------------------------------------------------- */

static void (*g_net_log)(const char *line);
static const char *(*g_redirect)(const char *host);
void psp_net_set_resolve_redirect(const char *(*fn)(const char *host)) { g_redirect = fn; }
void psp_net_set_log(void (*fn)(const char *line)) { g_net_log = fn; }

void psp_net_log_line(const char *fmt, ...) {       /* for net_sock.c */
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fprintf(stderr, "net: %s\n", line);
    if (g_net_log) g_net_log(line);
}

static void net_log(const char *fmt, ...) {
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    fprintf(stderr, "net: %s\n", line);
    if (g_net_log) g_net_log(line);
}

/* ---- sceWlanDrv --------------------------------------------------------------- */

/* 1 = the WLAN switch is on. A PSP game shows "the WLAN switch is OFF" for
 * 0, so this follows the host's connection. */
static void hle_WlanGetSwitchState(void) {
    psp_ret(psp_net_host_info(NULL) ? 1u : 0u);
}

static void hle_WlanGetEtherAddr(void) {
    const uint32_t out = psp_arg(0);
    uint8_t mac[6];
    psp_net_ether_addr(mac);
    if (out) psp_mem_write_block(out, mac, 6);
    psp_ret(0);
}

/* scePowerCheckWlanCoexistenceClock: whether the CPU clock allows WLAN at
 * the same time. Always compatible here (0). */
static void hle_PowerCheckWlanCoexistenceClock(void) { psp_ret(0); }

/* ---- sceNet core ---------------------------------------------------------------- */

static int g_net_inited, g_inet_inited;

static void hle_NetInit(void) {
    sockets_up();
    if (!g_net_inited) net_log("sceNetInit (host networking %s)", psp_net_host_info(NULL) ? "available" : "UNAVAILABLE");
    g_net_inited = 1;
    psp_ret(0);
}
static void hle_NetTerm(void) { g_net_inited = 0; psp_ret(0); }
static void hle_NetFreeThreadinfo(void) { psp_ret(0); }

static void hle_NetEtherNtostr(void) {
    uint8_t mac[6];
    char s[18];
    if (psp_mem_read_block(mac, psp_arg(0), 6) != 0 || !psp_arg(1)) { psp_ret(0); return; }
    snprintf(s, sizeof s, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    psp_mem_write_block(psp_arg(1), s, 18);
    psp_ret(0);
}

static void hle_NetEtherStrton(void) {
    char s[32];
    unsigned b[6];
    psp_str(psp_arg(0), s, sizeof s);
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6 && psp_arg(1)) {
        uint8_t mac[6];
        for (int i = 0; i < 6; i++) mac[i] = (uint8_t)b[i];
        psp_mem_write_block(psp_arg(1), mac, 6);
    }
    psp_ret(0);
}

/* ---- sceNetInet ---------------------------------------------------------------------- */

static void hle_InetInit(void) {
    if (g_inet_inited) { psp_ret(SCE_NET_INET_ERROR_ALREADY_INITIALIZED); return; }
    g_inet_inited = 1;
    psp_ret(0);
}
static void hle_InetTerm(void) { g_inet_inited = 0; psp_net_sock_close_all(); psp_ret(0); }

/* inet_addr: network byte order, as stored in memory (little-endian word of
 * the big-endian address); INADDR_NONE (0xFFFFFFFF) for a bad string. */
static void hle_InetInetAddr(void) {
    char s[64];
    unsigned a, b, c, d;
    psp_str(psp_arg(0), s, sizeof s);
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255 || c > 255 || d > 255) {
        psp_ret(0xFFFFFFFFu);
        return;
    }
    psp_ret(a | (b << 8) | (c << 16) | (d << 24));
}

/* inet_ntop(af, src, dst, size): AF_INET (2) only. */
static void hle_InetInetNtop(void) {
    const uint32_t af = psp_arg(0), src = psp_arg(1), dst = psp_arg(2), size = psp_arg(3);
    if (af != 2 || !src || !dst) { psp_ret(0); return; }
    uint8_t b[4];
    psp_mem_read_block(b, src, 4);
    char s[16];
    snprintf(s, sizeof s, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    if (strlen(s) + 1 > size) { psp_ret(0); return; }
    psp_mem_write_block(dst, s, (uint32_t)strlen(s) + 1);
    psp_ret(dst);
}

/* The socket calls themselves (and the errno accessors): net_sock.c. */

/* ---- sceNetApctl ---------------------------------------------------------------------- */

static int g_apctl_inited, g_apctl_state;
static struct { uint32_t func, arg; int used; } g_apctl_h[8];

static void apctl_set_state(int state, int event, uint32_t error) {
    const int old = g_apctl_state;
    g_apctl_state = state;
    for (int i = 0; i < 8; i++)
        if (g_apctl_h[i].used)
            psp_sched_post_call(g_apctl_h[i].func, (uint32_t)old, (uint32_t)state, (uint32_t)event, error, g_apctl_h[i].arg);
}

static void hle_ApctlInit(void) {
    if (g_apctl_inited) { psp_ret(SCE_NET_APCTL_ERROR_ALREADY_INITIALIZED); return; }
    g_apctl_inited = 1;
    g_apctl_state = APCTL_DISCONNECTED;
    psp_ret(0);
}
static void hle_ApctlTerm(void) {
    g_apctl_inited = 0;
    g_apctl_state = APCTL_DISCONNECTED;
    memset(g_apctl_h, 0, sizeof g_apctl_h);
    psp_ret(0);
}

static void hle_ApctlAddHandler(void) {
    for (int i = 0; i < 8; i++)
        if (!g_apctl_h[i].used) {
            g_apctl_h[i].used = 1; g_apctl_h[i].func = psp_arg(0); g_apctl_h[i].arg = psp_arg(1);
            psp_ret((uint32_t)i);
            return;
        }
    psp_ret(SCE_NET_APCTL_ERROR_INVALID_ID);
}
static void hle_ApctlDelHandler(void) {
    const uint32_t id = psp_arg(0);
    if (id >= 8 || !g_apctl_h[id].used) { psp_ret(SCE_NET_APCTL_ERROR_INVALID_ID); return; }
    g_apctl_h[id].used = 0;
    psp_ret(0);
}

static void hle_ApctlDisconnect(void) {
    if (g_apctl_state != APCTL_DISCONNECTED) apctl_set_state(APCTL_DISCONNECTED, APCTL_EV_DISCONNECT_REQUEST, 0);
    psp_ret(0);
}

/* sceNetApctlGetInfo(code, info): the connection's details, from the host. */
static void hle_ApctlGetInfo(void) {
    const uint32_t code = psp_arg(0), out = psp_arg(1);
    psp_net_host h;
    if (g_apctl_state != APCTL_GOT_IP || !psp_net_host_info(&h)) { psp_ret(SCE_NET_APCTL_ERROR_NOT_IN_BSS); return; }
    if (!out) { psp_ret(SCE_NET_APCTL_ERROR_INVALID_CODE); return; }
    char s[64];
    uint32_t v;
    switch (code) {
    case 0:  psp_mem_write_block(out, "Host network", 13); break;               /* profile name */
    case 1: { uint8_t bssid[6]; psp_net_ether_addr(bssid); bssid[0] = 0x02; bssid[1] = 0x41;
              psp_mem_write_block(out, bssid, 6); break; }                       /* BSSID */
    case 2:  psp_mem_write_block(out, "HostNetwork", 12); break;                 /* SSID */
    case 3:  v = 11; psp_mem_write_block(out, &v, 4); break;                     /* SSID length */
    case 4:  v = 0;  psp_mem_write_block(out, &v, 4); break;                     /* security: none */
    case 5:  { uint8_t q = 100; psp_mem_write_block(out, &q, 1); break; }        /* strength % */
    case 6:  { uint8_t ch = 1; psp_mem_write_block(out, &ch, 1); break; }        /* channel */
    case 7:  { uint8_t ps = 0; psp_mem_write_block(out, &ps, 1); break; }        /* power save */
    case 8:  ip_str(h.ipv4, s);    psp_mem_write_block(out, s, (uint32_t)strlen(s) + 1); break;
    case 9:  ip_str(h.netmask, s); psp_mem_write_block(out, s, (uint32_t)strlen(s) + 1); break;
    case 10: ip_str(h.gateway, s); psp_mem_write_block(out, s, (uint32_t)strlen(s) + 1); break;
    case 11: ip_str(h.dns1 ? h.dns1 : h.gateway, s); psp_mem_write_block(out, s, (uint32_t)strlen(s) + 1); break;
    case 12: ip_str(h.dns2, s);    psp_mem_write_block(out, s, (uint32_t)strlen(s) + 1); break;
    case 13: v = 0; psp_mem_write_block(out, &v, 4); break;                      /* no proxy */
    case 14: psp_mem_write_block(out, "", 1); break;
    case 15: { uint16_t p = 0; psp_mem_write_block(out, &p, 2); break; }
    case 16: v = 0; psp_mem_write_block(out, &v, 4); break;
    case 17: v = 0; psp_mem_write_block(out, &v, 4); break;
    case 18: v = 0; psp_mem_write_block(out, &v, 4); break;
    default: psp_ret(SCE_NET_APCTL_ERROR_INVALID_CODE); return;
    }
    psp_ret(0);
}

/* ---- sceNetResolver ------------------------------------------------------------------- */

#define MAX_RESOLVERS 8
static int g_resolver_used[MAX_RESOLVERS];

static void hle_ResolverInit(void) { sockets_up(); psp_ret(0); }
static void hle_ResolverTerm(void) { memset(g_resolver_used, 0, sizeof g_resolver_used); psp_ret(0); }

static void hle_ResolverCreate(void) {
    const uint32_t out = psp_arg(0);
    if (!out) { psp_ret(SCE_NET_RESOLVER_ERROR_INVALID_PTR); return; }
    for (int i = 0; i < MAX_RESOLVERS; i++)
        if (!g_resolver_used[i]) { g_resolver_used[i] = 1; psp_write32(out, (uint32_t)i + 1); psp_ret(0); return; }
    psp_ret(SCE_NET_RESOLVER_ERROR_ID_MAX);
}
static void hle_ResolverDelete(void) {
    const uint32_t id = psp_arg(0);
    if (id < 1 || id > MAX_RESOLVERS || !g_resolver_used[id - 1]) { psp_ret(SCE_NET_RESOLVER_ERROR_INVALID_ID); return; }
    g_resolver_used[id - 1] = 0;
    psp_ret(0);
}

/* StartNtoA(id, hostname, in_addr *out, timeout, retry): the host's DNS. */
static void hle_ResolverStartNtoA(void) {
    const uint32_t id = psp_arg(0), out = psp_arg(2);
    char host[256];
    psp_str(psp_arg(1), host, sizeof host);
    if (id < 1 || id > MAX_RESOLVERS || !g_resolver_used[id - 1]) { psp_ret(SCE_NET_RESOLVER_ERROR_INVALID_ID); return; }
    if (!out) { psp_ret(SCE_NET_RESOLVER_ERROR_INVALID_PTR); return; }
    if (!host[0]) { psp_ret(SCE_NET_RESOLVER_ERROR_INVALID_HOST); return; }
    if (!psp_net_host_info(NULL)) { net_log("resolve %s: no host network", host); psp_ret(SCE_NET_RESOLVER_ERROR_NO_RECORD); return; }
    const char *look = g_redirect ? g_redirect(host) : NULL;
    if (look) net_log("resolve %s: redirected to %s (settings file)", host, look);
    else look = host;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    if (getaddrinfo(look, NULL, &hints, &res) != 0 || !res) {
        net_log("resolve %s: no record", look);
        psp_ret(SCE_NET_RESOLVER_ERROR_NO_RECORD);
        return;
    }
    const uint32_t a = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;   /* network order */
    freeaddrinfo(res);
    psp_write32(out, a);
    const uint32_t hb = ntohl(a);
    net_log("resolve %s -> %u.%u.%u.%u", host, hb >> 24, (hb >> 16) & 255, (hb >> 8) & 255, hb & 255);
    psp_ret(0);
}

/* ---- sceNetUpnp ------------------------------------------------------------------------- */

/* UPnP port mapping is not performed. Init/Start/Stop/Term succeed as no-ops
 * (the library being present), and GetNatInfo reports an unknown NAT (zeros),
 * which a game treats as "no UPnP mapping". */
static void hle_UpnpOk(void) { psp_ret(0); }
static void hle_UpnpGetNatInfo(void) {
    if (psp_arg(0)) { uint8_t z[16] = { 0 }; psp_mem_write_block(psp_arg(0), z, sizeof z); }
    psp_ret(0);
}

/* ---- sceUtilityNetconf (the "connect to an access point" dialog) ------------------------ */

enum { DLG_NONE = 0, DLG_INIT = 1, DLG_RUNNING = 2, DLG_FINISHED = 3, DLG_SHUTDOWN = 4 };
static int g_nc_status, g_nc_action, g_nc_polls;
static uint32_t g_nc_param;

static void hle_NetconfInitStart(void) {
    g_nc_param = psp_arg(0);
    g_nc_action = g_nc_param ? (int)psp_read32(g_nc_param + 0x30) : 0;
    g_nc_status = DLG_INIT;
    g_nc_polls = 0;
    net_log("network dialog: action %d", g_nc_action);
    if (g_nc_action == 2 || g_nc_action == 4 || g_nc_action == 5) {
        /* ad hoc: SceUtilityNetconfParam.adhocparam -> {char group[8], int timeout} */
        char group[8] = { 0 };
        const uint32_t data = psp_read32(g_nc_param + 0x34);
        if (data) psp_mem_read_block(group, data, 8);
        adhoc_netconf_start(g_nc_action, group);
    }
    psp_ret(0);
}

/* The dialog "runs" for a few frames, then finishes: actions 0/1/3 connect
 * to the infrastructure network (here: the host's), the ad hoc ones (2/4/5)
 * are not supported. Result 0 = success, else the Apctl error. */
static void netconf_finish(void) {
    uint32_t result;
    if (g_nc_action == 0 || g_nc_action == 1 || g_nc_action == 3) {
        if (psp_net_host_info(NULL)) {
            if (g_apctl_state != APCTL_GOT_IP) {
                apctl_set_state(APCTL_JOINING, APCTL_EV_CONNECT_REQUEST, 0);
                apctl_set_state(APCTL_GETTING_IP, APCTL_EV_ESTABLISHED, 0);
                apctl_set_state(APCTL_GOT_IP, APCTL_EV_GET_IP, 0);
            }
            result = 0;
            net_log("network dialog: connected through the host network");
        } else {
            result = SCE_NET_APCTL_ERROR_WLAN_SWITCH_OFF;
            net_log("network dialog: no host network -- failed");
        }
    } else {
        /* ad hoc: the dialog stays until adhocctl is connected to the group (adhoc.c) */
        const int r = adhoc_netconf_poll();
        if (r == 0) return;
        result = r > 0 ? 0 : 1;                              /* 1: SCE_UTILITY_DIALOG_RESULT_ABORT */
        net_log("network dialog: ad hoc group %s", r > 0 ? "connected" : "not reached -- gave up");
    }
    if (g_nc_param) psp_write32(g_nc_param + 0x1C, result);    /* common.result */
    g_nc_status = DLG_FINISHED;
}

static void hle_NetconfUpdate(void) {
    if (g_nc_status == DLG_RUNNING && ++g_nc_polls >= 3) netconf_finish();
    psp_ret(0);
}

static void hle_NetconfGetStatus(void) {
    const int s = g_nc_status;
    if (g_nc_status == DLG_INIT) g_nc_status = DLG_RUNNING;
    else if (g_nc_status == DLG_SHUTDOWN) g_nc_status = DLG_NONE;
    psp_ret((uint32_t)s);
}

static void hle_NetconfShutdownStart(void) {
    if (g_nc_status == DLG_RUNNING) adhoc_netconf_cancel();
    g_nc_status = DLG_SHUTDOWN;
    psp_ret(0);
}

/* ---- registration ---------------------------------------------------------------- */

void psp_net_register(void) {
    psp_hle_register(0xD7763699, "sceWlanDrv", "sceWlanGetSwitchState", hle_WlanGetSwitchState);
    psp_hle_register(0x0C622081, "sceWlanDrv", "sceWlanGetEtherAddr",   hle_WlanGetEtherAddr);
    psp_hle_register(0xA85880D0, "scePower",   NULL, hle_PowerCheckWlanCoexistenceClock);   /* scePowerCheckWlanCoexistenceClock (behaviour; name unverified) */

    psp_hle_register(0x39AF39A6, "sceNet", "sceNetInit",           hle_NetInit);
    psp_hle_register(0x281928A9, "sceNet", "sceNetTerm",           hle_NetTerm);
    psp_hle_register(0x50647530, "sceNet", "sceNetFreeThreadinfo", hle_NetFreeThreadinfo);
    psp_hle_register(0x89360950, "sceNet", "sceNetEtherNtostr",    hle_NetEtherNtostr);
    psp_hle_register(0xD27961C9, "sceNet", "sceNetEtherStrton",    hle_NetEtherStrton);

    psp_hle_register(0x17943399, "sceNetInet", "sceNetInetInit",        hle_InetInit);
    psp_hle_register(0xA9ED66B9, "sceNetInet", "sceNetInetTerm",        hle_InetTerm);
    psp_hle_register(0xB75D5B0A, "sceNetInet", "sceNetInetInetAddr",    hle_InetInetAddr);
    psp_hle_register(0xD0792666, "sceNetInet", "sceNetInetInetNtop",    hle_InetInetNtop);
    psp_net_sock_register();

    psp_hle_register(0xE2F91F9B, "sceNetApctl", "sceNetApctlInit",       hle_ApctlInit);
    psp_hle_register(0xB3EDD0EC, "sceNetApctl", "sceNetApctlTerm",       hle_ApctlTerm);
    psp_hle_register(0x8ABADD51, "sceNetApctl", "sceNetApctlAddHandler", hle_ApctlAddHandler);
    psp_hle_register(0x5963991B, "sceNetApctl", "sceNetApctlDelHandler", hle_ApctlDelHandler);
    psp_hle_register(0x24FE91A1, "sceNetApctl", "sceNetApctlDisconnect", hle_ApctlDisconnect);
    psp_hle_register(0x2BEFDF23, "sceNetApctl", "sceNetApctlGetInfo",    hle_ApctlGetInfo);

    psp_hle_register(0xF3370E61, "sceNetResolver", "sceNetResolverInit",      hle_ResolverInit);
    psp_hle_register(0x6138194A, "sceNetResolver", "sceNetResolverTerm",      hle_ResolverTerm);
    psp_hle_register(0x244172AF, "sceNetResolver", "sceNetResolverCreate",    hle_ResolverCreate);
    psp_hle_register(0x94523E09, "sceNetResolver", "sceNetResolverDelete",    hle_ResolverDelete);
    psp_hle_register(0x224C5F44, "sceNetResolver", "sceNetResolverStartNtoA", hle_ResolverStartNtoA);

    psp_hle_register(0xE24220B5, "sceNetUpnp", NULL,       hle_UpnpOk);   /* sceNetUpnpInit (behaviour; name unverified) */
    psp_hle_register(0x3432B2E5, "sceNetUpnp", NULL,      hle_UpnpOk);   /* sceNetUpnpStart (behaviour; name unverified) */
    psp_hle_register(0x3E32ED9E, "sceNetUpnp", NULL,       hle_UpnpOk);   /* sceNetUpnpStop (behaviour; name unverified) */
    psp_hle_register(0x540491EF, "sceNetUpnp", NULL,       hle_UpnpOk);   /* sceNetUpnpTerm (behaviour; name unverified) */
    psp_hle_register(0x27045362, "sceNetUpnp", NULL, hle_UpnpGetNatInfo);   /* sceNetUpnpGetNatInfo (behaviour; name unverified) */

    psp_hle_register(0x4DB1E739, "sceUtility", "sceUtilityNetconfInitStart",     hle_NetconfInitStart);
    psp_hle_register(0x91E70E35, "sceUtility", "sceUtilityNetconfUpdate",        hle_NetconfUpdate);
    psp_hle_register(0x6332AA39, "sceUtility", "sceUtilityNetconfGetStatus",     hle_NetconfGetStatus);
    psp_hle_register(0xF88155F6, "sceUtility", "sceUtilityNetconfShutdownStart", hle_NetconfShutdownStart);

    psp_adhoc_register();
}
