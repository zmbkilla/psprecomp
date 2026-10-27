/* psprecomp — networking HLE: the PSP's WLAN, network and HTTP libraries
 * answered from the host (src/hle/net.c, net_sock.c, http.c). PSN and ad hoc
 * are not provided (src/hle/offline.c).
 *
 * The HLE side is platform neutral. An HTTP transport (psp_http_set_transport),
 * supplied by the host program, says how a game's HTTP requests are answered;
 * without one they fail with the firmware's error code. */
#ifndef PSPRECOMP_NET_H
#define PSPRECOMP_NET_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- the host connection ---------------------------------------------------- */

typedef struct {
    int      connected;    /* an interface up, not loopback, with IPv4 and a gateway */
    int      wireless;
    uint32_t ipv4, netmask, gateway, dns1, dns2;   /* host byte order */
} psp_net_host;

/* Fills *out (may be NULL); returns connected. PSPRECOMP_NET=off forces 0. */
int  psp_net_host_info(psp_net_host *out);
/* Nonzero: the host looks disconnected (the WLAN switch reads off), as with
 * PSPRECOMP_NET=off. */
void psp_net_set_forced_off(int off);
void psp_net_ether_addr(uint8_t mac[6]);
/* Every network event line (resolver lookups, the network dialog), for a log file. */
void psp_net_set_log(void (*fn)(const char *line));
/* Name redirection for the resolver: fn returns the host name to look up
 * instead of `host`, or NULL to look up `host` itself (a game's own servers
 * pointed at a replacement). */
void psp_net_set_resolve_redirect(const char *(*fn)(const char *host));

/* ---- HTTP ---------------------------------------------------------------------- */

typedef struct {
    const char *method, *scheme, *host, *path, *user_agent;
    uint32_t    port;
    const uint8_t *body;
    uint32_t    body_len;
} psp_http_request;

typedef struct {
    int      status;       /* HTTP status code */
    uint8_t *body;         /* malloc'd by the transport, freed by http.c */
    uint32_t len;
} psp_http_response;

typedef struct {
    /* Perform the request. 0 = a response is in *resp; otherwise an
     * SCE_HTTP_ERROR_* code for the game (e.g. 0x80431063 network). */
    int  (*send)(const psp_http_request *req, psp_http_response *resp);
    void (*log)(const char *line);
} psp_http_transport;

void psp_http_set_transport(const psp_http_transport *t);

void psp_net_register(void);
void psp_http_register(void);
/* PSN, NP matching and ad hoc are not provided: offline.c answers their
 * imports as unavailable. */
void psp_offline_register(void);

#ifdef __cplusplus
}
#endif

#endif /* PSPRECOMP_NET_H */
