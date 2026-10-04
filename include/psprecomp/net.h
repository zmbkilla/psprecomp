/* psprecomp — networking and PSN HLE: the PSP's WLAN, network, HTTP and NP
 * libraries answered from the host (src/hle/net.c, http.c, np.c).
 *
 * The HLE side is platform neutral. What needs a policy or a user interface
 * is supplied by the host program:
 *   - an HTTP transport (psp_http_set_transport): how a game's HTTP requests
 *     are answered and where they are logged;
 *   - an NP backend (psp_np_set_backend): PSN sign-in and auth tickets.
 * Without them, requests and sign-in fail with the firmware's error codes. */
#ifndef PSPRECOMP_NET_H
#define PSPRECOMP_NET_H

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

/* ---- NP (PSN) -------------------------------------------------------------------- */

enum { PSP_NP_SIGNIN_NONE = 0, PSP_NP_SIGNIN_BUSY, PSP_NP_SIGNIN_OK, PSP_NP_SIGNIN_FAILED, PSP_NP_SIGNIN_CANCELLED };

typedef struct {
    void        (*signin_begin)(void);        /* show the login screen / start signing in */
    int         (*signin_state)(void);        /* PSP_NP_SIGNIN_* */
    void        (*signin_cancel)(void);
    const char *(*online_id)(void);           /* while signed in */
    /* Auth tickets, for request slot `slot`. ticket_state: 0 pending, 1 ready
     * (*data/*len valid until the slot is cancelled), -1 failed (*err = an
     * SCE_NP_AUTH_ERROR_* code, or 0 for unknown). */
    void        (*ticket_begin)(int slot, const char *service_id, const uint8_t *cookie, uint32_t cookie_len);
    int         (*ticket_state)(int slot, const uint8_t **data, uint32_t *len, uint32_t *err);
    void        (*ticket_cancel)(int slot);
} psp_np_backend;

void psp_np_set_backend(const psp_np_backend *be);
/* Deliver backend results (ticket callbacks) to the game: call once per vblank. */
void psp_np_poll(void);

void psp_net_register(void);
void psp_http_register(void);
void psp_np_register(void);

#ifdef __cplusplus
}
#endif

#endif /* PSPRECOMP_NET_H */
