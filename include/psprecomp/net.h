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
    /* NP matching 2 (sceNpMatching2), on the signed-in session. Blocking;
     * com_id is "NPWRnnnnn_nn". Return the number of IDs written to `ids`
     * (at most `max`), or -1 with *err = an SCE_NP_MATCHING2_* error code.
     * May be NULL: matching then reports the server unavailable. */
    int         (*m2_server_list)(const char *com_id, uint16_t *ids, int max, uint32_t *err);
    int         (*m2_world_list)(const char *com_id, uint16_t server_id, uint32_t *ids, int max, uint32_t *err);
    /* Room requests (kind = PSP_M2_*): read the game's request at guest
     * address `param` now (game thread), send it, and complete it later with
     * psp_np2_request_done(req_id, ...). 0 = sent, else an SCE error to
     * report. May be NULL (rooms then report the service unavailable). */
    int         (*m2_room_request)(int kind, const char *com_id, uint32_t req_id, uint32_t param);
    /* Once per vblank on the game thread: deliver replies and notifications
     * (psp_np2_request_done / psp_np2_room_event / psp_np2_room_message). */
    void        (*m2_poll)(void);
    /* Where NP log lines go besides stderr (may be NULL). */
    void        (*log)(const char *line);
} psp_np_backend;

void psp_np_set_backend(const psp_np_backend *be);

enum {
    PSP_M2_SEARCH_ROOM = 1, PSP_M2_CREATE_JOIN_ROOM, PSP_M2_JOIN_ROOM, PSP_M2_LEAVE_ROOM,
    PSP_M2_GET_ROOM_DATA_EXTERNAL_LIST, PSP_M2_SET_ROOM_DATA_EXTERNAL, PSP_M2_SET_ROOM_DATA_INTERNAL,
    PSP_M2_SEND_ROOM_MESSAGE,
};
/* For the matching backend (game thread only). */
void     psp_np2_request_done(uint32_t req_id, uint32_t error, uint32_t data);   /* the request's callback */
void     psp_np2_room_event(uint64_t room_id, uint16_t member_id, uint16_t event, uint32_t data);
void     psp_np2_room_message(uint64_t room_id, uint16_t member_id, uint16_t event, uint32_t data);
uint32_t psp_np2_alloc(uint32_t size);   /* zeroed guest memory for event data (a ring: valid for a while) */
/* Deliver backend results (ticket callbacks) to the game: call once per vblank. */
void psp_np_poll(void);

/* ---- player-to-player (src/hle/p2p.c) ----------------------------------------------
 * Other players are reached through UDP port 3658 after NP signaling, as on a
 * PSP; the matching backend supplies what the matching server says (game
 * thread only; IPv4 addresses in host byte order, ports host order). */
/* After sign-in: the matching server's UDP address check (RPCN: its address,
 * port 3657), the account's user ID and online ID. Opens UDP port 3658. */
void psp_p2p_start(uint32_t server_ipv4, uint16_t server_udp_port, int64_t user_id, const char *npid);
void psp_p2p_stop(void);
/* A room member's online ID (from room data and join notifications). */
void psp_p2p_room_member(uint64_t room, uint16_t member, const char *npid);
/* Connect to a member at the address the matching server gave (JoinRoom's
 * signaling data, a member-joined notification). */
void psp_p2p_connect(uint64_t room, uint16_t member, uint32_t ipv4, uint16_t port);
/* The server asks us to open the path to a user (RPCN SignalingHelper). */
void psp_p2p_info(const char *npid, uint32_t ipv4, uint16_t port);
void psp_p2p_member_left(uint64_t room, uint16_t member);
/* We left the room, or it was destroyed: end its connections. */
void psp_p2p_room_closed(uint64_t room);

void psp_net_register(void);
void psp_http_register(void);
void psp_np_register(void);
void psp_np2_register(void);

/* ---- ad hoc (src/hle/adhoc.c, adhoc_mesh.c, adhoc_matching.c) ----------------------------
 * Ad hoc play over the internet through an ad hoc server (PPSSPP's protocol,
 * which also finds the players of a group). Three connection options:
 *   PSP_ADHOC_MODE_PPSSPP_DIRECT  PPSSPP style, direct: game data goes straight
 *                                 between players, every port shifted by
 *                                 port_offset; players' ports must be reachable;
 *   PSP_ADHOC_MODE_PPSSPP_RELAY   PPSSPP style, relayed: game data goes through
 *                                 the server ("aemu postoffice", relay_port) --
 *                                 works behind any NAT; plays with PPSSPP users
 *                                 on the relay too;
 *   PSP_ADHOC_MODE_MODERN         direct hosting through NAT traversal (recomp
 *                                 players only): one UDP socket (mesh_port) per
 *                                 player; addresses learned locally (IPv4 and
 *                                 IPv6), from a STUN server and from the ad hoc
 *                                 server are swapped through the relay, then
 *                                 both sides punch through their NATs (CGNAT
 *                                 included, unless it is symmetric). PTP gets a
 *                                 reliable stream over that UDP path. A pair that
 *                                 cannot punch through stays reachable: its
 *                                 packets are tunnelled through the relay. */
enum { PSP_ADHOC_MODE_PPSSPP_DIRECT = 0, PSP_ADHOC_MODE_PPSSPP_RELAY = 1, PSP_ADHOC_MODE_MODERN = 2 };
typedef struct {
    const char *server;          /* host name or address */
    uint16_t    server_port;     /* 0 = 27312 */
    uint16_t    relay_port;      /* 0 = 27313 */
    int         mode;            /* PSP_ADHOC_MODE_* */
    int         port_offset;     /* PPSSPP-style: added to every game port (PPSSPP default 10000) */
    const char *nickname;        /* shown to other players */
    const char *stun_server;     /* modern: host[:port]; NULL = stun.l.google.com:19302, "" = none */
    uint16_t    mesh_port;       /* modern: the UDP port; 0 = 27320 */
} psp_adhoc_config;
void psp_adhoc_configure(const psp_adhoc_config *c);

#ifdef __cplusplus
}
#endif

#endif /* PSPRECOMP_NET_H */
