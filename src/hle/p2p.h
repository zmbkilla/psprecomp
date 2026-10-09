/* psprecomp — player-to-player traffic over the shared UDP port 3658
 * (internal interface between p2p.c, net_sock.c and np2.c; the matching
 * backend's side is in psprecomp/net.h, psp_p2p_*). See p2p.c. */
#ifndef PSPRECOMP_P2P_H
#define PSPRECOMP_P2P_H

#include <stdint.h>

#define P2P_PORT 3658u              /* SCE_SIGN_PORT: every peer's P2P endpoint */

/* p2p.c */
int  p2p_active(void);              /* the shared socket is open */
void p2p_pump(void);                /* read the shared socket, run signaling timers */
/* Send one datagram from the shared socket (ip and port in network order). */
int  p2p_send_raw(uint32_t ip_n, uint16_t port_n, const uint8_t *p, uint32_t n);
/* A connected signaling peer: traffic to this address takes the P2P route. */
int  p2p_is_peer(uint32_t ip_n);
/* The address this host is known by (network order; 0 if unknown). */
uint32_t p2p_local_ip(void);
/* sceNpMatching2SignalingGetConnectionStatus: 0 inactive, 1 pending, 2 active
 * (*ip_n, *port_h set when active); -1 no such member, -2 no connection. */
int  p2p_conn_status(uint64_t room, uint16_t member, uint32_t *ip_n, uint16_t *port_h);
/* The vport a socket bound with vport 0 gets (the account's user ID, as the
 * reference emulator does), network order. */
uint16_t p2p_default_vport_n(void);

/* net_sock.c: a game packet that arrived on the shared socket (the 3-byte
 * vport header and the 11-byte extension already parsed; all u16 fields as
 * they were on the wire, i.e. network order). */
typedef struct {
    uint32_t src_ip_n;              /* the sender's real address */
    uint16_t src_udp_port_n;        /* ... and its real UDP port */
    uint16_t dst_port_n, dst_vport_n, src_port_n, src_vport_n;
    uint8_t  flags, sock_type;
    uint32_t seq;
    const uint8_t *data;
    uint32_t len;
} p2p_packet;
void net_sock_p2p_input(const p2p_packet *pk);
void net_sock_p2p_tick(uint64_t now_ms);    /* retransmissions */

/* np2.c: a signaling event for the game's signaling callback. */
void psp_np2_signaling_event(uint64_t room, uint16_t member, uint16_t event, uint32_t error);

#endif
