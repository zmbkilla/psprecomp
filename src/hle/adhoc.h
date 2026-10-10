/* psprecomp — ad hoc multiplayer (internal interface between adhoc.c,
 * adhoc_matching.c, net.c and np.c). See adhoc.c. */
#ifndef PSPRECOMP_ADHOC_H
#define PSPRECOMP_ADHOC_H

#include <stdint.h>

/* adhoc.c */
void     adhoc_pump(void);                       /* server connection, events, relay sockets */
uint64_t adhoc_guest_us(void);                   /* guest time, for timestamps games read */
uint64_t adhoc_real_us(void);
void     adhoc_local_mac(uint8_t mac[6]);
int      adhoc_is_local_mac(const uint8_t mac[6]);
void     adhoc_log(const char *fmt, ...);
/* Active peers in the current group (MACs); returns the count written. */
int      adhoc_active_peers(uint8_t (*macs)[6], int max);
void     adhoc_peer_seen(const uint8_t mac[6]);
/* PDP from inside the library (the matching library's socket): non-blocking. */
int      adhoc_pdp_create_internal(uint8_t mac[6], int port, int bufsize);
int      adhoc_pdp_send_internal(int id, const uint8_t mac[6], uint16_t port, const void *data, int len);
/* 0 = a datagram in buf (*len, *mac, *port), else an SCE error (WOULD_BLOCK). */
int      adhoc_pdp_recv_internal(int id, uint8_t mac[6], uint16_t *port, void *buf, int *len);
void     adhoc_pdp_delete_internal(int id);
void     adhoc_set_socket_alert(int id, int flags);
/* Guest scratch for callback data: a ring, valid for a while after use. */
uint32_t adhoc_guest_alloc(uint32_t size);

/* The network dialog's ad hoc actions (2 connect, 4 create, 5 join). */
void     adhoc_netconf_start(int action, const char group[8]);
int      adhoc_netconf_poll(void);               /* 0 running, 1 connected, <0 failed */
void     adhoc_netconf_cancel(void);

/* For adhoc_mesh.c: a group member's IPv4 as the server reported it (network
 * order; 0 = not in the group), and the relay's address (0 = not resolved yet). */
uint32_t adhoc_peer_ip(const uint8_t mac[6]);
/* The relay's address (a struct sockaddr_storage, port set) and its length;
 * 0 while the server is not resolved. */
int      adhoc_relay_sockaddr(void *ss, int *len);

/* adhoc_mesh.c: the modern connection (NAT traversal; see there) */
void     mesh_configure(const char *stun, uint16_t port);
int      mesh_start(void);                       /* 0 ok */
void     mesh_stop(void);
void     mesh_pump(void);
int      mesh_pdp_bind(uint16_t port);           /* 0 ok, -1 taken */
void     mesh_pdp_unbind(uint16_t port);
int      mesh_pdp_send(const uint8_t mac[6], uint16_t sport, uint16_t dport, const void *d, int len);   /* -1 unknown peer */
/* 1 = a datagram, 2 = larger than *len (*len = its size; kept), 0 = none. */
int      mesh_pdp_recv(uint16_t port, uint8_t mac[6], uint16_t *sport, void *buf, int *len);
uint32_t mesh_pdp_avail(uint16_t port);
int      mesh_stream_open(const uint8_t mac[6], uint16_t lport, uint16_t pport);   /* stream id, 0 = none */
int      mesh_stream_state(int sid);             /* 0 connecting, 1 established, -1 closed / refused */
int      mesh_stream_send(int sid, const void *d, int len);   /* bytes taken, 0 = full, -1 closed */
int      mesh_stream_recv(int sid, void *buf, int cap);       /* bytes, 0 = none yet, -1 closed */
uint32_t mesh_stream_avail(int sid);
uint32_t mesh_stream_unsent(int sid);
void     mesh_stream_close(int sid);
int      mesh_listen(uint16_t port);             /* 0 ok, -1 taken */
void     mesh_unlisten(uint16_t port);
int      mesh_accept(uint16_t port, uint8_t mac[6], uint16_t *pport);   /* stream id, 0 = none waiting */

/* adhoc_matching.c */
void     adhoc_matching_tick(void);
void     adhoc_matching_register(void);
void     adhoc_matching_reset(void);

void     psp_adhoc_register(void);

#endif
