/* psprecomp — ad hoc: the sockets shim and byte buffers shared by adhoc.c and
 * adhoc_mesh.c. */
#ifndef PSPRECOMP_ADHOC_SOCK_H
#define PSPRECOMP_ADHOC_SOCK_H

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
typedef SOCKET hsock;
#  define BAD_SOCK INVALID_SOCKET
#  define last_error() WSAGetLastError()
#  define close_sock closesocket
#  define WOULD_BLOCK(e) ((e) == WSAEWOULDBLOCK)
#  define IN_PROGRESS(e) ((e) == WSAEWOULDBLOCK || (e) == WSAEINPROGRESS || (e) == WSAEALREADY)
#else
#  include <arpa/inet.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/ioctl.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>
typedef int hsock;
#  define BAD_SOCK (-1)
#  define last_error() errno
#  define close_sock close
#  define WOULD_BLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#  define IN_PROGRESS(e) ((e) == EINPROGRESS || (e) == EALREADY || (e) == EAGAIN)
#endif

static inline void set_nonblocking(hsock s) {
#ifdef _WIN32
    u_long one = 1;
    ioctlsocket(s, FIONBIO, &one);
    BOOL off = FALSE;
    DWORD got = 0;
    WSAIoctl(s, _WSAIOW(IOC_VENDOR, 12), &off, sizeof off, NULL, 0, &got, NULL, NULL);   /* no UDP CONNRESET */
#else
    fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
#endif
}

/* ---- byte buffers (relay framing, queues) ---- */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint8_t *p; uint32_t len, cap; } buf_t;

static inline int buf_add(buf_t *b, const void *d, uint32_t n) {
    if (b->len + n > b->cap) {
        uint32_t c = b->cap ? b->cap : 4096;
        while (c < b->len + n) c *= 2;
        uint8_t *q = (uint8_t *)realloc(b->p, c);
        if (!q) return -1;
        b->p = q; b->cap = c;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
    return 0;
}
static inline void buf_drop(buf_t *b, uint32_t n) {
    if (n >= b->len) { b->len = 0; return; }
    memmove(b->p, b->p + n, b->len - n);
    b->len -= n;
}
static inline void buf_free(buf_t *b) { free(b->p); memset(b, 0, sizeof *b); }

#endif
