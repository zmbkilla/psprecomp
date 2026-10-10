/* modern_server: the modern ad hoc connection's server on its own, for a
 * machine the players can reach (a PC with an open port, a VPS, a Raspberry
 * Pi). Players behind any NAT, carrier-grade NAT included, set
 * modern_server=<this machine's address>; they then play directly with each
 * other where their NATs allow, and through this server's relay where not.
 *
 *   modern_server [port]      lobby on TCP port (default 27330), relay on port+1
 *
 * It is the same code the game runs with modern_server=host
 * (src/hle/adhoc_server.c), IPv6 and IPv4. Stop it with Ctrl+C. */

#include "psprecomp/net.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  define sleep_s(n) Sleep((n) * 1000)
#else
#  include <unistd.h>
#  define sleep_s(n) sleep(n)
#endif

static void log_line(const char *line) {
    char when[32];
    const time_t t = time(NULL);
    strftime(when, sizeof when, "%Y-%m-%d %H:%M:%S", localtime(&t));
    printf("[%s] %s\n", when, line);
    fflush(stdout);
}

int main(int argc, char **argv) {
    const int port = argc > 1 ? atoi(argv[1]) : 27330;
    if (port <= 0 || port >= 65535) { fprintf(stderr, "usage: modern_server [port]\n"); return 2; }
    if (psp_adhoc_server_start((uint16_t)port, (uint16_t)(port + 1), log_line) != 0) return 1;
    char v4[64], v6[64];
    psp_adhoc_host_addresses(v4, sizeof v4, v6, sizeof v6);
    printf("players set modern_server to this machine's public address%s%s (on this network: %s)\n",
           v6[0] ? "; its IPv6 address is " : "", v6, v4);
    int last = -1;
    for (;;) {
        sleep_s(5);
        const int n = psp_adhoc_server_players();
        if (n != last) { printf("%d player(s) connected\n", n); fflush(stdout); last = n; }
    }
}
