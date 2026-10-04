/* psprecomp — sceHttp / sceSsl.
 *
 * Templates, connections and requests are kept as the firmware exposes them;
 * sending a request hands it to a transport the host provides
 * (psp_http_set_transport): the port logs it and either answers it from a
 * local stub, sends it with the host's HTTP stack (modern TLS), or reports
 * the server unreachable. Without a transport every request fails with
 * SCE_HTTP_ERROR_NETWORK. Every call that shapes or reads a request is
 * reported to the transport's log, so what a game sends -- and what it then
 * asks of the response (status code, length, how much it reads) -- can be
 * seen in full. */

#include "psprecomp/hle.h"
#include "psprecomp/net.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SCE_HTTP_ERROR_BEFORE_INIT   0x80431001u
#define SCE_HTTP_ERROR_ALREADY_INITED 0x80431020u
#define SCE_HTTP_ERROR_NETWORK       0x80431063u
#define SCE_HTTP_ERROR_BEFORE_SEND   0x80431065u
#define SCE_HTTP_ERROR_INVALID_ID    0x80431100u

#define MAX_OBJ 64

typedef struct {
    int  used, kind;              /* 1 template, 2 connection, 3 request */
    int  parent;
    char agent[128];              /* template */
    char host[256], scheme[16];   /* connection */
    uint32_t port;
    int  method;                  /* request: 0 GET, 1 POST, 2 HEAD */
    char path[1024];
    uint64_t content_length;
    int  sent;
    psp_http_response resp;
    uint32_t read_pos;
} http_obj;

static http_obj g_obj[MAX_OBJ];
static int g_http_inited, g_https_inited;
static const psp_http_transport *g_tr;

void psp_http_set_transport(const psp_http_transport *t) { g_tr = t; }

static void hlog(const char *fmt, ...) {
    char line[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (g_tr && g_tr->log) g_tr->log(line);
    else fprintf(stderr, "http: %s\n", line);
}

static int alloc_obj(int kind, int parent) {
    for (int i = 1; i < MAX_OBJ; i++)
        if (!g_obj[i].used) {
            memset(&g_obj[i], 0, sizeof g_obj[i]);
            g_obj[i].used = 1; g_obj[i].kind = kind; g_obj[i].parent = parent;
            return i;
        }
    return -1;
}

static http_obj *obj(uint32_t id, int kind) {
    if (id == 0 || id >= MAX_OBJ || !g_obj[id].used || g_obj[id].kind != kind) return NULL;
    return &g_obj[id];
}

static void free_obj(int id) {
    if (g_obj[id].kind == 3) free(g_obj[id].resp.body);
    memset(&g_obj[id], 0, sizeof g_obj[id]);
}

/* ---- init ---------------------------------------------------------------------- */

static void hle_HttpInit(void) {
    if (g_http_inited) { psp_ret(SCE_HTTP_ERROR_ALREADY_INITED); return; }
    g_http_inited = 1;
    hlog("sceHttpInit(pool %u bytes)", psp_arg(0));
    psp_ret(0);
}
static void hle_HttpEnd(void) {
    for (int i = 1; i < MAX_OBJ; i++) if (g_obj[i].used) free_obj(i);
    g_http_inited = 0;
    psp_ret(0);
}
static void hle_HttpsInit(void) {
    g_https_inited = 1;
    hlog("sceHttpsInit(%d root certificates from the firmware, %d client certs, %d ...)",
         (int)psp_arg(0), (int)psp_arg(1), (int)psp_arg(2));
    psp_ret(0);
}
static void hle_HttpsEnd(void) { g_https_inited = 0; psp_ret(0); }
static void hle_SslInit(void) { psp_ret(0); }
static void hle_SslEnd(void) { psp_ret(0); }

static void hle_HttpsEnableOption(void)  { hlog("sceHttpsEnableOption(0x%X)", psp_arg(0));  psp_ret(0); }
static void hle_HttpsDisableOption(void) { hlog("sceHttpsDisableOption(0x%X)", psp_arg(0)); psp_ret(0); }

/* ---- objects ---------------------------------------------------------------------- */

static void hle_CreateTemplate(void) {
    if (!g_http_inited) { psp_ret(SCE_HTTP_ERROR_BEFORE_INIT); return; }
    const int id = alloc_obj(1, 0);
    if (id < 0) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    psp_str(psp_arg(0), g_obj[id].agent, sizeof g_obj[id].agent);
    hlog("template %d: User-Agent \"%s\", HTTP/1.%d, auto proxy %d", id, g_obj[id].agent, (int)psp_arg(1), (int)psp_arg(2));
    psp_ret((uint32_t)id);
}

/* Options on templates, connections or requests: recorded in the log. */
static void opt_log(const char *what) {
    hlog("%s(id %d, %u)", what, (int)psp_arg(0), psp_arg(1));
    psp_ret(0);
}
static void hle_SetResolveTimeOut(void) { opt_log("sceHttpSetResolveTimeOut"); }
static void hle_SetResolveRetry(void)   { opt_log("sceHttpSetResolveRetry"); }
static void hle_SetConnectTimeOut(void) { opt_log("sceHttpSetConnectTimeOut"); }
static void hle_SetSendTimeOut(void)    { opt_log("sceHttpSetSendTimeOut"); }
static void hle_SetRecvTimeOut(void)    { opt_log("sceHttpSetRecvTimeOut"); }
static void hle_DisableAuth(void)       { opt_log("sceHttpDisableAuth"); }
static void hle_DisableCookie(void)     { opt_log("sceHttpDisableCookie"); }
static void hle_EnableRedirect(void)    { opt_log("sceHttpEnableRedirect"); }

static void hle_CreateConnection(void) {
    if (!obj(psp_arg(0), 1)) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    const int id = alloc_obj(2, (int)psp_arg(0));
    if (id < 0) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    psp_str(psp_arg(1), g_obj[id].host, sizeof g_obj[id].host);
    psp_str(psp_arg(2), g_obj[id].scheme, sizeof g_obj[id].scheme);
    g_obj[id].port = psp_arg(3) & 0xFFFF;
    hlog("connection %d: %s://%s:%u (keep-alive %d)", id, g_obj[id].scheme, g_obj[id].host, g_obj[id].port, (int)psp_arg(4));
    psp_ret((uint32_t)id);
}

static void hle_CreateRequest(void) {
    if (!obj(psp_arg(0), 2)) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    const int id = alloc_obj(3, (int)psp_arg(0));
    if (id < 0) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    g_obj[id].method = (int)psp_arg(1);
    psp_str(psp_arg(2), g_obj[id].path, sizeof g_obj[id].path);
    g_obj[id].content_length = (uint64_t)psp_arg(4) | ((uint64_t)psp_arg(5) << 32);   /* u64 in $t0:$t1 */
    static const char *const M[] = { "GET", "POST", "HEAD" };
    hlog("request %d: %s %s (content length %llu)", id, g_obj[id].method < 3 ? M[g_obj[id].method] : "?",
         g_obj[id].path, (unsigned long long)g_obj[id].content_length);
    psp_ret((uint32_t)id);
}

static void hle_DeleteRequest(void) {
    if (!obj(psp_arg(0), 3)) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    hlog("request %d deleted", (int)psp_arg(0));
    free_obj((int)psp_arg(0));
    psp_ret(0);
}
static void hle_DeleteConnection(void) {
    if (!obj(psp_arg(0), 2)) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    free_obj((int)psp_arg(0));
    psp_ret(0);
}

/* ---- the exchange ------------------------------------------------------------------- */

static void hle_SendRequest(void) {
    http_obj *r = obj(psp_arg(0), 3);
    if (!r) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    http_obj *c = obj((uint32_t)r->parent, 2);
    http_obj *t = c ? obj((uint32_t)c->parent, 1) : NULL;
    psp_http_request q;
    memset(&q, 0, sizeof q);
    static const char *const M[] = { "GET", "POST", "HEAD" };
    q.method = r->method < 3 ? M[r->method] : "GET";
    q.scheme = c ? c->scheme : "http";
    q.host = c ? c->host : "";
    q.port = c ? c->port : 80;
    q.path = r->path;
    q.user_agent = t ? t->agent : "";
    q.body_len = psp_arg(2);
    uint8_t *body = NULL;
    if (q.body_len && psp_arg(1)) {
        body = (uint8_t *)malloc(q.body_len);
        if (body) psp_mem_read_block(body, psp_arg(1), q.body_len);
    }
    q.body = body;
    free(r->resp.body);
    memset(&r->resp, 0, sizeof r->resp);
    int rc = g_tr && g_tr->send ? g_tr->send(&q, &r->resp) : (int)SCE_HTTP_ERROR_NETWORK;
    free(body);
    r->sent = rc == 0;
    r->read_pos = 0;
    psp_ret((uint32_t)rc);
}

static void hle_GetStatusCode(void) {
    http_obj *r = obj(psp_arg(0), 3);
    if (!r) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    if (!r->sent) { hlog("request %d: game asked for the status code before a successful send", (int)psp_arg(0)); psp_ret(SCE_HTTP_ERROR_BEFORE_SEND); return; }
    if (psp_arg(1)) psp_write32(psp_arg(1), (uint32_t)r->resp.status);
    hlog("request %d: game read the status code (%d)", (int)psp_arg(0), r->resp.status);
    psp_ret(0);
}

static void hle_GetContentLength(void) {
    http_obj *r = obj(psp_arg(0), 3);
    if (!r) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    if (!r->sent) { psp_ret(SCE_HTTP_ERROR_BEFORE_SEND); return; }
    if (psp_arg(1)) { psp_write32(psp_arg(1), r->resp.len); psp_write32(psp_arg(1) + 4, 0); }
    hlog("request %d: game read the content length (%u)", (int)psp_arg(0), r->resp.len);
    psp_ret(0);
}

static void hle_ReadData(void) {
    http_obj *r = obj(psp_arg(0), 3);
    if (!r) { psp_ret(SCE_HTTP_ERROR_INVALID_ID); return; }
    if (!r->sent) { psp_ret(SCE_HTTP_ERROR_BEFORE_SEND); return; }
    const uint32_t want = psp_arg(2);
    uint32_t n = r->resp.len - r->read_pos;
    if (n > want) n = want;
    if (n && psp_arg(1)) psp_mem_write_block(psp_arg(1), r->resp.body + r->read_pos, n);
    r->read_pos += n;
    hlog("request %d: game read %u of %u requested bytes (at %u of %u)", (int)psp_arg(0), n, want,
         r->read_pos - n, r->resp.len);
    psp_ret(n);
}

void psp_http_register(void) {
    psp_hle_register(0xAB1ABE07, "sceHttp", "sceHttpInit",              hle_HttpInit);
    psp_hle_register(0xD1C8945E, "sceHttp", "sceHttpEnd",               hle_HttpEnd);
    psp_hle_register(0xE4D21302, "sceHttp", "sceHttpsInit",             hle_HttpsInit);
    psp_hle_register(0xF9D8EB63, "sceHttp", "sceHttpsEnd",              hle_HttpsEnd);
    psp_hle_register(0xBAC31BF1, "sceHttp", "sceHttpsEnableOption",     hle_HttpsEnableOption);
    psp_hle_register(0xB3FAF831, "sceHttp", "sceHttpsDisableOption",    hle_HttpsDisableOption);
    psp_hle_register(0x9B1F1F36, "sceHttp", "sceHttpCreateTemplate",    hle_CreateTemplate);
    psp_hle_register(0x47940436, "sceHttp", "sceHttpSetResolveTimeOut", hle_SetResolveTimeOut);
    psp_hle_register(0x03D9526F, "sceHttp", "sceHttpSetResolveRetry",   hle_SetResolveRetry);
    psp_hle_register(0x8ACD1F73, "sceHttp", "sceHttpSetConnectTimeOut", hle_SetConnectTimeOut);
    psp_hle_register(0x9988172D, "sceHttp", "sceHttpSetSendTimeOut",    hle_SetSendTimeOut);
    psp_hle_register(0x1F0FC3E3, "sceHttp", "sceHttpSetRecvTimeOut",    hle_SetRecvTimeOut);
    psp_hle_register(0xAE948FEE, "sceHttp", "sceHttpDisableAuth",       hle_DisableAuth);
    psp_hle_register(0x0B12ABFB, "sceHttp", "sceHttpDisableCookie",     hle_DisableCookie);
    psp_hle_register(0x0809C831, "sceHttp", "sceHttpEnableRedirect",    hle_EnableRedirect);
    psp_hle_register(0x8EEFD953, "sceHttp", "sceHttpCreateConnection",  hle_CreateConnection);
    psp_hle_register(0x47347B50, "sceHttp", "sceHttpCreateRequest",     hle_CreateRequest);
    psp_hle_register(0xA5512E01, "sceHttp", "sceHttpDeleteRequest",     hle_DeleteRequest);
    psp_hle_register(0x5152773B, "sceHttp", "sceHttpDeleteConnection",  hle_DeleteConnection);
    psp_hle_register(0xBB70706F, "sceHttp", "sceHttpSendRequest",       hle_SendRequest);
    psp_hle_register(0x4CC7D78F, "sceHttp", "sceHttpGetStatusCode",     hle_GetStatusCode);
    psp_hle_register(0x0282A3BD, "sceHttp", "sceHttpGetContentLength",  hle_GetContentLength);
    psp_hle_register(0xEDEEB999, "sceHttp", "sceHttpReadData",          hle_ReadData);
    psp_hle_register(0x957ECBE2, "sceSsl",  "sceSslInit",               hle_SslInit);
    psp_hle_register(0x191CDEFF, "sceSsl",  "sceSslEnd",                hle_SslEnd);
}
