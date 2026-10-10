/* psprecomp — IoFileMgrForUser.
 *
 * The PSP's file API, mapped onto a host directory. Games address the UMD as
 * `disc0:/` and the Memory Stick as `ms0:/`, so those prefixes are rewritten to
 * subdirectories of a root the host chooses.
 *
 * Reads go straight into guest memory, which means a game loading assets is
 * doing the real thing -- and a texture or model that arrives byte-correct is
 * strong evidence the recompiled code around it is behaving too.
 */

#include "psprecomp/hle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#  include <io.h>
#  include <direct.h>
#  define fseek64 _fseeki64
#  define ftell64 _ftelli64
#  define host_mkdir(p) _mkdir(p)
#else
#  include <dirent.h>
#  include <strings.h>
#  include <unistd.h>
#  define fseek64 fseeko
#  define ftell64 ftello
#  define host_mkdir(p) mkdir(p, 0777)
#endif

#define MAX_FILES 64
#define MAX_DIRS  16

/* Open flags, as the guest passes them. */
#define PSP_O_RDONLY 0x0001
#define PSP_O_WRONLY 0x0002
#define PSP_O_RDWR   0x0003
#define PSP_O_APPEND 0x0100
#define PSP_O_CREAT  0x0200
#define PSP_O_TRUNC  0x0400

#define ERR_ENOENT   0x80010002u
#define ERR_EEXIST   0x80010011u
#define ERR_EINVAL   0x80010016u
#define ERR_EMFILE   0x80010018u
#define ERR_ENOTSUP  0x80010086u
#define ERR_BADF     0x80020323u
#define ERR_ASYNC_BUSY 0x80020329u
#define ERR_NOASYNC  0x8002032Au

/* An open file. Asynchronous operations complete at once -- the data is on a
 * host disk -- and park their result for sceIoWaitAsync / sceIoPollAsync. */
typedef struct {
    FILE   *f;
    int     used;
    int     async_pending;
    int64_t async_result;
    /* A raw-sector open (disc0:/sce_lbn...) is a window onto one file:
     * `base` is where the window starts in the host file, `limit` its length.
     * An ordinary open has base 0 and limit -1. */
    int64_t base;
    int64_t limit;
} io_file;

/* The UMD's sector map: where each file starts on the disc. The host serves
 * the disc from extracted files, which have no sectors, so the extraction
 * step records them (<root>/disc_lba.txt: "LBN SIZE PATH" per line). Games
 * read a file's start sector from SceIoStat.st_private[0] -- the UMD
 * filesystem fills it -- and then open the data by sector range. */
typedef struct { uint32_t lba, size; char path[192]; } umd_entry;
static umd_entry *g_umd;
static int        g_numd;
#define UMD_SECTOR 2048u

typedef struct {
    int used;
    char path[1024];
    int  is_disc;        /* a disc0:/umd0: directory ... */
    char disc[512];      /* ... and its path within the disc */
#ifdef _WIN32
    intptr_t handle;
    struct _finddata_t data;
    int first;
    int done;
#else
    DIR *dir;
#endif
} io_dir;

static io_file g_file[MAX_FILES];
static io_dir  g_dir[MAX_DIRS];
static char    g_root[512];
static uint64_t g_bytes_read;
static int     g_trace = -1;

static void load_lba_map(void) {
    free(g_umd);
    g_umd = NULL;
    g_numd = 0;
    char p[600];
    snprintf(p, sizeof p, "%s/disc_lba.txt", g_root);
    FILE *f = fopen(p, "r");
    if (!f) return;
    int cap = 0;
    char line[300];
    while (fgets(line, sizeof line, f)) {
        unsigned lba, size;
        char path[192];
        if (sscanf(line, "%u %u %191[^\r\n]", &lba, &size, path) != 3) continue;
        if (g_numd == cap) {
            cap = cap ? cap * 2 : 64;
            umd_entry *n = (umd_entry *)realloc(g_umd, (size_t)cap * sizeof *n);
            if (!n) break;
            g_umd = n;
        }
        g_umd[g_numd].lba = lba;
        g_umd[g_numd].size = size;
        snprintf(g_umd[g_numd].path, sizeof g_umd[g_numd].path, "%s", path);
        g_numd++;
    }
    fclose(f);
}

/* Optional separate folder for the memory stick (ms0:), e.g. a test copy of
 * the saves; empty = <root>/ms. */
static char g_ms_root[512];
void psp_io_set_ms_root(const char *dir) { snprintf(g_ms_root, sizeof g_ms_root, "%s", dir ? dir : ""); }

void psp_io_set_root(const char *root) {
    snprintf(g_root, sizeof g_root, "%s", root ? root : ".");
    load_lba_map();
}

/* The path within the disc for a disc0:/umd0: guest path, else NULL. */
static const char *disc_rel(const char *guest) {
    const char *p;
    if      (!strncmp(guest, "disc0:", 6)) p = guest + 6;
    else if (!strncmp(guest, "umd0:", 5))  p = guest + 5;
    else return NULL;
    while (*p == '/' || *p == '\\') p++;
    return p;
}

static int path_eq(const char *a, const char *b) {
    for (; *a && *b; a++, b++) {
        char x = *a == '\\' ? '/' : *a, y = *b == '\\' ? '/' : *b;
        if (x >= 'a' && x <= 'z') x -= 32;
        if (y >= 'a' && y <= 'z') y -= 32;
        if (x != y) return 0;
    }
    return *a == *b;
}

static const umd_entry *umd_find(const char *rel) {
    for (int i = 0; i < g_numd; i++) if (path_eq(g_umd[i].path, rel)) return &g_umd[i];
    return NULL;
}

/* The file whose extent contains sector `lbn`. */
static const umd_entry *umd_find_lbn(uint32_t lbn) {
    for (int i = 0; i < g_numd; i++) {
        uint32_t secs = (g_umd[i].size + UMD_SECTOR - 1) / UMD_SECTOR;
        if (lbn >= g_umd[i].lba && lbn < g_umd[i].lba + (secs ? secs : 1)) return &g_umd[i];
    }
    return NULL;
}

void psp_io_reset(void) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (g_file[i].used && g_file[i].f) fclose(g_file[i].f);
        memset(&g_file[i], 0, sizeof g_file[i]);
    }
    memset(g_dir, 0, sizeof g_dir);
    g_bytes_read = 0;
    if (!g_root[0]) psp_io_set_root(".");
}

void psp_io_init(void) { g_root[0] = '\0'; psp_io_reset(); }

uint64_t psp_io_bytes_read(void) { return g_bytes_read; }

/* Host callback for memory-stick opens (ms0:), e.g. a game's download data. */
static void (*g_ms_log)(const char *line);
void psp_io_set_ms_log(void (*fn)(const char *line)) { g_ms_log = fn; }

static int tracing(void) {
    if (g_trace < 0) g_trace = getenv("PSPRECOMP_IO_TRACE") != NULL;
    return g_trace;
}

/* Rewrite a PSP path into a host path. The device prefix becomes a
 * subdirectory so a disc image and a memory-stick image can coexist under one
 * root without colliding. */
#ifndef _WIN32
/* PSP paths ignore case; a case-sensitive host filesystem (Linux, some
 * Android storage) needs a missing component matched against its directory.
 * Only the part after `prefix` (the root and the device folder) is fixed. */
static void fix_case(char *path, size_t prefix) {
    if (access(path, F_OK) == 0) return;
    size_t i = prefix;
    while (path[i]) {
        while (path[i] == '/') i++;
        const size_t start = i;
        while (path[i] && path[i] != '/') i++;
        if (i == start) break;
        const char saved = path[i];
        path[i] = '\0';
        if (access(path, F_OK) != 0) {
            path[start - 1] = '\0';                         /* the directory holding it */
            DIR *d = opendir(path);
            path[start - 1] = '/';
            struct dirent *e;
            while (d && (e = readdir(d)) != NULL)
                if (strlen(e->d_name) == i - start && !strcasecmp(e->d_name, path + start)) {
                    memcpy(path + start, e->d_name, i - start);
                    break;
                }
            if (d) closedir(d);
        }
        const int found = access(path, F_OK) == 0;
        path[i] = saved;
        if (!found) return;                                 /* missing: nothing below it exists either */
    }
}
#endif

static void map_path(const char *guest, char *out, size_t cap) {
    const char *p = guest;
    const char *sub = "disc";

    if      (!strncmp(p, "disc0:", 6))  { p += 6; sub = "disc"; }
    else if (!strncmp(p, "umd0:",  5))  { p += 5; sub = "disc"; }
    else if (!strncmp(p, "ms0:",   4))  { p += 4; sub = "ms";   }
    else if (!strncmp(p, "fatms0:",7))  { p += 7; sub = "ms";   }
    else if (!strncmp(p, "flash0:",7))  { p += 7; sub = "flash";}
    else if (!strncmp(p, "host0:", 6))  { p += 6; sub = "host"; }

    while (*p == '/' || *p == '\\') p++;
    if (g_ms_root[0] && !strcmp(sub, "ms")) snprintf(out, cap, "%s/%s", g_ms_root, p);
    else snprintf(out, cap, "%s/%s/%s", g_root, sub, p);
#ifndef _WIN32
    const size_t prefix = strlen(out) - strlen(p);
    if (prefix > 0 && prefix < strlen(out)) fix_case(out, prefix);
#endif
}

/* For other HLE modules that touch guest paths (the savedata utility). */
void psp_io_host_path(const char *guest, char *out, size_t cap) { map_path(guest, out, cap); }

/* ---- files --------------------------------------------------------------- */

/* Open `guest` with PSP flags. Returns a descriptor or an error code; with
 * `keep_on_error` a descriptor is allocated even when the open fails, and the
 * failure is reported through `*err` (the asynchronous form). */
static uint32_t do_open(const char *guest, uint32_t flags, int keep_on_error, int64_t *err) {
    char host[1024];
    map_path(guest, host, sizeof host);

    /* disc0:/sce_lbn0x<sector>_size0x<bytes>: the disc by sector range. It is
     * served from whichever extracted file contains the range. */
    int64_t base = 0, limit = -1;
    const char *rel = disc_rel(guest);
    unsigned lbn, rsize;
    if (rel && sscanf(rel, "sce_lbn0x%x_size0x%x", &lbn, &rsize) == 2) {
        const umd_entry *e = umd_find_lbn(lbn);
        if (!e) {
            fprintf(stderr, "psprecomp: raw UMD access to sector 0x%X lies outside every file "
                            "(%s)%s\n", lbn, guest, g_numd ? "" : " -- no disc_lba.txt under the root");
            *err = (int64_t)(int32_t)ERR_ENOENT;
            if (!keep_on_error) return ERR_ENOENT;
            host[0] = '\0';
        } else {
            snprintf(host, sizeof host, "%s/disc/%s", g_root, e->path);
            base = (int64_t)(lbn - e->lba) * UMD_SECTOR;
            limit = (int64_t)e->size - base;
            if ((int64_t)rsize < limit) limit = rsize;
        }
    }

    const char *mode = "rb";
    if (flags & PSP_O_TRUNC)                      mode = (flags & PSP_O_RDWR) == PSP_O_RDWR ? "w+b" : "wb";
    else if (flags & PSP_O_APPEND)                mode = "ab";
    else if (flags & (PSP_O_WRONLY | PSP_O_RDWR)) mode = "r+b";

    FILE *f = fopen(host, mode);
    /* O_CREAT without O_TRUNC creates a missing file but keeps an existing
     * one's contents. */
    if (!f && (flags & PSP_O_CREAT)) f = fopen(host, "w+b");
    *err = 0;
    if (tracing()) fprintf(stderr, "sceIoOpen(%s, 0x%X)%s\n", guest, flags, f ? "" : " -> not found");
    if (g_ms_log && (!strncmp(guest, "ms0:", 4) || !strncmp(guest, "fatms0:", 7))) {
        char line[600];
        snprintf(line, sizeof line, "sceIoOpen(%s, 0x%X)%s", guest, flags, f ? "" : " -> not found");
        g_ms_log(line);
    }
    if (!f) {
        /* A failed open is normal (a game probing for a save file) and is not
         * worth a warning; PSPRECOMP_IO_TRACE shows them when a game cannot
         * find assets it expects. */
        *err = (int64_t)(int32_t)ERR_ENOENT;
        if (!keep_on_error) return ERR_ENOENT;
    }

    for (int i = 0; i < MAX_FILES; i++) {
        if (g_file[i].used) continue;
        memset(&g_file[i], 0, sizeof g_file[i]);
        g_file[i].f = f;
        g_file[i].used = 1;
        g_file[i].base = base;
        g_file[i].limit = limit;
        if (f && base) fseek64(f, base, SEEK_SET);
        return (uint32_t)(i + 3);                 /* 0-2 are the std streams */
    }
    if (f) fclose(f);
    return ERR_EMFILE;
}

static void hle_Open(void) {
    char guest[512];
    int64_t err;
    psp_str(psp_arg(0), guest, sizeof guest);
    psp_ret(do_open(guest, psp_arg(1), 0, &err));
}

static void hle_OpenAsync(void) {
    /* The descriptor is returned at once; whether the open succeeded is the
     * async result. */
    char guest[512];
    int64_t err;
    psp_str(psp_arg(0), guest, sizeof guest);
    uint32_t fd = do_open(guest, psp_arg(1), 1, &err);
    if ((int32_t)fd >= 3) {
        io_file *h = &g_file[fd - 3];
        h->async_pending = 1;
        h->async_result = err ? err : (int64_t)fd;
    }
    psp_ret(fd);
}

static io_file *fd_arg(void) {
    int32_t fd = (int32_t)psp_arg(0) - 3;
    if (fd < 0 || fd >= MAX_FILES || !g_file[fd].used) return NULL;
    return &g_file[fd];
}

static void hle_Close(void) {
    io_file *h = fd_arg();
    if (!h) { psp_ret(ERR_BADF); return; }
    if (h->f) fclose(h->f);
    h->f = NULL;
    h->used = 0;
    psp_ret(0);
}

static int64_t do_read(io_file *h, uint32_t dst, uint32_t size) {
    if (!h->f) return (int64_t)(int32_t)ERR_BADF;
    if (h->limit >= 0) {                     /* a sector window ends where it ends */
        int64_t at = ftell64(h->f) - h->base;
        int64_t left = h->limit - at;
        if (left <= 0) return 0;
        if ((int64_t)size > left) size = (uint32_t)left;
    }
    if (!size) return 0;

    /* Read through a host buffer and then place it, so a read that straddles
     * the end of a guest region is rejected by the memory layer rather than
     * writing past it. */
    uint8_t *tmp = (uint8_t *)malloc(size);
    if (!tmp) return (int64_t)(int32_t)SCE_KERNEL_ERROR_NO_MEMORY;

    size_t got = fread(tmp, 1, size, h->f);
    if (got && psp_mem_write_block(dst, tmp, (uint32_t)got) != 0) {
        /* Fall back to byte-at-a-time so a partially mapped destination still
         * gets what fits, and the bad-access counter records the rest. */
        for (size_t i = 0; i < got; i++) psp_write8(dst + (uint32_t)i, tmp[i]);
    }
    free(tmp);
    g_bytes_read += got;
    if (tracing()) fprintf(stderr, "sceIoRead(fd %d, 0x%08X, %u) -> %u\n",
                           (int)(h - g_file) + 3, dst, size, (unsigned)got);
    return (int64_t)got;
}

static void hle_Read(void) {
    io_file *h = fd_arg();
    if (!h) { psp_ret(ERR_BADF); return; }
    psp_ret((uint32_t)do_read(h, psp_arg(1), psp_arg(2)));
}

static void hle_ReadAsync(void) {
    io_file *h = fd_arg();
    if (!h) { psp_ret(ERR_BADF); return; }
    if (h->async_pending) { psp_ret(ERR_ASYNC_BUSY); return; }
    h->async_result = do_read(h, psp_arg(1), psp_arg(2));
    h->async_pending = 1;
    psp_ret(0);
}

/* (fd, SceInt64 *res). The operation already completed; hand back its result.
 * WaitAsync and PollAsync differ only in whether they would have blocked. */
static void wait_async(int poll) {
    io_file *h = fd_arg();
    if (!h) { psp_ret(ERR_BADF); return; }
    if (!h->async_pending) { psp_ret(poll ? 1 : ERR_NOASYNC); return; }
    uint32_t out = psp_arg(1);
    if (out) {
        psp_write32(out, (uint32_t)h->async_result);
        psp_write32(out + 4, (uint32_t)((uint64_t)h->async_result >> 32));
    }
    h->async_pending = 0;
    psp_ret(0);
}
static void hle_WaitAsync(void) { wait_async(0); }
static void hle_PollAsync(void) { wait_async(1); }

static void hle_Write(void) {
    io_file *h = fd_arg();
    uint32_t src = psp_arg(1), size = psp_arg(2);

    /* fd 1 and 2 are stdout/stderr: a game writing there is talking to us. */
    int32_t fd = (int32_t)psp_arg(0);
    if (fd == 1 || fd == 2) {
        for (uint32_t i = 0; i < size; i++) fputc(psp_read8(src + i), stderr);
        psp_ret(size);
        return;
    }
    if (!h || !h->f) { psp_ret(ERR_BADF); return; }

    uint8_t *tmp = (uint8_t *)malloc(size ? size : 1);
    if (!tmp) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }
    for (uint32_t i = 0; i < size; i++) tmp[i] = psp_read8(src + i);
    size_t put = fwrite(tmp, 1, size, h->f);
    free(tmp);
    psp_ret((uint32_t)put);
}

/* sceIoLseek takes a 64-bit offset and returns one. Under o32 a 64-bit
 * argument is register-aligned, so it lands in $a2:$a3 rather than $a1:$a2 --
 * and the result comes back in $v0:$v1. Getting either wrong makes every seek
 * land somewhere plausible but wrong. */
static void hle_Lseek(void) {
    io_file *h = fd_arg();
    uint64_t off = (uint64_t)psp_arg(2) | ((uint64_t)psp_arg(3) << 32);
    uint32_t whence = psp_arg(4);
    if (!h || !h->f) {
        psp_cpu.r[PSP_REG_V0] = ERR_BADF;
        psp_cpu.r[PSP_REG_V1] = 0xFFFFFFFFu;
        return;
    }

    /* Positions are relative to the window for a sector-range open. */
    int64_t target;
    if (whence == 1)      target = ftell64(h->f) + (int64_t)off;
    else if (whence == 2) {
        int64_t end;
        if (h->limit >= 0) end = h->base + h->limit;
        else { fseek64(h->f, 0, SEEK_END); end = ftell64(h->f); }
        target = end + (int64_t)off;
    } else                target = h->base + (int64_t)off;
    if (target < h->base || fseek64(h->f, target, SEEK_SET) != 0) {
        psp_cpu.r[PSP_REG_V0] = ERR_EINVAL;
        psp_cpu.r[PSP_REG_V1] = 0xFFFFFFFFu;
        return;
    }

    int64_t pos = ftell64(h->f) - h->base;
    if (tracing()) fprintf(stderr, "sceIoLseek(fd %d, %lld, %u) -> %lld\n",
                           (int)(h - g_file) + 3, (long long)off, whence, (long long)pos);
    psp_cpu.r[PSP_REG_V0] = (uint32_t)pos;
    psp_cpu.r[PSP_REG_V1] = (uint32_t)((uint64_t)pos >> 32);
}

static void hle_Rename(void) {
    char a[512], b[512], ha[1024], hb[1024];
    psp_str(psp_arg(0), a, sizeof a);
    psp_str(psp_arg(1), b, sizeof b);
    map_path(a, ha, sizeof ha);
    map_path(b, hb, sizeof hb);
    psp_ret(rename(ha, hb) == 0 ? 0 : ERR_ENOENT);
}

/* ---- stat ---------------------------------------------------------------- */

/* SceIoStat (88 bytes): st_mode, st_attr, SceOff st_size, three
 * ScePspDateTime (u16 year..second, u32 microsecond; 16 bytes each) for
 * ctime/atime/mtime, then six private words. */
#define SCE_IO_STAT_SIZE 88

static void write_datetime(uint32_t at, time_t t) {
    struct tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    psp_write16(at + 0,  (uint16_t)(tmv.tm_year + 1900));
    psp_write16(at + 2,  (uint16_t)(tmv.tm_mon + 1));
    psp_write16(at + 4,  (uint16_t)tmv.tm_mday);
    psp_write16(at + 6,  (uint16_t)tmv.tm_hour);
    psp_write16(at + 8,  (uint16_t)tmv.tm_min);
    psp_write16(at + 10, (uint16_t)tmv.tm_sec);
    psp_write32(at + 12, 0);
}

/* Fill a SceIoStat from a host path. Returns 0, or -1 if the path is absent.
 * `disc` is the path within the UMD for a disc0: file (NULL otherwise): the
 * UMD filesystem reports a file's start sector in st_private[0]. */
static int fill_stat(const char *host, uint32_t out, const char *disc) {
#ifdef _WIN32
    struct _stat64 st;
    if (_stat64(host, &st) != 0) return -1;
    int is_dir = (st.st_mode & _S_IFDIR) != 0;
#else
    struct stat st;
    if (stat(host, &st) != 0) return -1;
    int is_dir = S_ISDIR(st.st_mode);
#endif
    for (uint32_t i = 0; i < SCE_IO_STAT_SIZE; i += 4) psp_write32(out + i, 0);
    /* FIO_S_IFDIR 0x1000 / FIO_S_IFREG 0x2000, rwx for everyone; the
     * attribute word mirrors it as FIO_SO_IFDIR 0x10 / FIO_SO_IFREG 0x20. */
    psp_write32(out + 0, (is_dir ? 0x1000u : 0x2000u) | 0x1FFu);
    psp_write32(out + 4, (is_dir ? 0x10u : 0x20u) | 0x7u);
    uint64_t size = is_dir ? 0 : (uint64_t)st.st_size;
    psp_write32(out + 8, (uint32_t)size);
    psp_write32(out + 12, (uint32_t)(size >> 32));
    write_datetime(out + 16, st.st_ctime);
    write_datetime(out + 32, st.st_atime);
    write_datetime(out + 48, st.st_mtime);
    if (disc && !is_dir) {
        const umd_entry *e = umd_find(disc);
        if (e) psp_write32(out + 64, e->lba);
    }
    return 0;
}

static void hle_Getstat(void) {
    char guest[512], host[1024];
    psp_str(psp_arg(0), guest, sizeof guest);
    map_path(guest, host, sizeof host);
    int rc = fill_stat(host, psp_arg(1), disc_rel(guest));
    if (tracing()) fprintf(stderr, "sceIoGetstat(%s)%s\n", guest, rc ? " -> not found" : "");
    psp_ret(rc == 0 ? 0 : ERR_ENOENT);
}

static void hle_Mkdir(void) {
    char guest[512], host[1024];
    psp_str(psp_arg(0), guest, sizeof guest);
    map_path(guest, host, sizeof host);
    psp_ret(host_mkdir(host) == 0 ? 0 : ERR_EEXIST);
}

static void hle_Remove(void) {
    char guest[512], host[1024];
    psp_str(psp_arg(0), guest, sizeof guest);
    map_path(guest, host, sizeof host);
    psp_ret(remove(host) == 0 ? 0 : ERR_ENOENT);
}

/* Device control. Only commands whose meaning is established are answered;
 * anything else is reported by number and refused, rather than acknowledged
 * with a made-up success. */
static void hle_Devctl(void) {
    char dev[64];
    psp_str(psp_arg(0), dev, sizeof dev);
    uint32_t cmd = psp_arg(1), in = psp_arg(2);
    uint32_t out = psp_arg(4), outlen = psp_arg(5);

    int ms = !strncmp(dev, "ms0:", 4) || !strncmp(dev, "fatms0:", 7);
    if (ms) {
        switch (cmd) {
        case 0x02025806:   /* is a memory stick inserted? -> 1 */
            if (out && outlen >= 4) psp_write32(out, 1);
            psp_ret(0);
            return;
        case 0x02025801:   /* memory stick driver state -> 4, ready */
            if (out && outlen >= 4) psp_write32(out, 4);
            psp_ret(0);
            return;
        case 0x02415821:   /* register insert/eject callback: indata = &cbid */
            if (in) psp_sched_notify_callback(psp_read32(in), 1);   /* 1 = inserted */
            psp_ret(0);
            return;
        case 0x02415822:   /* unregister it */
            psp_ret(0);
            return;
        case 0x02425818: { /* free space: indata holds a pointer to the result */
            /* { maxClusters, freeClusters, maxSectors, sectorSize,
             *   sectorsPerCluster }: a 2 GB stick with 1 GB free in 32 KB
             * clusters. */
            uint32_t r = in ? psp_read32(in) : 0;
            if (!r) { psp_ret(ERR_EINVAL); return; }
            psp_write32(r + 0, 0x10000);
            psp_write32(r + 4, 0x8000);
            psp_write32(r + 8, 0x8000);
            psp_write32(r + 12, 0x200);
            psp_write32(r + 16, 0x40);
            psp_ret(0);
            return;
        }
        default:
            break;
        }
    }
    fprintf(stderr, "psprecomp: sceIoDevctl(\"%s\", 0x%08X) not implemented\n", dev, cmd);
    psp_ret(ERR_ENOTSUP);
}

static void hle_Ioctl(void) {
    fprintf(stderr, "psprecomp: sceIoIoctl(fd %d, 0x%08X) not implemented\n",
            (int32_t)psp_arg(0), psp_arg(1));
    psp_ret(ERR_ENOTSUP);
}

/* ---- directories --------------------------------------------------------- */

static void hle_Dopen(void) {
    char guest[512], host[1024];
    psp_str(psp_arg(0), guest, sizeof guest);
    map_path(guest, host, sizeof host);

    for (int i = 0; i < MAX_DIRS; i++) {
        if (g_dir[i].used) continue;
#ifdef _WIN32
        char pattern[1088];
        snprintf(pattern, sizeof pattern, "%s/*", host);
        g_dir[i].handle = _findfirst(pattern, &g_dir[i].data);
        if (g_dir[i].handle == -1) { psp_ret(ERR_ENOENT); return; }
        g_dir[i].first = 1;
        g_dir[i].done = 0;
#else
        g_dir[i].dir = opendir(host);
        if (!g_dir[i].dir) { psp_ret(ERR_ENOENT); return; }
#endif
        snprintf(g_dir[i].path, sizeof g_dir[i].path, "%s", host);
        const char *rel = disc_rel(guest);
        g_dir[i].is_disc = rel != NULL;
        snprintf(g_dir[i].disc, sizeof g_dir[i].disc, "%s", rel ? rel : "");
        /* No trailing separator: entries are joined with one. */
        size_t dl = strlen(g_dir[i].disc);
        while (dl && (g_dir[i].disc[dl - 1] == '/' || g_dir[i].disc[dl - 1] == '\\')) g_dir[i].disc[--dl] = '\0';
        g_dir[i].used = 1;
        psp_ret((uint32_t)(i + 1));
        return;
    }
    psp_ret(ERR_EMFILE);
}

/* Fill a SceIoDirent: an 88-byte SceIoStat, then char d_name[256], then
 * d_private and a pad word. */
static void hle_Dread(void) {
    int32_t id = (int32_t)psp_arg(0) - 1;
    uint32_t dirent = psp_arg(1);
    if (id < 0 || id >= MAX_DIRS || !g_dir[id].used) { psp_ret(ERR_BADF); return; }

    const char *name = NULL;
#ifdef _WIN32
    if (g_dir[id].done) { psp_ret(0); return; }
    if (g_dir[id].first) {
        g_dir[id].first = 0;
        name = g_dir[id].data.name;
    } else if (_findnext(g_dir[id].handle, &g_dir[id].data) == 0) {
        name = g_dir[id].data.name;
    } else {
        g_dir[id].done = 1;
        psp_ret(0);
        return;
    }
#else
    struct dirent *de = readdir(g_dir[id].dir);
    if (!de) { psp_ret(0); return; }
    name = de->d_name;
#endif

    char host[1300], disc[700];
    snprintf(host, sizeof host, "%s/%s", g_dir[id].path, name);
    snprintf(disc, sizeof disc, "%s%s%s", g_dir[id].disc, g_dir[id].disc[0] ? "/" : "", name);
    if (fill_stat(host, dirent, g_dir[id].is_disc ? disc : NULL) != 0)
        for (uint32_t i = 0; i < SCE_IO_STAT_SIZE; i += 4) psp_write32(dirent + i, 0);
    uint32_t at = dirent + SCE_IO_STAT_SIZE;
    size_t n = strlen(name);
    if (n > 255) n = 255;
    for (uint32_t i = 0; i < (uint32_t)n; i++) psp_write8(at + i, (uint8_t)name[i]);
    psp_write8(at + (uint32_t)n, 0);

    psp_ret(1);                       /* more entries may follow */
}

static void hle_Dclose(void) {
    int32_t id = (int32_t)psp_arg(0) - 1;
    if (id < 0 || id >= MAX_DIRS || !g_dir[id].used) { psp_ret(ERR_BADF); return; }
#ifdef _WIN32
    if (g_dir[id].handle != -1) _findclose(g_dir[id].handle);
#else
    if (g_dir[id].dir) closedir(g_dir[id].dir);
#endif
    g_dir[id].used = 0;
    psp_ret(0);
}

void psp_io_register(void) {
    psp_hle_register(0x109F50BC, "IoFileMgrForUser", "sceIoOpen",      hle_Open);
    psp_hle_register(0x89AA9906, "IoFileMgrForUser", "sceIoOpenAsync", hle_OpenAsync);
    psp_hle_register(0x810C4BC3, "IoFileMgrForUser", "sceIoClose",     hle_Close);
    psp_hle_register(0x6A638D83, "IoFileMgrForUser", "sceIoRead",      hle_Read);
    psp_hle_register(0xA0B5A7C2, "IoFileMgrForUser", "sceIoReadAsync", hle_ReadAsync);
    psp_hle_register(0xE23EEC33, "IoFileMgrForUser", "sceIoWaitAsync", hle_WaitAsync);
    psp_hle_register(0x3251EA56, "IoFileMgrForUser", "sceIoPollAsync", hle_PollAsync);
    psp_hle_register(0x42EC03AC, "IoFileMgrForUser", "sceIoWrite",     hle_Write);
    psp_hle_register(0x27EB27B8, "IoFileMgrForUser", "sceIoLseek",     hle_Lseek);
    psp_hle_register(0x779103A0, "IoFileMgrForUser", "sceIoRename",    hle_Rename);
    psp_hle_register(0xACE946E8, "IoFileMgrForUser", "sceIoGetstat",   hle_Getstat);
    psp_hle_register(0x06A70004, "IoFileMgrForUser", "sceIoMkdir",     hle_Mkdir);
    psp_hle_register(0xF27A9C51, "IoFileMgrForUser", "sceIoRemove",    hle_Remove);
    psp_hle_register(0x54F5FB11, "IoFileMgrForUser", "sceIoDevctl",    hle_Devctl);
    psp_hle_register(0x63632449, "IoFileMgrForUser", "sceIoIoctl",     hle_Ioctl);
    psp_hle_register(0xB29DDF9C, "IoFileMgrForUser", "sceIoDopen",     hle_Dopen);
    psp_hle_register(0xE3EB004C, "IoFileMgrForUser", "sceIoDread",     hle_Dread);
    psp_hle_register(0xEB092469, "IoFileMgrForUser", "sceIoDclose",    hle_Dclose);
}
