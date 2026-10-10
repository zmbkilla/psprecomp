/* psprecomp — IoFileMgrForUser.
 *
 * The PSP's file API, mapped onto a host directory. Games address the UMD as
 * `disc0:/` and the Memory Stick as `ms0:/`, so those prefixes are rewritten to
 * subdirectories of a root the host chooses.
 *
 * The UMD can instead be served straight from a disc image (an ISO9660 .iso,
 * psp_io_set_disc_image): files, directories and sector-range reads come from
 * the image, read-only, and the other devices stay under the root.
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
    /* From the disc image: f is NULL, the window is in the image, and `pos`
     * is the position within it (the image's FILE is shared). */
    int     iso;
    int64_t pos;
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
    int iso;             /* listing the disc image: */
    int cursor;          /* 0 ".", 1 "..", then g_umd[cursor - 2] onward */
} io_dir;

static io_file g_file[MAX_FILES];
static io_dir  g_dir[MAX_DIRS];
static char    g_root[512];
static uint64_t g_bytes_read;
static int     g_trace = -1;

/* ---- a disc image ----------------------------------------------------------- */

static FILE    *g_iso;
static int64_t  g_iso_size;
static uint8_t *g_umd_dir;       /* per g_umd entry: a directory (images only) */
static time_t  *g_umd_time;      /* per g_umd entry: its recorded date (images only) */

static int iso_read(int64_t off, void *dst, size_t n) {
    if (fseek64(g_iso, off, SEEK_SET) != 0) return 0;
    return fread(dst, 1, n, g_iso) == n;
}

static uint32_t le32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static void umd_add(uint32_t lba, uint32_t size, const char *path, int is_dir, const uint8_t *date) {
    static int cap;
    if (g_numd == 0) cap = 0;
    if (g_numd == cap) {
        cap = cap ? cap * 2 : 256;
        umd_entry *n = (umd_entry *)realloc(g_umd, (size_t)cap * sizeof *n);
        uint8_t *d = (uint8_t *)realloc(g_umd_dir, (size_t)cap);
        time_t *t = (time_t *)realloc(g_umd_time, (size_t)cap * sizeof *t);
        if (n) g_umd = n;
        if (d) g_umd_dir = d;
        if (t) g_umd_time = t;
        if (!n || !d || !t) { cap = g_numd; return; }
    }
    g_umd[g_numd].lba = lba;
    g_umd[g_numd].size = size;
    snprintf(g_umd[g_numd].path, sizeof g_umd[g_numd].path, "%s", path);
    g_umd_dir[g_numd] = (uint8_t)is_dir;
    struct tm tmv;
    memset(&tmv, 0, sizeof tmv);
    tmv.tm_year = date[0];
    tmv.tm_mon = date[1] ? date[1] - 1 : 0;
    tmv.tm_mday = date[2] ? date[2] : 1;
    tmv.tm_hour = date[3];
    tmv.tm_min = date[4];
    tmv.tm_sec = date[5];
    g_umd_time[g_numd] = mktime(&tmv);
    g_numd++;
}

/* Every entry of the directory at (lba, size), recursively, as paths under `prefix`. */
static void iso_walk(uint32_t lba, uint32_t size, const char *prefix, int depth) {
    if (depth > 16 || size > (16u << 20)) return;
    uint8_t *d = (uint8_t *)malloc(size);
    if (!d) return;
    if (!iso_read((int64_t)lba * UMD_SECTOR, d, size)) { free(d); return; }
    for (uint32_t i = 0; i < size; ) {
        const uint32_t len = d[i];
        if (len == 0) { i = (i / UMD_SECTOR + 1) * UMD_SECTOR; continue; }   /* records never cross a sector */
        if (len < 34 || i + len > size) break;
        const uint8_t *e = d + i;
        const uint32_t nl = e[32];
        if (nl && 33 + nl <= len && !(nl == 1 && (e[33] == 0 || e[33] == 1))) {
            char name[128];
            uint32_t k = 0;
            for (; k < nl && k < sizeof name - 1 && e[33 + k] != ';'; k++) name[k] = (char)e[33 + k];
            name[k] = '\0';
            if (k && name[k - 1] == '.') name[k - 1] = '\0';                  /* "NAME." with no extension */
            char path[192];
            snprintf(path, sizeof path, "%s%s%s", prefix, prefix[0] ? "/" : "", name);
            const int is_dir = (e[25] & 2) != 0;
            umd_add(le32(e + 2), le32(e + 10), path, is_dir, e + 18);
            if (is_dir) iso_walk(le32(e + 2), le32(e + 10), path, depth + 1);
        }
        i += len;
    }
    free(d);
}

/* Serve the UMD from an ISO9660 image (the runtime keeps `f`, read-only).
 * 0, or -1 if it is not one. NULL goes back to the extracted files. */
int psp_io_set_disc_image(FILE *f) {
    if (g_iso) fclose(g_iso);
    g_iso = NULL;
    free(g_umd); free(g_umd_dir); free(g_umd_time);
    g_umd = NULL; g_umd_dir = NULL; g_umd_time = NULL;
    g_numd = 0;
    if (!f) { if (g_root[0]) psp_io_set_root(g_root); return 0; }
    g_iso = f;
    uint8_t pvd[UMD_SECTOR];
    if (!iso_read(16 * (int64_t)UMD_SECTOR, pvd, sizeof pvd) || pvd[0] != 1 || memcmp(pvd + 1, "CD001", 5) != 0) {
        g_iso = NULL;
        return -1;
    }
    fseek64(f, 0, SEEK_END);
    g_iso_size = ftell64(f);
    iso_walk(le32(pvd + 156 + 2), le32(pvd + 156 + 10), "", 0);
    fprintf(stderr, "psprecomp: UMD from a disc image: %d files and folders, %lld MB\n",
            g_numd, (long long)(g_iso_size >> 20));
    return g_numd ? 0 : -1;
}

int psp_io_open_disc_image(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (psp_io_set_disc_image(f) != 0) { fclose(f); return -1; }
    return 0;
}

int psp_io_has_disc_image(void) { return g_iso != NULL; }

static void load_lba_map(void) {
    if (g_iso) return;                       /* the image has its own sectors */
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

/* A whole file from the disc image (e.g. the EBOOT), malloc'd, or NULL. */
uint8_t *psp_io_disc_file(const char *rel, uint32_t *len) {
    while (*rel == '/' || *rel == '\\') rel++;
    const umd_entry *e = g_iso ? umd_find(rel) : NULL;
    if (!e || g_umd_dir[e - g_umd]) return NULL;
    uint8_t *b = (uint8_t *)malloc(e->size ? e->size : 1);
    if (!b || !iso_read((int64_t)e->lba * UMD_SECTOR, b, e->size)) { free(b); return NULL; }
    *len = e->size;
    return b;
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
static uint32_t new_fd(FILE *f, int64_t base, int64_t limit, int iso) {
    for (int i = 0; i < MAX_FILES; i++) {
        if (g_file[i].used) continue;
        memset(&g_file[i], 0, sizeof g_file[i]);
        g_file[i].f = f;
        g_file[i].used = 1;
        g_file[i].base = base;
        g_file[i].limit = limit;
        g_file[i].iso = iso;
        if (f && base) fseek64(f, base, SEEK_SET);
        return (uint32_t)(i + 3);                 /* 0-2 are the std streams */
    }
    if (f) fclose(f);
    return ERR_EMFILE;
}

/* A disc0:/umd0: open served by the disc image. */
static uint32_t iso_open(const char *guest, const char *rel, uint32_t flags, int keep_on_error, int64_t *err) {
    int64_t base = -1, limit = -1;
    unsigned lbn, rsize;
    if (sscanf(rel, "sce_lbn0x%x_size0x%x", &lbn, &rsize) == 2) {
        base = (int64_t)lbn * UMD_SECTOR;
        limit = rsize;
    } else if (!rel[0]) {
        base = 0; limit = g_iso_size;            /* the whole disc */
    } else {
        const umd_entry *e = umd_find(rel);
        if (e && !g_umd_dir[e - g_umd]) { base = (int64_t)e->lba * UMD_SECTOR; limit = e->size; }
    }
    if (base >= 0 && base + limit > g_iso_size) limit = g_iso_size > base ? g_iso_size - base : 0;
    const int ok = base >= 0 && !(flags & (PSP_O_WRONLY | PSP_O_TRUNC | PSP_O_CREAT | PSP_O_APPEND) & ~PSP_O_RDONLY);
    if (tracing()) fprintf(stderr, "sceIoOpen(%s, 0x%X) [image]%s\n", guest, flags, ok ? "" : " -> not found");
    *err = ok ? 0 : (int64_t)(int32_t)ERR_ENOENT;
    if (!ok && !keep_on_error) return ERR_ENOENT;
    return new_fd(NULL, ok ? base : 0, ok ? limit : 0, 1);
}

static uint32_t do_open(const char *guest, uint32_t flags, int keep_on_error, int64_t *err) {
    char host[1024];
    {
        const char *r = disc_rel(guest);
        if (r && g_iso) return iso_open(guest, r, flags, keep_on_error, err);
    }
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

    return new_fd(f, base, limit, 0);
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
    if (h->f) fclose(h->f);                 /* never the shared disc image (f is NULL for it) */
    h->f = NULL;
    h->used = 0;
    psp_ret(0);
}

static int64_t do_read(io_file *h, uint32_t dst, uint32_t size) {
    if (!h->f && !h->iso) return (int64_t)(int32_t)ERR_BADF;
    if (h->iso && !g_iso) return (int64_t)(int32_t)ERR_BADF;
    if (h->limit >= 0) {                     /* a sector window ends where it ends */
        int64_t at = h->iso ? h->pos : ftell64(h->f) - h->base;
        int64_t left = h->limit - at;
        if (left <= 0) return 0;
        if ((int64_t)size > left) size = (uint32_t)left;
    }
    if (!size) return 0;
    if (h->iso && fseek64(g_iso, h->base + h->pos, SEEK_SET) != 0) return 0;

    /* Read through a host buffer and then place it, so a read that straddles
     * the end of a guest region is rejected by the memory layer rather than
     * writing past it. */
    uint8_t *tmp = (uint8_t *)malloc(size);
    if (!tmp) return (int64_t)(int32_t)SCE_KERNEL_ERROR_NO_MEMORY;

    size_t got = fread(tmp, 1, size, h->iso ? g_iso : h->f);
    if (h->iso) h->pos += (int64_t)got;
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
    if (h && h->iso) {                      /* positions within the image window */
        int64_t target = whence == 1 ? h->pos + (int64_t)off : whence == 2 ? h->limit + (int64_t)off : (int64_t)off;
        if (target < 0) {
            psp_cpu.r[PSP_REG_V0] = ERR_EINVAL;
            psp_cpu.r[PSP_REG_V1] = 0xFFFFFFFFu;
            return;
        }
        h->pos = target;
        psp_cpu.r[PSP_REG_V0] = (uint32_t)target;
        psp_cpu.r[PSP_REG_V1] = (uint32_t)((uint64_t)target >> 32);
        return;
    }
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

/* A SceIoStat for a disc-image entry (rel "" = the root). 0, or -1 if absent. */
static int iso_stat(const char *rel, uint32_t out) {
    int is_dir = 1;
    uint32_t size = 0, lba = 0;
    time_t t = 0;
    while (*rel == '/' || *rel == '\\') rel++;
    if (rel[0]) {
        const umd_entry *e = umd_find(rel);
        if (!e) return -1;
        is_dir = g_umd_dir[e - g_umd];
        size = is_dir ? 0 : e->size;
        lba = e->lba;
        t = g_umd_time[e - g_umd];
    }
    for (uint32_t i = 0; i < SCE_IO_STAT_SIZE; i += 4) psp_write32(out + i, 0);
    psp_write32(out + 0, (is_dir ? 0x1000u : 0x2000u) | 0x16Du);   /* read and execute only */
    psp_write32(out + 4, (is_dir ? 0x10u : 0x20u) | 0x5u);
    psp_write32(out + 8, size);
    write_datetime(out + 16, t);
    write_datetime(out + 32, t);
    write_datetime(out + 48, t);
    if (!is_dir) psp_write32(out + 64, lba);
    return 0;
}

static void hle_Getstat(void) {
    char guest[512], host[1024];
    psp_str(psp_arg(0), guest, sizeof guest);
    if (g_iso && disc_rel(guest)) {
        const int r = iso_stat(disc_rel(guest), psp_arg(1));
        if (tracing()) fprintf(stderr, "sceIoGetstat(%s) [image]%s\n", guest, r ? " -> not found" : "");
        psp_ret(r == 0 ? 0 : ERR_ENOENT);
        return;
    }
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
        if (g_iso && disc_rel(guest)) {         /* a directory of the disc image */
            const char *rel = disc_rel(guest);
            char d[512];
            snprintf(d, sizeof d, "%s", rel);
            size_t dl = strlen(d);
            while (dl && (d[dl - 1] == '/' || d[dl - 1] == '\\')) d[--dl] = '\0';
            const umd_entry *e = d[0] ? umd_find(d) : NULL;
            if (d[0] && (!e || !g_umd_dir[e - g_umd])) { psp_ret(ERR_ENOENT); return; }
            memset(&g_dir[i], 0, sizeof g_dir[i]);
#ifdef _WIN32
            g_dir[i].handle = -1;
#endif
            g_dir[i].iso = 1;
            g_dir[i].is_disc = 1;
            snprintf(g_dir[i].disc, sizeof g_dir[i].disc, "%s", d);
            g_dir[i].used = 1;
            psp_ret((uint32_t)(i + 1));
            return;
        }
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
    if (g_dir[id].iso) {
        io_dir *dd = &g_dir[id];
        char entry_path[700];
        if (dd->cursor < 2) {
            name = dd->cursor == 0 ? "." : "..";
            snprintf(entry_path, sizeof entry_path, "%s", dd->disc);
            dd->cursor++;
        } else {
            int k = dd->cursor - 2;
            for (; k < g_numd; k++) {                /* the next entry whose folder is this one */
                const char *p = g_umd[k].path, *slash = strrchr(p, '/');
                char parent[192];
                snprintf(parent, sizeof parent, "%.*s", slash ? (int)(slash - p) : 0, p);
                if (path_eq(parent, dd->disc)) break;
            }
            if (k >= g_numd) { psp_ret(0); return; }
            name = strrchr(g_umd[k].path, '/') ? strrchr(g_umd[k].path, '/') + 1 : g_umd[k].path;
            snprintf(entry_path, sizeof entry_path, "%s", g_umd[k].path);
            dd->cursor = k + 3;
        }
        if (iso_stat(entry_path, dirent) != 0)
            for (uint32_t i = 0; i < SCE_IO_STAT_SIZE; i += 4) psp_write32(dirent + i, 0);
        uint32_t at = dirent + SCE_IO_STAT_SIZE;
        size_t n = strlen(name);
        if (n > 255) n = 255;
        for (uint32_t i = 0; i < (uint32_t)n; i++) psp_write8(at + i, (uint8_t)name[i]);
        psp_write8(at + (uint32_t)n, 0);
        psp_ret(1);
        return;
    }
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
    if (!g_dir[id].iso && g_dir[id].handle != -1) _findclose(g_dir[id].handle);
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
