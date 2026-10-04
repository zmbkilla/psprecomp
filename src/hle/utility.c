/* psprecomp — sceUtility: the savedata utility.
 *
 * The firmware's save/load service. A game fills a SceUtilitySavedataParam,
 * calls InitStart, polls GetStatus until the utility reports FINISHED (3),
 * reads base.result, calls ShutdownStart and polls until NONE (0).
 *
 * Save data lives under ms0:/PSP/SAVEDATA/<gameName><saveName>/<fileName>,
 * with PARAM.SFO and any icon/picture/sound files the game supplies. A
 * saveName of "<>" means no particular save: the directory is <gameName>.
 * On hardware the data file is encrypted with a per-game key and PARAM.SFO
 * carries its hashes (SAVEDATA_FILE_LIST, SAVEDATA_PARAMS). With a host
 * crypto provider (psp_savedata_set_crypto) saves are read and written that
 * way, interchangeable with a PSP or PPSSPP; encrypted saves are recognised
 * by SAVEDATA_PARAMS, so plain saves written earlier still load. Without a
 * provider the data file is stored as given.
 *
 * Implemented modes: AUTOLOAD/LOAD (0/2), AUTOSAVE/SAVE (1/3), and GETSIZE
 * (22) for the no-save case. Any other
 * mode is reported by number and completes with an error result rather than
 * a fabricated success.
 */

#include "psprecomp/hle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#  include <direct.h>
#  define host_mkdir(p) _mkdir(p)
#else
#  include <sys/stat.h>
#  define host_mkdir(p) mkdir(p, 0777)
#endif

enum { ST_NONE = 0, ST_INIT = 1, ST_RUNNING = 2, ST_FINISHED = 3, ST_SHUTDOWN = 4 };

/* SceUtilitySavedataParam offsets (pspsdk psputility_savedata.h). */
#define SD_RESULT    0x1C      /* base.result */
#define SD_MODE      0x30
#define SD_GAMENAME  0x3C      /* char[13] */
#define SD_SAVENAME  0x4C      /* char[20] */
#define SD_FILENAME  0x64      /* char[13] */
#define SD_DATABUF   0x74
#define SD_BUFSIZE   0x78
#define SD_DATASIZE  0x7C
#define SD_KEY       0x5DC     /* u8[16]: the game's save key (0 = none) */
#define SD_SECUREVER 0x5EC     /* secureVersion */
#define SD_SIZEINFO  0x5FC     /* SceUtilitySavedataSizeInfo *, used by GETSIZE */

#define SAVEDATA_LOAD_NO_DATA     0x80110307u
#define SAVEDATA_LOAD_ACCESS_ERR  0x80110305u
#define SAVEDATA_SAVE_ACCESS_ERR  0x80110385u
#define UTILITY_INVALID_PARAM     0x80110001u   /* used for modes not implemented */

static const psp_savedata_crypto *g_crypto;
void psp_savedata_set_crypto(const psp_savedata_crypto *c) { g_crypto = c; }

static int      g_status;
static uint32_t g_param;
static int      g_polls;

void psp_utility_reset(void) { g_status = ST_NONE; g_param = 0; g_polls = 0; }
void psp_utility_init(void)  { psp_utility_reset(); }

#define SD_NAMELIST  0x60      /* char (*)[20], for the list modes */
#define SD_SFO       0x80      /* SceUtilitySavedataSFOParam */
#define SFO_TITLE    0x000     /* char[0x80] */
#define SFO_SDTITLE  0x080     /* char[0x80] */
#define SFO_DETAIL   0x100     /* char[0x400] */
#define SFO_PARENTAL 0x500     /* u8 */
#define SD_ICON0     0x584     /* PspUtilitySavedataFileData: buf, bufSize, size, unknown */
#define SD_ICON1     0x594
#define SD_PIC1      0x5A4
#define SD_SND0      0x5B4

/* The save's directory name. "<>" is not a name: it stands for "no
 * particular save" (the reference behaviour is to use no suffix at all), so
 * the directory is the game name alone -- the same rule GETSIZE uses. Pasting
 * it in literally also made an invalid Windows path ('<' and '>' are not
 * allowed), which is what failed mode 1 with SAVE_ACCESS_ERROR. */
static void save_name(uint32_t p, char *out, size_t cap) {
    psp_str(p + SD_SAVENAME, out, cap);
    if (!strcmp(out, "<>")) out[0] = '\0';
}

static void savedir(uint32_t p, char *out, size_t cap) {
    char game[14], save[21];
    psp_str(p + SD_GAMENAME, game, sizeof game);
    save_name(p, save, sizeof save);
    snprintf(out, cap, "ms0:/PSP/SAVEDATA/%s%s", game, save);
}

/* PSPRECOMP_SAVEDATA_TRACE: the parameter block as the game filled it. */
static void trace_param(uint32_t p) {
    static int on = -1;
    if (on < 0) on = getenv("PSPRECOMP_SAVEDATA_TRACE") != NULL;
    if (!on) return;
    char game[14], save[21], file[14], title[129], sdtitle[129];
    psp_str(p + SD_GAMENAME, game, sizeof game);
    psp_str(p + SD_SAVENAME, save, sizeof save);
    psp_str(p + SD_FILENAME, file, sizeof file);
    psp_str(p + SD_SFO + SFO_TITLE, title, sizeof title);
    psp_str(p + SD_SFO + SFO_SDTITLE, sdtitle, sizeof sdtitle);
    fprintf(stderr, "savedata: param size 0x%X mode %u game '%s' save '%s' list 0x%08X file '%s'\n"
                    "          data 0x%08X bufSize %u dataSize %u; title '%s' savedataTitle '%s'\n"
                    "          icon0 %u bytes, icon1 %u, pic1 %u, snd0 %u\n",
            psp_read32(p), psp_read32(p + SD_MODE), game, save, psp_read32(p + SD_NAMELIST), file,
            psp_read32(p + SD_DATABUF), psp_read32(p + SD_BUFSIZE), psp_read32(p + SD_DATASIZE),
            title, sdtitle, psp_read32(p + SD_ICON0 + 8), psp_read32(p + SD_ICON1 + 8),
            psp_read32(p + SD_PIC1 + 8), psp_read32(p + SD_SND0 + 8));
}

/* A whole host file, malloc'd. */
static uint8_t *read_file(const char *host, uint32_t *len) {
    FILE *f = fopen(host, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    uint8_t *b = (uint8_t *)malloc(n > 0 ? (size_t)n : 1);
    *len = b ? (uint32_t)fread(b, 1, n > 0 ? (size_t)n : 0, f) : 0;
    fclose(f);
    return b;
}

/* A PARAM.SFO value: pointer into sfo and its length, or NULL. */
static const uint8_t *sfo_value(const uint8_t *sfo, uint32_t n, const char *key, uint32_t *len) {
    if (n < 20 || memcmp(sfo, "\0PSF", 4)) return NULL;
    uint32_t keys, data, count;
    memcpy(&keys, sfo + 8, 4); memcpy(&data, sfo + 12, 4); memcpy(&count, sfo + 16, 4);
    for (uint32_t i = 0; i < count && 20 + 16 * i + 16 <= n; i++) {
        const uint8_t *ix = sfo + 20 + 16 * i;
        uint16_t ko; uint32_t l, off;
        memcpy(&ko, ix, 2); memcpy(&l, ix + 4, 4); memcpy(&off, ix + 12, 4);
        if (keys + ko >= n || data + off + l > n) continue;
        if (strncmp((const char *)sfo + keys + ko, key, n - keys - ko)) continue;
        *len = l;
        return sfo + data + off;
    }
    return NULL;
}

static int has_key(uint32_t p) {
    if (psp_read32(p) < 1536) return 0;
    for (uint32_t i = 0; i < 16; i++) if (psp_read8(p + SD_KEY + i)) return 1;
    return 0;
}

/* The crypt mode the firmware uses for this request (PPSSPP's
 * DetermineCryptMode; games built with SDK 4+ -- PSP2i is 6.03 -- get the
 * new hash): 1 without the full-size request, else by secureVersion. */
static int crypt_mode_for(uint32_t p) {
    if (psp_read32(p) < 1536) return 1;
    switch (psp_read32(p + SD_SECUREVER)) {
    case 0: return 5;
    case 2: return 3;
    case 3: return 5;
    default: return 1;
    }
}

static uint32_t do_load(uint32_t p) {
    char dir[64], file[14], guest[96], host[1024];
    savedir(p, dir, sizeof dir);
    psp_str(p + SD_FILENAME, file, sizeof file);
    snprintf(guest, sizeof guest, "%s/%s", dir, file);
    psp_io_host_path(guest, host, sizeof host);
    uint32_t flen = 0;
    uint8_t *fdata = read_file(host, &flen);
    if (!fdata) return SAVEDATA_LOAD_NO_DATA;
    uint8_t *data = fdata;
    uint32_t len = flen;

    /* Encrypted? SAVEDATA_PARAMS' first byte says how (0 = written plain). */
    snprintf(guest, sizeof guest, "%s/PARAM.SFO", dir);
    char shost[1024];
    psp_io_host_path(guest, shost, sizeof shost);
    uint32_t slen = 0, vl = 0;
    uint8_t *sfo = read_file(shost, &slen);
    int file_mode = 0;
    const uint8_t *v = sfo ? sfo_value(sfo, slen, "SAVEDATA_PARAMS", &vl) : NULL;
    if (v && vl) file_mode = v[0] == 0 ? 0 : v[0] == 0x01 ? 1 : v[0] == 0x21 ? 3 : v[0] == 0x41 ? 5 : 1;
    if (file_mode) {
        uint8_t hash[16], key[16];
        int have_hash = 0;
        const uint8_t *fl = sfo_value(sfo, slen, "SAVEDATA_FILE_LIST", &vl);
        for (uint32_t o = 0; fl && o + 32 <= vl; o += 32) {
            if (!strncmp((const char *)fl + o, file, 13)) {
                memcpy(hash, fl + o + 13, 16);
                for (int i = 0; i < 16; i++) have_hash |= hash[i] != 0;
                break;
            }
        }
        for (uint32_t i = 0; i < 16; i++) key[i] = psp_read8(p + SD_KEY + i);
        const int keyed = has_key(p), want = crypt_mode_for(p);
        uint8_t *plain = NULL;
        uint32_t plen = 0;
        int rc = -1, used = file_mode;
        if (!g_crypto) {
            fprintf(stderr, "psprecomp: savedata %s is encrypted (mode %d) and no crypto provider is set\n", guest, file_mode);
        } else if (file_mode > 1 && !keyed) {
            fprintf(stderr, "psprecomp: savedata %s needs the game's key (mode %d), the request has none\n", guest, file_mode);
        } else {
            /* the file's mode first, then the request's, then without the hash check */
            rc = g_crypto->decrypt(file_mode, fdata, flen, keyed ? key : NULL, have_hash ? hash : NULL, &plain, &plen);
            if (rc && want != file_mode) { used = want; rc = g_crypto->decrypt(want, fdata, flen, keyed ? key : NULL, have_hash ? hash : NULL, &plain, &plen); }
            if (rc && have_hash) {
                used = file_mode;
                rc = g_crypto->decrypt(file_mode, fdata, flen, keyed ? key : NULL, NULL, &plain, &plen);
                if (!rc) fprintf(stderr, "psprecomp: savedata %s: hash mismatch (loaded anyway, as PPSSPP does)\n", guest);
            }
        }
        if (!rc) {
            fprintf(stderr, "psprecomp: savedata %s/%s decrypted (mode %d, %u -> %u bytes)\n", dir, file, used, flen, plen);
            data = plain;
            len = plen;
        } else {
            fprintf(stderr, "psprecomp: savedata %s/%s could not be decrypted (mode %d): passing it on as stored\n", dir, file, file_mode);
        }
    }
    free(sfo);

    uint32_t buf = psp_read32(p + SD_DATABUF), cap = psp_read32(p + SD_BUFSIZE);
    const uint32_t n = len < cap ? len : cap;
    for (uint32_t i = 0; i < n; i++) psp_write8(buf + i, data[i]);
    if (data != fdata) free(data);
    free(fdata);
    psp_write32(p + SD_DATASIZE, n);
    return 0;
}

/* Copy `size` guest bytes at `addr` into a host file. 0 on success. */
static int write_guest(const char *host, uint32_t addr, uint32_t size) {
    FILE *f = fopen(host, "wb");
    if (!f) return -1;
    uint8_t chunk[4096];
    for (uint32_t done = 0; done < size;) {
        uint32_t n = size - done < sizeof chunk ? size - done : (uint32_t)sizeof chunk;
        for (uint32_t i = 0; i < n; i++) chunk[i] = psp_read8(addr + done + i);
        if (fwrite(chunk, 1, n, f) != n) { fclose(f); return -1; }
        done += n;
    }
    return fclose(f) == 0 ? 0 : -1;
}

/* PARAM.SFO for the save, in the standard PSF layout: a 20-byte header, one
 * 16-byte index entry per key (keys sorted), the key table, then the data
 * table (each value padded to its maximum length, 4-byte aligned). */
typedef struct { const char *key; int is_int; const char *s; uint32_t v; uint32_t max; const uint8_t *bin; } sfo_entry;

/* is_int 2 = binary (bin, max bytes). Builds into buf (zero-filled, at least
 * 16-byte padded past the end); returns the size, or 0. *params_off gets the
 * data offset of SAVEDATA_PARAMS if present. */
static uint32_t build_sfo(uint8_t *buf, uint32_t cap, const sfo_entry *e, int n, uint32_t *params_off) {
    memset(buf, 0, cap);
    uint32_t keys = 20 + 16u * (uint32_t)n, klen = 0, dlen = 0;
    for (int i = 0; i < n; i++) klen += (uint32_t)strlen(e[i].key) + 1;
    uint32_t data = (keys + klen + 3) & ~3u;
    for (int i = 0; i < n; i++) dlen += (e[i].max + 3) & ~3u;
    if (data + dlen + 16 > cap) return 0;
    memcpy(buf, "\0PSF", 4);
    const uint32_t hdr[4] = { 0x00000101u, keys, data, (uint32_t)n };
    memcpy(buf + 4, hdr, 16);
    uint32_t ko = 0, dof = 0;
    for (int i = 0; i < n; i++) {
        uint8_t *ix = buf + 20 + 16 * i;
        uint16_t kofs = (uint16_t)ko, fmt = e[i].is_int == 1 ? 0x0404 : e[i].is_int == 2 ? 0x0004 : 0x0204;
        uint32_t len = e[i].is_int == 1 ? 4u : e[i].is_int == 2 ? e[i].max : (uint32_t)strlen(e[i].s) + 1;
        if (len > e[i].max) len = e[i].max;
        memcpy(ix, &kofs, 2); memcpy(ix + 2, &fmt, 2); memcpy(ix + 4, &len, 4);
        memcpy(ix + 8, &e[i].max, 4); memcpy(ix + 12, &dof, 4);
        memcpy(buf + keys + ko, e[i].key, strlen(e[i].key) + 1);
        if (e[i].is_int == 1) memcpy(buf + data + dof, &e[i].v, 4);
        else if (e[i].is_int == 2) { if (e[i].bin) memcpy(buf + data + dof, e[i].bin, len); }
        else memcpy(buf + data + dof, e[i].s, len);
        if (params_off && !strcmp(e[i].key, "SAVEDATA_PARAMS")) *params_off = data + dof;
        ko += (uint32_t)strlen(e[i].key) + 1;
        dof += (e[i].max + 3) & ~3u;
    }
    return data + dlen;
}

static int write_host(const char *host, const uint8_t *b, size_t n) {
    FILE *f = fopen(host, "wb");
    if (!f) return -1;
    int ok = fwrite(b, 1, n, f) == n;
    return fclose(f) == 0 && ok ? 0 : -1;
}

/* AUTOSAVE / SAVE: create the directory, then write the data file, the
 * icon/picture/sound files the game provides, and PARAM.SFO. The data file
 * is stored unencrypted (see the note at the top of this file). */
static uint32_t do_save(uint32_t p) {
    char dir[64], file[14], guest[96], host[1024];
    savedir(p, dir, sizeof dir);
    psp_str(p + SD_FILENAME, file, sizeof file);
    if (!file[0]) return SAVEDATA_SAVE_ACCESS_ERR;
    /* Create every missing component of the host path (a fresh root has no
     * ms/ or PSP/SAVEDATA/ yet); existing directories are fine. */
    psp_io_host_path(dir, host, sizeof host);
    for (char *c = host + 1; *c; c++) {
        if (*c != '/' && *c != '\\') continue;
        const char keep = *c;
        *c = '\0';
        host_mkdir(host);
        *c = keep;
    }
    host_mkdir(host);

    snprintf(guest, sizeof guest, "%s/%s", dir, file);
    psp_io_host_path(guest, host, sizeof host);
    /* Encrypted as the firmware does when a provider is set (the mode the
     * request calls for; a keyed mode needs the game's key). */
    const uint32_t dbuf = psp_read32(p + SD_DATABUF), dsize = psp_read32(p + SD_DATASIZE);
    int mode = g_crypto ? crypt_mode_for(p) : 0;
    if (mode > 1 && !has_key(p)) mode = 0;
    uint8_t hash[16] = { 0 };
    if (mode && dsize) {
        uint8_t *plain = (uint8_t *)malloc(dsize), *enc = NULL, key[16];
        uint32_t elen = 0;
        for (uint32_t i = 0; i < 16; i++) key[i] = psp_read8(p + SD_KEY + i);
        if (plain) psp_mem_read_block(plain, dbuf, dsize);
        if (!plain || g_crypto->encrypt(mode, plain, dsize, mode > 1 ? key : NULL, &enc, &elen, hash) != 0) {
            fprintf(stderr, "psprecomp: savedata %s: encryption failed -- writing it plain\n", guest);
            mode = 0;
        } else {
            if (write_host(host, enc, elen) != 0) { free(plain); free(enc); return SAVEDATA_SAVE_ACCESS_ERR; }
            fprintf(stderr, "psprecomp: savedata %s written encrypted (mode %d, %u bytes)\n", guest, mode, elen);
        }
        free(plain);
        free(enc);
    }
    if (!mode && write_guest(host, dbuf, dsize) != 0)
        return SAVEDATA_SAVE_ACCESS_ERR;

    static const struct { uint32_t off; const char *name; } EXTRA[4] = {
        { SD_ICON0, "ICON0.PNG" }, { SD_ICON1, "ICON1.PMF" }, { SD_PIC1, "PIC1.PNG" }, { SD_SND0, "SND0.AT3" } };
    for (int i = 0; i < 4; i++) {
        uint32_t buf = psp_read32(p + EXTRA[i].off), size = psp_read32(p + EXTRA[i].off + 8);
        if (!buf || !size) continue;
        snprintf(guest, sizeof guest, "%s/%s", dir, EXTRA[i].name);
        psp_io_host_path(guest, host, sizeof host);
        if (write_guest(host, buf, size) != 0) return SAVEDATA_SAVE_ACCESS_ERR;
    }

    char game[14], save[21], title[129], sdtitle[129], detail[1025], dirname[64];
    psp_str(p + SD_GAMENAME, game, sizeof game);
    save_name(p, save, sizeof save);
    snprintf(dirname, sizeof dirname, "%s%s", game, save);
    psp_str(p + SD_SFO + SFO_TITLE, title, sizeof title);
    psp_str(p + SD_SFO + SFO_SDTITLE, sdtitle, sizeof sdtitle);
    psp_str(p + SD_SFO + SFO_DETAIL, detail, sizeof detail);
    /* SAVEDATA_FILE_LIST: 99 entries of name[13], hash[16], pad[3];
     * SAVEDATA_PARAMS: 128 bytes, filled by the hash below (zero = plain). */
    static uint8_t file_list[99 * 32];
    memset(file_list, 0, sizeof file_list);
    snprintf((char *)file_list, 13, "%s", file);
    memcpy(file_list + 13, hash, 16);
    const sfo_entry sfo[8] = {
        { "CATEGORY",           0, "MS",    0, 4, NULL },
        { "PARENTAL_LEVEL",     1, NULL,    psp_read8(p + SD_SFO + SFO_PARENTAL), 4, NULL },
        { "SAVEDATA_DETAIL",    0, detail,  0, 1024, NULL },
        { "SAVEDATA_DIRECTORY", 0, dirname, 0, 64, NULL },
        { "SAVEDATA_FILE_LIST", 2, NULL,    0, sizeof file_list, file_list },
        { "SAVEDATA_PARAMS",    2, NULL,    0, 128, NULL },
        { "SAVEDATA_TITLE",     0, sdtitle, 0, 128, NULL },
        { "TITLE",              0, title,   0, 128, NULL },
    };
    static uint8_t sbuf[8192];
    uint32_t params_off = 0;
    const uint32_t ssize = build_sfo(sbuf, sizeof sbuf, sfo, 8, &params_off);
    if (!ssize) return SAVEDATA_SAVE_ACCESS_ERR;
    if (mode && params_off) g_crypto->sfo_hash(sbuf, ssize, params_off, mode);
    snprintf(guest, sizeof guest, "%s/PARAM.SFO", dir);
    psp_io_host_path(guest, host, sizeof host);
    if (write_host(host, sbuf, ssize) != 0) return SAVEDATA_SAVE_ACCESS_ERR;
    return 0;
}

/* RW_NO_DATA is 0x80110327 -- the value PSP2i itself tests for after GETSIZE
 * (0x08D68D5C). 0x8011032C, used here before, is RW_BAD_STATUS. */
#define SAVEDATA_RW_NO_DATA 0x80110327u

/* SceUtilitySavedataSizeInfo (60 bytes) and its entries (u64 size, name[16]). */
#define SI_NSECURE   0
#define SI_NNORMAL   4
#define SI_SECURE    8
#define SI_NORMAL    12
#define SI_SECTOR    16
#define SI_FREESECT  20
#define SI_FREEKB    24
#define SI_FREESTR   28
#define SI_NEEDKB    36
#define SI_NEEDSTR   40
#define SI_OVERKB    48
#define SI_OVERSTR   52

/* The memory stick this runtime reports everywhere (see sceIoDevctl in
 * iofilemgr.c): 1 GB free in 32 KB clusters. */
#define MS_SECTOR    0x8000u
#define MS_FREE      (1024ull * 1024 * 1024)

/* Firmware-style size text: "1 GB", "512 KB", "0 KB". */
static void space_text(uint64_t bytes, int round_up, char out[8]) {
    static const char *const suf[] = { "B", "KB", "MB", "GB" };
    char t[24];
    int i = 0;
    while (i < 3 && bytes >= 1024) { if (round_up) bytes += 1023; bytes /= 1024; i++; }
    snprintf(t, sizeof t, "%llu %s", (unsigned long long)bytes, suf[i]);
    memcpy(out, t, 7);
    out[7] = '\0';
}

static void write_text(uint32_t at, const char s[8]) {
    for (uint32_t i = 0; i < 8; i++) psp_write8(at + i, (uint8_t)s[i]);
}

/* GETSIZE (22): how much space would writing these files need. The
 * firmware fills the size-info block whether or not the save exists, and
 * returns 0 for an existing save or SAVEDATA_RW_NO_DATA for a new one --
 * both of which PSP2i treats as a successful query, then reads neededKB
 * (0x08D68D5C). A saveName of "<>" means any save of this game. */
static uint32_t do_getsize(uint32_t p) {
    char guest[64], host[1024];
    savedir(p, guest, sizeof guest);
    psp_io_host_path(guest, host, sizeof host);
    struct stat st;
    const int exists = stat(host, &st) == 0;

    uint32_t si = psp_read32(p + SD_SIZEINFO);
    if (si) {
        /* Bytes to write, and bytes already occupied by the same files
         * (which a save would overwrite). */
        uint64_t write = 0, overwrite = 0;
        for (int list = 0; list < 2; list++) {
            uint32_t n = psp_read32(si + (list ? SI_NNORMAL : SI_NSECURE));
            uint32_t e = psp_read32(si + (list ? SI_NORMAL : SI_SECURE));
            for (uint32_t k = 0; k < n && k < 64 && e; k++, e += 24) {
                write += (uint64_t)psp_read32(e) | ((uint64_t)psp_read32(e + 4) << 32);
                char name[17], fpath[1100];
                psp_str(e + 8, name, sizeof name);
                snprintf(fpath, sizeof fpath, "%s/%s", host, name);
                struct stat fs;
                if (exists && stat(fpath, &fs) == 0) overwrite += (uint64_t)fs.st_size;
            }
        }
        char txt[8];
        psp_write32(si + SI_SECTOR, MS_SECTOR);
        psp_write32(si + SI_FREESECT, (uint32_t)(MS_FREE / MS_SECTOR));
        psp_write32(si + SI_FREEKB, (uint32_t)(MS_FREE / 1024));
        space_text(MS_FREE, 0, txt);
        write_text(si + SI_FREESTR, txt);
        uint64_t need = write > overwrite + MS_FREE ? write - overwrite - MS_FREE : 0;
        psp_write32(si + SI_NEEDKB, (uint32_t)((need + 1023) / 1024));
        space_text(need, 1, txt);
        write_text(si + SI_NEEDSTR, txt);
        psp_write32(si + SI_OVERKB, (uint32_t)((need + 1023) / 1024));
        write_text(si + SI_OVERSTR, txt);
    }
    return exists ? 0 : SAVEDATA_RW_NO_DATA;
}

static void hle_SavedataInitStart(void) {
    uint32_t p = psp_arg(0);
    if (g_status != ST_NONE) { psp_ret(0x80110002u); return; }   /* busy */
    g_param = p;
    uint32_t mode = psp_read32(p + SD_MODE);
    trace_param(p);
    char dir[64], file[14];
    savedir(p, dir, sizeof dir);
    psp_str(p + SD_FILENAME, file, sizeof file);
    uint32_t result;
    switch (mode) {
    case 0: case 2: result = do_load(p); break;
    case 1: case 3: result = do_save(p); break;
    case 22:        result = do_getsize(p); break;
    default:
        result = UTILITY_INVALID_PARAM;
        fprintf(stderr, "psprecomp: sceUtilitySavedata mode %u not implemented (%s/%s)\n", mode, dir, file);
        break;
    }
    fprintf(stderr, "psprecomp: sceUtilitySavedata mode %u %s/%s -> 0x%08X\n", mode, dir, file, result);
    psp_write32(p + SD_RESULT, result);
    g_status = ST_INIT;
    g_polls = 0;
    psp_ret(0);
}

/* INIT -> RUNNING -> FINISHED on successive polls (the work is already done),
 * SHUTDOWN -> NONE after ShutdownStart. */
static void hle_SavedataGetStatus(void) {
    int s = g_status;
    if (g_status == ST_INIT) g_status = ST_RUNNING;
    else if (g_status == ST_RUNNING) g_status = ST_FINISHED;
    else if (g_status == ST_SHUTDOWN) g_status = ST_NONE;
    psp_ret((uint32_t)s);
}

/* (animSpeed): the per-frame tick that drives the dialog. The work was done in
 * InitStart, so there is nothing left for it to advance. */
static void hle_SavedataUpdate(void) { psp_ret(0); }

static void hle_SavedataShutdownStart(void) {
    if (g_status != ST_FINISHED) { psp_ret(0x80110005u); return; }  /* bad status */
    g_status = ST_SHUTDOWN;
    psp_ret(0);
}

void psp_utility_register(void) {
    psp_hle_register(0x50C4CD57, "sceUtility", "sceUtilitySavedataInitStart",     hle_SavedataInitStart);
    psp_hle_register(0x8874DBE0, "sceUtility", "sceUtilitySavedataGetStatus",     hle_SavedataGetStatus);
    psp_hle_register(0x9790B33C, "sceUtility", "sceUtilitySavedataShutdownStart", hle_SavedataShutdownStart);
    psp_hle_register(0xD4B95FFB, "sceUtility", "sceUtilitySavedataUpdate",        hle_SavedataUpdate);
}
