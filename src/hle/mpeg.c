/* psprecomp — sceMpeg: PSMF movie playback.
 *
 * A game plays a movie (.pmf: a 2048-byte PSMF header, then an MPEG-2 program
 * stream holding H.264 video and ATRAC3plus audio) through a ring buffer of
 * 2048-byte packets it owns:
 *
 *   RingbufferConstruct  the ring and the game's read callback
 *   Create               the library's handle (the game's memory)
 *   QueryStreamOffset    parse the PSMF header
 *   RegistStream         pick the video and audio streams
 *   loop:
 *     RingbufferAvailableSize / RingbufferPut
 *                        the library calls the read callback to fill free
 *                        packets: callback(dest, packets, arg) -> packets read
 *     GetAvcAu, AvcDecodeYCbCr, AvcCsc
 *                        next picture, converted into the game's frame buffer
 *     GetAtracAu, AtracDecode
 *                        next 2048 stereo samples, which the game outputs
 *   until GetAvcAu reports no data with dts = -1 (the end).
 *
 * Here every packet the callback reads is copied out of the ring at once and
 * demultiplexed: video payload goes to an H.264 elementary-stream buffer,
 * audio payload to an ATRAC one. The ring is only flow control after that: it
 * reports as filled what is buffered and not yet decoded. Pictures are split
 * at the access-unit delimiters the PSP encoder writes before every picture
 * and decoded by the host's codec (psp_mpeg_set_video_codec); audio frames go
 * through the host's ATRAC codec (psp_atrac_get_codec). Without a video codec
 * movies keep their sound and timing over black frames.
 *
 * The decoded picture stays on the host; AvcDecodeYCbCr does not fill the
 * game's YCbCr buffer and AvcCsc converts from the host copy, which is all a
 * game can observe through these calls.
 *
 * Behaviour (structure layouts, error codes, timing, what each call returns
 * when data runs out) follows the observed firmware as PPSSPP documents it;
 * this is an independent implementation in C.
 */

#include "psprecomp/hle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MPEG    2
#define MAX_STREAMS 8
#define PACKET      2048

#define ERR_NO_DATA           0x80618001u
#define ERR_BAD_VERSION       0x80610002u
#define ERR_INVALID_VALUE     0x806101FEu
#define ERR_NO_MEMORY         0x80610022u
#define ERR_NOT_YET_INIT      0x80618009u
#define ERR_AVC_DECODE_FATAL  0x80628002u
#define ERR_ILLEGAL_ADDR      0x800200D3u
#define ERR_KERNEL_INVALID    0x800001FEu

#define LIB_VERSION        0x010A       /* the version PSP2i's libmpeg behaves as */
#define MEMSIZE            0x10000
#define AVC_ES_SIZE        2048
#define ATRAC_ES_SIZE      2112
#define ATRAC_OUT_SIZE     8192
#define DATA_ES_SIZE       0xA0000
#define PSMF_MAGIC         0x464D5350u  /* "PSMF" */
#define VIDEO_PTS_STEP     3003         /* 90 kHz ticks per picture at 29.97 fps */
#define AUDIO_PTS_STEP     4180         /* 2048 samples at 44.1 kHz */

enum { ST_AVC = 0, ST_ATRAC = 1, ST_PCM = 2, ST_DATA = 3, ST_AUDIO = 15 };

/* SceMpegRingbuffer field offsets */
enum { RB_PACKETS = 0, RB_READ = 4, RB_WRITEPOS = 8, RB_AVAIL = 12, RB_SIZE = 16, RB_DATA = 20,
       RB_CALLBACK = 24, RB_CBARG = 28, RB_UPPER = 32, RB_SEMA = 36, RB_MPEG = 40, RB_GP = 44 };

/* A FIFO of bytes; `base` counts the bytes ever removed, so positions in the
 * stream (for PES timestamps) stay meaningful as it drains. */
typedef struct {
    uint8_t *p;
    uint32_t off, len, cap;
    uint64_t base;
} fifo;

static int fifo_push(fifo *f, const uint8_t *src, uint32_t n) {
    if (f->off && f->off + f->len + n > f->cap) {
        memmove(f->p, f->p + f->off, f->len);
        f->off = 0;
    }
    if (f->len + n > f->cap) {
        uint32_t cap = f->cap ? f->cap : 65536;
        while (cap < f->len + n) cap *= 2;
        uint8_t *q = (uint8_t *)realloc(f->p, cap);
        if (!q) return -1;
        f->p = q;
        f->cap = cap;
    }
    memcpy(f->p + f->off + f->len, src, n);
    f->len += n;
    return 0;
}
static const uint8_t *fifo_data(const fifo *f) { return f->p + f->off; }
static void fifo_pop(fifo *f, uint32_t n) {
    if (n > f->len) n = f->len;
    f->off += n;
    f->len -= n;
    f->base += n;
    if (!f->len) f->off = 0;
}
static void fifo_clear(fifo *f) { f->base += f->len; f->off = f->len = 0; }
static void fifo_free(fifo *f) { free(f->p); memset(f, 0, sizeof *f); }

#define MAX_PTS 64
typedef struct { uint64_t at; int64_t pts; } pts_mark;

typedef struct {
    int      used;
    uint32_t handle;               /* dataPtr + 0x30, what *mpeg holds */
    uint32_t ring;
    uint32_t frame_width;          /* Create's default for AvcCsc */
    int      pixel_mode;           /* GE format 0..3 */
    int      es_buf[2];

    /* PSMF header */
    int      analyzed;
    uint32_t stream_size;
    int64_t  first_ts;
    int      hdr_w, hdr_h;

    struct { int used; uint32_t sid; int type, num, needs_reset; } st[MAX_STREAMS];
    int      video_num, audio_num;

    /* demultiplexing */
    fifo     raw;                  /* program stream not yet parsed (partial packs) */
    fifo     ves, aes;             /* H.264 and ATRAC elementary streams */
    pts_mark vpts_q[MAX_PTS];
    int      vpts_n;
    uint64_t put_bytes;
    int      eos;                  /* the whole stream has been read */
    int64_t  last_in_pts;

    /* video */
    void    *vdec;
    const psp_video_codec *vcodec; /* the codec vdec belongs to */
    uint32_t *pic;                 /* the last picture, ABGR8888 (R in the low byte) */
    int      pic_w, pic_h, have_pic;
    int64_t  vpts;                 /* relative to first_ts */
    int      video_end;
    uint32_t frames;
    uint32_t frame_status, decode_result;
    int      warned;

    /* audio */
    void    *adec;
    const psp_atrac_codec *acodec;
    int      a_channels, a_block;
    uint32_t a_frames;
} mpeg_ctx;

static mpeg_ctx g_mp[MAX_MPEG];
static uint32_t g_sid = 1;
static const psp_video_codec *g_vcodec;

void psp_mpeg_set_video_codec(const psp_video_codec *codec) { g_vcodec = codec; }

static void delay(uint32_t us) {
    if (psp_sched_active()) psp_sched_sleep_until(psp_sched_now_us() + us);
}

static void decoders_close(mpeg_ctx *c) {
    if (c->vdec && c->vcodec) c->vcodec->close(c->vdec);
    c->vdec = NULL;
    c->vcodec = NULL;
    if (c->adec && c->acodec) c->acodec->close(c->adec);
    c->adec = NULL;
    c->acodec = NULL;
}

/* Forget everything about the stream being played (a new movie, a flush). */
static void stream_reset(mpeg_ctx *c) {
    decoders_close(c);
    fifo_clear(&c->raw);
    fifo_clear(&c->ves);
    fifo_clear(&c->aes);
    c->vpts_n = 0;
    c->put_bytes = 0;
    c->eos = 0;
    c->last_in_pts = -1;
    c->have_pic = 0;
    c->vpts = 0;
    c->video_end = 0;
    c->frames = 0;
    c->frame_status = 0;
    c->decode_result = 1;
    c->a_frames = 0;
}

static void ctx_free(mpeg_ctx *c) {
    decoders_close(c);
    fifo_free(&c->raw);
    fifo_free(&c->ves);
    fifo_free(&c->aes);
    free(c->pic);
    memset(c, 0, sizeof *c);
}

void psp_mpeg_reset(void) {
    for (int i = 0; i < MAX_MPEG; i++) if (g_mp[i].used) ctx_free(&g_mp[i]);
    g_sid = 1;
}
void psp_mpeg_init(void) { psp_mpeg_reset(); }

/* The context behind a game's mpeg handle (the address holding it). */
static mpeg_ctx *ctx_of(uint32_t mpeg) {
    if (!mpeg) return NULL;
    uint32_t h = psp_read32(mpeg);
    for (int i = 0; i < MAX_MPEG; i++) if (g_mp[i].used && g_mp[i].handle == h) return &g_mp[i];
    return NULL;
}

static int ring_ok(uint32_t ring) { return ring && psp_mem_ptr(ring, 48) != NULL; }

/* ---- PSMF header ------------------------------------------------------------- */

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static int64_t psmf_ts(const uint8_t *p) {   /* 48-bit big-endian */
    return (int64_t)p[0] << 40 | (int64_t)p[1] << 32 | (int64_t)be32(p + 2);
}

typedef struct { uint32_t magic, offset, size; int version_ok; int64_t first; int w, h; } psmf_info;

static int psmf_read(uint32_t addr, psmf_info *pi) {
    uint8_t h[0x90];
    memset(pi, 0, sizeof *pi);
    if (psp_mem_read_block(h, addr, sizeof h) != 0) return -1;
    pi->magic = (uint32_t)h[0] | (uint32_t)h[1] << 8 | (uint32_t)h[2] << 16 | (uint32_t)h[3] << 24;
    /* version: "0012", "0013", "0014", "0015" */
    pi->version_ok = h[4] == '0' && h[5] == '0' && h[6] == '1' && h[7] >= '2' && h[7] <= '5';
    pi->offset = be32(h + 8);
    pi->size = be32(h + 12);
    pi->first = psmf_ts(h + 0x54);
    pi->w = h[142] * 16;
    pi->h = h[143] * 16;
    return 0;
}

/* ---- demultiplexing -------------------------------------------------------- */

static void ves_mark_pts(mpeg_ctx *c, int64_t pts) {
    if (c->vpts_n == MAX_PTS) { memmove(c->vpts_q, c->vpts_q + 1, sizeof c->vpts_q[0] * (MAX_PTS - 1)); c->vpts_n--; }
    c->vpts_q[c->vpts_n].at = c->ves.base + c->ves.len;
    c->vpts_q[c->vpts_n].pts = pts;
    c->vpts_n++;
}

static int64_t read_pts(const uint8_t *p) {
    return (int64_t)(p[0] >> 1 & 7) << 30 | (int64_t)p[1] << 22 | (int64_t)(p[2] >> 1) << 15 |
           (int64_t)p[3] << 7 | (p[4] >> 1);
}

/* One PES packet: id 0xE0..0xEF (video) or 0xBD (private stream 1: audio). */
static void pes(mpeg_ctx *c, int id, const uint8_t *p, uint32_t len) {
    if (len < 3 || (p[0] & 0xC0) != 0x80) return;             /* MPEG-2 PES header only */
    const uint32_t flags = p[1], hlen = p[2];
    if (3 + hlen > len) return;
    int64_t pts = -1;
    if ((flags & 0x80) && hlen >= 5) pts = read_pts(p + 3);
    const uint8_t *pay = p + 3 + hlen;
    uint32_t n = len - 3 - hlen;

    if (id >= 0xE0 && id <= 0xEF) {
        if (id - 0xE0 != c->video_num) return;
        if (pts >= 0) ves_mark_pts(c, pts);
        fifo_push(&c->ves, pay, n);
    } else if (id == 0xBD && n >= 4) {
        const int ch = pay[0];
        uint32_t skip = 4;                         /* the sub-stream id and a 3-byte header */
        if (ch >= 0xB0 && ch <= 0xBF) skip++;
        if (n <= skip || (ch & 0x0F) != c->audio_num || c->audio_num < 0) return;
        fifo_push(&c->aes, pay + skip, n - skip);
    }
}

/* Parse every complete pack/packet in c->raw. */
static void demux(mpeg_ctx *c) {
    const uint8_t *b = fifo_data(&c->raw);
    uint32_t n = c->raw.len, i = 0;
    while (i + 4 <= n) {
        if (b[i] != 0 || b[i + 1] != 0 || b[i + 2] != 1) { i++; continue; }
        const int code = b[i + 3];
        if (code == 0xBA) {                                    /* pack header */
            if (i + 14 > n) break;
            const uint32_t hl = (b[i + 4] & 0xC0) == 0x40 ? 14u + (b[i + 13] & 7u) : 12u;
            if (i + hl > n) break;
            i += hl;
        } else if (code == 0xB9) {                             /* program end */
            i += 4;
        } else if (code >= 0xBB) {                             /* system header and PES packets */
            if (i + 6 > n) break;
            const uint32_t len = (uint32_t)b[i + 4] << 8 | b[i + 5];
            if (i + 6 + len > n) break;
            if ((code >= 0xE0 && code <= 0xEF) || code == 0xBD) pes(c, code, b + i + 6, len);
            i += 6 + len;
        } else {
            i += 3;                                            /* not a stream start code */
        }
    }
    fifo_pop(&c->raw, i);
}

/* Packets the ring reports as filled: what is buffered and not yet decoded,
 * plus one, as the firmware never reports an empty ring once data flows. */
static uint32_t ring_filled(mpeg_ctx *c, uint32_t packets) {
    if (!c->put_bytes) return 0;
    uint64_t pending = (uint64_t)c->raw.len + c->ves.len + c->aes.len;
    uint64_t f = 1 + (pending + PACKET - 1) / PACKET;
    return f > packets ? packets : (uint32_t)f;
}

static void ring_update(mpeg_ctx *c) {
    if (!ring_ok(c->ring)) return;
    const uint32_t packets = psp_read32(c->ring + RB_PACKETS);
    psp_write32(c->ring + RB_AVAIL, ring_filled(c, packets));
}

/* ---- video ----------------------------------------------------------------- */

static int find_aud(const uint8_t *p, uint32_t from, uint32_t n) {
    for (uint32_t i = from; i + 4 <= n; i++)
        if (p[i] == 0 && p[i + 1] == 0 && p[i + 2] == 1 && (p[i + 3] & 0x1F) == 9)
            return (int)(i > from && p[i - 1] == 0 ? i - 1 : i);      /* a 4-byte start code */
    return -1;
}

/* The next access unit, from the head of the stream up to the next access
 * unit delimiter (or to the end once the whole stream is in). */
static int next_au(mpeg_ctx *c, uint32_t *len, int64_t *pts) {
    const uint8_t *p = fifo_data(&c->ves);
    const uint32_t n = c->ves.len;
    if (!n) return 0;
    int start = find_aud(p, 0, n);
    if (start > 0) { fifo_pop(&c->ves, (uint32_t)start); return next_au(c, len, pts); }   /* junk before the first */
    int end = find_aud(p, 4, n);
    if (end < 0) {
        if (c->eos || (start < 0 && n > 0x100000)) end = (int)n;
        else return 0;
    }
    *len = (uint32_t)end;
    /* a PES timestamp belongs to the first unit starting at or after it */
    const uint64_t at = c->ves.base;
    *pts = -1;
    int k = 0;
    while (k < c->vpts_n && c->vpts_q[k].at <= at) *pts = c->vpts_q[k++].pts;
    if (k) { memmove(c->vpts_q, c->vpts_q + k, sizeof c->vpts_q[0] * (size_t)(c->vpts_n - k)); c->vpts_n -= k; }
    if (*pts < 0) *pts = c->last_in_pts < 0 ? c->first_ts : c->last_in_pts + VIDEO_PTS_STEP;
    c->last_in_pts = *pts;
    return 1;
}

static uint8_t clamp8(int v) { return (uint8_t)(v < 0 ? 0 : v > 255 ? 255 : v); }

static void keep_picture(mpeg_ctx *c, const psp_video_frame *f) {
    if (f->width <= 0 || f->height <= 0 || f->width > 1024 || f->height > 1024) return;
    if (c->pic_w * c->pic_h < f->width * f->height) {
        uint32_t *q = (uint32_t *)realloc(c->pic, (size_t)f->width * f->height * 4);
        if (!q) return;
        c->pic = q;
    }
    c->pic_w = f->width;
    c->pic_h = f->height;
    /* BT.601, studio range */
    for (int y = 0; y < f->height; y++) {
        const uint8_t *yr = f->y + (size_t)y * f->ystride;
        const uint8_t *ur = f->u + (size_t)(y >> 1) * f->uvstride, *vr = f->v + (size_t)(y >> 1) * f->uvstride;
        uint32_t *o = c->pic + (size_t)y * f->width;
        for (int x = 0; x < f->width; x++) {
            const int Y = 298 * (yr[x] - 16), U = ur[x >> 1] - 128, V = vr[x >> 1] - 128;
            const uint8_t r = clamp8((Y + 409 * V + 128) >> 8);
            const uint8_t g = clamp8((Y - 100 * U - 208 * V + 128) >> 8);
            const uint8_t b = clamp8((Y + 516 * U + 128) >> 8);
            o[x] = (uint32_t)r | (uint32_t)g << 8 | (uint32_t)b << 16;
        }
    }
    c->have_pic = 1;
}

/* Decode until a picture comes out. 1 = a new picture, 0 = none (yet). */
static int decode_picture(mpeg_ctx *c) {
    if (g_vcodec && !c->vdec && c->vcodec != g_vcodec) {
        c->vcodec = g_vcodec;
        c->vdec = g_vcodec->open();
    }
    if (!c->warned) {
        c->warned = 1;
        fprintf(stderr, "mpeg: movie %dx%d, video codec %s\n", c->hdr_w, c->hdr_h,
                c->vdec ? c->vcodec->name : "none (black frames)");
    }
    for (int tries = 0; tries < 16; tries++) {
        uint32_t len;
        int64_t pts;
        psp_video_frame f;
        if (!next_au(c, &len, &pts)) {
            if (!c->eos) return 0;
            /* the end: pictures still held for reordering, then nothing */
            if (c->vdec && c->vcodec->decode(c->vdec, NULL, 0, 0, &f) == 1) {
                keep_picture(c, &f);
                c->vpts = f.pts - c->first_ts;
                return 1;
            }
            c->video_end = 1;
            return 0;
        }
        if (!c->vdec) {                       /* no codec: count the picture */
            fifo_pop(&c->ves, len);
            c->vpts = pts - c->first_ts;
            return 1;
        }
        const int r = c->vcodec->decode(c->vdec, fifo_data(&c->ves), (int)len, pts, &f);
        fifo_pop(&c->ves, len);
        if (r < 0) {
            fprintf(stderr, "mpeg: %s gave up; the rest of the movie is black\n", c->vcodec->name);
            c->vcodec->close(c->vdec);
            c->vdec = NULL;                   /* c->vcodec stays set: no reopen */
            c->have_pic = 0;
            return 1;
        }
        if (r == 1) {
            keep_picture(c, &f);
            c->vpts = f.pts - c->first_ts;
            return 1;
        }
    }
    return 0;
}

/* ---- audio ----------------------------------------------------------------- */

/* The next ATRAC3plus frame: an 8-byte header 0F D0 c1 c2 ..., then
 * ((((c1 & 3) << 8) | c2) + 1) * 8 bytes. 0 if none is complete. */
static int next_audio(mpeg_ctx *c, uint32_t *skip, uint32_t *size, int *channels) {
    const uint8_t *p = fifo_data(&c->aes);
    const uint32_t n = c->aes.len;
    for (uint32_t i = 0; i + 8 <= n; i++) {
        if (p[i] != 0x0F || p[i + 1] != 0xD0) continue;
        const uint32_t sz = ((((uint32_t)p[i + 2] & 3) << 8 | p[i + 3]) + 1) * 8;
        if (i + 8 + sz > n) return 0;
        *skip = i;
        *size = sz;
        *channels = (p[i + 2] >> 2) & 7;
        return 1;
    }
    return 0;
}

static int audio_ready(mpeg_ctx *c) {
    uint32_t s, z;
    int ch;
    return next_audio(c, &s, &z, &ch);
}

/* Decode the next audio frame into `out` (8192 bytes, already zeroed). */
static void decode_audio(mpeg_ctx *c, uint32_t out) {
    uint32_t skip, size;
    int ch;
    if (!next_audio(c, &skip, &size, &ch)) return;
    const psp_atrac_codec *ac = psp_atrac_get_codec();
    if (ac && (!c->adec || c->acodec != ac || c->a_channels != ch || c->a_block != (int)size)) {
        if (c->adec && c->acodec) c->acodec->close(c->adec);
        c->acodec = ac;
        c->a_channels = ch;
        c->a_block = (int)size;
        c->adec = ac->open(1, ch ? ch : 2, (int)size, 44100);
    }
    if (c->adec) {
        int16_t pcm[2048 * 2];
        const int got = c->acodec->decode(c->adec, fifo_data(&c->aes) + skip + 8, (int)size, pcm, 2048);
        if (got > 0) psp_mem_write_block(out, pcm, (uint32_t)got * 4);
    }
    fifo_pop(&c->aes, skip + 8 + size);
    c->a_frames++;
}

/* ---- SceMpegAu ------------------------------------------------------------- */

static void au_write(uint32_t au, int64_t pts, int64_t dts) {
    psp_write32(au + 0, (uint32_t)((uint64_t)pts >> 32));
    psp_write32(au + 4, (uint32_t)pts);
    psp_write32(au + 8, (uint32_t)((uint64_t)dts >> 32));
    psp_write32(au + 12, (uint32_t)dts);
}

static int stream_of(mpeg_ctx *c, uint32_t sid) {
    for (int i = 0; i < MAX_STREAMS; i++) if (c->st[i].used && c->st[i].sid == sid) return i;
    return -1;
}

/* ---- the calls ------------------------------------------------------------- */

static void hle_Init(void)  { psp_ret(0); delay(750); }
static void hle_Finish(void) { psp_ret(0); delay(250); }
static void hle_QueryMemSize(void) { psp_ret(MEMSIZE); }
static void hle_RingbufferQueryMemSize(void) { psp_ret(psp_arg(0) * (104 + PACKET)); }
static void hle_RingbufferDestruct(void) { psp_ret(0); }

static void hle_RingbufferConstruct(void) {
    const uint32_t ring = psp_arg(0), packets = psp_arg(1), data = psp_arg(2), size = psp_arg(3);
    const uint32_t cb = psp_arg(4), cbarg = psp_arg(5);
    if (!ring_ok(ring)) { psp_ret(ERR_ILLEGAL_ADDR); return; }
    if ((int32_t)size < 0) { psp_ret(ERR_NO_MEMORY); return; }
    if ((uint64_t)packets * (104 + PACKET) > size && packets < 0x00100000) { psp_ret(ERR_NO_MEMORY); return; }
    psp_write32(ring + RB_PACKETS, packets);
    psp_write32(ring + RB_READ, 0);
    psp_write32(ring + RB_WRITEPOS, 0);
    psp_write32(ring + RB_AVAIL, 0);
    psp_write32(ring + RB_SIZE, PACKET);
    psp_write32(ring + RB_DATA, data);
    psp_write32(ring + RB_CALLBACK, cb);
    psp_write32(ring + RB_CBARG, cbarg);
    psp_write32(ring + RB_UPPER, data + packets * PACKET);
    psp_write32(ring + RB_MPEG, 0);
    psp_write32(ring + RB_GP, psp_cpu.r[28]);
    psp_ret(0);
}

static void hle_Create(void) {
    const uint32_t mpeg = psp_arg(0), data = psp_arg(1), size = psp_arg(2), ring = psp_arg(3);
    const uint32_t frame_width = psp_arg(4);
    if (!mpeg || !psp_mem_ptr(mpeg, 4)) { psp_ret(0xFFFFFFFFu); return; }
    if (size < MEMSIZE) { psp_ret(ERR_NO_MEMORY); return; }
    const uint32_t handle = data + 0x30;
    mpeg_ctx *c = NULL;
    for (int i = 0; i < MAX_MPEG && !c; i++) if (g_mp[i].used && g_mp[i].handle == handle) { ctx_free(&g_mp[i]); c = &g_mp[i]; }
    for (int i = 0; i < MAX_MPEG && !c; i++) if (!g_mp[i].used) c = &g_mp[i];
    if (!c) { fprintf(stderr, "mpeg: more than %d players\n", MAX_MPEG); psp_ret(ERR_NO_MEMORY); return; }
    memset(c, 0, sizeof *c);
    c->used = 1;
    c->handle = handle;
    c->ring = ring;
    c->frame_width = frame_width;
    c->pixel_mode = 3;
    c->video_num = 0;
    c->audio_num = 0;
    stream_reset(c);

    if (ring_ok(ring)) {
        const uint32_t ps = psp_read32(ring + RB_SIZE);
        const uint32_t packets = psp_read32(ring + RB_PACKETS);
        psp_write32(ring + RB_AVAIL, ps ? packets - (psp_read32(ring + RB_UPPER) - psp_read32(ring + RB_DATA)) / ps : 0);
        psp_write32(ring + RB_MPEG, mpeg);
    }
    psp_write32(mpeg, handle);
    psp_mem_write_block(handle, "LIBMPEG\0" "001\0", 12);
    psp_write32(handle + 12, 0xFFFFFFFFu);
    if (ring_ok(ring)) {
        psp_write32(handle + 16, ring);
        psp_write32(handle + 20, psp_read32(ring + RB_UPPER));
    }
    psp_ret(0);
    delay(29000);
}

static void hle_Delete(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    ctx_free(c);
    psp_ret(0);
    delay(40000);
}

static void hle_QueryStreamOffset(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t buf = psp_arg(1), out = psp_arg(2);
    if (!psp_mem_ptr(buf, 0x90) || !psp_mem_ptr(out, 4)) { psp_ret(0xFFFFFFFFu); return; }
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    psmf_info pi;
    psmf_read(buf, &pi);
    if (pi.magic != PSMF_MAGIC) { psp_write32(out, 0); psp_ret(ERR_INVALID_VALUE); return; }
    if (!pi.version_ok) { psp_write32(out, 0); psp_ret(ERR_BAD_VERSION); return; }
    if ((pi.offset & 2047) || !pi.offset) { psp_write32(out, 0); psp_ret(ERR_INVALID_VALUE); return; }
    if (!c->analyzed) {                     /* a new movie */
        stream_reset(c);
        c->analyzed = 1;
    }
    c->stream_size = pi.size;
    c->first_ts = pi.first;
    c->hdr_w = pi.w;
    c->hdr_h = pi.h;
    c->warned = 0;
    psp_write32(out, pi.offset);
    psp_ret(0);
}

static void hle_QueryStreamSize(void) {
    const uint32_t buf = psp_arg(0), out = psp_arg(1);
    if (!psp_mem_ptr(buf, 0x90) || !psp_mem_ptr(out, 4)) { psp_ret(0xFFFFFFFFu); return; }
    psmf_info pi;
    psmf_read(buf, &pi);
    if (pi.magic != PSMF_MAGIC || (pi.offset & 2047)) { psp_write32(out, 0); psp_ret(ERR_INVALID_VALUE); return; }
    psp_write32(out, pi.size);
    psp_ret(0);
}

static void hle_RegistStream(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const int type = (int)psp_arg(1), num = (int)psp_arg(2);
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    int i = 0;
    while (i < MAX_STREAMS && c->st[i].used) i++;
    if (i == MAX_STREAMS) i = 0;                      /* reuse the oldest slot */
    c->st[i].used = 1;
    c->st[i].sid = g_sid++;
    c->st[i].type = type;
    c->st[i].num = num;
    c->st[i].needs_reset = 1;
    if (type == ST_AVC) c->video_num = num & 15;
    else if (type == ST_ATRAC || type == ST_AUDIO) c->audio_num = num & 15;
    psp_ret(c->st[i].sid);
}

static void hle_UnRegistStream(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    const int i = stream_of(c, psp_arg(1));
    if (i >= 0) c->st[i].used = 0;
    c->analyzed = 0;
    psp_ret(0);
}

static void hle_MallocAvcEsBuf(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    for (int i = 0; i < 2; i++) if (!c->es_buf[i]) { c->es_buf[i] = 1; psp_ret((uint32_t)i + 1); return; }
    psp_ret(0);
}

static void hle_FreeAvcEsBuf(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const int es = (int)psp_arg(1);
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    if (es == 0) { psp_ret(ERR_INVALID_VALUE); return; }
    if (es >= 1 && es <= 2) c->es_buf[es - 1] = 0;
    psp_ret(0);
}

static void hle_InitAu(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t es = psp_arg(1), au = psp_arg(2);
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    if (es >= 1 && es <= 2 && c->es_buf[es - 1]) {
        au_write(au, 0, 0);
        psp_write32(au + 16, 0);
        psp_write32(au + 20, AVC_ES_SIZE);
    } else {
        au_write(au, 0, -1);
        psp_write32(au + 16, 0);
        psp_write32(au + 20, ATRAC_ES_SIZE);
    }
    psp_ret(0);
}

static void hle_QueryAtracEsSize(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t es = psp_arg(1), out = psp_arg(2);
    if (!psp_mem_ptr(es, 4) || !psp_mem_ptr(out, 4)) { psp_ret(0xFFFFFFFFu); return; }
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    psp_write32(es, ATRAC_ES_SIZE);
    psp_write32(out, ATRAC_OUT_SIZE);
    psp_ret(0);
}

static void hle_QueryUserdataEsSize(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t es = psp_arg(1), out = psp_arg(2);
    if (!psp_mem_ptr(es, 4) || !psp_mem_ptr(out, 4) || !c) { psp_ret(0xFFFFFFFFu); return; }
    psp_write32(es, DATA_ES_SIZE);
    psp_write32(out, DATA_ES_SIZE);
    psp_ret(0);
}

static void hle_RingbufferAvailableSize(void) {
    const uint32_t ring = psp_arg(0);
    if (!ring_ok(ring)) { psp_ret(ERR_ILLEGAL_ADDR); return; }
    mpeg_ctx *c = ctx_of(psp_read32(ring + RB_MPEG));
    if (!c) { psp_ret(ERR_NOT_YET_INIT); return; }
    c->ring = ring;
    const uint32_t packets = psp_read32(ring + RB_PACKETS);
    if (c->analyzed) psp_write32(ring + RB_AVAIL, ring_filled(c, packets));
    psp_ret(packets - psp_read32(ring + RB_AVAIL));
}

/* Fill free packets through the game's read callback, which may need several
 * calls when the free space wraps around the end of the ring. */
static void hle_RingbufferPut(void) {
    const uint32_t ring = psp_arg(0);
    int32_t want = (int32_t)psp_arg(1);
    const int32_t available = (int32_t)psp_arg(2);
    if (!ring_ok(ring)) { psp_ret(0xFFFFFFFFu); return; }
    const int32_t packets = (int32_t)psp_read32(ring + RB_PACKETS);
    if (want > available) want = available;
    if (want > packets - (int32_t)psp_read32(ring + RB_AVAIL)) want = packets - (int32_t)psp_read32(ring + RB_AVAIL);
    if (want <= 0 || packets <= 0) { psp_ret(0); return; }
    mpeg_ctx *c = ctx_of(psp_read32(ring + RB_MPEG));
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    const uint32_t cb = psp_read32(ring + RB_CALLBACK), data = psp_read32(ring + RB_DATA);
    if (!cb) { psp_ret(0); return; }

    int32_t total = 0;
    while (want > 0) {
        const int32_t wo = (int32_t)(psp_read32(ring + RB_WRITEPOS) % (uint32_t)packets);
        const int32_t n = want < packets - wo ? want : packets - wo;
        const uint32_t dest = data + (uint32_t)wo * PACKET;
        int32_t got = (int32_t)psp_call_guest(cb, dest, (uint32_t)n, psp_read32(ring + RB_CBARG));
        if (got < 0) { if (!total) { psp_ret((uint32_t)got); return; } break; }
        if (got > n) got = n;
        if (got) {
            const uint8_t *src = (const uint8_t *)psp_mem_ptr(dest, (uint32_t)got * PACKET);
            if (src) {
                fifo_push(&c->raw, src, (uint32_t)got * PACKET);
                c->put_bytes += (uint64_t)got * PACKET;
                c->video_end = 0;
                demux(c);
            }
            psp_write32(ring + RB_READ, psp_read32(ring + RB_READ) + (uint32_t)got);
            psp_write32(ring + RB_WRITEPOS, psp_read32(ring + RB_WRITEPOS) + (uint32_t)got);
        }
        total += got;
        want -= got;
        if (got < n) {                        /* the file ran out */
            if (got == 0 && c->put_bytes) c->eos = 1;
            break;
        }
    }
    if (c->stream_size && c->put_bytes >= c->stream_size) c->eos = 1;
    c->analyzed = 1;
    psp_write32(ring + RB_AVAIL, ring_filled(c, (uint32_t)packets));
    psp_ret((uint32_t)total);
}

static void hle_GetAvcAu(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t sid = psp_arg(1), au = psp_arg(2), attr = psp_arg(3);
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    if (!ring_ok(c->ring)) { psp_ret(0xFFFFFFFFu); return; }
    if (!psp_read32(c->ring + RB_READ) || !psp_read32(c->ring + RB_AVAIL)) {
        au_write(au, 0, 0);
        psp_ret(ERR_NO_DATA);
        delay(2000);
        return;
    }
    const int i = stream_of(c, sid);
    if (i < 0) { psp_ret(0xFFFFFFFFu); return; }
    c->st[i].needs_reset = 0;
    psp_write32(au + 16, (uint32_t)c->st[i].num);
    const int64_t pts = c->vpts + c->first_ts;
    if (c->video_end) {
        au_write(au, pts, -1);
        psp_ret(ERR_NO_DATA);
        delay(100);
        return;
    }
    au_write(au, pts, pts - VIDEO_PTS_STEP);
    if (attr && psp_mem_ptr(attr, 4)) psp_write32(attr, 1);
    psp_ret(0);
    delay(100);
}

static void hle_AvcDecodeYCbCr(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t au = psp_arg(1), bufp = psp_arg(2), initp = psp_arg(3);
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    if (!ring_ok(c->ring)) { psp_ret(0xFFFFFFFFu); return; }
    if (!psp_read32(c->ring + RB_READ) || c->video_end) { psp_ret(ERR_AVC_DECODE_FATAL); delay(320); return; }
    if (!psp_mem_ptr(bufp, 4) || !psp_mem_ptr(initp, 4)) { psp_ret(0xFFFFFFFFu); return; }

    c->frame_status = (uint32_t)decode_picture(c);
    if (c->frame_status) c->frames++;
    ring_update(c);
    const int64_t pts = c->vpts + c->first_ts;
    psp_write32(au + 0, (uint32_t)((uint64_t)pts >> 32));
    psp_write32(au + 4, (uint32_t)pts);
    psp_write32(initp, 1);                    /* libmpeg 0x010A and later */
    c->decode_result = 1;
    psp_ret(0);
    delay(c->frames <= 1 ? 3600 : 5400);
}

static void hle_AvcDecodeStopYCbCr(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t status = psp_arg(2);
    if (!c || !psp_mem_ptr(status, 4)) { psp_ret(0xFFFFFFFFu); return; }
    psp_write32(status, 0);
    psp_ret(0);
}

static void hle_AvcDecodeDetail(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t d = psp_arg(1);
    if (!psp_mem_ptr(d, 36)) { psp_ret(0xFFFFFFFFu); return; }
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    psp_write32(d + 0, c->decode_result);
    psp_write32(d + 4, c->frames);
    psp_write32(d + 8, (uint32_t)(c->have_pic ? c->pic_w : c->hdr_w));
    psp_write32(d + 12, (uint32_t)(c->have_pic ? c->pic_h : c->hdr_h));
    for (uint32_t o = 16; o < 32; o += 4) psp_write32(d + o, 0);
    psp_write32(d + 32, c->frame_status);
    psp_ret(0);
}

static void hle_AvcDecodeMode(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t m = psp_arg(1);
    if (!psp_mem_ptr(m, 8)) { psp_ret(0xFFFFFFFFu); return; }
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    const uint32_t pm = psp_read32(m + 4);
    if (pm <= 3) c->pixel_mode = (int)pm;
    psp_ret(0);
}

static void hle_AvcDecodeFlush(void) { psp_ret(ctx_of(psp_arg(0)) ? 0 : 0xFFFFFFFFu); }

static void hle_AvcInitYCbCr(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    if (!psp_mem_ptr(psp_arg(4), 4) || !c) { psp_ret(0xFFFFFFFFu); return; }
    psp_ret(0);
}

static void hle_AvcQueryYCbCrSize(void) {
    const uint32_t w = psp_arg(2), h = psp_arg(3), out = psp_arg(4);
    if ((w & 15) || (h & 15) || w > 480 || h > 272) { psp_ret(ERR_INVALID_VALUE); return; }
    if (psp_mem_ptr(out, 4)) psp_write32(out, (w / 2) * (h / 2) * 6 + 128);
    psp_ret(0);
}

/* The picture, region (x, y, w, h) of it, into the game's buffer in the
 * decode mode's pixel format, `frame_width` pixels per line. Alpha is 0. */
static void hle_AvcCsc(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t range = psp_arg(2), dest = psp_arg(4);
    int fw = (int)psp_arg(3);
    if (!psp_mem_ptr(psp_arg(1), 4) || !psp_mem_ptr(range, 16) || !psp_mem_ptr(dest, 4)) { psp_ret(0xFFFFFFFFu); return; }
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    if (!fw) fw = c->frame_width ? (int)c->frame_width : c->hdr_w;
    int x = (int)psp_read32(range), y = (int)psp_read32(range + 4);
    int w = (int)psp_read32(range + 8), h = (int)psp_read32(range + 12);
    if (x < 0 || y < 0 || w < 0 || h < 0) { psp_ret(ERR_KERNEL_INVALID); return; }
    const int bpp = c->pixel_mode == 3 ? 4 : 2;
    if (fw <= 0 || fw > 2048) { psp_ret(0); return; }
    const int pw = c->have_pic ? c->pic_w : c->hdr_w, ph = c->have_pic ? c->pic_h : c->hdr_h;
    if (w > pw - x) w = pw - x;
    if (h > ph - y) h = ph - y;
    if (w > fw) w = fw;
    for (int row = 0; row < h; row++) {
        uint8_t *o = (uint8_t *)psp_mem_ptr(dest + (uint32_t)(row * fw * bpp), (uint32_t)(w * bpp));
        if (!o) break;
        if (!c->have_pic) { memset(o, 0, (size_t)w * bpp); continue; }
        const uint32_t *s = c->pic + (size_t)(y + row) * c->pic_w + x;
        switch (c->pixel_mode) {
        case 0: for (int i = 0; i < w; i++) { const uint32_t p = s[i];
                    const uint16_t v = (uint16_t)((p >> 3 & 0x1F) | (p >> 10 & 0x3F) << 5 | (p >> 19 & 0x1F) << 11);
                    o[i * 2] = (uint8_t)v; o[i * 2 + 1] = (uint8_t)(v >> 8); } break;
        case 1: for (int i = 0; i < w; i++) { const uint32_t p = s[i];
                    const uint16_t v = (uint16_t)((p >> 3 & 0x1F) | (p >> 11 & 0x1F) << 5 | (p >> 19 & 0x1F) << 10);
                    o[i * 2] = (uint8_t)v; o[i * 2 + 1] = (uint8_t)(v >> 8); } break;
        case 2: for (int i = 0; i < w; i++) { const uint32_t p = s[i];
                    const uint16_t v = (uint16_t)((p >> 4 & 0xF) | (p >> 12 & 0xF) << 4 | (p >> 20 & 0xF) << 8);
                    o[i * 2] = (uint8_t)v; o[i * 2 + 1] = (uint8_t)(v >> 8); } break;
        default: memcpy(o, s, (size_t)w * 4); break;             /* alpha already 0 */
        }
    }
    psp_ret(0);
    delay(4000);
}

static void hle_GetAtracAu(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t sid = psp_arg(1), au = psp_arg(2), attr = psp_arg(3);
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    if (!ring_ok(c->ring)) { psp_ret(0xFFFFFFFFu); return; }
    const int i = stream_of(c, sid);
    if (i >= 0 && c->st[i].needs_reset) c->st[i].needs_reset = 0;
    if (!psp_read32(c->ring + RB_AVAIL)) {
        au_write(au, 0, 0);
        psp_ret(ERR_NO_DATA);
        delay(100);
        return;
    }
    if (i >= 0) psp_write32(au + 16, (uint32_t)c->st[i].num);
    const int64_t pts = (int64_t)c->a_frames * AUDIO_PTS_STEP + c->first_ts;
    if (!audio_ready(c)) {
        au_write(au, pts, -1);
        psp_ret(ERR_NO_DATA);
        delay(100);
        return;
    }
    au_write(au, pts, pts);
    if (attr && psp_mem_ptr(attr, 4)) psp_write32(attr, 0);
    psp_ret(0);
    delay(100);
}

static void hle_AtracDecode(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t au = psp_arg(1), out = psp_arg(2);
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    uint8_t *o = (uint8_t *)psp_mem_ptr(out, ATRAC_OUT_SIZE);
    if (!o) { psp_ret(0xFFFFFFFFu); return; }
    memset(o, 0, ATRAC_OUT_SIZE);
    decode_audio(c, out);
    const int64_t pts = (int64_t)c->a_frames * AUDIO_PTS_STEP + c->first_ts;
    psp_write32(au + 0, (uint32_t)((uint64_t)pts >> 32));
    psp_write32(au + 4, (uint32_t)pts);
    ring_update(c);
    psp_ret(0);
    delay(3000);
}

static void hle_GetUserdataAu(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    const uint32_t res = psp_arg(3);
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    if (psp_mem_ptr(res, 8)) { psp_write32(res, 0); psp_write32(res + 4, 0); }
    psp_ret(ERR_NO_DATA);                     /* no user data is demultiplexed */
}

static void hle_FlushAllStream(void) {
    mpeg_ctx *c = ctx_of(psp_arg(0));
    if (!c) { psp_ret(0xFFFFFFFFu); return; }
    c->analyzed = 0;
    stream_reset(c);
    if (ring_ok(c->ring)) {
        psp_write32(c->ring + RB_AVAIL, 0);
        psp_write32(c->ring + RB_READ, 0);
        psp_write32(c->ring + RB_WRITEPOS, 0);
    }
    psp_ret(0);
}

void psp_mpeg_register(void) {
    psp_hle_register(0x682A619B, "sceMpeg", "sceMpegInit",                    hle_Init);
    psp_hle_register(0x874624D6, "sceMpeg", "sceMpegFinish",                  hle_Finish);
    psp_hle_register(0xC132E22F, "sceMpeg", "sceMpegQueryMemSize",            hle_QueryMemSize);
    psp_hle_register(0xD7A29F46, "sceMpeg", "sceMpegRingbufferQueryMemSize",  hle_RingbufferQueryMemSize);
    psp_hle_register(0x37295ED8, "sceMpeg", "sceMpegRingbufferConstruct",     hle_RingbufferConstruct);
    psp_hle_register(0x13407F13, "sceMpeg", "sceMpegRingbufferDestruct",      hle_RingbufferDestruct);
    psp_hle_register(0xB5F6DC87, "sceMpeg", "sceMpegRingbufferAvailableSize", hle_RingbufferAvailableSize);
    psp_hle_register(0xB240A59E, "sceMpeg", "sceMpegRingbufferPut",           hle_RingbufferPut);
    psp_hle_register(0xD8C5F121, "sceMpeg", "sceMpegCreate",                  hle_Create);
    psp_hle_register(0x606A4649, "sceMpeg", "sceMpegDelete",                  hle_Delete);
    psp_hle_register(0x21FF80E4, "sceMpeg", "sceMpegQueryStreamOffset",       hle_QueryStreamOffset);
    psp_hle_register(0x611E9E11, "sceMpeg", "sceMpegQueryStreamSize",         hle_QueryStreamSize);
    psp_hle_register(0x42560F23, "sceMpeg", "sceMpegRegistStream",            hle_RegistStream);
    psp_hle_register(0x591A4AA2, "sceMpeg", "sceMpegUnRegistStream",          hle_UnRegistStream);
    psp_hle_register(0xA780CF7E, "sceMpeg", "sceMpegMallocAvcEsBuf",          hle_MallocAvcEsBuf);
    psp_hle_register(0xCEB870B1, "sceMpeg", "sceMpegFreeAvcEsBuf",            hle_FreeAvcEsBuf);
    psp_hle_register(0x167AFD9E, "sceMpeg", "sceMpegInitAu",                  hle_InitAu);
    psp_hle_register(0xF8DCB679, "sceMpeg", "sceMpegQueryAtracEsSize",        hle_QueryAtracEsSize);
    psp_hle_register(0xC45C99CC, "sceMpeg", "sceMpegQueryUserdataEsSize",     hle_QueryUserdataEsSize);
    psp_hle_register(0xFE246728, "sceMpeg", "sceMpegGetAvcAu",                hle_GetAvcAu);
    psp_hle_register(0xE1CE83A7, "sceMpeg", "sceMpegGetAtracAu",              hle_GetAtracAu);
    psp_hle_register(0x01977054, "sceMpeg", "sceMpegGetUserdataAu",           hle_GetUserdataAu);
    psp_hle_register(0xF0EB1125, "sceMpeg", "sceMpegAvcDecodeYCbCr",          hle_AvcDecodeYCbCr);
    psp_hle_register(0xF2930C9C, "sceMpeg", "sceMpegAvcDecodeStopYCbCr",      hle_AvcDecodeStopYCbCr);
    psp_hle_register(0x0F6C18D7, "sceMpeg", "sceMpegAvcDecodeDetail",         hle_AvcDecodeDetail);
    psp_hle_register(0xA11C7026, "sceMpeg", "sceMpegAvcDecodeMode",           hle_AvcDecodeMode);
    psp_hle_register(0x4571CC64, "sceMpeg", "sceMpegAvcDecodeFlush",          hle_AvcDecodeFlush);
    psp_hle_register(0x67179B1B, "sceMpeg", "sceMpegAvcInitYCbCr",            hle_AvcInitYCbCr);
    psp_hle_register(0x211A057C, "sceMpeg", "sceMpegAvcQueryYCbCrSize",       hle_AvcQueryYCbCrSize);
    psp_hle_register(0x31BD0272, "sceMpeg", "sceMpegAvcCsc",                  hle_AvcCsc);
    psp_hle_register(0x800C44DF, "sceMpeg", "sceMpegAtracDecode",             hle_AtracDecode);
    psp_hle_register(0x707B7629, "sceMpeg", "sceMpegFlushAllStream",          hle_FlushAllStream);
}
