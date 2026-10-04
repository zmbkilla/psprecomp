/* psprecomp — sceAtrac3plus.
 *
 * A game plays ATRAC3 / ATRAC3plus music by handing the library a buffer
 * holding the start of a RIFF/WAVE file and then calling DecodeData once per
 * frame, refilling the buffer through GetStreamDataInfo / AddStreamData when
 * the file is larger than the buffer. Everything about that protocol -- the
 * header, frame and sample accounting, the streaming window, end of data and
 * looping -- is implemented here.
 *
 * ## Decoding
 *
 * ATRAC3plus is a proprietary transform codec with no decoder in this
 * toolkit; the published decoders are GPL/LGPL and are kept out of this MIT
 * runtime. The host may supply one through psp_atrac_set_codec (the PSP2i
 * host loads FFmpeg's libavcodec at run time; another platform can supply its
 * own). The runtime stays codec-agnostic:
 *
 *   - every file byte the game supplies (the first buffer, then each
 *     AddStreamData chunk, copied from the window GetStreamDataInfo handed
 *     out) is kept in a host copy of the file;
 *   - DecodeData decodes, on demand, the frames covering the samples it must
 *     return, one ATRAC frame (nBlockAlign bytes) per codec call, and keeps
 *     the last two decoded frames;
 *   - a jump (loop, ResetPlayPosition) resets the codec and primes it with
 *     the frame before the target, since each frame overlaps the previous.
 *
 * The PSP counts samples after the encoder delay that the 'fact' chunk's
 * second value records, so sample s is decoded sample s + skip. Without a
 * codec (or if it fails), DecodeData produces silence of exactly the right
 * length: the game's audio thread keeps its real pacing and its control flow
 * sees correct positions, end-of-stream and loop events.
 */

#include "psprecomp/hle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ATRAC 6

#define ERR_NO_ID            0x80630003u
#define ERR_BAD_ID           0x80630005u
#define ERR_UNKNOWN_FORMAT   0x80630006u
#define ERR_NO_DATA          0x80630010u
#define ERR_SIZE_TOO_SMALL   0x80630011u
#define ERR_ADD_TOO_BIG      0x80630018u
#define ERR_NO_LOOP_INFO     0x80630021u
#define ERR_BUFFER_EMPTY     0x80630023u
#define ERR_ALL_DECODED      0x80630024u

typedef struct {
    int      used;
    uint32_t buf, bufsize;        /* the game's buffer */
    int      at3plus;
    uint32_t channels;
    uint32_t frame_bytes;         /* fmt nBlockAlign */
    uint32_t spf;                 /* samples per frame: 2048 (AT3+) or 1024 (AT3) */
    uint32_t data_off;            /* file offset of the first frame */
    uint32_t file_size;           /* data_off + data chunk size */
    int32_t  total_samples;       /* from 'fact', else derived */
    int32_t  skip;                /* 'fact' second value: decoded samples before sample 0 */
    int32_t  loop_start, loop_end;/* from 'smpl', or -1 */
    int32_t  loops;               /* remaining loops; -1 = forever */

    uint32_t written;             /* file bytes the game has supplied so far */
    uint32_t pos;                 /* file offset of the next frame to decode */
    int32_t  sample;              /* next output sample */
    int      streaming;

    uint8_t *bytes;               /* host copy of the file, [0, have) valid */
    uint32_t have;
    uint32_t last_wp;             /* where GetStreamDataInfo told the game to write */

    void    *codec;               /* the host codec's state, or NULL: silence */
    int32_t  next_frame;          /* the frame the codec expects next */
    int32_t  cache_frame[2];      /* decoded frames kept (stereo s16, spf each) */
    int16_t *cache_pcm[2];
    int      cache_next;          /* slot to replace */
} atrac;

static atrac g_at[MAX_ATRAC];
static int   g_warned;
static const psp_atrac_codec *g_codec;

void psp_atrac_set_codec(const psp_atrac_codec *codec) { g_codec = codec; }

static void release(atrac *t) {
    if (t->codec && g_codec) g_codec->close(t->codec);
    free(t->bytes);
    free(t->cache_pcm[0]);
    free(t->cache_pcm[1]);
    memset(t, 0, sizeof *t);
}

void psp_atrac_reset(void) {
    for (int i = 0; i < MAX_ATRAC; i++) if (g_at[i].used) release(&g_at[i]);
    memset(g_at, 0, sizeof g_at);
    g_warned = 0;
}
void psp_atrac_init(void) { psp_atrac_reset(); }

static uint32_t rd32(uint32_t a) { return psp_read32(a); }
static uint16_t rd16(uint32_t a) { return psp_read16(a); }

/* ---- decoding ------------------------------------------------------------------ */

static void codec_open(atrac *t) {
    t->cache_frame[0] = t->cache_frame[1] = -1;
    t->next_frame = 0;
    if (!g_codec || !t->bytes) return;
    t->cache_pcm[0] = (int16_t *)calloc(t->spf, 4);
    t->cache_pcm[1] = (int16_t *)calloc(t->spf, 4);
    if (!t->cache_pcm[0] || !t->cache_pcm[1]) return;
    t->codec = g_codec->open(t->at3plus, (int)t->channels, (int)t->frame_bytes, 44100);
}

/* Decode frame `f` into `out` (stereo s16, spf frames). 1 on success. */
static int decode_one(atrac *t, int32_t f, int16_t *out) {
    const uint32_t off = t->data_off + (uint32_t)f * t->frame_bytes;
    if (f < 0 || off + t->frame_bytes > t->have) return 0;       /* not supplied (yet) */
    int got = g_codec->decode(t->codec, t->bytes + off, (int)t->frame_bytes, out, (int)t->spf);
    if (got < 0) { g_codec->close(t->codec); t->codec = NULL; return 0; }   /* codec gave up */
    if ((uint32_t)got < t->spf) memset(out + got * 2, 0, (t->spf - (uint32_t)got) * 4);
    t->next_frame = f + 1;
    return 1;
}

/* The decoded samples of frame `f`, or NULL. */
static const int16_t *frame_pcm(atrac *t, int32_t f) {
    for (int i = 0; i < 2; i++) if (t->cache_frame[i] == f) return t->cache_pcm[i];
    if (!t->codec) return NULL;
    if (f != t->next_frame) {
        /* A jump: frames overlap their predecessor, so restart the codec
         * and run the previous frame through it first. */
        g_codec->reset(t->codec);
        int16_t *slot = t->cache_pcm[t->cache_next];
        if (f > 0 && decode_one(t, f - 1, slot)) {
            t->cache_frame[t->cache_next] = f - 1;
            t->cache_next ^= 1;
        }
        if (!t->codec) return NULL;
    }
    int16_t *slot = t->cache_pcm[t->cache_next];
    if (!decode_one(t, f, slot)) return NULL;
    t->cache_frame[t->cache_next] = f;
    t->cache_next ^= 1;
    return slot;
}

/* Write decoded samples [first, first + n) to guest `out` as stereo s16.
 * 1 if any real audio was available. */
static int decode_range(atrac *t, uint32_t first, uint32_t n, uint32_t out) {
    if (!t->codec) return 0;
    int any = 0;
    for (uint32_t i = 0; i < n; ) {
        const uint32_t idx = first + i;
        const int32_t f = (int32_t)(idx / t->spf);
        const uint32_t in = idx % t->spf;
        uint32_t k = t->spf - in;
        if (k > n - i) k = n - i;
        const int16_t *pcm = frame_pcm(t, f);
        for (uint32_t j = 0; j < k; j++) {
            uint32_t v = 0;
            if (pcm) { memcpy(&v, &pcm[(in + j) * 2], 4); any = 1; }
            psp_write32(out + (i + j) * 4, v);
        }
        i += k;
    }
    return any;
}

/* Extend the host copy of the file with `n` guest bytes at `src`, which hold
 * file bytes from offset `at`. */
static void take_bytes(atrac *t, uint32_t at, uint32_t src, uint32_t n) {
    if (!t->bytes || at > t->have || at + n <= t->have) return;   /* a gap, or nothing new */
    uint32_t skip = t->have - at, end = at + n;
    if (end > t->file_size) end = t->file_size;
    uint32_t from = t->have;
    for (uint32_t o = from; o < end; o++) t->bytes[o] = psp_read8(src + skip + (o - from));
    t->have = end;
}

/* ---- the protocol -------------------------------------------------------------- */

/* Parse the RIFF header out of guest memory. 0 or an error code. */
static uint32_t parse(atrac *t) {
    const uint32_t b = t->buf, n = t->bufsize;
    if (n < 12 || rd32(b) != 0x46464952u /* RIFF */ || rd32(b + 8) != 0x45564157u /* WAVE */)
        return ERR_UNKNOWN_FORMAT;
    t->loop_start = t->loop_end = -1;
    t->total_samples = -1;
    t->skip = 0;
    uint32_t off = 12;
    int have_fmt = 0;
    while (off + 8 <= n) {
        uint32_t id = rd32(b + off), len = rd32(b + off + 4);
        uint32_t body = off + 8;
        if (id == 0x20746D66u) {                         /* "fmt " */
            uint16_t tag = rd16(b + body);
            t->channels = rd16(b + body + 2);
            t->frame_bytes = rd16(b + body + 12);
            if (tag == 0xFFFE) t->at3plus = 1;          /* WAVE_FORMAT_EXTENSIBLE: AT3+ */
            else if (tag == 0x0270) t->at3plus = 0;     /* ATRAC3 */
            else return ERR_UNKNOWN_FORMAT;
            have_fmt = 1;
        } else if (id == 0x74636166u) {                  /* "fact" */
            t->total_samples = (int32_t)rd32(b + body);
            if (len >= 8) t->skip = (int32_t)rd32(b + body + 4);
        } else if (id == 0x6C706D73u) {                  /* "smpl" */
            if (len >= 36 + 24 && rd32(b + body + 28) >= 1) {
                t->loop_start = (int32_t)rd32(b + body + 36 + 8);
                t->loop_end   = (int32_t)rd32(b + body + 36 + 12);
            }
        } else if (id == 0x61746164u) {                  /* "data" */
            if (!have_fmt || !t->frame_bytes) return ERR_UNKNOWN_FORMAT;
            t->data_off = body;
            t->file_size = body + len;
            t->spf = t->at3plus ? 2048 : 1024;
            if (t->total_samples < 0)
                t->total_samples = (int32_t)(len / t->frame_bytes * t->spf);
            if (t->skip < 0 || t->skip > 65536) t->skip = 0;
            return 0;
        }
        off = body + ((len + 1) & ~1u);
    }
    return ERR_SIZE_TOO_SMALL;
}

static atrac *id_arg(int k) {
    int32_t id = (int32_t)psp_arg(k);
    if (id < 0 || id >= MAX_ATRAC || !g_at[id].used) return NULL;
    return &g_at[id];
}

/* (buf, bufsize) -> id */
static void hle_SetDataAndGetID(void) {
    int id = -1;
    for (int i = 0; i < MAX_ATRAC; i++) if (!g_at[i].used) { id = i; break; }
    if (id < 0) { psp_ret(ERR_NO_ID); return; }
    atrac *t = &g_at[id];
    memset(t, 0, sizeof *t);
    t->buf = psp_arg(0);
    t->bufsize = psp_arg(1);
    uint32_t err = parse(t);
    if (err) { psp_ret(err); return; }
    t->used = 1;
    t->written = t->bufsize < t->file_size ? t->bufsize : t->file_size;
    t->streaming = t->bufsize < t->file_size;
    t->pos = t->data_off;
    t->sample = 0;
    t->loops = 0;

    t->bytes = (uint8_t *)malloc(t->file_size);
    codec_open(t);
    if (!g_warned) {
        g_warned = 1;
        if (t->codec)
            fprintf(stderr, "psprecomp: ATRAC%s stream opened (%u ch, %d samples), decoding with %s\n",
                    t->at3plus ? "3plus" : "3", t->channels, t->total_samples, g_codec->name);
        else
            fprintf(stderr, "psprecomp: ATRAC%s stream opened (%u ch, %d samples). No decoder: "
                            "playback is silent (see src/hle/atrac.c)\n",
                    t->at3plus ? "3plus" : "3", t->channels, t->total_samples);
    }
    take_bytes(t, 0, t->buf, t->written);
    psp_ret((uint32_t)id);
}

static void hle_ReleaseAtracID(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    release(t);
    psp_ret(0);
}

/* Frames decodable from data already supplied; -1 when the whole file is in
 * memory (PSP_ATRAC_ALLDATA_IS_ON_MEMORY). */
static int32_t remain_frames(const atrac *t) {
    if (!t->streaming) return -1;
    if (t->written >= t->file_size && t->loops == 0) return -1;
    return (int32_t)((t->written > t->pos ? t->written - t->pos : 0) / t->frame_bytes);
}

/* (id, u16 *out, int *nsamples, int *end, int *remainFrame) */
static void hle_DecodeData(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    uint32_t out = psp_arg(1), pn = psp_arg(2), pend = psp_arg(3), prem = psp_arg(4);

    int32_t end_sample = t->total_samples;
    if (t->loop_end >= 0 && t->loops != 0) end_sample = t->loop_end + 1;

    if (t->sample >= end_sample) {
        if (t->loops != 0 && t->loop_start >= 0) {
            if (t->loops > 0) t->loops--;
            t->sample = t->loop_start;
            t->pos = t->data_off + (uint32_t)(t->loop_start / (int32_t)t->spf) * t->frame_bytes;
        } else {
            if (pn) psp_write32(pn, 0);
            if (pend) psp_write32(pend, 1);
            if (prem) psp_write32(prem, (uint32_t)remain_frames(t));
            psp_ret(ERR_ALL_DECODED);
            return;
        }
    }
    if (t->pos + t->frame_bytes > t->written) {      /* the game has not supplied it yet */
        if (pn) psp_write32(pn, 0);
        psp_ret(ERR_BUFFER_EMPTY);
        return;
    }

    uint32_t n = t->spf;
    if (t->sample + (int32_t)n > end_sample) n = (uint32_t)(end_sample - t->sample);
    /* Output is interleaved stereo s16 regardless of the source's channels. */
    if (out && !decode_range(t, (uint32_t)(t->sample + t->skip), n, out))
        for (uint32_t i = 0; i < n * 2; i++) psp_write16(out + i * 2, 0);
    t->pos += t->frame_bytes;
    t->sample += (int32_t)n;

    int done = t->sample >= end_sample && t->loops == 0;
    if (pn) psp_write32(pn, n);
    if (pend) psp_write32(pend, (uint32_t)done);
    if (prem) psp_write32(prem, (uint32_t)remain_frames(t));
    psp_ret(0);
}

static void hle_GetRemainFrame(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    if (psp_arg(1)) psp_write32(psp_arg(1), (uint32_t)remain_frames(t));
    psp_ret(0);
}

/* (id, int *endSample, int *loopStart, int *loopEnd) */
static void hle_GetSoundSample(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    if (psp_arg(1)) psp_write32(psp_arg(1), (uint32_t)(t->total_samples - 1));
    if (psp_arg(2)) psp_write32(psp_arg(2), (uint32_t)t->loop_start);
    if (psp_arg(3)) psp_write32(psp_arg(3), (uint32_t)t->loop_end);
    psp_ret(0);
}

static void hle_SetLoopNum(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    if (t->loop_start < 0) { psp_ret(ERR_NO_LOOP_INFO); return; }
    t->loops = (int32_t)psp_arg(1);
    psp_ret(0);
}

/* The streaming window. The game's buffer is used as a ring of whole frames
 * holding file bytes [pos, written); the next free space starts at the
 * ring position of `written`. The decoder takes each chunk from where this
 * says it was written (take_bytes), so the accounting only has to be
 * self-consistent, so the game neither stalls nor overruns. */
static uint32_t ring_used(const atrac *t) { return t->written - (t->pos < t->written ? t->pos : t->written); }

/* (id, u8 **writePtr, u32 *available, u32 *readOffset) */
static void hle_GetStreamDataInfo(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    uint32_t wp = t->buf, avail = 0, roff = t->written;
    if (t->streaming && t->written < t->file_size) {
        uint32_t ring = t->bufsize / t->frame_bytes * t->frame_bytes;
        uint32_t at = (t->written - t->data_off) % (ring ? ring : 1);
        uint32_t free_total = ring > ring_used(t) ? ring - ring_used(t) : 0;
        uint32_t contiguous = ring - at;
        avail = free_total < contiguous ? free_total : contiguous;
        if (avail > t->file_size - t->written) avail = t->file_size - t->written;
        wp = t->buf + at;
    }
    t->last_wp = wp;
    if (psp_arg(1)) psp_write32(psp_arg(1), wp);
    if (psp_arg(2)) psp_write32(psp_arg(2), avail);
    if (psp_arg(3)) psp_write32(psp_arg(3), roff);
    psp_ret(0);
}

static void hle_AddStreamData(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    uint32_t n = psp_arg(1);
    if (t->written + n > t->file_size) { psp_ret(ERR_ADD_TOO_BIG); return; }
    take_bytes(t, t->written, t->last_wp, n);      /* the game filled the window it was given */
    t->written += n;
    psp_ret(0);
}

/* (id, sample, bytesWrittenFirstBuf, bytesWrittenSecondBuf): restart at
 * `sample`; the game has refilled the buffer from the matching file offset. */
static void hle_ResetPlayPosition(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    int32_t s = (int32_t)psp_arg(1);
    if (s < 0 || s > t->total_samples) { psp_ret(0x80630022u); return; }   /* BAD_SAMPLE */
    t->sample = s;
    t->pos = t->data_off + (uint32_t)(s / (int32_t)t->spf) * t->frame_bytes;
    if (t->streaming) {
        uint32_t w = t->pos + psp_arg(2) + psp_arg(3);
        t->written = w < t->file_size ? w : t->file_size;
        /* Bytes refilled at the buffer's start for [pos, ...). Only new ones
         * matter: the decoder already has everything up to `have`. */
        take_bytes(t, t->pos, t->buf, psp_arg(2));
    }
    psp_ret(0);
}

void psp_atrac_register(void) {
    psp_hle_register(0x7A20E7AF, "sceAtrac3plus", "sceAtracSetDataAndGetID",   hle_SetDataAndGetID);
    psp_hle_register(0x61EB33F5, "sceAtrac3plus", "sceAtracReleaseAtracID",    hle_ReleaseAtracID);
    psp_hle_register(0x6A8C3CD5, "sceAtrac3plus", "sceAtracDecodeData",        hle_DecodeData);
    psp_hle_register(0x9AE849A7, "sceAtrac3plus", "sceAtracGetRemainFrame",    hle_GetRemainFrame);
    psp_hle_register(0xA2BBA8BE, "sceAtrac3plus", "sceAtracGetSoundSample",    hle_GetSoundSample);
    psp_hle_register(0x868120B5, "sceAtrac3plus", "sceAtracSetLoopNum",        hle_SetLoopNum);
    psp_hle_register(0x5D268707, "sceAtrac3plus", "sceAtracGetStreamDataInfo", hle_GetStreamDataInfo);
    psp_hle_register(0x7DB31251, "sceAtrac3plus", "sceAtracAddStreamData",     hle_AddStreamData);
    psp_hle_register(0x644E5607, "sceAtrac3plus", "sceAtracResetPlayPosition", hle_ResetPlayPosition);
}
