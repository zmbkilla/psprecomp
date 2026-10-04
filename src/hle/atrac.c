/* psprecomp — sceAtrac3plus.
 *
 * A game plays ATRAC3 / ATRAC3plus music by handing the library a buffer
 * holding the start of a RIFF/WAVE file and then calling DecodeData once per
 * frame, refilling the buffer through GetStreamDataInfo / AddStreamData when
 * the file is larger than the buffer. Everything about that protocol -- the
 * header, frame and sample accounting, the streaming window, end of data and
 * looping -- is implemented here.
 *
 * What is NOT implemented is the codec. ATRAC3plus is a proprietary transform
 * codec with no decoder in this toolkit; the published decoders are GPL/LGPL
 * and are kept out of this MIT runtime. DecodeData therefore produces frames
 * of silence of exactly the right length, and says so once at run time. The
 * game's audio thread keeps its real pacing (it blocks on sceAudioOutput) and
 * its control flow sees correct positions, end-of-stream and loop events; only
 * the sound itself is missing.
 */

#include "psprecomp/hle.h"

#include <stdio.h>
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
    int32_t  loop_start, loop_end;/* from 'smpl', or -1 */
    int32_t  loops;               /* remaining loops; -1 = forever */

    uint32_t written;             /* file bytes the game has supplied so far */
    uint32_t pos;                 /* file offset of the next frame to decode */
    int32_t  sample;              /* next output sample */
    int      streaming;
} atrac;

static atrac g_at[MAX_ATRAC];
static int   g_warned;

void psp_atrac_reset(void) { memset(g_at, 0, sizeof g_at); g_warned = 0; }
void psp_atrac_init(void)  { psp_atrac_reset(); }

static uint32_t rd32(uint32_t a) { return psp_read32(a); }
static uint16_t rd16(uint32_t a) { return psp_read16(a); }

/* Parse the RIFF header out of guest memory. 0 or an error code. */
static uint32_t parse(atrac *t) {
    const uint32_t b = t->buf, n = t->bufsize;
    if (n < 12 || rd32(b) != 0x46464952u /* RIFF */ || rd32(b + 8) != 0x45564157u /* WAVE */)
        return ERR_UNKNOWN_FORMAT;
    t->loop_start = t->loop_end = -1;
    t->total_samples = -1;
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
    if (!g_warned) {
        g_warned = 1;
        fprintf(stderr, "psprecomp: ATRAC%s stream opened (%u ch, %d samples). The codec is not "
                        "available in this runtime: playback is silent (see src/hle/atrac.c)\n",
                t->at3plus ? "3plus" : "3", t->channels, t->total_samples);
    }
    psp_ret((uint32_t)id);
}

static void hle_ReleaseAtracID(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    t->used = 0;
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
    if (out) for (uint32_t i = 0; i < n * 2; i++) psp_write16(out + i * 2, 0);
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
 * ring position of `written`. Data content is never read (no codec), so only
 * the accounting has to be right -- and self-consistent, so the game neither
 * stalls nor overruns. */
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
