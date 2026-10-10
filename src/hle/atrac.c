/* psprecomp — sceAtrac3plus.
 *
 * A game plays ATRAC3 / ATRAC3plus music by handing the library a buffer
 * holding the start of a RIFF/WAVE file and then calling DecodeData once per
 * frame. When the file is larger than the buffer, the buffer is a ring the
 * game keeps refilling: GetStreamDataInfo says where to write, how much and
 * from which file offset, AddStreamData says it was done.
 *
 * The state kept per ID mirrors the firmware's own context (as PPSSPP's
 * hardware-tested implementation documents it): the decode position in
 * samples (counting the codec's start-up samples), the file offset of the
 * next frame, the bytes buffered and where in the ring they start. Every
 * number the game sees -- write pointers, read offsets, remaining frames,
 * the special remaining-frame codes, end and loop flags -- is computed from
 * that state the way the firmware computes it, so a game's streaming loop
 * behaves as on hardware: a looping track keeps asking for data from the
 * loop start once the file end is buffered; a reset is refilled from the
 * frame before the target.
 *
 * Frames are decoded from the game's own buffer, where the protocol put
 * them. States handled: the whole file in the buffer, streaming without a
 * loop, and streaming with a loop that ends at the file end (all PSP2i's
 * looping music). A loop followed by a trailer needs a second buffer, which
 * PSP2i never sets; such a track streams as if it looped from the end.
 *
 * ## Decoding
 *
 * ATRAC3plus is a proprietary transform codec with no decoder in this
 * toolkit; the published decoders are GPL/LGPL and are kept out of this MIT
 * runtime. The host may supply one through psp_atrac_set_codec (the PSP2i
 * host loads an LGPL decoder DLL at run time). Without a codec, or for a
 * frame the codec rejects, DecodeData produces silence of exactly the right
 * length, so the game's audio thread keeps its pacing and sees correct
 * positions, end-of-stream and loop events.
 */

#include "psprecomp/hle.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ATRAC 6

#define ERR_API_FAIL           0x80630002u
#define ERR_NO_ID              0x80630003u
#define ERR_BAD_ID             0x80630005u
#define ERR_UNKNOWN_FORMAT     0x80630006u
#define ERR_BAD_CODEC_PARAMS   0x80630008u
#define ERR_SIZE_TOO_SMALL     0x80630011u
#define ERR_SECOND_BUFFER_NEEDED 0x80630012u
#define ERR_BAD_SAMPLE         0x80630015u
#define ERR_BAD_FIRST_RESET    0x80630016u
#define ERR_BAD_SECOND_RESET   0x80630017u
#define ERR_ADD_TOO_BIG        0x80630018u
#define ERR_NO_LOOP_INFO       0x80630021u
#define ERR_BUFFER_EMPTY       0x80630023u
#define ERR_ALL_DECODED        0x80630024u

/* GetRemainFrame's special values */
#define ALLDATA_IS_ON_MEMORY          (-1)
#define NONLOOP_STREAM_DATA_ON_MEMORY (-2)
#define LOOP_STREAM_DATA_ON_MEMORY    (-3)

enum { ST_ALL_DATA_LOADED = 2, ST_HALFWAY_BUFFER = 3, ST_STREAMED_WITHOUT_LOOP = 4,
       ST_STREAMED_LOOP_FROM_END = 5, ST_STREAMED_LOOP_WITH_TRAILER = 6 };

typedef struct {
    int      used;
    int      state;
    int      at3plus;
    int      channels;
    uint32_t sample_size;      /* bytes per frame (nBlockAlign) */
    int32_t  first_valid;      /* first sample returned: the encoder delay plus the codec's */
    int32_t  end_sample;       /* last sample, counted like decode_pos */
    int32_t  loop_start, loop_end;   /* likewise; loop_end 0 = no loop */
    int32_t  decode_pos;       /* next sample to decode */
    int      skip_frames;      /* frames to decode and discard before output */
    int32_t  loop_num;         /* loops left; -1 = forever */
    uint32_t data_off;         /* file offset of the first frame */
    uint32_t file_end;         /* file offset after the last frame */
    uint32_t cur_file_off;     /* file offset of the next frame decoded */
    int32_t  stream_data;      /* bytes buffered from cur_file_off on */
    uint32_t stream_off;       /* where in the buffer cur_file_off's frame is (streaming) */
    uint32_t buffer, buffer_bytes;

    void    *codec;            /* the host codec's state, or NULL: silence */
    int      fails;            /* frames the codec rejected (reported, then counted) */
    int      dry;              /* in a BUFFER_IS_EMPTY spell (logged once) */
    int      ended;            /* ALL_DATA_DECODED logged */
} atrac;

static atrac g_at[MAX_ATRAC];
static int   g_warned;
static const psp_atrac_codec *g_codec;

static void (*g_log)(const char *line);

void psp_atrac_set_codec(const psp_atrac_codec *codec) { g_codec = codec; }
void psp_atrac_set_log(void (*fn)(const char *line)) { g_log = fn; }

static void alog(const char *fmt, ...) {
    char line[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (g_log) g_log(line);
    else fprintf(stderr, "atrac: %s\n", line);
}

static const char *state_name(int s) {
    switch (s) {
    case ST_ALL_DATA_LOADED: return "in memory";
    case ST_HALFWAY_BUFFER: return "halfway";
    case ST_STREAMED_WITHOUT_LOOP: return "streamed";
    case ST_STREAMED_LOOP_FROM_END: return "streamed, looping";
    default: return "streamed, loop with trailer";
    }
}
const psp_atrac_codec *psp_atrac_get_codec(void) { return g_codec; }

static void release(atrac *t) {
    if (t->codec && g_codec) g_codec->close(t->codec);
    memset(t, 0, sizeof *t);
}

void psp_atrac_reset(void) {
    for (int i = 0; i < MAX_ATRAC; i++) if (g_at[i].used) release(&g_at[i]);
    memset(g_at, 0, sizeof g_at);
    g_warned = 0;
}
void psp_atrac_init(void) { psp_atrac_reset(); }

static int is_streaming(const atrac *t) { return t->state >= ST_STREAMED_WITHOUT_LOOP; }
static int32_t spf(const atrac *t) { return t->at3plus ? 2048 : 1024; }
static int32_t frame_mask(const atrac *t) { return spf(t) - 1; }
static int32_t codec_skip(const atrac *t) { return t->at3plus ? 0x170 : 0x45; }

static int32_t imin(int32_t a, int32_t b) { return a < b ? a : b; }
static int32_t imax(int32_t a, int32_t b) { return a > b ? a : b; }
static int32_t round_down(int32_t size, int32_t grain) { return size - size % grain; }
/* `size` rounded down to whole `grain`s counted from `offset`. */
static int32_t round_down_from(int32_t offset, int32_t size, int32_t grain) {
    return size > offset ? (size - offset) / grain * grain + offset : size;
}

/* ---- positions -------------------------------------------------------------------- */

/* Frames to decode and throw away before `pos` is output: the frame before
 * it primes the codec, two when `pos` lies in a frame's start-up samples. */
static int skip_frames_at(const atrac *t, int32_t pos) {
    return (pos & frame_mask(t)) < codec_skip(t) ? 2 : 1;
}

/* File offset decoding resumes from to output `pos`. */
static uint32_t file_offset_at(const atrac *t, int32_t pos) {
    int32_t off = (pos / spf(t) - 1) * (int32_t)t->sample_size;
    if ((pos & frame_mask(t)) < codec_skip(t) && off != 0) off -= (int32_t)t->sample_size;
    return (uint32_t)(off + (int32_t)t->data_off);
}

/* File offset just past the frame holding `pos` (the loop end, inclusive). */
static uint32_t loop_end_file_offset(const atrac *t, int32_t pos) {
    return (uint32_t)((pos / spf(t) + 1) * (int32_t)t->sample_size + (int32_t)t->data_off);
}

/* Samples the next DecodeData returns: the rest of the current frame, short
 * of the end of the track. */
static int32_t next_samples(const atrac *t) {
    const int32_t end_of_frame = t->decode_pos | frame_mask(t);
    const int32_t over = imax(0, end_of_frame - t->end_sample);
    return imax(0, spf(t) - ((t->decode_pos & frame_mask(t)) + over));
}

/* ---- remaining frames --------------------------------------------------------------- */

static int32_t remain_stream(const atrac *t) {
    if (t->stream_data >= (int32_t)(t->file_end - t->cur_file_off)) return NONLOOP_STREAM_DATA_ON_MEMORY;
    return imax(0, t->stream_data / (int32_t)t->sample_size - t->skip_frames);
}

static int32_t remain_looped(const atrac *t) {
    const int32_t ss = (int32_t)t->sample_size;
    const int32_t loop_start_off = (int32_t)file_offset_at(t, t->loop_start);
    const int32_t loop_end_off = (int32_t)loop_end_file_offset(t, t->loop_end);
    const int32_t write_off = (int32_t)t->cur_file_off + t->stream_data;
    int32_t frames;
    if (write_off <= loop_end_off) {
        frames = t->stream_data / ss;
    } else {
        /* the buffered data wraps through the loop, maybe more than once */
        const int32_t past = write_off - loop_end_off;
        const int32_t loop_len = loop_end_off - loop_start_off;
        const int32_t skip_at_loop = skip_frames_at(t, t->loop_start);
        const int32_t tail = past % loop_len;
        frames = (loop_end_off - (int32_t)t->cur_file_off) / ss + (past / loop_len) * (loop_len / ss - skip_at_loop);
        if (tail > skip_at_loop * ss) frames += tail / ss - skip_at_loop;
    }
    frames = imax(0, frames - t->skip_frames);
    if (t->loop_num < 0) return frames;                       /* looping forever: never done */
    if (write_off >= loop_end_off) {
        const int32_t buffered_loops = (write_off - loop_end_off) / (loop_end_off - loop_start_off);
        if (t->loop_num <= buffered_loops) return LOOP_STREAM_DATA_ON_MEMORY;
    }
    return frames;
}

static int32_t remain_frames(const atrac *t) {
    switch (t->state) {
    case ST_ALL_DATA_LOADED: return ALLDATA_IS_ON_MEMORY;
    case ST_HALFWAY_BUFFER: {
        const int32_t write_off = (int32_t)(t->data_off + (uint32_t)t->stream_data);
        if ((int32_t)t->cur_file_off < write_off)
            return imax(0, (write_off - (int32_t)t->cur_file_off) / (int32_t)t->sample_size - t->skip_frames);
        return 0;
    }
    case ST_STREAMED_WITHOUT_LOOP: return remain_stream(t);
    case ST_STREAMED_LOOP_FROM_END: return remain_looped(t);
    default: return t->decode_pos <= t->loop_end ? remain_looped(t) : remain_stream(t);
    }
}

/* ---- decoding ------------------------------------------------------------------------ */

/* Decode the frame at `in` into `pcm` (stereo s16). Silence when it cannot. */
static void decode_frame(atrac *t, uint32_t in, int16_t *pcm) {
    const int32_t n = spf(t);
    const uint8_t *src = (const uint8_t *)psp_mem_ptr(in, t->sample_size);
    int got = -1;
    if (t->codec && src) got = g_codec->decode(t->codec, src, (int)t->sample_size, pcm, n);
    if (got < 0) {
        if (t->codec && t->fails++ < 3)
            alog("id %d: frame at file offset 0x%X rejected by the codec; silence", (int)(t - g_at), t->cur_file_off);
        if (t->codec && got < 0) g_codec->reset(t->codec);     /* start clean on the next frame */
        got = 0;
    }
    if (got < n) memset(pcm + got * 2, 0, (size_t)(n - got) * 4);
}

/* One frame: decoded, output (or skipped) and accounted for. */
static uint32_t decode_internal(atrac *t, uint32_t out, uint32_t *nsamples, int *finish) {
    const int32_t samples = next_samples(t);
    const uint32_t next_off = t->cur_file_off + t->sample_size;
    if (next_off > t->file_end || t->decode_pos > t->end_sample) { *finish = 1; return ERR_ALL_DECODED; }
    if (is_streaming(t) && t->stream_data < (int32_t)t->sample_size) { *finish = 0; return ERR_BUFFER_EMPTY; }
    if (t->state == ST_HALFWAY_BUFFER && t->data_off + (uint32_t)t->stream_data < next_off) { *finish = 0; return ERR_BUFFER_EMPTY; }

    int16_t pcm[2048 * 2];
    decode_frame(t, t->buffer + (is_streaming(t) ? t->stream_off : t->cur_file_off), pcm);
    t->cur_file_off += t->sample_size;

    if (t->skip_frames == 0) {
        *nsamples = (uint32_t)samples;
        *finish = t->end_sample < t->decode_pos + samples ? t->loop_num == 0 : 0;
        if (out && samples > 0) psp_mem_write_block(out, pcm, (uint32_t)samples * 4);
        t->decode_pos += samples;
        if (t->loop_end != 0 && t->loop_num != 0 && t->decode_pos > t->loop_end) {
            t->cur_file_off = file_offset_at(t, t->loop_start);
            t->skip_frames = skip_frames_at(t, t->loop_start);
            t->decode_pos = t->loop_start;
            if (t->loop_num > 0) t->loop_num--;
        }
    } else {
        t->skip_frames--;
    }

    if (is_streaming(t)) {
        t->stream_data -= (int32_t)t->sample_size;
        const uint32_t next = t->stream_off + t->sample_size;
        t->stream_off = next + t->sample_size > t->buffer_bytes ? 0 : next;   /* a frame never wraps */
    }
    return 0;
}

/* Decode and discard the frames that prime the codec. */
static uint32_t skip_frames(atrac *t) {
    while (t->skip_frames > 0) {
        uint32_t n = 0;
        int fin = 0;
        const uint32_t r = decode_internal(t, 0, &n, &fin);
        if (r) return r;
    }
    return 0;
}

/* Streaming: the last frame of the first buffer may straddle the ring's end;
 * its start is copied to the buffer's start, where the ring continues. */
static void wrap_last_frame(atrac *t) {
    if (!is_streaming(t)) return;
    const int32_t to_end = round_down((int32_t)(t->buffer_bytes - t->stream_off), (int32_t)t->sample_size);
    if (t->stream_data < to_end) {
        for (uint32_t i = 0; i < 128; i++) psp_write8(t->buffer + i, 0);      /* as the firmware does */
    } else {
        const uint32_t from = t->stream_off + (uint32_t)to_end, n = t->buffer_bytes - from;
        for (uint32_t i = 0; i < n; i++) psp_write8(t->buffer + i, psp_read8(t->buffer + from + i));
    }
}

/* ---- the file header ---------------------------------------------------------------- */

typedef struct {
    int at3plus, channels;
    uint32_t block_align, data_off, data_size;
    int32_t end_sample, first_offset;   /* 'fact' */
    int32_t loop_start, loop_end;       /* 'smpl', or -1 */
} wave_info;

static uint32_t rd32(uint32_t a) { return psp_read32(a); }
static uint16_t rd16(uint32_t a) { return psp_read16(a); }

static uint32_t parse_wave(uint32_t b, uint32_t n, wave_info *w) {
    memset(w, 0, sizeof *w);
    w->loop_start = w->loop_end = -1;
    w->at3plus = -1;
    uint32_t off = 0;
    for (;;) {                                           /* the RIFF/WAVE header */
        if (off + 12 >= n) return ERR_SIZE_TOO_SMALL;
        if (rd32(b + off) != 0x46464952u) return ERR_UNKNOWN_FORMAT;   /* RIFF */
        const uint32_t size = (rd32(b + off + 4) + 1) & ~1u;
        if (rd32(b + off + 8) == 0x45564157u) { off += 12; break; }    /* WAVE */
        if (size < 4) return ERR_SIZE_TOO_SMALL;
        off += 8 + size;
    }
    int extended_fact = 0;
    for (;;) {
        if (off + 8 >= n) return ERR_SIZE_TOO_SMALL;
        const uint32_t id = rd32(b + off), size = (rd32(b + off + 4) + 1) & ~1u, body = off + 8;
        if (id != 0x61746164u && body + size > n) return ERR_SIZE_TOO_SMALL;
        if (id == 0x61746164u) {                         /* "data": the frames, to the end */
            if (w->at3plus < 0) return ERR_UNKNOWN_FORMAT;
            w->data_size = size;
            w->data_off = body;
            if (!w->first_offset) w->first_offset = w->at3plus ? 0x800 : 0x400;
            if (extended_fact && w->at3plus) {
                w->first_offset -= 0xB8;
                if (w->loop_end >= 0) { w->loop_end -= 0xB8; w->loop_start -= 0xB8; }
            }
            return 0;
        } else if (id == 0x20746D66u) {                  /* "fmt " */
            if (w->at3plus >= 0 || size < 0x20) return ERR_UNKNOWN_FORMAT;
            const uint16_t tag = rd16(b + body);
            w->channels = rd16(b + body + 2);
            if (w->channels != 1 && w->channels != 2) return ERR_UNKNOWN_FORMAT;
            if (rd32(b + body + 4) != 44100) return ERR_UNKNOWN_FORMAT;
            w->block_align = rd16(b + body + 12);
            if (!w->block_align) return ERR_UNKNOWN_FORMAT;
            if (tag == 0xFFFE) w->at3plus = 1;
            else if (tag == 0x0270) w->at3plus = 0;
            else return ERR_UNKNOWN_FORMAT;
        } else if (id == 0x6C706D73u) {                  /* "smpl" */
            if (w->loop_start < 0 && size >= 0x20 && rd32(b + body + 0x1C) != 0) {
                if (size < 0x34) return ERR_SIZE_TOO_SMALL;
                w->loop_start = (int32_t)rd32(b + body + 0x2C);
                w->loop_end = (int32_t)rd32(b + body + 0x30);
                if (w->loop_end <= w->loop_start) return ERR_BAD_CODEC_PARAMS;
            }
        } else if (id == 0x74636166u) {                  /* "fact" */
            if (size < 4) return ERR_UNKNOWN_FORMAT;
            w->end_sample = (int32_t)rd32(b + body);
            if (size == 8) w->first_offset = (int32_t)rd32(b + body + 4);
            else if (size >= 12) { w->first_offset = (int32_t)rd32(b + body + 8); extended_fact = 1; }
        }
        off = body + size;
    }
}

static atrac *id_arg(int k) {
    const int32_t id = (int32_t)psp_arg(k);
    if (id < 0 || id >= MAX_ATRAC || !g_at[id].used) return NULL;
    return &g_at[id];
}

/* ---- the calls -------------------------------------------------------------------------- */

/* (buffer, bufferSize) -> id. The buffer holds the file's first bufferSize bytes. */
static void hle_SetDataAndGetID(void) {
    const uint32_t buf = psp_arg(0);
    uint32_t size = psp_arg(1);
    if ((int32_t)size < 0) size = 0x10000000;
    wave_info w;
    uint32_t err = parse_wave(buf, size, &w);
    if (err) { alog("SetDataAndGetID(%08X, %u): not a usable WAVE header (%08X)", buf, size, err); psp_ret(err); return; }
    int id = -1;
    for (int i = 0; i < MAX_ATRAC; i++) if (!g_at[i].used) { id = i; break; }
    if (id < 0) { alog("SetDataAndGetID: all %d IDs are in use (NO_ATRACID)", MAX_ATRAC); psp_ret(ERR_NO_ID); return; }
    atrac *t = &g_at[id];
    memset(t, 0, sizeof *t);
    t->at3plus = w.at3plus;
    t->channels = w.channels;
    t->sample_size = w.block_align;
    const int shift = t->at3plus ? 11 : 10;
    t->first_valid = w.first_offset + codec_skip(t);
    const int32_t samples = w.end_sample == 0 ? (int32_t)(w.data_size / t->sample_size) << shift
                                              : w.end_sample + t->first_valid;
    t->decode_pos = t->first_valid;
    t->end_sample = samples - 1;
    t->skip_frames = t->first_valid >> shift;
    if (w.loop_start >= 0) { t->loop_start = w.loop_start + codec_skip(t); t->loop_end = w.loop_end + codec_skip(t); }
    t->data_off = w.data_off;
    t->file_end = w.data_off + w.data_size;
    t->cur_file_off = w.data_off;
    t->stream_off = w.data_off;
    t->stream_data = (int32_t)(size - w.data_off);
    t->buffer = buf;
    t->buffer_bytes = size;
    if (t->sample_size > size || t->loop_end > t->end_sample ||
        (uint32_t)(t->end_sample >> shift) * t->sample_size >= w.data_size) {
        alog("SetDataAndGetID: inconsistent header (BAD_CODEC_PARAMS)");
        psp_ret(ERR_BAD_CODEC_PARAMS);
        return;
    }
    if (size < t->file_end) {
        if (t->stream_data < 2 * (int32_t)t->sample_size) { alog("SetDataAndGetID: first buffer too small (%u)", size); psp_ret(ERR_SIZE_TOO_SMALL); return; }
        if (!t->loop_end) t->state = ST_STREAMED_WITHOUT_LOOP;
        else if (t->loop_end == t->end_sample) t->state = ST_STREAMED_LOOP_FROM_END;
        else {
            t->state = ST_STREAMED_LOOP_WITH_TRAILER;
            const int32_t upto = (int32_t)(loop_end_file_offset(t, t->loop_end) - t->data_off) + 1;
            if (upto < t->stream_data) t->stream_data = upto;
        }
    } else {
        t->state = ST_ALL_DATA_LOADED;               /* SetDataAndGetID: what was read is the buffer */
    }
    t->used = 1;
    if (g_codec) t->codec = g_codec->open(t->at3plus, t->channels, (int)t->sample_size, 44100);
    if (!g_warned) {
        g_warned = 1;
        fprintf(stderr, "psprecomp: ATRAC%s stream opened (%d ch), %s\n", t->at3plus ? "3plus" : "3", t->channels,
                t->codec ? g_codec->name : "no decoder: playback is silent (see src/hle/atrac.c)");
    }
    if (t->state == ST_STREAMED_LOOP_WITH_TRAILER)
        fprintf(stderr, "psprecomp: ATRAC track loops before its end (needs a second buffer); streamed as if it looped at the end\n");
    skip_frames(t);
    wrap_last_frame(t);
    alog("id %d: %s, %d ch, %u-byte frames, file %u bytes, buffer %u at %08X, %d samples%s",
         id, state_name(t->state), t->channels, t->sample_size, t->file_end, size, buf,
         (int)(t->end_sample - t->first_valid + 1), t->loop_end ? ", has a loop" : "");
    psp_ret((uint32_t)id);
}

static void hle_ReleaseAtracID(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    alog("id %d: released at sample %d", (int)(t - g_at), (int)(t->decode_pos - t->first_valid));
    release(t);
    psp_ret(0);
}

/* (id, u16 *out, int *nsamples, int *end, int *remainFrame) */
static void hle_DecodeData(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    const uint32_t out = psp_arg(1), pn = psp_arg(2), pend = psp_arg(3), prem = psp_arg(4);
    uint32_t n = 0;
    int finish = 0;
    const int tries = t->skip_frames + 1;
    for (int i = 0; i < tries; i++) {
        const uint32_t r = decode_internal(t, out, &n, &finish);
        if (r == ERR_BUFFER_EMPTY && !t->dry) {
            t->dry = 1;
            alog("id %d: ran out of data at file offset 0x%X (the game has not refilled the buffer)", (int)(t - g_at), t->cur_file_off);
        } else if (r == ERR_ALL_DECODED && !t->ended) {
            t->ended = 1;
            alog("id %d: end of the track", (int)(t - g_at));
        } else if (r && r != ERR_BUFFER_EMPTY && r != ERR_ALL_DECODED) {
            alog("id %d: DecodeData error %08X", (int)(t - g_at), r);
        }
        if (r) {
            if (pn) psp_write32(pn, 0);
            if (pend) psp_write32(pend, (uint32_t)finish);
            psp_ret(r);
            return;
        }
    }
    t->dry = 0;
    if (pn) psp_write32(pn, n);
    if (pend) psp_write32(pend, (uint32_t)finish);
    if (prem) psp_write32(prem, (uint32_t)remain_frames(t));
    psp_ret(0);
}

static void hle_GetRemainFrame(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    if (psp_arg(1)) psp_write32(psp_arg(1), (uint32_t)remain_frames(t));
    psp_ret(0);
}

/* (id, int *endSample, int *loopStart, int *loopEnd), in the game's sample count */
static void hle_GetSoundSample(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    const int noloop = t->loop_end == 0;
    if (psp_arg(1)) psp_write32(psp_arg(1), (uint32_t)(t->end_sample - t->first_valid));
    if (psp_arg(2)) psp_write32(psp_arg(2), noloop ? 0xFFFFFFFFu : (uint32_t)(t->loop_start - t->first_valid));
    if (psp_arg(3)) psp_write32(psp_arg(3), noloop ? 0xFFFFFFFFu : (uint32_t)(t->loop_end - t->first_valid));
    psp_ret(0);
}

static void hle_SetLoopNum(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    if (t->loop_end <= 0) { alog("id %d: SetLoopNum(%d) on a track without a loop", (int)(t - g_at), (int)psp_arg(1)); psp_ret(ERR_NO_LOOP_INFO); return; }
    t->loop_num = (int32_t)psp_arg(1);
    psp_ret(0);
}

/* The ring buffer's free window: where, how much, from which file offset. */
static void stream_window(const atrac *t, uint32_t *wp, uint32_t *bytes, uint32_t *roff) {
    const int32_t ss = (int32_t)t->sample_size, used = t->stream_data, so = (int32_t)t->stream_off;
    const int32_t limit = round_down_from(so, (int32_t)t->buffer_bytes, ss);
    const int32_t pos = so + used;
    int32_t space = pos >= limit ? limit - used : limit - pos;
    if (space < 0) space = 0;
    const int32_t wrapped = pos >= limit ? pos - limit : pos;       /* buffer offset of the write position */
    const int32_t stream_file_off = (int32_t)t->cur_file_off + used;

    if (t->state == ST_STREAMED_WITHOUT_LOOP ||
        (t->state == ST_STREAMED_LOOP_WITH_TRAILER && t->decode_pos > t->loop_end)) {
        *bytes = (uint32_t)imax(0, imin((int32_t)t->file_end - stream_file_off, space));
        if (stream_file_off < (int32_t)t->file_end) { *roff = (uint32_t)stream_file_off; *wp = t->buffer + (uint32_t)wrapped; }
        else { *roff = 0; *wp = t->buffer; }
        return;
    }
    /* looping: once the file end is buffered, reading continues at the loop start */
    const int32_t ls = (int32_t)file_offset_at(t, t->loop_start), le = (int32_t)loop_end_file_offset(t, t->loop_end);
    const int32_t loop_len = le - ls;
    const int32_t writable = stream_file_off >= le ? loop_len - (stream_file_off - le) % loop_len : le - stream_file_off;
    *bytes = (uint32_t)imin(writable, space);
    *roff = (uint32_t)(stream_file_off >= le ? ls + (stream_file_off - le) % loop_len : stream_file_off);
    *wp = t->buffer + (uint32_t)wrapped;
}

/* (id, u8 **writePtr, u32 *writableBytes, u32 *readOffset) */
static void hle_GetStreamDataInfo(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    uint32_t wp = t->buffer, bytes = 0, roff = 0;
    if (t->state == ST_HALFWAY_BUFFER) {
        const uint32_t fo = t->data_off + (uint32_t)t->stream_data;
        wp = t->buffer + fo; bytes = t->file_end - fo; roff = fo;
    } else if (is_streaming(t)) {
        stream_window(t, &wp, &bytes, &roff);
    }
    if (psp_arg(1)) psp_write32(psp_arg(1), wp);
    if (psp_arg(2)) psp_write32(psp_arg(2), bytes);
    if (psp_arg(3)) psp_write32(psp_arg(3), roff);
    psp_ret(0);
}

static void hle_AddStreamData(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    const uint32_t n = psp_arg(1);
    if (t->state == ST_HALFWAY_BUFFER) {
        const uint32_t end = (uint32_t)t->stream_data + t->data_off + n;
        if (end > t->file_end) { psp_ret(ERR_ADD_TOO_BIG); return; }
        if (end == t->file_end) t->state = ST_ALL_DATA_LOADED;
    }
    t->stream_data += (int32_t)n;
    psp_ret(0);
}

/* (id, sample, bytesWrittenFirstBuf, bytesWrittenSecondBuf): restart at
 * `sample`. When streaming, the game has refilled the buffer from its start
 * with the file from file_offset_at(sample) on. */
static void hle_ResetPlayPosition(void) {
    atrac *t = id_arg(0);
    if (!t) { psp_ret(ERR_BAD_ID); return; }
    const int32_t seek = (int32_t)psp_arg(1) + t->first_valid;
    const uint32_t first = psp_arg(2), second = psp_arg(3);
    alog("id %d: ResetPlayPosition(sample %d, %u + %u bytes)", (int)(t - g_at), (int)psp_arg(1), first, second);
    if ((uint32_t)seek > (uint32_t)t->end_sample) { alog("  past the end (BAD_SAMPLE)"); psp_ret(ERR_BAD_SAMPLE); return; }

    /* what sceAtracGetBufferInfoForResetting would have asked for */
    uint32_t writable = 0, min_write = 0;
    const uint32_t seek_off = file_offset_at(t, seek);
    if (t->state == ST_HALFWAY_BUFFER) {
        const uint32_t stream_pos = t->data_off + (uint32_t)t->stream_data;
        const int32_t need = (int32_t)(t->data_off + (uint32_t)(seek / spf(t) + 1) * t->sample_size) - (int32_t)stream_pos;
        writable = t->file_end - stream_pos;
        min_write = (uint32_t)imax(0, need);
    } else if (is_streaming(t)) {
        writable = (uint32_t)imin((int32_t)(t->file_end - seek_off), round_down((int32_t)t->buffer_bytes, (int32_t)t->sample_size));
        min_write = (uint32_t)(skip_frames_at(t, seek) + 1) * t->sample_size;
    }
    if (first < min_write || first > writable) {
        alog("  refill of %u bytes outside %u..%u (BAD_FIRST_RESET_SIZE)", first, min_write, writable);
        psp_ret(ERR_BAD_FIRST_RESET);
        return;
    }
    if (second != 0) { alog("  second buffer bytes without one (BAD_SECOND_RESET_SIZE)"); psp_ret(ERR_BAD_SECOND_RESET); return; }

    t->decode_pos = seek;
    t->skip_frames = skip_frames_at(t, seek);
    t->loop_num = 0;
    t->cur_file_off = seek_off;
    if (t->state == ST_HALFWAY_BUFFER) {
        t->stream_data += (int32_t)first;
        if (t->data_off + (uint32_t)t->stream_data >= t->file_end) t->state = ST_ALL_DATA_LOADED;
    } else if (is_streaming(t)) {
        t->stream_data = (int32_t)first;
        t->stream_off = 0;
    }
    if (t->codec) g_codec->reset(t->codec);
    t->ended = 0;
    skip_frames(t);
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
