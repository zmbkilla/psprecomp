/* psprecomp — sceGe_user: display-list execution.
 *
 * The GE is the PSP's GPU. It is not driven by function calls: user code builds
 * a **display list** — an array of 32-bit words, each an 8-bit command and 24
 * bits of argument — and hands the GE a pointer plus a *stall address*. The GE
 * consumes commands up to the stall, and the CPU moves the stall forward as it
 * writes more. That producer/consumer arrangement is the whole API.
 *
 * So `sceGu*` (the list-building library) is ordinary user code and gets
 * recompiled like anything else. Only list *execution* is emulated: this file
 * walks lists and follows their control flow; every state command and every
 * primitive goes to gpu.c, which holds the register file and rasterizes.
 *
 * Lists run synchronously, inside the call that enqueues them or moves their
 * stall address. Every way a game can observe progress -- ListSync, DrawSync,
 * the finish and signal callbacks -- then sees a completed list, which is
 * indistinguishable from a GE that happens to be fast.
 */

#include "psprecomp/hle.h"
#include "psprecomp/render.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GE_NOP          0x00
#define GE_VADDR        0x01
#define GE_IADDR        0x02
#define GE_PRIM         0x04
#define GE_BEZIER       0x05
#define GE_SPLINE       0x06
#define GE_BBOX         0x07
#define GE_JUMP         0x08
#define GE_BJUMP        0x09
#define GE_CALL         0x0A
#define GE_RET          0x0B
#define GE_END          0x0C
#define GE_SIGNAL       0x0E
#define GE_FINISH       0x0F
#define GE_BASE         0x10
#define GE_VTYPE        0x12
#define GE_OFFSET_ADDR  0x13
#define GE_ORIGIN_ADDR  0x14

/* SIGNAL behaviours (bits 16-23 of the SIGNAL argument), acted on by the END
 * that follows the SIGNAL. */
#define SIG_SUSPEND  0x01
#define SIG_CONTINUE 0x02
#define SIG_PAUSE    0x03
#define SIG_SYNC     0x08
#define SIG_JUMP     0x10
#define SIG_CALL     0x11
#define SIG_RET      0x12
#define SIG_RJUMP    0x13
#define SIG_RCALL    0x14
#define SIG_OJUMP    0x15
#define SIG_OCALL    0x16

#define MAX_QUEUES 16
#define GE_STACK   32
#define MAX_CB     16

void psp_gpu_reset(void);
void psp_gpu_cmd(uint32_t cmd, uint32_t arg);
void psp_gpu_prim(uint32_t type, uint32_t count, uint32_t vaddr, uint32_t iaddr);
uint32_t psp_gpu_reg(uint32_t cmd);
uint64_t psp_gpu_pixels(void);
void psp_gpu_dump_stats(FILE *out);
uint32_t psp_gpu_vertex_bytes(uint32_t count);
uint32_t psp_gpu_index_bytes(uint32_t count);

static const char *const PRIM_NAME[8] = {
    "points", "lines", "line-strip", "triangles",
    "triangle-strip", "triangle-fan", "sprites", "?"
};

typedef struct {
    uint32_t id;
    uint32_t start;     /* where the list began */
    uint32_t list;      /* current read pointer */
    uint32_t stall;     /* stop before this address; 0 means "no stall" */
    int      cbid;      /* callback set for FINISH / SIGNAL, or -1 */
    uint32_t stack[GE_STACK];
    int      sp;
    int      used;
    int      done;
} ge_queue;

typedef struct { uint32_t signal_func, signal_arg, finish_func, finish_arg; int used; } ge_cb;

static ge_queue g_queue[MAX_QUEUES];
static ge_cb    g_cb[MAX_CB];
static uint32_t g_next_id;

/* Address state shared by every list: BASE supplies the high bits, OFFSET
 * (or ORIGIN) a displacement, and VADDR/IADDR are resolved against both. */
static uint32_t g_vaddr, g_iaddr, g_offset;

static struct {
    uint64_t commands, vertices, lists, finishes, signals;
    uint64_t prims[8];
    uint64_t by_cmd[256];
} g_ge;

void psp_ge_reset(void) {
    memset(g_queue, 0, sizeof g_queue);
    memset(g_cb, 0, sizeof g_cb);
    memset(&g_ge, 0, sizeof g_ge);
    g_vaddr = g_iaddr = g_offset = 0;
    psp_gpu_reset();
    psp_render_reset_pixels();
    g_next_id = 0x00080000u;
}

void psp_ge_init(void) { psp_ge_reset(); }

uint64_t psp_ge_command_count(void) { return g_ge.commands; }
uint64_t psp_ge_vertex_count(void)  { return g_ge.vertices; }
uint64_t psp_ge_pixels(void)        { return psp_gpu_pixels(); }

void psp_ge_dump_stats(FILE *out) {
    fprintf(out, "GE: %llu lists, %llu commands, %llu finishes, %llu signals\n",
            (unsigned long long)g_ge.lists, (unsigned long long)g_ge.commands,
            (unsigned long long)g_ge.finishes, (unsigned long long)g_ge.signals);
    fprintf(out, "    framebuffer 0x%06X stride %u format %u, vertex type 0x%06X\n",
            psp_gpu_reg(0x9C), psp_gpu_reg(0x9D) & 0x7FF, psp_gpu_reg(0xD2), psp_gpu_reg(0x12));
    fprintf(out, "    vertices submitted: %llu\n", (unsigned long long)g_ge.vertices);
    for (int i = 0; i < 8; i++)
        if (g_ge.prims[i])
            fprintf(out, "    %-15s %llu\n", PRIM_NAME[i], (unsigned long long)g_ge.prims[i]);
    fprintf(out, "    pixels written: %llu\n", (unsigned long long)psp_gpu_pixels());
    psp_gpu_dump_stats(out);
    fprintf(out, "    commands by opcode:");
    for (int c = 0, k = 0; c < 256; c++)
        if (g_ge.by_cmd[c])
            fprintf(out, "%s %02X:%llu", (k++ % 10) ? "" : "\n     ", c, (unsigned long long)g_ge.by_cmd[c]);
    fprintf(out, "\n");
}

static uint32_t rel(uint32_t arg) {
    return (((psp_gpu_reg(GE_BASE) & 0x0F0000u) << 8) | (arg & 0xFFFFFFu)) + g_offset;
}

static void callback(const ge_queue *q, int finish, uint32_t value) {
    if (q->cbid < 0 || q->cbid >= MAX_CB || !g_cb[q->cbid].used) return;
    const ge_cb *c = &g_cb[q->cbid];
    if (finish) psp_sched_call_interrupt(c->finish_func, value, c->finish_arg);
    else        psp_sched_call_interrupt(c->signal_func, value, c->signal_arg);
}

/* Walk a list until it ends, reaches its stall address, or exhausts a step
 * budget. The budget is not paranoia: a list whose JUMP forms a cycle is a
 * normal intermediate state while the CPU is still writing, and without a
 * bound a malformed or partially-written list hangs the host. */
static uint64_t g_list_us, g_prim_us;
uint64_t psp_ge_host_us(void)   { return g_list_us; }
uint64_t psp_gpu_host_us(void)  { return g_prim_us; }

static void run_list_inner(ge_queue *q);
static void run_list(ge_queue *q) {
    uint64_t t0 = psp_sched_now_us();
    run_list_inner(q);
    g_list_us += psp_sched_now_us() - t0;
}

static void run_list_inner(ge_queue *q) {
    uint64_t budget = 1u << 24;
    uint32_t pending_signal = 0;
    int have_signal = 0;

    g_ge.lists++;

    while (budget--) {
        if (q->stall && q->list == q->stall) return;   /* caught up to the CPU */

        const uint32_t at = q->list;
        uint32_t word = psp_read32(at);
        uint32_t cmd  = word >> 24;
        uint32_t arg  = word & 0x00FFFFFF;
        q->list += 4;
        g_ge.commands++;
        g_ge.by_cmd[cmd]++;

        switch (cmd) {
        case GE_NOP:
            break;
        case GE_VADDR: g_vaddr = rel(arg); break;
        case GE_IADDR: g_iaddr = rel(arg); break;

        case GE_PRIM: {
            uint32_t type  = (arg >> 16) & 7;
            uint32_t count = arg & 0xFFFF;
            g_ge.prims[type]++;
            g_ge.vertices += count;
            { uint64_t t1 = psp_sched_now_us();
              psp_gpu_prim(type, count, g_vaddr, g_iaddr);
              g_prim_us += psp_sched_now_us() - t1; }
            /* The hardware leaves the vertex (or index) pointer just past
             * what it consumed, so consecutive PRIMs continue the buffer. */
            if ((psp_gpu_reg(GE_VTYPE) >> 11) & 3) g_iaddr += psp_gpu_index_bytes(count);
            else                                    g_vaddr += psp_gpu_vertex_bytes(count);
            break;
        }

        case GE_JUMP:
            q->list = rel(arg) & ~3u;
            break;
        case GE_BJUMP:
            /* Conditional on the bounding-box test (BBOX), which is not
             * evaluated: not taking it draws the enclosed geometry, the
             * conservative direction. */
            break;
        case GE_CALL:
            if (q->sp < GE_STACK) q->stack[q->sp++] = q->list;
            q->list = rel(arg) & ~3u;
            break;
        case GE_RET:
            if (q->sp > 0) q->list = q->stack[--q->sp];
            break;

        case GE_SIGNAL:
            pending_signal = arg;
            have_signal = 1;
            g_ge.signals++;
            continue;                                   /* keep have_signal for the END */

        case GE_FINISH:
            g_ge.finishes++;
            callback(q, 1, arg & 0xFFFF);
            break;

        case GE_END:
            if (have_signal) {
                /* SIGNAL + END: the signal's behaviour decides what happens. */
                const uint32_t beh = (pending_signal >> 16) & 0xFF;
                const uint32_t target = (((pending_signal & 0xFFFF) << 16) | (arg & 0xFFFF)) & 0x0FFFFFFCu;
                have_signal = 0;
                switch (beh) {
                case SIG_SUSPEND: case SIG_CONTINUE: case SIG_PAUSE:
                    callback(q, 0, pending_signal & 0xFFFF);
                    break;
                case SIG_SYNC:
                    break;
                case SIG_JUMP:  q->list = target; break;
                case SIG_RJUMP: q->list = at + target; break;
                case SIG_OJUMP: q->list = q->start + target; break;
                case SIG_CALL: case SIG_RCALL: case SIG_OCALL:
                    if (q->sp < GE_STACK) q->stack[q->sp++] = q->list;
                    q->list = beh == SIG_CALL ? target : beh == SIG_RCALL ? at + target : q->start + target;
                    break;
                case SIG_RET:
                    if (q->sp > 0) q->list = q->stack[--q->sp];
                    break;
                default:
                    fprintf(stderr, "psprecomp: GE signal behaviour 0x%02X not handled\n", beh);
                    break;
                }
                continue;
            }
            /* A bare END (normally after FINISH) ends the list. */
            q->done = 1;
            return;

        case GE_BASE:
            psp_gpu_cmd(cmd, arg);
            break;
        case GE_OFFSET_ADDR: g_offset = arg << 8; break;
        case GE_ORIGIN_ADDR: g_offset = at; break;

        default:
            {
                /* PSP2I_GE_MATRIX_FLIP=N: where in memory frame N's matrix
                 * uploads come from (to find the code that built them). */
                static long want = -2;
                if (want == -2) { const char *e = getenv("PSP2I_GE_MATRIX_FLIP"); want = e ? atol(e) : -1; }
                if (want >= 0 && psp_display_flips() == (uint64_t)want && cmd >= 0x3A && cmd <= 0x3F)
                    fprintf(stderr, "ge-matrix: cmd 0x%02X arg 0x%06X at list 0x%08X\n", cmd, arg, at);
            }
            psp_gpu_cmd(cmd, arg);
            break;
        }
        have_signal = 0;
    }
    fprintf(stderr, "psprecomp: GE list at 0x%08X exceeded its step budget\n", q->start);
    q->done = 1;
}

/* ---- the calls ----------------------------------------------------------- */

static ge_queue *find_queue(uint32_t id) {
    for (int i = 0; i < MAX_QUEUES; i++)
        if (g_queue[i].used && g_queue[i].id == id) return &g_queue[i];
    return NULL;
}

static void enqueue(int head) {
    /* (list, stall, cbid, arg) */
    /* A completed list has left the hardware queue, so its slot is free. Not
     * reusing completed slots filled the queue after a handful of frames, and
     * every list after that was refused -- the game kept rendering into lists
     * that never ran. (A completed list's id stays findable until its slot is
     * reused, so a late ListSync on it still reports completion.) */
    ge_queue *q = NULL;
    for (int i = 0; i < MAX_QUEUES && !q; i++) if (!g_queue[i].used) q = &g_queue[i];
    for (int i = 0; i < MAX_QUEUES && !q; i++) if (g_queue[i].done) q = &g_queue[i];
    if (!q) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }

    memset(q, 0, sizeof *q);
    q->id    = g_next_id++;
    q->start = q->list = psp_arg(0) & 0x0FFFFFFCu;
    q->stall = psp_arg(1) & 0x0FFFFFFCu;
    q->cbid  = (int32_t)psp_arg(2);
    q->used  = 1;
    (void)head;
    run_list(q);
    psp_ret(q->id);
}

static void hle_ListEnQueue(void)     { enqueue(0); }
static void hle_ListEnQueueHead(void) { enqueue(1); }

static void hle_ListDeQueue(void) {
    ge_queue *q = find_queue(psp_arg(0));
    if (!q) { psp_ret(0x80000100); return; }
    q->used = 0;
    psp_ret(0);
}

static void hle_ListUpdateStallAddr(void) {
    ge_queue *q = find_queue(psp_arg(0));
    if (!q) { psp_ret(0x80000100); return; }
    q->stall = psp_arg(1) & 0x0FFFFFFCu;
    if (!q->done) run_list(q);          /* the new stall released more commands */
    psp_ret(SCE_KERNEL_ERROR_OK);
}

/* Lists complete synchronously, so a sync never waits. In query mode (1) the
 * answer is "completed" (0) for a finished list and "drawing" (2) for one
 * still parked at its stall address. */
static void hle_ListSync(void) {
    ge_queue *q = find_queue(psp_arg(0));
    if (psp_arg(1) == 1) { psp_ret(q && !q->done ? 3 : 0); return; }   /* 3: stall reached */
    psp_ret(SCE_KERNEL_ERROR_OK);
}
static void hle_DrawSync(void) {
    if (psp_arg(0) == 1) {
        for (int i = 0; i < MAX_QUEUES; i++)
            if (g_queue[i].used && !g_queue[i].done) { psp_ret(2); return; }
        psp_ret(0);
        return;
    }
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void hle_Break(void)    { psp_ret(SCE_KERNEL_ERROR_OK); }
static void hle_Continue(void) { psp_ret(SCE_KERNEL_ERROR_OK); }

/* (PspGeCallbackData *): signal func/arg, finish func/arg. Returns an id. */
static void hle_SetCallback(void) {
    uint32_t d = psp_arg(0);
    for (int i = 0; i < MAX_CB; i++) {
        if (g_cb[i].used) continue;
        g_cb[i].signal_func = psp_read32(d);
        g_cb[i].signal_arg  = psp_read32(d + 4);
        g_cb[i].finish_func = psp_read32(d + 8);
        g_cb[i].finish_arg  = psp_read32(d + 12);
        g_cb[i].used = 1;
        psp_ret((uint32_t)i);
        return;
    }
    psp_ret(0x80000022);
}

static void hle_UnsetCallback(void) {
    uint32_t i = psp_arg(0);
    if (i >= MAX_CB || !g_cb[i].used) { psp_ret(0x80000100); return; }
    g_cb[i].used = 0;
    psp_ret(SCE_KERNEL_ERROR_OK);
}

/* eDRAM is the GPU-visible VRAM window: 2 MB at 0x04000000. */
static void hle_EdramGetAddr(void) { psp_ret(PSP_VRAM_BASE); }
static void hle_EdramGetSize(void) { psp_ret(PSP_VRAM_SIZE); }

void psp_ge_register(void) {
    psp_hle_register(0xAB49E76A, "sceGe_user", "sceGeListEnQueue",         hle_ListEnQueue);
    psp_hle_register(0x1C0D95A6, "sceGe_user", "sceGeListEnQueueHead",     hle_ListEnQueueHead);
    psp_hle_register(0x5FB86AB0, "sceGe_user", "sceGeListDeQueue",         hle_ListDeQueue);
    psp_hle_register(0xE0D68148, "sceGe_user", "sceGeListUpdateStallAddr", hle_ListUpdateStallAddr);
    psp_hle_register(0x03444EB4, "sceGe_user", "sceGeListSync",            hle_ListSync);
    psp_hle_register(0xB287BD61, "sceGe_user", "sceGeDrawSync",            hle_DrawSync);
    psp_hle_register(0xB448EC0D, "sceGe_user", "sceGeBreak",               hle_Break);
    psp_hle_register(0x4C06E472, "sceGe_user", "sceGeContinue",            hle_Continue);
    psp_hle_register(0xA4FC06A4, "sceGe_user", "sceGeSetCallback",         hle_SetCallback);
    psp_hle_register(0x05DB22CE, "sceGe_user", "sceGeUnsetCallback",       hle_UnsetCallback);
    psp_hle_register(0xE47E40E4, "sceGe_user", "sceGeEdramGetAddr",        hle_EdramGetAddr);
    psp_hle_register(0x1F6752AD, "sceGe_user", "sceGeEdramGetSize",        hle_EdramGetSize);
}
