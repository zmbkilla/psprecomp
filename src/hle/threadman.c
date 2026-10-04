/* psprecomp — ThreadManForUser (and the thread-shaped parts of Kernel_Library
 * and InterruptManager).
 *
 * ## Two execution models
 *
 * Recompiled functions are ordinary C functions sharing one global register
 * file (`psp_cpu`). Running more than one PSP thread therefore needs a host
 * execution context per thread -- a host stack for the nested C calls the
 * recompiled code makes -- plus a saved copy of `psp_cpu` for each.
 *
 *   - **Run-to-completion** (the default, and what the unit tests exercise).
 *     `sceKernelStartThread` runs the thread inline with the caller's context
 *     saved around it; `sceKernelExitThread` unwinds with longjmp; a wait that
 *     would block returns a timeout and says so once. Exact for the
 *     `module_start` -> create -> start -> return shape, and nothing more.
 *
 *   - **Scheduled** (opt-in: `psp_sched_run`). Each PSP thread runs on its own
 *     host fiber. The scheduler is the PSP's: strict priority (lower number
 *     wins), FIFO within a priority, a woken thread joins the back of its
 *     priority's queue and a preempted one keeps its place at the front. The
 *     PSP is single-core, so exactly one fiber runs at a time and `psp_cpu`
 *     is swapped at every switch -- no locking is involved anywhere.
 *
 * ## Where preemption happens
 *
 * On hardware a higher-priority thread made ready by an interrupt (vblank, a
 * timer, I/O completion) preempts immediately. Here the only points at which
 * control can leave a running thread are firmware calls: every HLE call ends
 * in `psp_sched_after_hle`, which delivers due events and switches if a
 * higher-priority thread became ready. While the guest has interrupts masked
 * (`sceKernelCpuSuspendIntr`) no preemption happens, as on hardware.
 *
 * The consequence: a thread that spins *without making any firmware call*
 * waiting for another thread to change memory will never yield. That pattern
 * is rare in PSP code (it is equally broken on hardware unless the other
 * thread has higher priority) but it is a real difference and is recorded as
 * such.
 *
 * ## Time
 *
 * The system clock is the host's monotonic clock in microseconds since the
 * scheduler started. Delays, timeouts, vblank (59.94 Hz) and audio pacing are
 * all measured against it, so the game runs at real-time speed when the host
 * keeps up.
 */

#include "psprecomp/hle.h"
#include "psprecomp/dispatch.h"

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <time.h>
#  include <ucontext.h>
#  include <unistd.h>
#endif

#define MAX_THREADS 128
#define MAX_SEMAS   256
#define MAX_FLAGS   256
#define MAX_CBS     64
#define MAX_MUTEXES 256
#define MAX_MBXS    64
#define MAX_FPLS    64
#define MAX_MBX_MSGS 1024
#define UID_BASE    0x00040000u

/* Per-object error codes, as the firmware returns them. */
#define ERR_UNKNOWN_THID          0x80020198u
#define ERR_UNKNOWN_SEMID         0x80020199u
#define ERR_UNKNOWN_EVFID         0x8002019Au
#define ERR_UNKNOWN_MBXID         0x8002019Bu
#define ERR_UNKNOWN_FPLID         0x8002019Du
#define ERR_UNKNOWN_CBID          0x800201A1u
#define ERR_ILLEGAL_PRIORITY      0x80020193u
#define ERR_ILLEGAL_STACK_SIZE    0x80020194u
#define ERR_ILLEGAL_MODE          0x80020195u
#define ERR_ILLEGAL_ENTRY         0x80020192u
#define ERR_DORMANT               0x800201A2u
#define ERR_NOT_DORMANT           0x800201A4u
#define ERR_NOT_WAIT              0x800201A6u
#define ERR_CAN_NOT_WAIT          0x800201A7u
#define ERR_WAIT_TIMEOUT          0x800201A8u
#define ERR_WAIT_CANCEL           0x800201A9u
#define ERR_RELEASE_WAIT          0x800201AAu
#define ERR_SEMA_OVF              0x800201AEu
#define ERR_EVF_MULTI             0x800201B0u
#define ERR_EVF_ILPAT             0x800201B1u
#define ERR_MBOX_NOMSG            0x800201B2u
#define ERR_WAIT_DELETE           0x800201B5u
#define ERR_ILLEGAL_COUNT         0x800201BDu
#define ERR_MUTEX_NOT_FOUND       0x800201C3u
#define ERR_MUTEX_LOCKED          0x800201C4u
#define ERR_MUTEX_UNLOCKED        0x800201C5u
#define ERR_MUTEX_LOCK_OVERFLOW   0x800201C6u
#define ERR_MUTEX_UNLOCK_UNDERFLOW 0x800201C7u
#define ERR_MUTEX_RECURSIVE       0x800201C8u
#define ERR_LWMUTEX_NOT_FOUND     0x800201CAu
#define ERR_LWMUTEX_LOCKED        0x800201CBu
#define ERR_LWMUTEX_UNLOCKED      0x800201CCu
#define ERR_LWMUTEX_LOCK_OVERFLOW 0x800201CDu
#define ERR_LWMUTEX_UNLOCK_UNDERFLOW 0x800201CEu
#define ERR_LWMUTEX_RECURSIVE     0x800201CFu

/* Object attributes. */
#define ATTR_PRIORITY_ORDER  0x100   /* wake waiters by priority, not FIFO */
#define EVF_ATTR_MULTI       0x200
#define MUTEX_ATTR_RECURSIVE 0x200
#define MBX_ATTR_MSG_PRIORITY 0x400

#define PSP_EVENT_WAITAND      0x00
#define PSP_EVENT_WAITOR       0x01
#define PSP_EVENT_WAITCLEARALL 0x10
#define PSP_EVENT_WAITCLEAR    0x20

#define THREAD_ATTR_NO_FILLSTACK 0x00100000u

enum { TH_DORMANT = 0, TH_READY, TH_RUNNING, TH_WAITING };

enum {
    W_NONE = 0, W_SLEEP, W_DELAY, W_THREADEND, W_SEMA, W_EVF, W_MUTEX,
    W_LWMUTEX, W_MBX, W_FPL, W_VBLANK
};
static const char *const WAIT_NAME[] = {
    "none", "sleep", "delay", "thread-end", "sema", "event-flag", "mutex",
    "lwmutex", "mbx", "fpl", "vblank"
};

/* ---- host fibers --------------------------------------------------------- */

/* Host stack per PSP thread. Recompiled code nests one C frame per guest call
 * plus one per tail call, and the generated functions can have large frames,
 * so this is generous. Only `reserve` is address space; pages are committed
 * on demand. */
#define FIBER_STACK_RESERVE (64u << 20)

#ifdef _WIN32
typedef void *fiber_t;
static fiber_t g_main_fiber;
#else
typedef ucontext_t *fiber_t;
static ucontext_t g_main_ctx;
static fiber_t g_main_fiber = &g_main_ctx;
#endif

typedef struct psp_thread {
    uint32_t uid;
    char     name[32];
    uint32_t entry;
    uint32_t priority, init_priority;
    uint32_t stack_size;
    uint32_t stack_base;   /* low address of the allocation */
    uint32_t attr;
    uint32_t gp;
    int      state;
    int      suspended;
    uint32_t exit_status;
    int      used;
    int      delete_on_exit;

    /* run-to-completion model */
    jmp_buf  unwind;
    int      unwind_set;

    /* scheduled model */
    fiber_t  fiber;
    int      fiber_done;   /* the fiber has finished and can be deleted */
    psp_cpu_state ctx;
    int64_t  ready_seq;

    int      wait;
    uint32_t wait_id;
    uint32_t wait_a, wait_b, wait_c;
    uint32_t wait_timeout_ptr;
    uint64_t wait_until;   /* absolute us; 0 = no timeout */
    int      wait_cb;
    uint64_t wait_seq;
    uint64_t wait_start;          /* when the current wait began (accounting) */
    uint64_t waited_us[11];       /* total time blocked, by wait kind */
    struct { uint32_t kind, id; uint64_t us; } wait_top[6];   /* biggest waits by object */
    uint32_t wait_result;
    int      wake_cb;      /* woken only to deliver callbacks */
    uint32_t wakeup_count;
} psp_thread;

typedef struct {
    uint32_t uid;
    char     name[32];
    uint32_t attr;
    int32_t  init_count;
    int32_t  count;
    int32_t  max_count;
    int      used;
} psp_sema;

typedef struct {
    uint32_t uid;
    char     name[32];
    uint32_t attr;
    uint32_t init_pattern;
    uint32_t pattern;
    int      used;
} psp_evflag;

typedef struct {
    uint32_t uid;
    char     name[32];
    uint32_t func;
    uint32_t arg;
    uint32_t owner;
    uint32_t notify_count;
    uint32_t notify_arg;
    int      used;
} psp_callback;

typedef struct {
    uint32_t uid;
    char     name[32];
    uint32_t attr;
    int32_t  count;
    uint32_t owner;
    uint32_t workarea;     /* nonzero for a LwMutex: state lives in guest memory */
    int      used;
} psp_mutex;

typedef struct {
    uint32_t uid;
    char     name[32];
    uint32_t attr;
    uint32_t msgs[MAX_MBX_MSGS];
    int      nmsgs;
    int      used;
} psp_mbx;

typedef struct {
    uint32_t uid;
    char     name[32];
    uint32_t attr;
    uint32_t base;
    uint32_t block_size;   /* rounded to the alignment */
    uint32_t nblocks;
    uint8_t *in_use;
    int      used;
} psp_fpl;

static psp_thread   g_thread[MAX_THREADS];
static psp_sema     g_sema[MAX_SEMAS];
static psp_evflag   g_flag[MAX_FLAGS];
static psp_callback g_cb[MAX_CBS];
static psp_mutex    g_mutex[MAX_MUTEXES];
static psp_mbx      g_mbx[MAX_MBXS];
static psp_fpl      g_fpl[MAX_FPLS];
static uint32_t     g_next_uid;
static psp_thread  *g_current;
static int          g_warned_block;

/* scheduler state */
static int      g_sched_on;
static int      g_resched;
static int64_t  g_seq_back, g_seq_front;
static uint64_t g_wait_seq;
static uint64_t g_next_vblank;
static uint64_t g_vblank_count;
static int      g_in_interrupt;
static uint32_t g_intr_stack;
static void   (*g_vblank_hook)(void);
static uint64_t g_last_progress;
static uint64_t g_idle_us;           /* host time spent with no thread runnable */
uint64_t psp_sched_idle_us(void) { return g_idle_us; }

#define VBLANK_US 16683u          /* 1e6 / 59.94 */

/* Sub-interrupt handlers (sceKernelRegisterSubIntrHandler). Only what the
 * scheduler can actually raise is delivered: the vblank, interrupt 30. */
#define PSP_VBLANK_INT 30
#define MAX_INTR 67
#define MAX_SUBINTR 32
typedef struct { uint32_t handler, arg; int enabled, used; } subintr;
static subintr g_subintr[MAX_INTR][MAX_SUBINTR];

void psp_threadman_reset(void) {
    memset(g_thread, 0, sizeof g_thread);
    memset(g_sema, 0, sizeof g_sema);
    memset(g_flag, 0, sizeof g_flag);
    memset(g_cb, 0, sizeof g_cb);
    for (int i = 0; i < MAX_FPLS; i++) free(g_fpl[i].in_use);
    memset(g_mutex, 0, sizeof g_mutex);
    memset(g_mbx, 0, sizeof g_mbx);
    memset(g_fpl, 0, sizeof g_fpl);
    memset(g_subintr, 0, sizeof g_subintr);
    g_next_uid = UID_BASE;
    g_current = NULL;
    g_warned_block = 0;
    g_sched_on = 0;
    g_resched = 0;
    g_seq_back = g_seq_front = 0;
    g_wait_seq = 0;
    g_vblank_count = 0;
    g_in_interrupt = 0;
    g_intr_stack = 0;
}

void psp_threadman_init(void) { psp_threadman_reset(); }

/* ---- time ---------------------------------------------------------------- */

static uint64_t host_us(void) {
#ifdef _WIN32
    static LARGE_INTEGER freq;
    LARGE_INTEGER c;
    if (!freq.QuadPart) QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&c);
    return (uint64_t)((double)c.QuadPart * 1000000.0 / (double)freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
#endif
}

static uint64_t g_time_base;
uint64_t psp_sched_now_us(void) {
    if (!g_time_base) g_time_base = host_us() - 1;
    return host_us() - g_time_base;
}

static void host_sleep_us(uint64_t us) {
#ifdef _WIN32
    Sleep(us >= 2000 ? (DWORD)(us / 1000) - 1 : 0);
#else
    usleep((useconds_t)us);
#endif
}

/* ---- lookups ------------------------------------------------------------- */

/* Typed lookups rather than one generic macro. A macro taking a parameter
 * named `uid` also rewrites every `.uid` member access it expands around,
 * which is exactly the kind of subtlety not worth inviting to save twelve
 * lines. */
static psp_thread *find_thread(uint32_t id) {
    for (int i = 0; i < MAX_THREADS; i++)
        if (g_thread[i].used && g_thread[i].uid == id) return &g_thread[i];
    return NULL;
}
static psp_sema *find_sema(uint32_t id) {
    for (int i = 0; i < MAX_SEMAS; i++)
        if (g_sema[i].used && g_sema[i].uid == id) return &g_sema[i];
    return NULL;
}
static psp_evflag *find_flag(uint32_t id) {
    for (int i = 0; i < MAX_FLAGS; i++)
        if (g_flag[i].used && g_flag[i].uid == id) return &g_flag[i];
    return NULL;
}
static psp_callback *find_cb(uint32_t id) {
    for (int i = 0; i < MAX_CBS; i++)
        if (g_cb[i].used && g_cb[i].uid == id) return &g_cb[i];
    return NULL;
}
static psp_mutex *find_mutex(uint32_t id) {
    for (int i = 0; i < MAX_MUTEXES; i++)
        if (g_mutex[i].used && g_mutex[i].uid == id) return &g_mutex[i];
    return NULL;
}
static psp_mbx *find_mbx(uint32_t id) {
    for (int i = 0; i < MAX_MBXS; i++)
        if (g_mbx[i].used && g_mbx[i].uid == id) return &g_mbx[i];
    return NULL;
}
static psp_fpl *find_fpl(uint32_t id) {
    for (int i = 0; i < MAX_FPLS; i++)
        if (g_fpl[i].used && g_fpl[i].uid == id) return &g_fpl[i];
    return NULL;
}

/* Report a would-block exactly once. Repeating it for every frame of a game
 * that polls a semaphore drowns out everything else in the log. */
static void warn_block(const char *what) {
    if (g_warned_block) return;
    g_warned_block = 1;
    fprintf(stderr,
        "psprecomp: %s would block, returning timeout.\n"
        "  The thread model runs one thread to completion (see src/hle/threadman.c);\n"
        "  there is no other thread to yield to. Further blocks are not reported.\n",
        what);
}

/* ---- the scheduler core -------------------------------------------------- */

int psp_sched_active(void) { return g_sched_on; }
uint64_t psp_sched_vblank_count(void) { return g_vblank_count; }
void psp_sched_set_vblank_hook(void (*fn)(void)) { g_vblank_hook = fn; }

static void make_ready_back(psp_thread *t) {
    t->state = TH_READY;
    t->ready_seq = ++g_seq_back;
    if (g_current && t != g_current && t->priority < g_current->priority) g_resched = 1;
    if (!g_current) g_resched = 1;
}

/* End a wait. `result` is what the blocked firmware call returns. */
static void wake(psp_thread *t, uint32_t result) {
    if (t->wait_timeout_ptr) {
        uint64_t now = psp_sched_now_us();
        uint32_t left = 0;
        if (result != ERR_WAIT_TIMEOUT && t->wait_until > now)
            left = (uint32_t)(t->wait_until - now);
        psp_write32(t->wait_timeout_ptr, left);
    }
    {   /* accounting: time blocked by kind and by object (psp_sched_dump) */
        uint64_t d = psp_sched_now_us() - t->wait_start;
        if (t->wait < 11) t->waited_us[t->wait] += d;
        int slot = -1, small = 0;
        for (int i = 0; i < 6; i++) {
            if (t->wait_top[i].us && t->wait_top[i].kind == (uint32_t)t->wait && t->wait_top[i].id == t->wait_id) { slot = i; break; }
            if (t->wait_top[i].us < t->wait_top[small].us) small = i;
        }
        if (slot < 0) { slot = small; t->wait_top[slot].kind = (uint32_t)t->wait; t->wait_top[slot].id = t->wait_id; t->wait_top[slot].us = 0; }
        t->wait_top[slot].us += d;
    }
    t->wait = W_NONE;
    t->wait_result = result;
    t->wake_cb = 0;
    make_ready_back(t);
    g_last_progress = psp_sched_now_us();
}

/* Waiters on one object, in the order the object's attribute asks for. */
static int collect_waiters(int type, uint32_t id, uint32_t attr, psp_thread **out) {
    int n = 0;
    for (int i = 0; i < MAX_THREADS; i++) {
        psp_thread *t = &g_thread[i];
        if (t->used && t->state == TH_WAITING && t->wait == type && t->wait_id == id)
            out[n++] = t;
    }
    for (int i = 1; i < n; i++) {
        psp_thread *k = out[i];
        int j = i - 1;
        while (j >= 0) {
            int later = (attr & ATTR_PRIORITY_ORDER)
                ? (out[j]->priority > k->priority ||
                   (out[j]->priority == k->priority && out[j]->wait_seq > k->wait_seq))
                : out[j]->wait_seq > k->wait_seq;
            if (!later) break;
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = k;
    }
    return n;
}

static int run_callbacks(psp_thread *t);

static void switch_to_main(void) {
#ifdef _WIN32
    SwitchToFiber(g_main_fiber);
#else
    swapcontext(g_current->fiber, g_main_fiber);
#endif
}

/* Leave the running thread, whose state the caller has already set. Returns
 * when the scheduler next picks it. */
static void yield_to_scheduler(void) {
    psp_thread *t = g_current;
    t->ctx = psp_cpu;
    switch_to_main();
    /* The scheduler restored psp_cpu from t->ctx before switching back. */
}

/* Block the current thread. Returns the code the wait ended with. In the
 * run-to-completion model there is nothing to block on. */
static uint32_t wait_current(int type, uint32_t id, uint32_t timeout_ptr, int cb,
                             uint32_t a, uint32_t b, uint32_t c) {
    psp_thread *t = g_current;
    if (!g_sched_on || !t) return ERR_WAIT_TIMEOUT;
    if (g_in_interrupt) return ERR_CAN_NOT_WAIT;

    uint64_t until = 0;
    if (timeout_ptr) {
        uint32_t us = psp_read32(timeout_ptr);
        until = psp_sched_now_us() + (us ? us : 1);
    }
    for (;;) {
        if (cb) run_callbacks(t);
        t->wait = type;
        t->wait_id = id;
        t->wait_a = a; t->wait_b = b; t->wait_c = c;
        t->wait_timeout_ptr = timeout_ptr;
        t->wait_until = until;
        t->wait_cb = cb;
        t->wait_seq = ++g_wait_seq;
        t->wake_cb = 0;
        t->state = TH_WAITING; t->wait_start = psp_sched_now_us();
        yield_to_scheduler();
        if (t->wake_cb) continue;       /* callbacks to run; keep waiting */
        break;
    }
    return t->wait_result;
}

/* Wait until an absolute time. For host-side pacing (audio output). */
uint32_t psp_sched_sleep_until(uint64_t when_us) {
    if (!g_sched_on || !g_current || g_in_interrupt) return 0;
    psp_thread *t = g_current;
    t->wait = W_DELAY;
    t->wait_id = 0;
    t->wait_timeout_ptr = 0;
    t->wait_until = when_us ? when_us : 1;
    t->wait_cb = 0;
    t->wait_seq = ++g_wait_seq;
    t->state = TH_WAITING; t->wait_start = psp_sched_now_us();
    yield_to_scheduler();
    return t->wait_result;
}

uint32_t psp_sched_wait_vblank(int cb) {
    if (!g_sched_on || !g_current) { g_vblank_count++; return 0; }
    return wait_current(W_VBLANK, 0, 0, cb, 0, 0, 0);
}

/* ---- callbacks ----------------------------------------------------------- */

/* Run guest code at `func` with up to three arguments on the current host
 * stack, preserving the caller's whole register file. Used for callbacks and
 * interrupt handlers -- both are calls the firmware makes *into* the game. */
static uint32_t call_guest(uint32_t func, uint32_t a0, uint32_t a1, uint32_t a2, uint32_t sp) {
    psp_cpu_state saved = psp_cpu;
    psp_cpu.r[PSP_REG_A0] = a0;
    psp_cpu.r[PSP_REG_A1] = a1;
    psp_cpu.r[PSP_REG_A2] = a2;
    psp_cpu.r[PSP_REG_RA] = 0;
    psp_cpu.r[PSP_REG_SP] = sp & ~15u;
    psp_dispatch(func);
    uint32_t ret = psp_cpu.r[PSP_REG_V0];
    psp_cpu = saved;
    return ret;
}

/* Deliver every pending callback owned by `t`. Callbacks run on the owning
 * thread, below its current stack pointer. A nonzero return deletes the
 * callback, as on hardware. */
static int run_callbacks(psp_thread *t) {
    int ran = 0;
    for (int i = 0; i < MAX_CBS; i++) {
        psp_callback *c = &g_cb[i];
        if (!c->used || c->owner != t->uid || !c->notify_count) continue;
        uint32_t count = c->notify_count, arg = c->notify_arg;
        c->notify_count = 0;
        c->notify_arg = 0;
        uint32_t r = call_guest(c->func, count, arg, c->arg, psp_cpu.r[PSP_REG_SP] - 0x40);
        if (r != 0) c->used = 0;
        ran++;
    }
    return ran;
}

int psp_sched_notify_callback(uint32_t cbid, uint32_t arg) {
    psp_callback *c = find_cb(cbid);
    if (!c) return -1;
    c->notify_count++;
    c->notify_arg = arg;
    psp_thread *t = find_thread(c->owner);
    if (t && t->state == TH_WAITING && t->wait_cb) {
        t->wake_cb = 1;
        t->state = TH_READY;
        t->ready_seq = ++g_seq_back;
        if (g_current && t->priority < g_current->priority) g_resched = 1;
    }
    return 0;
}

/* ---- events -------------------------------------------------------------- */

static void run_interrupt(int intno) {
    if (!g_intr_stack) g_intr_stack = psp_sysmem_alloc(0x4000, 1);
    for (int s = 0; s < MAX_SUBINTR; s++) {
        subintr *h = &g_subintr[intno][s];
        if (!h->used || !h->enabled || !h->handler) continue;
        g_in_interrupt++;
        call_guest(h->handler, (uint32_t)s, h->arg, 0, g_intr_stack + 0x4000 - 0x40);
        g_in_interrupt--;
    }
}

/* Run a guest handler the way the kernel runs an interrupt handler: on the
 * interrupt stack, with the interrupted context preserved, unable to block.
 * For other HLE modules (GE finish/signal callbacks). */
uint32_t psp_sched_call_interrupt(uint32_t func, uint32_t a0, uint32_t a1) {
    if (!func) return 0;
    if (!g_intr_stack) g_intr_stack = psp_sysmem_alloc(0x4000, 1);
    g_in_interrupt++;
    uint32_t r = call_guest(func, a0, a1, 0, g_intr_stack + 0x4000 - 0x40);
    g_in_interrupt--;
    return r;
}

static int interrupts_enabled(void);

static void process_events(uint64_t now) {
    if (g_in_interrupt) return;

    while (now >= g_next_vblank) {
        g_vblank_count++;
        g_next_vblank += VBLANK_US;
        for (int i = 0; i < MAX_THREADS; i++) {
            psp_thread *t = &g_thread[i];
            if (t->used && t->state == TH_WAITING && t->wait == W_VBLANK) wake(t, 0);
        }
        if (interrupts_enabled()) run_interrupt(PSP_VBLANK_INT);
        if (g_vblank_hook) g_vblank_hook();
        /* A host that falls far behind should not replay hundreds of
         * vblanks in a burst. */
        if (now > g_next_vblank + 10 * VBLANK_US) g_next_vblank = now + VBLANK_US;
    }

    for (int i = 0; i < MAX_THREADS; i++) {
        psp_thread *t = &g_thread[i];
        if (!t->used || t->state != TH_WAITING || !t->wait_until) continue;
        if (now < t->wait_until) continue;
        wake(t, t->wait == W_DELAY ? 0 : ERR_WAIT_TIMEOUT);
    }
}

static uint64_t next_event(void) {
    uint64_t e = g_next_vblank;
    for (int i = 0; i < MAX_THREADS; i++) {
        psp_thread *t = &g_thread[i];
        if (t->used && t->state == TH_WAITING && t->wait_until && t->wait_until < e)
            e = t->wait_until;
    }
    return e;
}

static psp_thread *pick_ready(void) {
    psp_thread *best = NULL;
    for (int i = 0; i < MAX_THREADS; i++) {
        psp_thread *t = &g_thread[i];
        if (!t->used || t->state != TH_READY || t->suspended) continue;
        if (!best || t->priority < best->priority ||
            (t->priority == best->priority && t->ready_seq < best->ready_seq))
            best = t;
    }
    return best;
}

/* The preemption point. Called after every firmware call. */
void psp_sched_after_hle(void) {
    if (!g_sched_on || !g_current || g_in_interrupt) return;
    if (!interrupts_enabled()) return;
    uint64_t now = psp_sched_now_us();
    if (now >= g_next_vblank) process_events(now);
    else {
        /* Timeouts are cheap to check only when one could be due. */
        for (int i = 0; i < MAX_THREADS; i++) {
            psp_thread *t = &g_thread[i];
            if (t->used && t->state == TH_WAITING && t->wait_until && now >= t->wait_until) {
                process_events(now);
                break;
            }
        }
    }
    /* The host asked to stop (window closed, time limit): get back to the
     * scheduler loop, which is where that is acted on. A thread that never
     * blocks would otherwise never let it happen. */
    if (psp_exit_requested()) {
        g_current->state = TH_READY;
        g_current->ready_seq = --g_seq_front;
        yield_to_scheduler();
        return;
    }
    if (!g_resched) return;
    g_resched = 0;
    psp_thread *best = pick_ready();
    if (!best || best->priority >= g_current->priority) return;
    /* Preempted: back to READY at the *front* of its priority's queue. */
    g_current->state = TH_READY;
    g_current->ready_seq = --g_seq_front;
    yield_to_scheduler();
}

/* ---- thread bodies ------------------------------------------------------- */

static void wake_end_waiters(psp_thread *t) {
    for (int i = 0; i < MAX_THREADS; i++) {
        psp_thread *w = &g_thread[i];
        if (w->used && w->state == TH_WAITING && w->wait == W_THREADEND && w->wait_id == t->uid)
            wake(w, t->exit_status);
    }
}

static void release_thread(psp_thread *t) {
    if (t->stack_base) psp_sysmem_release(t->stack_base);
    t->stack_base = 0;
    for (int i = 0; i < MAX_CBS; i++)
        if (g_cb[i].used && g_cb[i].owner == t->uid) g_cb[i].used = 0;
    t->used = 0;
}

/* PSPRECOMP_THREAD_TRACE=1 logs every thread's life cycle. */
static int ttrace(void) {
    static int on = -1;
    if (on < 0) on = getenv("PSPRECOMP_THREAD_TRACE") != NULL;
    return on;
}

/* A thread's body ended -- returned, or ExitThread. Never returns. */
static void thread_finish(psp_thread *t, uint32_t status) {
    if (ttrace())
        fprintf(stderr, "[thread] %s (0x%X) ended, status 0x%08X, ra 0x%08X, t=%.3fs\n",
                t->name, t->uid, status, psp_cpu.r[PSP_REG_RA], psp_sched_now_us() / 1e6);
    t->exit_status = status;
    t->state = TH_DORMANT;
    t->wait = W_NONE;
    t->fiber_done = 1;
    wake_end_waiters(t);
    g_last_progress = psp_sched_now_us();
    t->ctx = psp_cpu;
    switch_to_main();
    /* unreachable: a finished fiber is deleted, never resumed */
    abort();
}

static void thread_body(psp_thread *t) {
    psp_dispatch(t->entry);
    thread_finish(t, psp_cpu.r[PSP_REG_V0]);
}

#ifdef _WIN32
static void WINAPI fiber_proc(void *p) { thread_body((psp_thread *)p); }
#else
static void fiber_proc(int hi, int lo) {
    uintptr_t p = ((uintptr_t)(uint32_t)hi << 32) | (uintptr_t)(uint32_t)lo;
    thread_body((psp_thread *)p);
}
#endif

static int fiber_create(psp_thread *t) {
#ifdef _WIN32
    t->fiber = CreateFiberEx(256 * 1024, FIBER_STACK_RESERVE, FIBER_FLAG_FLOAT_SWITCH,
                             fiber_proc, t);
    return t->fiber ? 0 : -1;
#else
    ucontext_t *uc = (ucontext_t *)calloc(1, sizeof *uc);
    if (!uc) return -1;
    getcontext(uc);
    uc->uc_stack.ss_sp = malloc(FIBER_STACK_RESERVE);
    uc->uc_stack.ss_size = FIBER_STACK_RESERVE;
    uc->uc_link = NULL;
    if (!uc->uc_stack.ss_sp) { free(uc); return -1; }
    uintptr_t p = (uintptr_t)t;
    makecontext(uc, (void (*)(void))fiber_proc, 2, (int)(p >> 32), (int)(uint32_t)p);
    t->fiber = uc;
    return 0;
#endif
}

static void fiber_delete(psp_thread *t) {
    if (!t->fiber) return;
#ifdef _WIN32
    DeleteFiber(t->fiber);
#else
    free(t->fiber->uc_stack.ss_sp);
    free(t->fiber);
#endif
    t->fiber = NULL;
    t->fiber_done = 0;
}

static void run_thread(psp_thread *t) {
    g_current = t;
    t->state = TH_RUNNING;
    psp_cpu = t->ctx;
    if (!t->fiber && fiber_create(t) != 0) {
        fprintf(stderr, "psprecomp: cannot create a host fiber for thread %s\n", t->name);
        t->state = TH_DORMANT;
        g_current = NULL;
        return;
    }
#ifdef _WIN32
    SwitchToFiber(t->fiber);
#else
    swapcontext(&g_main_ctx, t->fiber);
#endif
    g_current = NULL;
    if (t->fiber_done) {
        fiber_delete(t);
        if (t->delete_on_exit) release_thread(t);
    }
}

void psp_sched_dump(FILE *out) {
    fprintf(out, "  threads (vblank %llu, t=%.3fs):\n",
            (unsigned long long)g_vblank_count, psp_sched_now_us() / 1e6);
    for (int i = 0; i < MAX_THREADS; i++) {
        psp_thread *t = &g_thread[i];
        if (!t->used) continue;
        static const char *const ST[] = { "dormant", "ready", "running", "waiting" };
        fprintf(out, "    0x%05X %-24s prio %3u %-8s%s", t->uid, t->name, t->priority,
                ST[t->state], t->suspended ? " (suspended)" : "");
        if (t->state == TH_WAITING)
            fprintf(out, " on %s 0x%X%s", WAIT_NAME[t->wait], t->wait_id,
                    t->wait_until ? " (timed)" : "");
        fprintf(out, "  pc~ra 0x%08X\n", t->ctx.r[PSP_REG_RA]);
        fprintf(out, "        blocked:");
        for (int k = 1; k < 11; k++)
            if (t->waited_us[k]) fprintf(out, " %s %.1fs", WAIT_NAME[k], t->waited_us[k] / 1e6);
        fprintf(out, "\n        top:");
        for (int i = 0; i < 6; i++)
            if (t->wait_top[i].us) fprintf(out, " %s 0x%X %.1fs;", WAIT_NAME[t->wait_top[i].kind], t->wait_top[i].id, t->wait_top[i].us / 1e6);
        fprintf(out, "\n");
    }
}

/* Set up a thread's initial register file, as the kernel does at start. */
static void prepare_start(psp_thread *t, uint32_t arglen, uint32_t argp, uint32_t gp) {
    memset(&t->ctx, 0, sizeof t->ctx);
    uint32_t top = t->stack_base + t->stack_size;
    /* The kernel reserves the top of the stack for its own use and copies the
     * argument block just below it, passing the *copy*: the creator's buffer
     * may be a local that is gone by the time the thread runs. */
    uint32_t k0 = (top - 0x100) & ~15u;
    uint32_t sp = k0;
    uint32_t args = 0;
    if (argp && arglen) {
        sp = (sp - arglen) & ~15u;
        for (uint32_t i = 0; i < arglen; i++) psp_write8(sp + i, psp_read8(argp + i));
        args = sp;
    }
    sp -= 64;
    t->ctx.r[PSP_REG_A0] = arglen;
    t->ctx.r[PSP_REG_A1] = args;
    t->ctx.r[PSP_REG_SP] = sp & ~15u;
    t->ctx.r[PSP_REG_K0] = k0;
    t->ctx.r[PSP_REG_GP] = gp;
    t->ctx.r[PSP_REG_RA] = 0;
    t->priority = t->init_priority;
    t->exit_status = 0;
    t->wakeup_count = 0;
    t->fiber_done = 0;
    t->wait = W_NONE;
}

static psp_thread *new_thread(const char *name, uint32_t entry, uint32_t prio,
                              uint32_t stack_size, uint32_t attr) {
    psp_thread *t = NULL;
    for (int i = 0; i < MAX_THREADS; i++) if (!g_thread[i].used) { t = &g_thread[i]; break; }
    if (!t) return NULL;
    memset(t, 0, sizeof *t);
    snprintf(t->name, sizeof t->name, "%s", name);
    t->entry = entry;
    t->priority = t->init_priority = prio;
    t->stack_size = (stack_size + 0xFF) & ~0xFFu;
    t->attr = attr;
    /* Stacks grow down, so allocate from the top of the heap: a stack that
     * overflows then runs into free space rather than into another block. */
    t->stack_base = psp_sysmem_alloc(t->stack_size, 1);
    if (!t->stack_base) return NULL;
    /* The kernel fills a new stack with 0xFF (unless asked not to) and stores
     * the thread's id in its lowest word; stack-usage checks read both. */
    if (!(attr & THREAD_ATTR_NO_FILLSTACK))
        for (uint32_t a = 0; a < t->stack_size; a += 4) psp_write32(t->stack_base + a, 0xFFFFFFFFu);
    t->uid = g_next_uid++;
    psp_write32(t->stack_base, t->uid);
    t->state = TH_DORMANT;
    t->used = 1;
    return t;
}

/* Run the game: `entry` becomes the first thread, and the scheduler runs
 * until every thread has ended, the game exits, or nothing can ever run again
 * (reported, with every thread's state). */
int psp_sched_run(uint32_t entry, uint32_t arglen, uint32_t argp,
                  uint32_t prio, uint32_t stack_size, uint32_t gp) {
#ifdef _WIN32
    g_main_fiber = ConvertThreadToFiberEx(NULL, FIBER_FLAG_FLOAT_SWITCH);
    if (!g_main_fiber) { fprintf(stderr, "psprecomp: ConvertThreadToFiber failed\n"); return -1; }
#endif
    g_sched_on = 1;
    g_next_vblank = psp_sched_now_us() + VBLANK_US;
    g_last_progress = psp_sched_now_us();

    psp_thread *root = new_thread("root", entry, prio, stack_size, 0);
    if (!root) { fprintf(stderr, "psprecomp: cannot create the root thread\n"); return -1; }
    prepare_start(root, arglen, argp, gp);
    make_ready_back(root);

    int rc = 0;
    for (;;) {
        if (psp_exit_requested()) break;
        uint64_t now = psp_sched_now_us();
        process_events(now);
        psp_thread *t = pick_ready();
        if (t) { run_thread(t); continue; }

        int alive = 0;
        for (int i = 0; i < MAX_THREADS; i++)
            if (g_thread[i].used && g_thread[i].state != TH_DORMANT) alive++;
        if (!alive) break;

        /* Nothing can run. If nothing has woken in a long while and no wait
         * can time out, the game is deadlocked; say so instead of idling. */
        int timed = 0;
        for (int i = 0; i < MAX_THREADS; i++) {
            psp_thread *w = &g_thread[i];
            if (w->used && w->state == TH_WAITING && (w->wait_until || w->wait == W_VBLANK)) timed = 1;
        }
        if (!timed && now - g_last_progress > 10u * 1000000u) {
            fprintf(stderr, "psprecomp: deadlock -- no thread can run and no wait can time out\n");
            psp_sched_dump(stderr);
            rc = 1;
            break;
        }
        uint64_t e = next_event();
        if (e > now) { uint64_t t0 = psp_sched_now_us(); host_sleep_us(e - now); g_idle_us += psp_sched_now_us() - t0; }
    }
    g_sched_on = 0;
    return rc;
}

/* ---- threads ------------------------------------------------------------- */

static void hle_CreateThread(void) {
    /* (name, entry, priority, stackSize, attr, option) */
    char name[32];
    psp_str(psp_arg(0), name, sizeof name);
    uint32_t prio = psp_arg(2), stack = psp_arg(3);
    if (g_sched_on) {
        if (prio < 0x08 || prio > 0x77) { psp_ret(ERR_ILLEGAL_PRIORITY); return; }
        if (stack < 0x200) { psp_ret(ERR_ILLEGAL_STACK_SIZE); return; }
    }
    if (stack < 0x1000) stack = 0x1000;
    psp_thread *t = new_thread(name, psp_arg(1), prio, stack, psp_arg(4));
    if (!t) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }
    if (ttrace())
        fprintf(stderr, "[thread] create %s (0x%X) entry 0x%08X prio %u stack 0x%X\n",
                name, t->uid, t->entry, prio, t->stack_size);
    psp_ret(t->uid);
}

static void start_inline(psp_thread *t, uint32_t arglen, uint32_t argp) {
    /* Save the caller's whole context. The thread runs on the same register
     * file, so this *is* the context switch. */
    psp_cpu_state saved = psp_cpu;
    psp_thread   *prev  = g_current;

    psp_cpu.r[PSP_REG_A0] = arglen;
    psp_cpu.r[PSP_REG_A1] = argp;
    /* Stack pointer starts at the top of the allocation, 16-byte aligned, with
     * a little headroom so a callee storing below $sp cannot run off the end. */
    psp_cpu.r[PSP_REG_SP] = (t->stack_base + t->stack_size - 64) & ~15u;
    psp_cpu.r[PSP_REG_RA] = 0;

    t->state = TH_RUNNING;
    g_current = t;

    if (setjmp(t->unwind) == 0) {
        t->unwind_set = 1;
        psp_dispatch(t->entry);          /* runs to completion */
        t->exit_status = psp_cpu.r[PSP_REG_V0];
    }
    /* Landing here with a nonzero setjmp result means sceKernelExitThread
     * unwound out of the thread; exit_status was recorded there. */
    t->unwind_set = 0;
    t->state = TH_DORMANT;

    g_current = prev;
    psp_cpu = saved;
}

static void hle_StartThread(void) {
    /* (thid, arglen, argp) */
    psp_thread *t = find_thread(psp_arg(0));
    if (!t) { psp_ret(SCE_KERNEL_ERROR_ILLEGAL_THID); return; }
    if (t->state != TH_DORMANT) { psp_ret(ERR_NOT_DORMANT); return; }

    if (!g_sched_on) {
        start_inline(t, psp_arg(1), psp_arg(2));
        psp_ret(SCE_KERNEL_ERROR_OK);
        return;
    }
    prepare_start(t, psp_arg(1), psp_arg(2), psp_cpu.r[PSP_REG_GP]);
    make_ready_back(t);
    if (ttrace())
        fprintf(stderr, "[thread] start %s (0x%X) by %s\n", t->name, t->uid,
                g_current ? g_current->name : "host");
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void exit_current(uint32_t status, int del) {
    if (g_sched_on && g_current) {
        g_current->delete_on_exit = del;
        thread_finish(g_current, status);
    }
    if (g_current && g_current->unwind_set) {
        g_current->exit_status = status;
        longjmp(g_current->unwind, 1);
    }
    /* Nothing to unwind to: the module called ExitThread from its entry rather
     * than from a started thread. Nothing further can run. */
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void hle_ExitThread(void)       { exit_current(psp_arg(0), 0); }
static void hle_ExitDeleteThread(void) { exit_current(psp_arg(0), 1); }

static void hle_DeleteThread(void) {
    psp_thread *t = find_thread(psp_arg(0));
    if (!t) { psp_ret(SCE_KERNEL_ERROR_ILLEGAL_THID); return; }
    if (g_sched_on && t->state != TH_DORMANT) { psp_ret(ERR_NOT_DORMANT); return; }
    fiber_delete(t);
    release_thread(t);
    psp_ret(SCE_KERNEL_ERROR_OK);
}

/* Stop another thread wherever it is. Its fiber is abandoned mid-call; that
 * is safe because nothing on a fiber's host stack outlives it. */
static uint32_t terminate(psp_thread *t) {
    if (t == g_current) return SCE_KERNEL_ERROR_ILLEGAL_THID;
    if (t->state == TH_DORMANT) return ERR_DORMANT;
    t->state = TH_DORMANT;
    t->wait = W_NONE;
    t->exit_status = 0x800201ACu;   /* THREAD_TERMINATED */
    fiber_delete(t);
    wake_end_waiters(t);
    return 0;
}

static void hle_TerminateThread(void) {
    psp_thread *t = find_thread(psp_arg(0));
    if (!t) { psp_ret(ERR_UNKNOWN_THID); return; }
    psp_ret(terminate(t));
}

static void hle_TerminateDeleteThread(void) {
    psp_thread *t = find_thread(psp_arg(0));
    if (!t) { psp_ret(ERR_UNKNOWN_THID); return; }
    uint32_t r = terminate(t);
    if (r == 0 || r == ERR_DORMANT) { release_thread(t); r = 0; }
    psp_ret(r);
}

static void hle_DelayThread(void) {
    if (!g_sched_on || !g_current) { psp_ret(SCE_KERNEL_ERROR_OK); return; }
    uint32_t us = psp_arg(0);
    if (us < 200) us = 200;          /* the kernel's minimum effective delay */
    g_current->wait_until = 0;
    uint64_t until = psp_sched_now_us() + us;
    psp_thread *t = g_current;
    t->wait = W_DELAY; t->wait_id = 0; t->wait_timeout_ptr = 0;
    t->wait_until = until; t->wait_cb = 0; t->wait_seq = ++g_wait_seq;
    t->state = TH_WAITING; t->wait_start = psp_sched_now_us();
    yield_to_scheduler();
    psp_ret(0);
}

static void hle_DelayThreadCB(void) {
    if (!g_sched_on || !g_current) { psp_ret(SCE_KERNEL_ERROR_OK); return; }
    uint32_t us = psp_arg(0);
    if (us < 200) us = 200;
    psp_thread *t = g_current;
    uint64_t until = psp_sched_now_us() + us;
    for (;;) {
        run_callbacks(t);
        t->wait = W_DELAY; t->wait_id = 0; t->wait_timeout_ptr = 0;
        t->wait_until = until; t->wait_cb = 1; t->wait_seq = ++g_wait_seq;
        t->wake_cb = 0;
        t->state = TH_WAITING; t->wait_start = psp_sched_now_us();
        yield_to_scheduler();
        if (!t->wake_cb) break;
    }
    psp_ret(0);
}

static void sleep_thread(int cb) {
    psp_thread *t = g_current;
    if (t && t->wakeup_count) { t->wakeup_count--; psp_ret(0); return; }
    if (!g_sched_on || !t) { warn_block("sceKernelSleepThread"); psp_ret(0); return; }
    psp_ret(wait_current(W_SLEEP, 0, 0, cb, 0, 0, 0));
}
static void hle_SleepThread(void)   { sleep_thread(0); }
static void hle_SleepThreadCB(void) { sleep_thread(1); }

static void hle_WakeupThread(void) {
    psp_thread *t = find_thread(psp_arg(0));
    if (!t) { psp_ret(ERR_UNKNOWN_THID); return; }
    if (t->state == TH_WAITING && t->wait == W_SLEEP) wake(t, 0);
    else t->wakeup_count++;
    psp_ret(0);
}

static void hle_WaitThreadEnd(void) {
    /* (thid, timeout*) -- returns the exit status. */
    psp_thread *t = find_thread(psp_arg(0));
    if (!t) { psp_ret(SCE_KERNEL_ERROR_ILLEGAL_THID); return; }
    if (t->state == TH_DORMANT || !g_sched_on) { psp_ret(t->exit_status); return; }
    psp_ret(wait_current(W_THREADEND, t->uid, psp_arg(1), 0, 0, 0, 0));
}

static void hle_GetThreadExitStatus(void) {
    psp_thread *t = find_thread(psp_arg(0));
    if (!t) { psp_ret(ERR_UNKNOWN_THID); return; }
    psp_ret(t->state == TH_DORMANT ? t->exit_status : ERR_NOT_DORMANT);
}

static void hle_ReleaseWaitThread(void) {
    psp_thread *t = find_thread(psp_arg(0));
    if (!t) { psp_ret(ERR_UNKNOWN_THID); return; }
    if (t->state != TH_WAITING) { psp_ret(ERR_NOT_WAIT); return; }
    wake(t, ERR_RELEASE_WAIT);
    psp_ret(0);
}

static void hle_GetThreadId(void) { psp_ret(g_current ? g_current->uid : 0); }

static void hle_SuspendThread(void) {
    psp_thread *t = find_thread(psp_arg(0));
    if (!t) { psp_ret(SCE_KERNEL_ERROR_ILLEGAL_THID); return; }
    t->suspended = 1;
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void hle_ResumeThread(void) {
    psp_thread *t = find_thread(psp_arg(0));
    if (!t) { psp_ret(SCE_KERNEL_ERROR_ILLEGAL_THID); return; }
    t->suspended = 0;
    if (!g_sched_on && t->state != TH_DORMANT) t->state = TH_READY;
    if (g_current && t->state == TH_READY && t->priority < g_current->priority) g_resched = 1;
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void hle_ChangeThreadPriority(void) {
    uint32_t id = psp_arg(0);
    psp_thread *t = id ? find_thread(id) : g_current;
    if (!t) { psp_ret(SCE_KERNEL_ERROR_ILLEGAL_THID); return; }
    uint32_t prio = psp_arg(1);
    if (prio == 0) prio = g_current ? g_current->priority : t->priority;
    t->priority = prio;
    g_resched = 1;
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void hle_GetThreadCurrentPriority(void) {
    psp_ret(g_current ? g_current->priority : 0);
}

static void hle_ChangeCurrentThreadAttr(void) {
    if (g_current) g_current->attr = (g_current->attr & ~psp_arg(0)) | psp_arg(1);
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void hle_GetThreadStackFreeSize(void) {
    /* The firmware counts the untouched 0xFF fill from the bottom of the
     * stack. The fill is painted at creation, so this is the real answer. */
    uint32_t id = psp_arg(0);
    psp_thread *t = id ? find_thread(id) : g_current;
    if (!t) { psp_ret(0); return; }
    uint32_t n = 0;
    for (uint32_t a = t->stack_base + 4; a < t->stack_base + t->stack_size; a += 4) {
        if (psp_read32(a) != 0xFFFFFFFFu) break;
        n += 4;
    }
    psp_ret(n);
}

/* ---- semaphores ---------------------------------------------------------- */

static void hle_CreateSema(void) {
    /* (name, attr, initVal, maxVal, option) */
    psp_sema *s = NULL;
    for (int i = 0; i < MAX_SEMAS; i++) if (!g_sema[i].used) { s = &g_sema[i]; break; }
    if (!s) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }

    memset(s, 0, sizeof *s);
    psp_str(psp_arg(0), s->name, sizeof s->name);
    s->attr       = psp_arg(1);
    s->init_count = s->count = (int32_t)psp_arg(2);
    s->max_count  = (int32_t)psp_arg(3);
    s->uid = g_next_uid++;
    s->used = 1;
    psp_ret(s->uid);
}

static void wake_all(int type, uint32_t id, uint32_t result) {
    for (int i = 0; i < MAX_THREADS; i++) {
        psp_thread *t = &g_thread[i];
        if (t->used && t->state == TH_WAITING && t->wait == type && t->wait_id == id)
            wake(t, result);
    }
}

static void hle_DeleteSema(void) {
    psp_sema *s = find_sema(psp_arg(0));
    if (!s) { psp_ret(ERR_UNKNOWN_SEMID); return; }
    wake_all(W_SEMA, s->uid, ERR_WAIT_DELETE);
    s->used = 0;
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void sema_wake(psp_sema *s) {
    psp_thread *w[MAX_THREADS];
    int n = collect_waiters(W_SEMA, s->uid, s->attr, w);
    for (int i = 0; i < n; i++) {
        if ((int32_t)w[i]->wait_a > s->count) {
            /* FIFO order: a waiter that cannot be satisfied holds the queue. */
            if (!(s->attr & ATTR_PRIORITY_ORDER)) break;
            continue;
        }
        s->count -= (int32_t)w[i]->wait_a;
        wake(w[i], 0);
    }
}

static void hle_SignalSema(void) {
    psp_sema *s = find_sema(psp_arg(0));
    if (!s) { psp_ret(ERR_UNKNOWN_SEMID); return; }
    int32_t n = (int32_t)psp_arg(1);
    /* Overflow is refused, not saturated: the count is left unchanged. */
    if (s->max_count > 0 && s->count + n > s->max_count) { psp_ret(ERR_SEMA_OVF); return; }
    s->count += n;
    sema_wake(s);
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void wait_sema(int cb) {
    psp_sema *s = find_sema(psp_arg(0));
    if (!s) { psp_ret(ERR_UNKNOWN_SEMID); return; }
    int32_t need = (int32_t)psp_arg(1);
    if (need <= 0 || (s->max_count > 0 && need > s->max_count)) { psp_ret(ERR_ILLEGAL_COUNT); return; }
    if (s->count >= need) {
        s->count -= need;
        if (cb && g_current) run_callbacks(g_current);
        psp_ret(SCE_KERNEL_ERROR_OK);
        return;
    }
    if (!g_sched_on) { warn_block("sceKernelWaitSema"); psp_ret(ERR_WAIT_TIMEOUT); return; }
    psp_ret(wait_current(W_SEMA, s->uid, psp_arg(2), cb, (uint32_t)need, 0, 0));
}
static void hle_WaitSema(void)   { wait_sema(0); }
static void hle_WaitSemaCB(void) { wait_sema(1); }

static void hle_PollSema(void) {
    psp_sema *s = find_sema(psp_arg(0));
    if (!s) { psp_ret(ERR_UNKNOWN_SEMID); return; }
    int32_t need = (int32_t)psp_arg(1);
    if (need <= 0) { psp_ret(ERR_ILLEGAL_COUNT); return; }
    if (s->count < need) { psp_ret(0x800201ADu); return; }   /* SEMA_ZERO */
    s->count -= need;
    psp_ret(0);
}

static void hle_ReferSemaStatus(void) {
    psp_sema *s = find_sema(psp_arg(0));
    if (!s) { psp_ret(ERR_UNKNOWN_SEMID); return; }
    uint32_t info = psp_arg(1);
    psp_thread *w[MAX_THREADS];
    int nw = collect_waiters(W_SEMA, s->uid, s->attr, w);
    if (info && psp_read32(info) >= 0x38) {
        for (int i = 0; i < 32; i++) psp_write8(info + 4 + (uint32_t)i, (uint8_t)s->name[i]);
        psp_write32(info + 0x24, s->attr);
        psp_write32(info + 0x28, (uint32_t)s->init_count);
        psp_write32(info + 0x2C, (uint32_t)s->count);
        psp_write32(info + 0x30, (uint32_t)s->max_count);
        psp_write32(info + 0x34, (uint32_t)nw);
    }
    psp_ret(0);
}

/* ---- event flags --------------------------------------------------------- */

static void hle_CreateEventFlag(void) {
    /* (name, attr, bits, option) */
    psp_evflag *f = NULL;
    for (int i = 0; i < MAX_FLAGS; i++) if (!g_flag[i].used) { f = &g_flag[i]; break; }
    if (!f) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }

    memset(f, 0, sizeof *f);
    psp_str(psp_arg(0), f->name, sizeof f->name);
    f->attr = psp_arg(1);
    f->init_pattern = f->pattern = psp_arg(2);
    f->uid = g_next_uid++;
    f->used = 1;
    psp_ret(f->uid);
}

static void hle_DeleteEventFlag(void) {
    psp_evflag *f = find_flag(psp_arg(0));
    if (!f) { psp_ret(ERR_UNKNOWN_EVFID); return; }
    wake_all(W_EVF, f->uid, ERR_WAIT_DELETE);
    f->used = 0;
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static int evf_satisfied(uint32_t pattern, uint32_t bits, uint32_t mode) {
    return (mode & PSP_EVENT_WAITOR) ? (pattern & bits) != 0 : (pattern & bits) == bits;
}

static void evf_consume(psp_evflag *f, uint32_t bits, uint32_t mode, uint32_t out) {
    if (out) psp_write32(out, f->pattern);
    if (mode & PSP_EVENT_WAITCLEARALL) f->pattern = 0;
    else if (mode & PSP_EVENT_WAITCLEAR) f->pattern &= ~bits;
}

static void hle_SetEventFlag(void) {
    psp_evflag *f = find_flag(psp_arg(0));
    if (!f) { psp_ret(ERR_UNKNOWN_EVFID); return; }
    f->pattern |= psp_arg(1);
    psp_thread *w[MAX_THREADS];
    int n = collect_waiters(W_EVF, f->uid, f->attr, w);
    for (int i = 0; i < n; i++) {
        if (!evf_satisfied(f->pattern, w[i]->wait_a, w[i]->wait_b)) continue;
        evf_consume(f, w[i]->wait_a, w[i]->wait_b, w[i]->wait_c);
        wake(w[i], 0);
    }
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void hle_ClearEventFlag(void) {
    psp_evflag *f = find_flag(psp_arg(0));
    if (!f) { psp_ret(ERR_UNKNOWN_EVFID); return; }
    /* The argument is a mask of bits to KEEP, not bits to clear. Getting this
     * backwards leaves a game waiting on a flag that never clears. */
    f->pattern &= psp_arg(1);
    psp_ret(SCE_KERNEL_ERROR_OK);
}

static void wait_event_flag(int cb, int poll) {
    /* (evfid, bits, wait mode, outBits, timeout) */
    psp_evflag *f = find_flag(psp_arg(0));
    if (!f) { psp_ret(ERR_UNKNOWN_EVFID); return; }

    uint32_t bits = psp_arg(1);
    uint32_t mode = psp_arg(2);
    uint32_t out  = psp_arg(3);
    if (mode & ~(PSP_EVENT_WAITOR | PSP_EVENT_WAITCLEAR | PSP_EVENT_WAITCLEARALL)) {
        psp_ret(ERR_ILLEGAL_MODE); return;
    }
    if (!bits) { psp_ret(ERR_EVF_ILPAT); return; }

    if (evf_satisfied(f->pattern, bits, mode)) {
        evf_consume(f, bits, mode, out);
        if (cb && g_current) run_callbacks(g_current);
        psp_ret(SCE_KERNEL_ERROR_OK);
        return;
    }
    if (out) psp_write32(out, f->pattern);
    if (poll) { psp_ret(0x800201AFu); return; }               /* EVF_COND */
    if (!(f->attr & EVF_ATTR_MULTI)) {
        psp_thread *w[MAX_THREADS];
        if (collect_waiters(W_EVF, f->uid, f->attr, w) > 0) { psp_ret(ERR_EVF_MULTI); return; }
    }
    if (!g_sched_on) { warn_block("sceKernelWaitEventFlag"); psp_ret(ERR_WAIT_TIMEOUT); return; }
    psp_ret(wait_current(W_EVF, f->uid, psp_arg(4), cb, bits, mode, out));
}
static void hle_WaitEventFlag(void)   { wait_event_flag(0, 0); }
static void hle_WaitEventFlagCB(void) { wait_event_flag(1, 0); }
static void hle_PollEventFlag(void)   { wait_event_flag(0, 1); }

static void hle_ReferEventFlagStatus(void) {
    psp_evflag *f = find_flag(psp_arg(0));
    if (!f) { psp_ret(ERR_UNKNOWN_EVFID); return; }
    uint32_t info = psp_arg(1);
    psp_thread *w[MAX_THREADS];
    int nw = collect_waiters(W_EVF, f->uid, f->attr, w);
    /* SceKernelEventFlagInfo: size, name[32], attr, initPattern,
     * currentPattern, numWaitThreads. Written up to the caller's size. */
    uint32_t size = info ? psp_read32(info) : 0;
    if (size >= 0x24) for (int i = 0; i < 32; i++) psp_write8(info + 4 + (uint32_t)i, (uint8_t)f->name[i]);
    if (size >= 0x28) psp_write32(info + 0x24, f->attr);
    if (size >= 0x2C) psp_write32(info + 0x28, f->init_pattern);
    if (size >= 0x30) psp_write32(info + 0x2C, f->pattern);
    if (size >= 0x34) psp_write32(info + 0x30, (uint32_t)nw);
    psp_ret(0);
}

/* ---- callbacks ----------------------------------------------------------- */

static void hle_CreateCallback(void) {
    psp_callback *c = NULL;
    for (int i = 0; i < MAX_CBS; i++) if (!g_cb[i].used) { c = &g_cb[i]; break; }
    if (!c) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }

    memset(c, 0, sizeof *c);
    psp_str(psp_arg(0), c->name, sizeof c->name);
    c->func  = psp_arg(1);
    c->arg   = psp_arg(2);
    c->owner = g_current ? g_current->uid : 0;
    c->uid   = g_next_uid++;
    c->used  = 1;
    psp_ret(c->uid);
}

static void hle_DeleteCallback(void) {
    psp_callback *c = find_cb(psp_arg(0));
    if (!c) { psp_ret(ERR_UNKNOWN_CBID); return; }
    c->used = 0;
    psp_ret(0);
}

static void hle_CheckCallback(void) {
    psp_ret(g_current ? (uint32_t)(run_callbacks(g_current) > 0) : 0);
}

/* ---- mutexes ------------------------------------------------------------- */

static psp_mutex *mutex_alloc(void) {
    for (int i = 0; i < MAX_MUTEXES; i++)
        if (!g_mutex[i].used) { memset(&g_mutex[i], 0, sizeof g_mutex[i]); return &g_mutex[i]; }
    return NULL;
}

static uint32_t cur_thid(void) { return g_current ? g_current->uid : 0; }

/* A LwMutex keeps its state in a guest work area so the user-mode fast path
 * can lock it without a syscall: count, owner thread, attr, waiter count, uid. */
static void lw_sync(psp_mutex *m) {
    if (!m->workarea) return;
    psp_thread *w[MAX_THREADS];
    psp_write32(m->workarea + 0, (uint32_t)m->count);
    psp_write32(m->workarea + 4, m->count ? m->owner : 0);
    psp_write32(m->workarea + 8, m->attr);
    psp_write32(m->workarea + 12, (uint32_t)collect_waiters(W_LWMUTEX, m->uid, m->attr, w));
    psp_write32(m->workarea + 16, m->uid);
}

static void hle_CreateMutex(void) {
    /* (name, attr, initCount, option) */
    psp_mutex *m = mutex_alloc();
    if (!m) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }
    psp_str(psp_arg(0), m->name, sizeof m->name);
    m->attr = psp_arg(1);
    m->count = (int32_t)psp_arg(2);
    m->owner = m->count ? cur_thid() : 0;
    m->uid = g_next_uid++;
    m->used = 1;
    psp_ret(m->uid);
}

static void hle_CreateLwMutex(void) {
    /* (workarea, name, attr, initCount, option) */
    psp_mutex *m = mutex_alloc();
    if (!m) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }
    m->workarea = psp_arg(0);
    psp_str(psp_arg(1), m->name, sizeof m->name);
    m->attr = psp_arg(2);
    m->count = (int32_t)psp_arg(3);
    m->owner = m->count ? cur_thid() : 0;
    m->uid = g_next_uid++;
    m->used = 1;
    lw_sync(m);
    psp_ret(0);
}

static psp_mutex *find_lw(uint32_t workarea) {
    uint32_t uid = psp_read32(workarea + 16);
    psp_mutex *m = find_mutex(uid);
    return (m && m->workarea == workarea) ? m : NULL;
}

static void mutex_delete(psp_mutex *m, int type) {
    wake_all(type, m->uid, ERR_WAIT_DELETE);
    m->used = 0;
}

static void hle_DeleteMutex(void) {
    psp_mutex *m = find_mutex(psp_arg(0));
    if (!m || m->workarea) { psp_ret(ERR_MUTEX_NOT_FOUND); return; }
    mutex_delete(m, W_MUTEX);
    psp_ret(0);
}

static void hle_DeleteLwMutex(void) {
    psp_mutex *m = find_lw(psp_arg(0));
    if (!m) { psp_ret(ERR_LWMUTEX_NOT_FOUND); return; }
    mutex_delete(m, W_LWMUTEX);
    psp_write32(psp_arg(0) + 16, 0);
    psp_ret(0);
}

/* Try to take `n` counts. 1 = taken, 0 = must wait, else an error code. */
static uint32_t mutex_try(psp_mutex *m, int32_t n, int lw) {
    if (n <= 0) return ERR_ILLEGAL_COUNT;
    if (m->count == 0) {
        m->count = n;
        m->owner = cur_thid();
        return 1;
    }
    if (m->owner == cur_thid()) {
        if (!(m->attr & MUTEX_ATTR_RECURSIVE)) return lw ? ERR_LWMUTEX_RECURSIVE : ERR_MUTEX_RECURSIVE;
        if (m->count + n < m->count) return lw ? ERR_LWMUTEX_LOCK_OVERFLOW : ERR_MUTEX_LOCK_OVERFLOW;
        m->count += n;
        return 1;
    }
    return 0;
}

static uint32_t mutex_lock(psp_mutex *m, int32_t n, uint32_t timeout, int cb, int try_only, int lw) {
    uint32_t r = mutex_try(m, n, lw);
    if (r == 1) { lw_sync(m); return 0; }
    if (r != 0) return r;
    if (try_only) return lw ? ERR_LWMUTEX_LOCKED : ERR_MUTEX_LOCKED;
    if (!g_sched_on) { warn_block("mutex lock"); return ERR_WAIT_TIMEOUT; }
    return wait_current(lw ? W_LWMUTEX : W_MUTEX, m->uid, timeout, cb, (uint32_t)n, 0, 0);
}

static uint32_t mutex_unlock(psp_mutex *m, int32_t n, int lw) {
    if (n <= 0) return ERR_ILLEGAL_COUNT;
    if (m->count == 0 || m->owner != cur_thid()) return lw ? ERR_LWMUTEX_UNLOCKED : ERR_MUTEX_UNLOCKED;
    if (n > m->count) return lw ? ERR_LWMUTEX_UNLOCK_UNDERFLOW : ERR_MUTEX_UNLOCK_UNDERFLOW;
    m->count -= n;
    if (m->count == 0) {
        m->owner = 0;
        psp_thread *w[MAX_THREADS];
        int nw = collect_waiters(lw ? W_LWMUTEX : W_MUTEX, m->uid, m->attr, w);
        if (nw) {
            /* Hand the lock straight to the next waiter. */
            m->count = (int32_t)w[0]->wait_a;
            m->owner = w[0]->uid;
            wake(w[0], 0);
        }
    }
    lw_sync(m);
    return 0;
}

static void hle_LockMutex(void) {
    psp_mutex *m = find_mutex(psp_arg(0));
    if (!m || m->workarea) { psp_ret(ERR_MUTEX_NOT_FOUND); return; }
    psp_ret(mutex_lock(m, (int32_t)psp_arg(1), psp_arg(2), 0, 0, 0));
}
static void hle_TryLockMutex(void) {
    psp_mutex *m = find_mutex(psp_arg(0));
    if (!m || m->workarea) { psp_ret(ERR_MUTEX_NOT_FOUND); return; }
    psp_ret(mutex_lock(m, (int32_t)psp_arg(1), 0, 0, 1, 0));
}
static void hle_UnlockMutex(void) {
    psp_mutex *m = find_mutex(psp_arg(0));
    if (!m || m->workarea) { psp_ret(ERR_MUTEX_NOT_FOUND); return; }
    psp_ret(mutex_unlock(m, (int32_t)psp_arg(1), 0));
}
static void hle_LockLwMutex(void) {
    psp_mutex *m = find_lw(psp_arg(0));
    if (!m) { psp_ret(ERR_LWMUTEX_NOT_FOUND); return; }
    psp_ret(mutex_lock(m, (int32_t)psp_arg(1), psp_arg(2), 0, 0, 1));
}
static void hle_UnlockLwMutex(void) {
    psp_mutex *m = find_lw(psp_arg(0));
    if (!m) { psp_ret(ERR_LWMUTEX_NOT_FOUND); return; }
    psp_ret(mutex_unlock(m, (int32_t)psp_arg(1), 1));
}

/* ---- message boxes ------------------------------------------------------- */

static void hle_CreateMbx(void) {
    psp_mbx *b = NULL;
    for (int i = 0; i < MAX_MBXS; i++) if (!g_mbx[i].used) { b = &g_mbx[i]; break; }
    if (!b) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }
    memset(b, 0, sizeof *b);
    psp_str(psp_arg(0), b->name, sizeof b->name);
    b->attr = psp_arg(1);
    b->uid = g_next_uid++;
    b->used = 1;
    psp_ret(b->uid);
}

static void hle_DeleteMbx(void) {
    psp_mbx *b = find_mbx(psp_arg(0));
    if (!b) { psp_ret(ERR_UNKNOWN_MBXID); return; }
    wake_all(W_MBX, b->uid, ERR_WAIT_DELETE);
    b->used = 0;
    psp_ret(0);
}

static void hle_SendMbx(void) {
    psp_mbx *b = find_mbx(psp_arg(0));
    if (!b) { psp_ret(ERR_UNKNOWN_MBXID); return; }
    uint32_t msg = psp_arg(1);
    psp_thread *w[MAX_THREADS];
    if (collect_waiters(W_MBX, b->uid, b->attr, w) > 0) {
        if (w[0]->wait_c) psp_write32(w[0]->wait_c, msg);
        wake(w[0], 0);
        psp_ret(0);
        return;
    }
    if (b->nmsgs >= MAX_MBX_MSGS) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }
    /* SceKernelMsgPacket: next pointer, then a priority byte. With the
     * priority attribute, lower values are received first; otherwise FIFO. */
    int at = b->nmsgs;
    if (b->attr & MBX_ATTR_MSG_PRIORITY) {
        uint8_t p = psp_read8(msg + 4);
        while (at > 0 && psp_read8(b->msgs[at - 1] + 4) > p) { b->msgs[at] = b->msgs[at - 1]; at--; }
    }
    b->msgs[at] = msg;
    b->nmsgs++;
    psp_write32(msg, 0);
    psp_ret(0);
}

static void hle_PollMbx(void) {
    psp_mbx *b = find_mbx(psp_arg(0));
    if (!b) { psp_ret(ERR_UNKNOWN_MBXID); return; }
    if (!b->nmsgs) { psp_ret(ERR_MBOX_NOMSG); return; }
    uint32_t out = psp_arg(1);
    if (out) psp_write32(out, b->msgs[0]);
    memmove(b->msgs, b->msgs + 1, (size_t)(b->nmsgs - 1) * sizeof b->msgs[0]);
    b->nmsgs--;
    psp_ret(0);
}

static void receive_mbx(int cb) {
    psp_mbx *b = find_mbx(psp_arg(0));
    if (!b) { psp_ret(ERR_UNKNOWN_MBXID); return; }
    if (b->nmsgs) { hle_PollMbx(); return; }
    if (!g_sched_on) { warn_block("sceKernelReceiveMbx"); psp_ret(ERR_WAIT_TIMEOUT); return; }
    psp_ret(wait_current(W_MBX, b->uid, psp_arg(2), cb, 0, 0, psp_arg(1)));
}
static void hle_ReceiveMbx(void)   { receive_mbx(0); }
static void hle_ReceiveMbxCB(void) { receive_mbx(1); }

/* ---- fixed-size pools ---------------------------------------------------- */

static void hle_CreateFpl(void) {
    /* (name, partition, attr, blocksize, numblocks, option) */
    psp_fpl *p = NULL;
    for (int i = 0; i < MAX_FPLS; i++) if (!g_fpl[i].used) { p = &g_fpl[i]; break; }
    if (!p) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }
    uint32_t bs = psp_arg(3), nb = psp_arg(4), opt = psp_arg(5);
    if (!bs || !nb) { psp_ret(0x800201BCu); return; }          /* ILLEGAL_SIZE */
    uint32_t align = 4;
    if (opt && psp_read32(opt) >= 8) align = psp_read32(opt + 4);
    if (!align || (align & (align - 1))) align = 4;
    uint32_t stride = (bs + align - 1) & ~(align - 1);
    uint32_t base = psp_sysmem_alloc(stride * nb + align, 0);
    if (!base) { psp_ret(SCE_KERNEL_ERROR_NO_MEMORY); return; }
    memset(p, 0, sizeof *p);
    psp_str(psp_arg(0), p->name, sizeof p->name);
    p->attr = psp_arg(2);
    p->base = (base + align - 1) & ~(align - 1);
    p->block_size = stride;
    p->nblocks = nb;
    p->in_use = (uint8_t *)calloc(nb, 1);
    p->uid = g_next_uid++;
    p->used = 1;
    psp_ret(p->uid);
}

static void hle_DeleteFpl(void) {
    psp_fpl *p = find_fpl(psp_arg(0));
    if (!p) { psp_ret(ERR_UNKNOWN_FPLID); return; }
    wake_all(W_FPL, p->uid, ERR_WAIT_DELETE);
    free(p->in_use);
    p->in_use = NULL;
    p->used = 0;
    psp_ret(0);
}

static int fpl_take(psp_fpl *p, uint32_t out) {
    for (uint32_t i = 0; i < p->nblocks; i++) {
        if (p->in_use[i]) continue;
        p->in_use[i] = 1;
        if (out) psp_write32(out, p->base + i * p->block_size);
        return 1;
    }
    return 0;
}

static void allocate_fpl(int cb, int try_only) {
    psp_fpl *p = find_fpl(psp_arg(0));
    if (!p) { psp_ret(ERR_UNKNOWN_FPLID); return; }
    if (fpl_take(p, psp_arg(1))) { psp_ret(0); return; }
    if (try_only) { psp_ret(0x800201B4u); return; }             /* NO_MEMORY-ish: MPP_EMPTY */
    if (!g_sched_on) { warn_block("sceKernelAllocateFpl"); psp_ret(ERR_WAIT_TIMEOUT); return; }
    psp_ret(wait_current(W_FPL, p->uid, psp_arg(2), cb, 0, 0, psp_arg(1)));
}
static void hle_AllocateFpl(void)    { allocate_fpl(0, 0); }
static void hle_AllocateFplCB(void)  { allocate_fpl(1, 0); }
static void hle_TryAllocateFpl(void) { allocate_fpl(0, 1); }

static void hle_FreeFpl(void) {
    psp_fpl *p = find_fpl(psp_arg(0));
    if (!p) { psp_ret(ERR_UNKNOWN_FPLID); return; }
    uint32_t a = psp_arg(1);
    if (a < p->base || (a - p->base) % p->block_size || (a - p->base) / p->block_size >= p->nblocks) {
        psp_ret(SCE_KERNEL_ERROR_ILLEGAL_MEMBLOCK); return;
    }
    uint32_t i = (a - p->base) / p->block_size;
    p->in_use[i] = 0;
    psp_thread *w[MAX_THREADS];
    if (collect_waiters(W_FPL, p->uid, p->attr, w) > 0 && fpl_take(p, w[0]->wait_c)) wake(w[0], 0);
    psp_ret(0);
}

/* ---- system time --------------------------------------------------------- */

static void hle_GetSystemTime(void) {
    uint32_t out = psp_arg(0);
    uint64_t t = psp_sched_now_us();
    if (out) { psp_write32(out, (uint32_t)t); psp_write32(out + 4, (uint32_t)(t >> 32)); }
    psp_ret(0);
}

static void hle_GetSystemTimeWide(void) {
    uint64_t t = psp_sched_now_us();
    psp_cpu.r[PSP_REG_V0] = (uint32_t)t;
    psp_cpu.r[PSP_REG_V1] = (uint32_t)(t >> 32);
}

static void hle_GetSystemTimeLow(void) { psp_ret((uint32_t)psp_sched_now_us()); }

static void hle_SysClock2USec(void) {
    /* (const SceKernelSysClock *clock, u32 *sec, u32 *usec) */
    uint32_t c = psp_arg(0);
    uint64_t t = (uint64_t)psp_read32(c) | ((uint64_t)psp_read32(c + 4) << 32);
    if (psp_arg(1)) psp_write32(psp_arg(1), (uint32_t)(t / 1000000u));
    if (psp_arg(2)) psp_write32(psp_arg(2), (uint32_t)(t % 1000000u));
    psp_ret(0);
}

/* ---- interrupts ---------------------------------------------------------- */

static int interrupts_enabled(void) { return psp_intr_enabled(); }

static void hle_RegisterSubIntrHandler(void) {
    /* (intno, subintno, handler, arg) */
    uint32_t i = psp_arg(0), s = psp_arg(1);
    if (i >= MAX_INTR || s >= MAX_SUBINTR) { psp_ret(0x80020065u); return; }  /* ILLEGAL_INTRCODE */
    subintr *h = &g_subintr[i][s];
    if (h->used) { psp_ret(0x80020067u); return; }                            /* FOUND_HANDLER */
    h->handler = psp_arg(2);
    h->arg = psp_arg(3);
    h->enabled = 0;
    h->used = 1;
    psp_ret(0);
}

static void hle_ReleaseSubIntrHandler(void) {
    uint32_t i = psp_arg(0), s = psp_arg(1);
    if (i >= MAX_INTR || s >= MAX_SUBINTR) { psp_ret(0x80020065u); return; }
    if (!g_subintr[i][s].used) { psp_ret(0x80020068u); return; }              /* HANDLER_NOTFOUND */
    memset(&g_subintr[i][s], 0, sizeof g_subintr[i][s]);
    psp_ret(0);
}

static void hle_EnableSubIntr(void) {
    uint32_t i = psp_arg(0), s = psp_arg(1);
    if (i >= MAX_INTR || s >= MAX_SUBINTR) { psp_ret(0x80020065u); return; }
    if (!g_subintr[i][s].used) { psp_ret(0x80020068u); return; }
    g_subintr[i][s].enabled = 1;
    psp_ret(0);
}

/* ---- Kernel_Library ------------------------------------------------------ */

static void hle_KernelMemset(void) {
    /* (dst, c, size) -> dst */
    uint32_t d = psp_arg(0), n = psp_arg(2);
    uint8_t c = (uint8_t)psp_arg(1);
    void *p = psp_mem_ptr(d, n);
    if (p) memset(p, c, n);
    else for (uint32_t i = 0; i < n; i++) psp_write8(d + i, c);
    psp_ret(d);
}

void psp_threadman_register(void) {
    /* NIDs are SHA-1(name)[0:4] little-endian; tests/test_hle.c verifies every
     * pair below. */
    psp_hle_register(0x446D8DE6, "ThreadManForUser", "sceKernelCreateThread",            hle_CreateThread);
    psp_hle_register(0xF475845D, "ThreadManForUser", "sceKernelStartThread",             hle_StartThread);
    psp_hle_register(0xAA73C935, "ThreadManForUser", "sceKernelExitThread",              hle_ExitThread);
    psp_hle_register(0x809CE29B, "ThreadManForUser", "sceKernelExitDeleteThread",        hle_ExitDeleteThread);
    psp_hle_register(0x9FA03CD3, "ThreadManForUser", "sceKernelDeleteThread",            hle_DeleteThread);
    psp_hle_register(0x616403BA, "ThreadManForUser", "sceKernelTerminateThread",         hle_TerminateThread);
    psp_hle_register(0x383F7BCC, "ThreadManForUser", "sceKernelTerminateDeleteThread",   hle_TerminateDeleteThread);
    psp_hle_register(0xCEADEB47, "ThreadManForUser", "sceKernelDelayThread",             hle_DelayThread);
    psp_hle_register(0x68DA9E36, "ThreadManForUser", "sceKernelDelayThreadCB",           hle_DelayThreadCB);
    psp_hle_register(0x9ACE131E, "ThreadManForUser", "sceKernelSleepThread",             hle_SleepThread);
    psp_hle_register(0x82826F70, "ThreadManForUser", "sceKernelSleepThreadCB",           hle_SleepThreadCB);
    psp_hle_register(0xD59EAD2F, "ThreadManForUser", "sceKernelWakeupThread",            hle_WakeupThread);
    psp_hle_register(0x278C0DF5, "ThreadManForUser", "sceKernelWaitThreadEnd",           hle_WaitThreadEnd);
    psp_hle_register(0x3B183E26, "ThreadManForUser", "sceKernelGetThreadExitStatus",     hle_GetThreadExitStatus);
    psp_hle_register(0x2C34E053, "ThreadManForUser", "sceKernelReleaseWaitThread",       hle_ReleaseWaitThread);
    psp_hle_register(0x293B45B8, "ThreadManForUser", "sceKernelGetThreadId",             hle_GetThreadId);
    psp_hle_register(0x9944F31F, "ThreadManForUser", "sceKernelSuspendThread",           hle_SuspendThread);
    psp_hle_register(0x75156E8F, "ThreadManForUser", "sceKernelResumeThread",            hle_ResumeThread);
    psp_hle_register(0x71BC9871, "ThreadManForUser", "sceKernelChangeThreadPriority",    hle_ChangeThreadPriority);
    psp_hle_register(0x94AA61EE, "ThreadManForUser", "sceKernelGetThreadCurrentPriority",hle_GetThreadCurrentPriority);
    psp_hle_register(0xEA748E31, "ThreadManForUser", "sceKernelChangeCurrentThreadAttr", hle_ChangeCurrentThreadAttr);
    psp_hle_register(0x52089CA1, "ThreadManForUser", "sceKernelGetThreadStackFreeSize",  hle_GetThreadStackFreeSize);

    psp_hle_register(0xD6DA4BA1, "ThreadManForUser", "sceKernelCreateSema",              hle_CreateSema);
    psp_hle_register(0x28B6489C, "ThreadManForUser", "sceKernelDeleteSema",              hle_DeleteSema);
    psp_hle_register(0x3F53E640, "ThreadManForUser", "sceKernelSignalSema",              hle_SignalSema);
    psp_hle_register(0x4E3A1105, "ThreadManForUser", "sceKernelWaitSema",                hle_WaitSema);
    psp_hle_register(0x6D212BAC, "ThreadManForUser", "sceKernelWaitSemaCB",              hle_WaitSemaCB);
    psp_hle_register(0x58B1F937, "ThreadManForUser", "sceKernelPollSema",                hle_PollSema);
    psp_hle_register(0xBC6FEBC5, "ThreadManForUser", "sceKernelReferSemaStatus",         hle_ReferSemaStatus);

    psp_hle_register(0x55C20A00, "ThreadManForUser", "sceKernelCreateEventFlag",         hle_CreateEventFlag);
    psp_hle_register(0xEF9E4C70, "ThreadManForUser", "sceKernelDeleteEventFlag",         hle_DeleteEventFlag);
    psp_hle_register(0x1FB15A32, "ThreadManForUser", "sceKernelSetEventFlag",            hle_SetEventFlag);
    psp_hle_register(0x812346E4, "ThreadManForUser", "sceKernelClearEventFlag",          hle_ClearEventFlag);
    psp_hle_register(0x402FCF22, "ThreadManForUser", "sceKernelWaitEventFlag",           hle_WaitEventFlag);
    psp_hle_register(0x328C546A, "ThreadManForUser", "sceKernelWaitEventFlagCB",         hle_WaitEventFlagCB);
    psp_hle_register(0x30FD48F0, "ThreadManForUser", "sceKernelPollEventFlag",           hle_PollEventFlag);
    psp_hle_register(0xA66B0120, "ThreadManForUser", "sceKernelReferEventFlagStatus",    hle_ReferEventFlagStatus);

    psp_hle_register(0xE81CAF8F, "ThreadManForUser", "sceKernelCreateCallback",          hle_CreateCallback);
    psp_hle_register(0xEDBA5844, "ThreadManForUser", "sceKernelDeleteCallback",          hle_DeleteCallback);
    psp_hle_register(0x349D6D6C, "ThreadManForUser", "sceKernelCheckCallback",           hle_CheckCallback);

    psp_hle_register(0xB7D098C6, "ThreadManForUser", "sceKernelCreateMutex",             hle_CreateMutex);
    psp_hle_register(0xF8170FBE, "ThreadManForUser", "sceKernelDeleteMutex",             hle_DeleteMutex);
    psp_hle_register(0xB011B11F, "ThreadManForUser", "sceKernelLockMutex",               hle_LockMutex);
    psp_hle_register(0x0DDCD2C9, "ThreadManForUser", "sceKernelTryLockMutex",            hle_TryLockMutex);
    psp_hle_register(0x6B30100F, "ThreadManForUser", "sceKernelUnlockMutex",             hle_UnlockMutex);
    psp_hle_register(0x19CFF145, "ThreadManForUser", "sceKernelCreateLwMutex",           hle_CreateLwMutex);
    psp_hle_register(0x60107536, "ThreadManForUser", "sceKernelDeleteLwMutex",           hle_DeleteLwMutex);
    psp_hle_register(0xBEA46419, "Kernel_Library",   "sceKernelLockLwMutex",             hle_LockLwMutex);
    psp_hle_register(0x15B6446B, "Kernel_Library",   "sceKernelUnlockLwMutex",           hle_UnlockLwMutex);

    psp_hle_register(0x8125221D, "ThreadManForUser", "sceKernelCreateMbx",               hle_CreateMbx);
    psp_hle_register(0x86255ADA, "ThreadManForUser", "sceKernelDeleteMbx",               hle_DeleteMbx);
    psp_hle_register(0xE9B3061E, "ThreadManForUser", "sceKernelSendMbx",                 hle_SendMbx);
    psp_hle_register(0x0D81716A, "ThreadManForUser", "sceKernelPollMbx",                 hle_PollMbx);
    psp_hle_register(0x18260574, "ThreadManForUser", "sceKernelReceiveMbx",              hle_ReceiveMbx);
    psp_hle_register(0xF3986382, "ThreadManForUser", "sceKernelReceiveMbxCB",            hle_ReceiveMbxCB);

    psp_hle_register(0xC07BB470, "ThreadManForUser", "sceKernelCreateFpl",               hle_CreateFpl);
    psp_hle_register(0xED1410E0, "ThreadManForUser", "sceKernelDeleteFpl",               hle_DeleteFpl);
    psp_hle_register(0xD979E9BF, "ThreadManForUser", "sceKernelAllocateFpl",             hle_AllocateFpl);
    psp_hle_register(0xE7282CB6, "ThreadManForUser", "sceKernelAllocateFplCB",           hle_AllocateFplCB);
    psp_hle_register(0x623AE665, "ThreadManForUser", "sceKernelTryAllocateFpl",          hle_TryAllocateFpl);
    psp_hle_register(0xF6414A71, "ThreadManForUser", "sceKernelFreeFpl",                 hle_FreeFpl);

    psp_hle_register(0xDB738F35, "ThreadManForUser", "sceKernelGetSystemTime",           hle_GetSystemTime);
    psp_hle_register(0x82BC5777, "ThreadManForUser", "sceKernelGetSystemTimeWide",       hle_GetSystemTimeWide);
    psp_hle_register(0x369ED59D, "ThreadManForUser", "sceKernelGetSystemTimeLow",        hle_GetSystemTimeLow);
    psp_hle_register(0xBA6B92E2, "ThreadManForUser", "sceKernelSysClock2USec",           hle_SysClock2USec);

    psp_hle_register(0xCA04A2B9, "InterruptManager", "sceKernelRegisterSubIntrHandler",  hle_RegisterSubIntrHandler);
    psp_hle_register(0xD61E6961, "InterruptManager", "sceKernelReleaseSubIntrHandler",   hle_ReleaseSubIntrHandler);
    psp_hle_register(0xFB8E22EC, "InterruptManager", "sceKernelEnableSubIntr",           hle_EnableSubIntr);

    psp_hle_register(0xA089ECA4, "Kernel_Library",   "sceKernelMemset",                  hle_KernelMemset);
}
