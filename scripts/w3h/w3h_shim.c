/*
 * W3-H (#1164) entropy and wall-clock shim. Linux (x86_64, aarch64), test
 * processes only.
 *
 * Loaded with LD_PRELOAD by the nextest `w3h` profile wrapper. It does
 * NOTHING unless the process environment sets both
 *     W3H_SHIM_ACTIVE=1   and   W3H_ENTROPY_SEED=<integer>
 * when the library is loaded; otherwise every interposed call passes
 * straight through to the kernel / libc and w3h_shim_active() returns 0.
 *
 * When active it makes the two OS inputs a single-process simulation cannot
 * otherwise control deterministic:
 *
 *  1. Entropy. getrandom(), getentropy() and syscall(SYS_getrandom, ...)
 *     return SplitMix64 output (not a CSPRNG: test processes only). Each
 *     THREAD has its own stream, seeded by (W3H_ENTROPY_SEED, the thread's
 *     name, its ordinal among threads with that name), so one thread's
 *     draws never move another thread's position: the harness's test
 *     thread (named after the test by libtest, and running every daemon
 *     task on its current-thread runtime) sees the same values whatever
 *     the blocking pool does. Rust consumers in the lockfile reach one of
 *     these: getrandom 0.2 via syscall(SYS_getrandom), getrandom 0.3/0.4
 *     and std (HashMap RandomState, which also seeds tokio's select! RNG)
 *     via getrandom().
 *
 *  2. Wall clock. Once the harness calls w3h_shim_set_wall_offset_ns(),
 *     clock_gettime(CLOCK_REALTIME*) returns 2026-01-01T00:00:00Z plus the
 *     harness's virtual time. CLOCK_MONOTONIC is NOT changed: kernel waits
 *     with absolute monotonic deadlines (futex, condvars) keep real time.
 *
 * syscall() is interposed by an assembly trampoline that never reads
 * variadic arguments in C: SYS_getrandom is redirected with its three
 * register arguments; every other number is forwarded exactly as glibc's
 * own syscall.S does (registers shifted, arg 6 from the caller's stack
 * slot), so arbitrary-arity syscalls are passed through unchanged.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif
#ifndef GRND_RANDOM
#define GRND_RANDOM 0x0002
#endif
#ifndef GRND_INSECURE
#define GRND_INSECURE 0x0004
#endif

#define W3H_HIDDEN __attribute__((visibility("hidden")))
#define W3H_STR2(x) #x
#define W3H_STR(x) W3H_STR2(x)

/* ---- raw kernel entry (glibc-identical syscall semantics) ------------- */

/* long w3h_raw_syscall(long number, ...): glibc syscall() semantics
 * (-1 + errno on failure), implemented in assembly without va_arg. */
W3H_HIDDEN long w3h_raw_syscall(long number, ...);
/* errno = err; return -1. Tail-called from the assembly error path. */
W3H_HIDDEN long w3h_syscall_error(long err);
/* The SYS_getrandom arm of the interposed syscall(). */
W3H_HIDDEN long w3h_getrandom_syscall(void *buf, size_t len, unsigned int flags);

long w3h_syscall_error(long err) {
    errno = (int)err;
    return -1;
}

#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl w3h_raw_syscall\n"
    ".hidden w3h_raw_syscall\n"
    ".type w3h_raw_syscall,@function\n"
    "w3h_raw_syscall:\n"
    "    movq %rdi, %rax\n"
    "    movq %rsi, %rdi\n"
    "    movq %rdx, %rsi\n"
    "    movq %rcx, %rdx\n"
    "    movq %r8, %r10\n"
    "    movq %r9, %r8\n"
    "    movq 8(%rsp), %r9\n"
    "    syscall\n"
    "    cmpq $-4095, %rax\n"
    "    jae 1f\n"
    "    ret\n"
    "1:\n"
    "    negq %rax\n"
    "    movq %rax, %rdi\n"
    "    jmp w3h_syscall_error\n"
    ".size w3h_raw_syscall, .-w3h_raw_syscall\n"
    "\n"
    ".globl syscall\n"
    ".type syscall,@function\n"
    "syscall:\n"
    "    cmpq $" W3H_STR(SYS_getrandom) ", %rdi\n"
    "    jne w3h_raw_syscall\n"
    "    movq %rsi, %rdi\n"
    "    movq %rdx, %rsi\n"
    "    movl %ecx, %edx\n"
    "    jmp w3h_getrandom_syscall\n"
    ".size syscall, .-syscall\n");
#elif defined(__aarch64__)
__asm__(
    ".text\n"
    ".globl w3h_raw_syscall\n"
    ".hidden w3h_raw_syscall\n"
    ".type w3h_raw_syscall,%function\n"
    "w3h_raw_syscall:\n"
    "    uxtw x8, w0\n"
    "    mov x0, x1\n"
    "    mov x1, x2\n"
    "    mov x2, x3\n"
    "    mov x3, x4\n"
    "    mov x4, x5\n"
    "    mov x5, x6\n"
    "    svc #0\n"
    "    cmn x0, #4095\n"
    "    b.cs 1f\n"
    "    ret\n"
    "1:\n"
    "    neg x0, x0\n"
    "    b w3h_syscall_error\n"
    ".size w3h_raw_syscall, .-w3h_raw_syscall\n"
    "\n"
    ".globl syscall\n"
    ".type syscall,%function\n"
    "syscall:\n"
    "    cmp x0, #" W3H_STR(SYS_getrandom) "\n"
    "    b.ne w3h_raw_syscall\n"
    "    mov x0, x1\n"
    "    mov x1, x2\n"
    "    mov w2, w3\n"
    "    b w3h_getrandom_syscall\n"
    ".size syscall, .-syscall\n");
#else
#error "w3h_shim supports x86_64 and aarch64 Linux only"
#endif

/* ---- activation ------------------------------------------------------- */

static atomic_int shim_active;
static atomic_ulong entropy_calls;

static uint64_t entropy_seed;

/* Per-thread streams and their accounting. */
#define W3H_MAX_THREADS 512
#define W3H_NAME_LEN 16
struct thread_entry {
    char name[W3H_NAME_LEN];
    unsigned int ordinal;
    atomic_ulong draws;
};
static pthread_mutex_t registry_lock = PTHREAD_MUTEX_INITIALIZER;
static struct thread_entry registry[W3H_MAX_THREADS];
static atomic_int registry_len;
static atomic_ulong unregistered_draws;

static __thread int tl_seeded;
static __thread int tl_index = -1;
static __thread uint64_t tl_state;

typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
static _Atomic(clock_gettime_fn) real_clock_gettime;

__attribute__((constructor)) static void w3h_shim_init(void) {
    /* Constructors run single-threaded, before the Rust runtime starts, so
     * the resolution below cannot race a caller. Any call that arrives
     * before this point sees `shim_active == 0` / a NULL resolver and takes
     * the raw-syscall pass-through, so dlsym is never re-entered from an
     * interposed call. */
    void *resolved = dlsym(RTLD_NEXT, "clock_gettime");
    if (resolved != NULL) {
        clock_gettime_fn fn;
        memcpy(&fn, &resolved, sizeof fn);
        atomic_store(&real_clock_gettime, fn);
    }
    const char *active = getenv("W3H_SHIM_ACTIVE");
    const char *seed = getenv("W3H_ENTROPY_SEED");
    if (active == NULL || strcmp(active, "1") != 0 || seed == NULL || *seed == '\0') {
        return;
    }
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(seed, &end, 0);
    if (errno != 0 || end == NULL || *end != '\0') {
        return;
    }
    entropy_seed = (uint64_t)value;
    atomic_store(&shim_active, 1);
}

/* ---- entropy ---------------------------------------------------------- */

static uint64_t mix64(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static uint64_t splitmix64(uint64_t *state) {
    return mix64(*state += 0x9e3779b97f4a7c15ULL);
}

static uint64_t fnv1a(const char *text) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    for (; *text != '\0'; ++text) {
        hash ^= (unsigned char)*text;
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

/* First draw on this thread: find its name and its ordinal among threads
 * with the same name (registration order), and derive its stream. */
static void seed_this_thread(void) {
    char name[W3H_NAME_LEN];
    memset(name, 0, sizeof name);
    if (pthread_getname_np(pthread_self(), name, sizeof name) != 0) {
        strcpy(name, "?");
    }
    unsigned int ordinal = 0;
    pthread_mutex_lock(&registry_lock);
    int len = atomic_load(&registry_len);
    for (int i = 0; i < len; ++i) {
        if (strncmp(registry[i].name, name, W3H_NAME_LEN) == 0) {
            ordinal++;
        }
    }
    if (len < W3H_MAX_THREADS) {
        memcpy(registry[len].name, name, W3H_NAME_LEN);
        registry[len].ordinal = ordinal;
        atomic_store(&registry[len].draws, 0);
        tl_index = len;
        atomic_store(&registry_len, len + 1);
    }
    pthread_mutex_unlock(&registry_lock);
    tl_state = mix64(entropy_seed ^ mix64(fnv1a(name)) ^ mix64(0x5157ULL + ordinal));
    tl_seeded = 1;
}

static void fill(void *buf, size_t len) {
    unsigned char *out = (unsigned char *)buf;
    if (!tl_seeded) {
        seed_this_thread();
    }
    while (len > 0) {
        uint64_t word = splitmix64(&tl_state);
        size_t n = len < sizeof word ? len : sizeof word;
        memcpy(out, &word, n);
        out += n;
        len -= n;
    }
    atomic_fetch_add(&entropy_calls, 1);
    if (tl_index >= 0) {
        atomic_fetch_add(&registry[tl_index].draws, 1);
    } else {
        atomic_fetch_add(&unregistered_draws, 1);
    }
}

/* EFAULT for a non-NULL buffer the caller cannot write: let the kernel
 * write the WHOLE range first. getrandom(2) returns a short count when it
 * faults part-way (or for very large requests), so the probe continues from
 * the returned offset until the range is covered or the kernel reports
 * EFAULT. Whatever it wrote is then overwritten with the deterministic
 * stream; errno is preserved unless the buffer faults. Best effort, and
 * documented as such: when the kernel cannot serve the probe at all
 * (EAGAIN before its pool is ready, or ENOSYS) the range is not validated
 * and the fill proceeds, as a real getrandom would block or fail instead. */
static int buffer_faults(void *buf, size_t len) {
    int saved = errno;
    unsigned char *at = (unsigned char *)buf;
    size_t left = len;
    int fault = 0;
    while (left > 0) {
        long got = w3h_raw_syscall(SYS_getrandom, at, left, GRND_NONBLOCK);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            fault = errno == EFAULT;
            break;
        }
        if (got == 0) {
            break;
        }
        at += got;
        left -= (size_t)got;
    }
    errno = saved;
    return fault;
}

long w3h_getrandom_syscall(void *buf, size_t len, unsigned int flags) {
    if (!atomic_load(&shim_active)) {
        return w3h_raw_syscall(SYS_getrandom, buf, len, flags);
    }
    /* Linux getrandom(2) contract for an always-ready source: unknown flag
     * bits and GRND_RANDOM|GRND_INSECURE are EINVAL; a NULL buffer with a
     * non-zero length is EFAULT; otherwise the full request is served. */
    if ((flags & ~(unsigned int)(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE)) != 0 ||
        ((flags & GRND_RANDOM) && (flags & GRND_INSECURE))) {
        return w3h_syscall_error(EINVAL);
    }
    if (buf == NULL && len > 0) {
        return w3h_syscall_error(EFAULT);
    }
    if (len > 0 && buffer_faults(buf, len)) {
        return w3h_syscall_error(EFAULT);
    }
    if (len > 0) {
        fill(buf, len);
    }
    return (long)len;
}

ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
    return (ssize_t)w3h_getrandom_syscall(buf, buflen, flags);
}

int getentropy(void *buffer, size_t length) {
    if (length > 256) {
        errno = EIO;
        return -1;
    }
    if (!atomic_load(&shim_active)) {
        unsigned char *out = (unsigned char *)buffer;
        while (length > 0) {
            long got = w3h_raw_syscall(SYS_getrandom, out, length, 0);
            if (got < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            out += got;
            length -= (size_t)got;
        }
        return 0;
    }
    if ((buffer == NULL && length > 0) || (length > 0 && buffer_faults(buffer, length))) {
        errno = EFAULT;
        return -1;
    }
    fill(buffer, length);
    return 0;
}

/* ---- wall clock ------------------------------------------------------- */

/* 2026-01-01T00:00:00Z */
static const uint64_t WALL_BASE_SECS = 1767225600ULL;
static atomic_int wall_active;
static atomic_uint_fast64_t wall_offset_ns;

/* Exported for the harness (found with dlsym(RTLD_DEFAULT, ...)). */
unsigned int w3h_shim_version(void) { return 2; }

int w3h_shim_active(void) { return atomic_load(&shim_active); }

unsigned long w3h_shim_entropy_calls(void) { return atomic_load(&entropy_calls); }

/* Writes "name#ordinal=draws" entries separated by '\n' into `out` (NUL
 * terminated, truncated to `cap`). Returns the number of threads that drew
 * entropy. Diagnostics only: never part of the canonical trace. */
int w3h_shim_thread_stats(char *out, size_t cap) {
    if (out == NULL || cap == 0) {
        return -1;
    }
    out[0] = '\0';
    size_t used = 0;
    int len = atomic_load(&registry_len);
    for (int i = 0; i < len && used + 1 < cap; ++i) {
        int wrote = snprintf(out + used, cap - used, "%.*s#%u=%lu\n", W3H_NAME_LEN,
                             registry[i].name, registry[i].ordinal,
                             atomic_load(&registry[i].draws));
        if (wrote < 0) {
            break;
        }
        used += (size_t)wrote;
        if (used >= cap) {
            used = cap - 1;
            break;
        }
    }
    unsigned long extra = atomic_load(&unregistered_draws);
    if (extra > 0 && used + 1 < cap) {
        snprintf(out + used, cap - used, "(unregistered)=%lu\n", extra);
    }
    return len;
}

void w3h_shim_set_wall_offset_ns(uint64_t offset_ns) {
    if (!atomic_load(&shim_active)) {
        return;
    }
    atomic_store(&wall_offset_ns, offset_ns);
    atomic_store(&wall_active, 1);
}

int clock_gettime(clockid_t clockid, struct timespec *tp) {
    if (atomic_load(&wall_active) &&
        (clockid == CLOCK_REALTIME || clockid == CLOCK_REALTIME_COARSE)) {
        /* glibc declares `tp` nonnull; a NULL here is the caller's UB, as
         * with the real clock_gettime. */
        uint64_t offset = atomic_load(&wall_offset_ns);
        tp->tv_sec = (time_t)(WALL_BASE_SECS + offset / 1000000000ULL);
        tp->tv_nsec = (long)(offset % 1000000000ULL);
        return 0;
    }
    clock_gettime_fn real = atomic_load(&real_clock_gettime);
    if (real != NULL) {
        return real(clockid, tp);
    }
    /* Before the constructor (or if dlsym failed): the kernel directly. */
    return (int)w3h_raw_syscall(SYS_clock_gettime, (long)clockid, tp);
}
