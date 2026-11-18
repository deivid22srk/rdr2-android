#define _GNU_SOURCE 1
/* Differential test: original x86-64 function vs the C the lifter generated.
 *
 * Both run on the same host CPU. The original is called through harness/trampoline.S with a
 * full X64Ctx; the lifted function is plain C. Inputs are random register states; the image
 * is mapped at its real ImageBase so RIP-relative reads work.
 *
 * Only functions with stack-only or RIP-relative memory operands and no calls are selected
 * (tools/select_tests.py), so a test case never depends on global mutable state. A fault is
 * recorded: the case passes only if *both* versions fault.
 *
 * Build with -O0: the signal handler longjmps out of the trampoline, which is only safe when
 * the compiler has not cached callee-saved registers across the call.
 */
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#include "x64rt.h"
#include "lifted.h"
#include "tests.h"

extern void run_guest(X64Ctx *ctx, void *fn, void *stack_top);
extern uint64_t guest_done_addr;

static uint8_t *g_image;
static uint64_t g_base;
static sigjmp_buf g_jb;
static volatile int g_crashed;

static volatile unsigned long long g_fault_addr, g_fault_pc;
static volatile int g_timeout;

static void on_alarm(int sig)
{
    (void)sig;
    g_timeout = 1;
    siglongjmp(g_jb, 1);
}
static void on_segv(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    g_fault_addr = (unsigned long long)(uintptr_t)si->si_addr;
    g_fault_pc = (unsigned long long)((ucontext_t *)uc)->uc_mcontext.gregs[REG_RIP];
    g_crashed = 1;
    siglongjmp(g_jb, 1);
}

/* ---- PE mapping --------------------------------------------------------- */
static int map_image(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror("open"); return -1; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)n);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); return -1; }
    fclose(f);

    uint32_t pe = *(uint32_t *)(buf + 0x3c);
    uint16_t nsec = *(uint16_t *)(buf + pe + 6);
    uint16_t optsz = *(uint16_t *)(buf + pe + 20);
    uint64_t base = *(uint64_t *)(buf + pe + 24 + 24);
    uint32_t imgsz = *(uint32_t *)(buf + pe + 24 + 56);
    uint64_t *opt = (uint64_t *)(buf + pe + 24);

    g_base = base;
    g_image = mmap((void *)(uintptr_t)base, imgsz, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (g_image == MAP_FAILED) { perror("mmap image"); return -1; }
    memcpy(g_image, buf, (size_t)(optsz + 24 + (uint64_t)pe));
    for (uint16_t i = 0; i < nsec; i++) {
        uint8_t *s = buf + pe + 24 + optsz + 40 * i;
        uint32_t vsize = *(uint32_t *)(s + 8), va = *(uint32_t *)(s + 12);
        uint32_t rsize = *(uint32_t *)(s + 16), roff = *(uint32_t *)(s + 20);
        if (va + rsize > imgsz) continue;
        memcpy(g_image + va, buf + roff, rsize);
        if (vsize > rsize) memset(g_image + va + rsize, 0, vsize - rsize);
    }
    (void)opt;
    free(buf);
    printf("image mapped at %#llx (%u bytes)\n", (unsigned long long)base, imgsz);
    return 0;
}

/* ---- random inputs ------------------------------------------------------ */
static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
static uint64_t rnd(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static uint64_t interesting(void)
{
    switch (rnd() & 7) {
    case 0: return 0;
    case 1: return ~0ull;
    case 2: return rnd() & 0xff;
    case 3: return rnd() & 0xffff;
    case 4: return (uint32_t)rnd();
    case 5: return (uint64_t)-(int64_t)(rnd() & 0xffff);
    case 6: return (uint64_t)1 << (rnd() & 63);
    default: return rnd();
    }
}

#define ARENA_BASE 0x110000ull
#define ARENA_SIZE 0x100000ull

static uint8_t *g_arena;

static void fill_ctx(X64Ctx *c, uint8_t *stack, size_t stack_size, uint64_t fn_addr, int loop)
{
    memset(c, 0, sizeof *c);
    for (int i = 0; i < 16; i++)
        if (i != 4)
            /* Half the time a pointer into the arena, half the time a value that hits an
             * arithmetic edge case. A function with a loop gets only small values: with a
             * random 64-bit loop bound the case would never finish. */
            c->r[i] = (rnd() & 1)
                          ? (ARENA_BASE + (rnd() & (ARENA_SIZE - 0x2000)))
                          : (loop ? (rnd() & 7) : interesting());
    for (int i = 0; i < 16; i++) {
        c->xmm[i][0] = rnd();
        c->xmm[i][1] = rnd();
    }
    c->flags = 0x202 | (rnd() & (X64_CF | X64_PF | X64_AF | X64_ZF | X64_SF | X64_OF));
    uint64_t top = ((uint64_t)(uintptr_t)(stack + stack_size)) & ~15ull;
    *(uint64_t *)(uintptr_t)(top - 8) = guest_done_addr;
    c->r[4] = top - 8;
    c->rip = fn_addr;
}

/* ---- comparison --------------------------------------------------------- */
static int diff_ctx(const X64Ctx *a, const X64Ctx *b, char *why, size_t whysz)
{
    static const char *names[16] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                                    "r8","r9","r10","r11","r12","r13","r14","r15"};
    for (int i = 0; i < 16; i++)
        if (a->r[i] != b->r[i]) {
            snprintf(why, whysz, "%s: %#llx vs %#llx", names[i],
                     (unsigned long long)a->r[i], (unsigned long long)b->r[i]);
            return 1;
        }
    uint64_t fm = X64_CF | X64_PF | X64_ZF | X64_SF | X64_OF;
    if ((a->flags & fm) != (b->flags & fm)) {
        snprintf(why, whysz, "flags: %#llx vs %#llx",
                 (unsigned long long)(a->flags & fm), (unsigned long long)(b->flags & fm));
        return 1;
    }
    for (int i = 0; i < 16; i++)
        if (a->xmm[i][0] != b->xmm[i][0] || a->xmm[i][1] != b->xmm[i][1]) {
            snprintf(why, whysz, "xmm%d: %016llx%016llx vs %016llx%016llx", i,
                     (unsigned long long)a->xmm[i][1], (unsigned long long)a->xmm[i][0],
                     (unsigned long long)b->xmm[i][1], (unsigned long long)b->xmm[i][0]);
            return 1;
        }
    return 0;
}

int main(int argc, char **argv)
{
    const char *exe = argc > 1 ? argv[1] : NULL;
    int cases = argc > 2 ? atoi(argv[2]) : 8;
    if (!exe) { fprintf(stderr, "usage: %s <exe> [cases-per-function]\n", argv[0]); return 2; }
    if (map_image(exe)) return 2;

    struct sigaction sa = {0};
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    struct sigaction al = {0};
    al.sa_handler = on_alarm;
    sigaction(SIGALRM, &al, NULL);

    size_t stack_size = 1 << 16;
    uint8_t *stack = malloc(stack_size);
    if (!stack) return 2;
    /* Both versions must start from the same stack image: a function that reads a stack
     * slot it never wrote (an argument the caller never placed, a local it skipped) would
     * otherwise see whatever the previous run left there. */
    uint8_t *stack_image = malloc(stack_size);
    if (!stack_image) return 2;
    for (size_t i = 0; i < stack_size; i += 8)
        *(uint64_t *)(stack + i) = rnd();
    memcpy(stack_image, stack, stack_size);

    g_arena = mmap((void *)(uintptr_t)ARENA_BASE, ARENA_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (g_arena == MAP_FAILED) { perror("mmap arena"); return 2; }
    for (size_t i = 0; i < ARENA_SIZE; i += 8)
        *(uint64_t *)(g_arena + i) = rnd();

    int funcs = 0, oks = 0, mismatches = 0, both_crash = 0, only_one_crash = 0, skipped = 0;
    X64Ctx *a = malloc(sizeof *a), *b = malloc(sizeof *b);
    char why[256];
    uint64_t first_bad = 0;

    for (size_t t = 0; t < TEST_COUNT; t++) {
        uint64_t addr = kTests[t].addr, end = kTests[t].end;
        void *fn = g_image + (addr - g_base);
        (void)end;
        funcs++;
        if (getenv("DIFFTEST_VERBOSE")) { printf("FUNC %#llx\n", (unsigned long long)addr); fflush(stdout); }
        int bad = 0, timed_out = 0;
        for (int k = 0; k < cases; k++) {
            memcpy(stack, stack_image, stack_size);
            fill_ctx(a, stack, stack_size, addr, (int)kTests[t].loop);
            memcpy(b, a, sizeof *b);

            g_crashed = 0;
            g_timeout = 0;
            int crashed_a = 0;
            alarm(10);              /* a guest loop with a random bound must not hang the run */
            if (sigsetjmp(g_jb, 1) == 0) {
                run_guest(a, fn, (void *)(uintptr_t)(((uint64_t)(uintptr_t)(stack + stack_size)) & ~15ull));
            } else {
                crashed_a = 1;
            }
            alarm(0);
            if (g_timeout) { timed_out = 1; continue; }
            uint64_t after_a_rsp = a->r[4];

            memcpy(stack, stack_image, stack_size);
            g_crashed = 0;
            g_timeout = 0;
            int crashed_b = 0;
            alarm(10);
            if (sigsetjmp(g_jb, 1) == 0) {
                kTests[t].lifted(b);
            } else {
                crashed_b = 1;
            }
            alarm(0);
            if (g_timeout) { timed_out = 1; continue; }
            (void)after_a_rsp;

            if (crashed_a != crashed_b) {
                if (only_one_crash < 6)
                    printf("ONLY-ONE %#llx case %d: original %s (pc %#llx addr %#llx), lifted %s\n",
                           (unsigned long long)addr, k, crashed_a ? "crashed" : "ok",
                           g_fault_pc, g_fault_addr, crashed_b ? "crashed" : "ok");
                only_one_crash++; bad = 1; break;
            }
            if (crashed_a) { both_crash++; continue; }
            if (diff_ctx(a, b, why, sizeof why)) {
                mismatches++; bad = 1; break;
            }
        }
        if (timed_out) { skipped++; funcs--; continue; }
        if (!bad) oks++;
        else if (!first_bad) first_bad = addr;
        if (bad && mismatches + only_one_crash <= 12)
            printf("MISMATCH %#llx: %s\n", (unsigned long long)addr, why);
    }

    printf("\nfunctions: %d   ok: %d   mismatched: %d   "
           "both crashed: %d   one crashed: %d   skipped: %d\n",
           funcs, oks, mismatches, both_crash, only_one_crash, skipped);
    printf("cases per function: %d\n", cases);
    if (first_bad) printf("first failing function: %#llx\n", (unsigned long long)first_bad);
    return mismatches + only_one_crash ? 1 : 0;
}
