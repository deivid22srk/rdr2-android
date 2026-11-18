/* Cross-ABI check of the generated C: same inputs, same outputs on x86-64 and on AArch64.
 *
 * It contains no game code and does not execute the original: it calls the *lifted* functions
 * only. Build it twice with the same sources and compare the two outputs byte for byte. A
 * difference means the generated C depends on the host (undefined behaviour, FP contraction,
 * width assumptions) and must be fixed.
 *
 * The guest stack is mapped at a fixed address so RSP and stack contents are identical in both
 * builds.
 */
#define _GNU_SOURCE 1
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "x64rt.h"
#include "lifted.h"
#include "tests.h"

#define STACK_BASE 0x200000000ull
#define STACK_SIZE 0x20000ull
#define ARENA_BASE 0x110000ull
#define ARENA_SIZE 0x100000ull

static sigjmp_buf g_jb;
static volatile int g_crashed;

static void on_segv(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si; (void)uc;
    g_crashed = 1;
    siglongjmp(g_jb, 1);
}

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

static uint64_t fnv(const void *p, size_t n)
{
    const uint8_t *b = p;
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 1099511628211ull; }
    return h;
}

int main(int argc, char **argv)
{
    int cases = argc > 1 ? atoi(argv[1]) : 8;
    void *stack = mmap((void *)(uintptr_t)STACK_BASE, STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (stack == MAP_FAILED) { perror("mmap stack"); return 2; }
    uint64_t top = (STACK_BASE + STACK_SIZE) & ~15ull;
    uint8_t *arena = mmap((void *)(uintptr_t)ARENA_BASE, ARENA_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (arena == MAP_FAILED) { perror("mmap arena"); return 2; }
    for (size_t i = 0; i < ARENA_SIZE; i += 8)
        *(uint64_t *)(arena + i) = rnd();

    struct sigaction sa = {0};
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);

    uint64_t only = argc > 2 ? strtoull(argv[2], NULL, 16) : 0;
    X64Ctx c;
    for (size_t t = 0; t < TEST_COUNT; t++) {
        void (*fn)(X64Ctx *) = kTests[t].lifted;
        if (only && kTests[t].addr != only) { rng_state += 0; continue; }
        for (int k = 0; k < cases; k++) {
            memset(&c, 0, sizeof c);
            for (int i = 0; i < 16; i++)
                if (i != 4)
                    c.r[i] = (rnd() & 1) ? (ARENA_BASE + (rnd() & (ARENA_SIZE - 0x2000)))
                                         : (kTests[t].loop ? (rnd() & 7) : interesting());
            for (int i = 0; i < 16; i++) { c.xmm[i][0] = rnd(); c.xmm[i][1] = rnd(); }
            c.flags = 0x202 | (rnd() & (X64_CF | X64_PF | X64_AF | X64_ZF | X64_SF | X64_OF));
            *(uint64_t *)(uintptr_t)(top - 8) = 0;
            c.r[4] = top - 8;
            g_crashed = 0;
            if (sigsetjmp(g_jb, 1) == 0)
                fn(&c);
            if (g_crashed) {
                printf("%llx %d CRASH\n", (unsigned long long)kTests[t].addr, k);
                continue;
            }
            if (only) {
                printf("%llx case %d flags %04llx", (unsigned long long)kTests[t].addr, k,
                       (unsigned long long)c.flags);
                for (int i = 0; i < 16; i++)
                    printf(" r%d=%016llx", i, (unsigned long long)c.r[i]);
                for (int i = 0; i < 16; i++)
                    printf(" x%d=%016llx%016llx", i, (unsigned long long)c.xmm[i][1],
                           (unsigned long long)c.xmm[i][0]);
                printf("\n");
            } else {
                printf("%llx %d %016llx %016llx\n",
                       (unsigned long long)kTests[t].addr, k,
                       (unsigned long long)fnv(&c, sizeof c),
                       (unsigned long long)fnv(c.xmm, sizeof c.xmm));
            }
        }
    }
    return 0;
}
