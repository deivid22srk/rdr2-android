/* Single-function probe with a controlled context.
 *
 * Same idea as difftest.c but for one function and a deterministic (non-random) input, and
 * it prints every register on both sides. Use it to localise a divergence:
 *   probe <exe> <hex-address> [pattern-seed]
 */
#define _GNU_SOURCE 1
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>

#include "x64rt.h"
#include "lifted.h"
#include "tests.h"

extern void run_guest(X64Ctx *ctx, void *fn, void *stack_top);
extern uint64_t guest_done_addr;

#define STACK_BASE 0x200000000ull
#define STACK_SIZE 0x20000ull
#define ARENA_BASE 0x300000000ull
#define ARENA_SIZE 0x200000ull

static sigjmp_buf jb;
static volatile int crashed;
static volatile unsigned long long fault_pc, fault_addr;

static void on_segv(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    fault_addr = (unsigned long long)(uintptr_t)si->si_addr;
    fault_pc = (unsigned long long)((ucontext_t *)uc)->uc_mcontext.gregs[REG_RIP];
    crashed = 1;
    siglongjmp(jb, 1);
}

static const char *names[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s <exe> <addr> [seed]\n", argv[0]); return 2; }
    uint64_t seed = argc > 3 ? strtoull(argv[3], NULL, 0) : 0x123456789abcdefull;
    uint64_t addr = strtoull(argv[2], NULL, 16);

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("open"); return 2; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(n);
    if (fread(buf, 1, n, f) != (size_t)n) return 2;
    fclose(f);
    uint32_t pe = *(uint32_t *)(buf + 0x3c);
    uint16_t nsec = *(uint16_t *)(buf + pe + 6), optsz = *(uint16_t *)(buf + pe + 20);
    uint64_t base = *(uint64_t *)(buf + pe + 24 + 24);
    uint32_t imgsz = *(uint32_t *)(buf + pe + 24 + 56);
    uint8_t *img = mmap((void *)(uintptr_t)base, imgsz, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (img == MAP_FAILED) { perror("mmap image"); return 2; }
    memcpy(img, buf, pe + 24 + optsz);
    for (uint16_t i = 0; i < nsec; i++) {
        uint8_t *s = buf + pe + 24 + optsz + 40 * i;
        uint32_t va = *(uint32_t *)(s + 12), rs = *(uint32_t *)(s + 16), ro = *(uint32_t *)(s + 20);
        if (va + rs <= imgsz) memcpy(img + va, buf + ro, rs);
    }

    struct sigaction sa = {0};
    sa.sa_sigaction = on_segv; sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL); sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL); sigaction(SIGFPE, &sa, NULL);

    void *stack = mmap((void *)(uintptr_t)STACK_BASE, STACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (stack == MAP_FAILED) { perror("mmap stack"); return 2; }
    uint8_t *arena = mmap((void *)(uintptr_t)ARENA_BASE, ARENA_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (arena == MAP_FAILED) { perror("mmap arena"); return 2; }
    for (size_t i = 0; i < ARENA_SIZE; i += 4)
        *(uint32_t *)(arena + i) = (uint32_t)(seed * (i + 1) * 2654435761u);
    uint64_t top = (STACK_BASE + STACK_SIZE) & ~15ull;
    *(uint64_t *)(uintptr_t)(top - 8) = guest_done_addr;

    X64Ctx a, b;
    memset(&a, 0, sizeof a);
    for (int i = 0; i < 16; i++) if (i != 4) a.r[i] = seed + i * 0x111111111ull;
    a.r[4] = top - 8;
    for (int i = 0; i < 16; i++) { a.xmm[i][0] = seed * (i + 1); a.xmm[i][1] = seed * (i + 17); }
    a.flags = 0x202;
    memcpy(&b, &a, sizeof b);

    void *fn = img + (addr - base);
    crashed = 0;
    if (sigsetjmp(jb, 1) == 0) run_guest(&a, fn, (void *)(uintptr_t)top);
    int ca = crashed;
    crashed = 0;
    X64Fn lifted = NULL;
    for (size_t i = 0; i < TEST_COUNT; i++) if (kTests[i].addr == addr) lifted = kTests[i].lifted;
    if (!lifted) { fprintf(stderr, "no lifted function for %#llx\n", (unsigned long long)addr); return 2; }
    if (sigsetjmp(jb, 1) == 0) lifted(&b);
    int cb = crashed;

    if (ca || cb) {
        printf("crashed: original %d (pc %#llx addr %#llx)  lifted %d\n", ca, fault_pc, fault_addr, cb);
        if (ca && cb) return 0;
    }
    int bad = 0;
    for (int i = 0; i < 16; i++) if (a.r[i] != b.r[i]) {
        printf("%-4s %016llx  %016llx\n", names[i], (unsigned long long)a.r[i], (unsigned long long)b.r[i]);
        bad = 1;
    }
    if ((a.flags & 0xcff) != (b.flags & 0xcff)) {
        printf("flags %04llx  %04llx\n", (unsigned long long)a.flags, (unsigned long long)b.flags);
        bad = 1;
    }
    for (int i = 0; i < 16; i++) if (a.xmm[i][0] != b.xmm[i][0] || a.xmm[i][1] != b.xmm[i][1]) {
        printf("xmm%-2d %016llx%016llx  %016llx%016llx\n", i,
               (unsigned long long)a.xmm[i][1], (unsigned long long)a.xmm[i][0],
               (unsigned long long)b.xmm[i][1], (unsigned long long)b.xmm[i][0]);
        bad = 1;
    }
    puts(bad ? "DIFFER" : "match");
    return bad;
}
