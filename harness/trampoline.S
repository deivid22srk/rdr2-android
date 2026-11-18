/* Calls a guest x86-64 function on the host CPU with a full register context.
 *
 * The guest function runs on its own stack; the first 8 bytes at the entry stack pointer
 * hold the address of the epilogue inside this file, so the guest's own `ret` brings us
 * back. Everything else is loaded from / stored to X64Ctx.
 *
 * X64Ctx layout (must match runtime/x64rt.h):
 *   r[0..15]      offset   0 .. 127   (rax rcx rdx rbx rsp rbp rsi rdi r8..r15)
 *   xmm[16][2]    offset 128 .. 383   (each XMM is one 16-byte slot)
 *   flags         offset 384
 *   rip           offset 392
 *
 * There is no free register to keep the context pointer in, so it lives in g_ctx; the only
 * register the epilogue needs as scratch is r11, whose guest value is spilled to g_r11
 * first (a store, which needs no register of its own).
 */
        .text
        .globl  run_guest
        .type   run_guest,@function
run_guest:                          /* (X64Ctx *ctx, void *fn, void *stack_top) */
        pushq   %rbp
        movq    %rsp, %rbp
        pushq   %rbx
        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15
        movq    %rsp, g_host_rsp(%rip)
        movq    %rdi, g_ctx(%rip)
        movq    %rsi, g_fn(%rip)

        movq    %rdx, %rsp          /* guest stack */
        leaq    .Ldone(%rip), %rax
        pushq   %rax                /* return address for the guest */

        movups  128+0*16(%rdi), %xmm0
        movups  128+1*16(%rdi), %xmm1
        movups  128+2*16(%rdi), %xmm2
        movups  128+3*16(%rdi), %xmm3
        movups  128+4*16(%rdi), %xmm4
        movups  128+5*16(%rdi), %xmm5
        movups  128+6*16(%rdi), %xmm6
        movups  128+7*16(%rdi), %xmm7
        movups  128+8*16(%rdi), %xmm8
        movups  128+9*16(%rdi), %xmm9
        movups  128+10*16(%rdi), %xmm10
        movups  128+11*16(%rdi), %xmm11
        movups  128+12*16(%rdi), %xmm12
        movups  128+13*16(%rdi), %xmm13
        movups  128+14*16(%rdi), %xmm14
        movups  128+15*16(%rdi), %xmm15

        movq    384(%rdi), %rax
        pushq   %rax
        popfq

        movq    0*8(%rdi), %rax
        movq    1*8(%rdi), %rcx
        movq    2*8(%rdi), %rdx
        movq    3*8(%rdi), %rbx
        movq    5*8(%rdi), %rbp
        movq    6*8(%rdi), %rsi
        movq    8*8(%rdi), %r8
        movq    9*8(%rdi), %r9
        movq    10*8(%rdi), %r10
        movq    12*8(%rdi), %r12
        movq    13*8(%rdi), %r13
        movq    14*8(%rdi), %r14
        movq    15*8(%rdi), %r15
        movq    11*8(%rdi), %r11     /* guest r11 and rdi last: rdi is the ctx pointer */
        movq    7*8(%rdi), %rdi
        jmpq    *g_fn(%rip)

.Ldone:
        movq    %r11, g_r11(%rip)   /* the only scratch is memory: r11 is also a guest reg */
        movq    g_ctx(%rip), %r11
        movq    %rsp, 4*8(%r11)     /* guest rsp, before switching back to the host stack */
        movq    g_host_rsp(%rip), %rsp
        movq    %rax, 0*8(%r11)
        movq    %rcx, 1*8(%r11)
        movq    %rdx, 2*8(%r11)
        movq    %rbx, 3*8(%r11)
        movq    %rbp, 5*8(%r11)
        movq    %rsi, 6*8(%r11)
        movq    %rdi, 7*8(%r11)
        movq    %r8,  8*8(%r11)
        movq    %r9,  9*8(%r11)
        movq    %r10, 10*8(%r11)
        movq    %r12, 12*8(%r11)
        movq    %r13, 13*8(%r11)
        movq    %r14, 14*8(%r11)
        movq    %r15, 15*8(%r11)
        movq    g_r11(%rip), %rax
        movq    %rax, 11*8(%r11)
        movups  %xmm0,  128+0*16(%r11)
        movups  %xmm1,  128+1*16(%r11)
        movups  %xmm2,  128+2*16(%r11)
        movups  %xmm3,  128+3*16(%r11)
        movups  %xmm4,  128+4*16(%r11)
        movups  %xmm5,  128+5*16(%r11)
        movups  %xmm6,  128+6*16(%r11)
        movups  %xmm7,  128+7*16(%r11)
        movups  %xmm8,  128+8*16(%r11)
        movups  %xmm9,  128+9*16(%r11)
        movups  %xmm10, 128+10*16(%r11)
        movups  %xmm11, 128+11*16(%r11)
        movups  %xmm12, 128+12*16(%r11)
        movups  %xmm13, 128+13*16(%r11)
        movups  %xmm14, 128+14*16(%r11)
        movups  %xmm15, 128+15*16(%r11)
        pushfq
        popq    %rax
        movq    %rax, 384(%r11)

        popq    %r15
        popq    %r14
        popq    %r13
        popq    %r12
        popq    %rbx
        popq    %rbp
        ret
        .size   run_guest, .-run_guest

        .globl  guest_done_addr
guest_done_addr:
        .quad   .Ldone

        .bss
        .align  8
g_host_rsp:
        .zero   8
g_ctx:
        .zero   8
g_fn:
        .zero   8
g_r11:
        .zero   8

        .section .note.GNU-stack,"",@progbits
