/* Calls a guest x86-64 function on the host CPU with a full register context.
 *
 * The guest function runs on its own stack; the first 8 bytes at the entry stack pointer
 * hold the address of the epilogue inside this file, so the guest's own `ret` brings us
 * back. Everything else is loaded from / stored to X64Ctx.
 *
 * X64Ctx layout (must match runtime/x64rt.h):
 *   r[0..15]      offset   0 .. 127   (rax rcx rdx rbx rsp rbp rsi rdi r8..r15)
 *   xmm[16][2]    offset 128 .. 383
 *   flags         offset 384
 *   rip           offset 392
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

        movq    %rdx, %rsp          /* guest stack */
        leaq    .Ldone(%rip), %rax
        pushq   %rax                /* return address for the guest */

        movq    %rdi, %r11          /* ctx, until r11 itself is loaded */
        movq    128+0*16(%r11), %xmm0
        movq    128+0*16+8(%r11), %xmm1
        movq    128+1*16(%r11), %xmm2
        movq    128+1*16+8(%r11), %xmm3
        movq    128+2*16(%r11), %xmm4
        movq    128+2*16+8(%r11), %xmm5
        movq    128+3*16(%r11), %xmm6
        movq    128+3*16+8(%r11), %xmm7
        movq    128+4*16(%r11), %xmm8
        movq    128+4*16+8(%r11), %xmm9
        movq    128+5*16(%r11), %xmm10
        movq    128+5*16+8(%r11), %xmm11
        movq    128+6*16(%r11), %xmm12
        movq    128+6*16+8(%r11), %xmm13
        movq    128+7*16(%r11), %xmm14
        movq    128+7*16+8(%r11), %xmm15

        movq    384(%r11), %rax
        pushq   %rax
        popfq
        movq    %rsi, %r10          /* fn */
        movq    0*8(%r11), %rax
        movq    1*8(%r11), %rcx
        movq    2*8(%r11), %rdx
        movq    3*8(%r11), %rbx
        movq    5*8(%r11), %rbp
        movq    6*8(%r11), %rsi
        movq    8*8(%r11), %r8
        movq    9*8(%r11), %r9
        movq    12*8(%r11), %r12
        movq    13*8(%r11), %r13
        movq    14*8(%r11), %r14
        movq    15*8(%r11), %r15
        movq    7*8(%r11), %rdi
        movq    10*8(%r11), %r10
        movq    11*8(%r11), %r11
        jmpq    *%r10

.Ldone:
        movq    g_host_rsp(%rip), %rsp
        movq    g_ctx(%rip), %r11
        movq    %rax, 0*8(%r11)
        movq    %rcx, 1*8(%r11)
        movq    %rdx, 2*8(%r11)
        movq    %rbx, 3*8(%r11)
        movq    %rbp, 5*8(%r11)
        movq    %rsi, 6*8(%r11)
        movq    %rdi, 7*8(%r11)
        movq    %r8,  8*8(%r11)
        movq    %r9,  9*8(%r11)
        movq    %r12, 12*8(%r11)
        movq    %r13, 13*8(%r11)
        movq    %r14, 14*8(%r11)
        movq    %r15, 15*8(%r11)
        movq    128+0*16(%r11), %xmm0
        movq    128+1*16(%r11), %xmm1
        movq    128+2*16(%r11), %xmm2
        movq    128+3*16(%r11), %xmm3
        movq    128+4*16(%r11), %xmm4
        movq    128+5*16(%r11), %xmm5
        movq    128+6*16(%r11), %xmm6
        movq    128+7*16(%r11), %xmm7
        movq    %rsp, %rax
        movq    %rax, 4*8(%r11)     /* final rsp (guest stack) */
        movq    %r11, 11*8(%r11)    /* r11 last: it is the ctx pointer */
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

        .section .note.GNU-stack,"",@progbits
