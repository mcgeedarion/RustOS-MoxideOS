# AP bringup trampoline — executed starting at physical address 0x8000.
# The CPU comes out of reset in 16-bit real mode at CS:IP = 0x0800:0x0000.
#
# Sequence:
#   real mode (16-bit)  → load GDT stub → enter protected mode (32-bit)
#   protected mode      → enable PAE + long mode bit → enable paging
#   long mode (64-bit)  → load kernel GDT/IDT → call ap_entry(cpu_id)
#
# The cpu_id is left by the BSP at physical address 0x8FF8.
# The kernel page-table PML4 physical address is at 0x8FF0.
# The kernel stack pointer for this AP is at 0x8FE8.

.section .ap_trampoline, "ax"
.code16
.global ap_trampoline_start
ap_trampoline_start:

    cli
    cld

    # Set up segments to address the trampoline page itself.
    xorw    %ax, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss

    # Load the 32-bit GDT stub (defined below, in this page).
    lgdtl   (gdt32_ptr - ap_trampoline_start + 0x8000)

    # Enter protected mode.
    movl    %cr0, %eax
    orl     $0x1, %eax
    movl    %eax, %cr0
    ljmpl   $0x08, $(pm32 - ap_trampoline_start + 0x8000)

.code32
pm32:
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss
    movw    %ax, %fs
    movw    %ax, %gs

    # Load PML4 from slot at 0x8FF0.
    movl    (0x8FF0), %eax
    movl    %eax, %cr3

    # Enable PAE.
    movl    %cr4, %eax
    orl     $0x20, %eax
    movl    %eax, %cr4

    # Set EFER.LME (long mode enable).
    movl    $0xC0000080, %ecx
    rdmsr
    orl     $0x100, %eax
    wrmsr

    # Enable paging + WP.
    movl    %cr0, %eax
    orl     $0x80010000, %eax
    movl    %eax, %cr0

    # Load the full 64-bit GDT (kernel GDT pointer stored at 0x8FD0).
    lgdtl   (0x8FD0)

    # Far jump into 64-bit compatibility segment.
    ljmpl   $0x08, $(lm64 - ap_trampoline_start + 0x8000)

.code64
lm64:
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %ss
    xorw    %ax, %ax
    movw    %ax, %fs
    movw    %ax, %gs

    # Load the per-AP stack pointer from 0x8FE8.
    movq    (0x8FE8), %rsp

    # Load cpu_id (u32) from 0x8FF8.
    movl    (0x8FF8), %edi    # first argument (System V ABI)

    # Jump to the Rust AP entry point.
    movabsq $ap_entry, %rax
    callq   *%rax

    # Should never return, but halt just in case.
1:  hlt
    jmp 1b

# ── Minimal 32-bit GDT (code + data, flat 4 GB) ──────────────────────────────
.align 8
gdt32:
    .quad 0x0000000000000000   # null
    .quad 0x00CF9A000000FFFF   # 32-bit code, DPL0
    .quad 0x00CF92000000FFFF   # 32-bit data, DPL0
gdt32_end:

gdt32_ptr:
    .word   gdt32_end - gdt32 - 1
    .long   gdt32 - ap_trampoline_start + 0x8000

.global ap_trampoline_end
ap_trampoline_end:
