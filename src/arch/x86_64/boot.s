; src/arch/x86_64/boot.s
; Multiboot2 header + bare-metal _start entry point.
; Assembled by nasm (x86_64 ELF64).

bits 32                         ; GRUB hands us 32-bit protected mode

; ── Multiboot2 constants ────────────────────────────────────────────────────
MB2_MAGIC       equ 0xe85250d6
MB2_ARCH_X86    equ 0           ; i386 protected mode
MB2_HEADER_LEN  equ (mb2_header_end - mb2_header_start)
MB2_CHECKSUM    equ -(MB2_MAGIC + MB2_ARCH_X86 + MB2_HEADER_LEN)

section .text.boot
global mb2_header_start
mb2_header_start:
    dd MB2_MAGIC
    dd MB2_ARCH_X86
    dd MB2_HEADER_LEN
    dd MB2_CHECKSUM & 0xffffffff

    ; ── End tag (type=0, flags=0, size=8) ───────────────────────────────
    dw 0            ; type
    dw 0            ; flags
    dd 8            ; size
mb2_header_end:

; ── _start ──────────────────────────────────────────────────────────────────
; GRUB jumps here in 32-bit protected mode with:
;   EAX = 0x36d76289  (multiboot2 magic)
;   EBX = physical address of multiboot2 info struct
;
; We set up a small boot stack, save EBX, then jump to kernel_main.
; kernel_main is a Rust #[no_mangle] extern "C" fn that takes
;   (mb2_magic: u32, mb2_info_phys: u32).

section .text
global _start
extern kernel_main

_start:
    ; Disable interrupts, clear direction flag
    cli
    cld

    ; Set up boot stack (defined in x86_64.ld as __boot_stack_top)
    extern __boot_stack_top
    mov esp, __boot_stack_top

    ; Push multiboot2 args: (magic: u32, info_phys: u32)
    ; EAX = magic, EBX = info ptr  — push right-to-left for C calling conv
    push ebx        ; arg1: info_phys (u32)
    push eax        ; arg0: magic    (u32)

    call kernel_main

    ; kernel_main should never return; halt if it does
.hang:
    hlt
    jmp .hang
