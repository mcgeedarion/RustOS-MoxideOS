; src/arch/x86_64/boot.s
; Multiboot2 header + bare-metal _start entry point.
; Assembled by nasm (x86_64 ELF64).
;
; GRUB2 / `qemu -kernel` enters _start in 32-bit protected mode with:
;   EAX = 0x36d76289  (multiboot2 magic)
;   EBX = physical address of the MBI structure
;
; We push both registers onto the boot stack and call the Rust shim
; `multiboot2_entry(magic: u32, info_phys: u32)` which:
;   1. Saves info_phys into the MBI_PTR static.
;   2. Calls kernel_main() with no arguments (UEFI / multiboot2 common path).

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

section .text
global _start
extern multiboot2_entry     ; Rust shim: fn(magic: u32, info_phys: u32) -> !

_start:
    ; Disable interrupts, clear direction flag.
    cli
    cld

    ; Set up boot stack.
    extern __boot_stack_top
    mov esp, __boot_stack_top

    ; Push multiboot2 args: (magic: u32, info_phys: u32)
    ; EAX = magic, EBX = MBI physical address — push right-to-left (C cdecl).
    push ebx        ; arg1: info_phys (u32)
    push eax        ; arg0: magic     (u32)

    call multiboot2_entry

    ; Should never return.
.hang:
    hlt
    jmp .hang
