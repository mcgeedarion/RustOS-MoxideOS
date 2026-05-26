; src/arch/x86_64/boot.s
; Bare-metal _start entry point for GRUB2 / `qemu -kernel`.
; Assembled by nasm (x86_64 ELF64).
;
; NOTE: The Multiboot2 header is emitted by the Rust static MULTIBOOT2_HEADER
; in multiboot2.rs (link_section = ".text.boot", repr(C, align(8))).
; Do NOT add a second header here.
;
; GRUB2 / qemu -kernel enters _start in 32-bit protected mode with:
;   EAX = 0x36d76289  (multiboot2 magic)
;   EBX = physical address of the MBI structure
;
; We transition to 64-bit long mode and call the Rust shim via SysV AMD64:
;   multiboot2_entry(magic: u32, info_phys: u32)
;                    rdi          rsi

bits 32

; ── Minimal boot GDT ────────────────────────────────────────────────────────
section .data
align 8
gdt64:
    dq 0                        ; null descriptor
.code: equ $ - gdt64
    dq (1<<44)|(1<<47)|(1<<41)|(1<<43)|(1<<53)  ; 64-bit code, DPL0, present
.ptr:
    dw $ - gdt64 - 1            ; limit
    dd gdt64                    ; base (32-bit physical — fine pre-paging)

; ── Minimal identity-map page tables ────────────────────────────────────────
; PML4[0] → PDPT, PDPT[0] → 1 GiB 1:1 mapping (PS=1, RW, P).
; Covers 0x000000..0x3FFFFFFF, which includes our load address 0x400000.
section .bss
align 4096
pml4_table: resb 4096
pdpt_table:  resb 4096

; ── _start ──────────────────────────────────────────────────────────────────
section .text
global _start
extern multiboot2_entry         ; fn(magic: u32, info_phys: u32) -> !  [SysV AMD64]
extern __boot_stack_top

_start:
    cli
    cld

    ; Stash multiboot2 args before we touch registers.
    ; EDI = magic, ESI = info_phys — these survive into 64-bit mode.
    mov edi, eax
    mov esi, ebx

    mov esp, __boot_stack_top

    ; ── Build identity-map page tables ──────────────────────────────────
    ; PML4[0] → pdpt_table (present, writable)
    mov eax, pdpt_table
    or  eax, 0x3                ; P + RW
    mov [pml4_table], eax

    ; PDPT[0] → 0x000000 1 GiB huge page (present, writable, PS)
    mov eax, 0x83               ; P + RW + PS(1GiB)
    mov [pdpt_table], eax

    ; ── Enable PAE ──────────────────────────────────────────────────────
    mov eax, cr4
    or  eax, (1 << 5)           ; PAE
    mov cr4, eax

    ; ── Load PML4 ───────────────────────────────────────────────────────
    mov eax, pml4_table
    mov cr3, eax

    ; ── Set EFER.LME ────────────────────────────────────────────────────
    mov ecx, 0xC0000080
    rdmsr
    or  eax, (1 << 8)           ; LME
    wrmsr

    ; ── Enable paging → activates long mode (compatibility mode) ────────
    mov eax, cr0
    or  eax, (1 << 31)          ; PG  (PE is already set by GRUB)
    mov cr0, eax

    ; ── Far jump into 64-bit code segment ───────────────────────────────
    lgdt [gdt64.ptr]
    jmp  gdt64.code:long_mode_start

bits 64
long_mode_start:
    ; Zero the segment registers (SS is handled by the ABI, others unused).
    xor eax, eax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; 16-byte align rsp before the call (SysV AMD64 ABI requirement).
    ; __boot_stack_top is already 16-byte aligned (linker script), but
    ; the lgdt / far-jmp path may have pushed nothing, so enforce it.
    and rsp, ~0xF

    ; Args are already in rdi (magic) and rsi (info_phys) from above.
    ; Zero-extend to 64 bits — they were set as 32-bit values.
    mov edi, edi
    mov esi, esi

    call multiboot2_entry

    ; Should never return.
.hang:
    hlt
    jmp .hang
