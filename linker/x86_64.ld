/* x86_64 UEFI kernel linker script.
 *
 * Primary entry: uefi_start (PE32+ UEFI application).
 * Fallback entry: _start    (bare-metal / debug harness).
 *
 * Load address: 0x400000 physical.  UEFI firmware identity-maps all RAM
 * before ExitBootServices, so this must be a reachable physical address.
 * The high-half virtual mapping (0xFFFFFFFF80000000) is established by
 * the kernel's own page-table setup *after* ExitBootServices returns.
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(uefi_start)

SECTIONS {
    . = 0x400000;

    .text : {
        KEEP(*(.text.uefi_start))
        KEEP(*(.text._start))
        *(.text .text.*)
    }

    .rodata : { *(.rodata .rodata.*) }

    .data : { *(.data .data.*) }

    .bss : {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Boot stack — 32 KiB, 16-byte aligned.
     * uefi_start switches to this stack immediately on entry via:
     *   lea rsp, [rip + __boot_stack_top]
     * NOLOAD: occupies address space but is not written to the ELF file. */
    .stack (NOLOAD) : {
        . = ALIGN(16);
        __boot_stack_bottom = .;
        . += 0x8000;   /* 32 KiB */
        . = ALIGN(16);
        __boot_stack_top = .;
    }

    /* Initramfs location symbols — default to 0 (no initramfs).
     * The UEFI stub sets these before jumping to kernel_main. */
    PROVIDE(__initramfs_start = 0);
    PROVIDE(__initramfs_end   = 0);

    /DISCARD/ : { *(.comment) *(.eh_frame) }
}
