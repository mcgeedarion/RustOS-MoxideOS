/* x86_64 UEFI kernel linker script.
 *
 * Primary entry: uefi_start (PE32+ UEFI application).
 * Fallback entry: _start    (bare-metal / debug harness).
 */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(uefi_start)

SECTIONS {
    . = 0xFFFFFFFF80000000;

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

    /* Initramfs location symbols — default to 0 (no initramfs).
     * The UEFI stub sets these before jumping to kernel_main. */
    PROVIDE(__initramfs_start = 0);
    PROVIDE(__initramfs_end   = 0);

    /DISCARD/ : { *(.comment) *(.eh_frame) }
}
