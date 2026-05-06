OUTPUT_ARCH(riscv)
ENTRY(_start)

/*
 * Initramfs location symbols.
 * Defaults to 0 (= no initramfs).  OpenSBI / bootloader overwrites these
 * with the physical address and byte length of the CPIO archive before
 * jumping to kernel_main.
 */
PROVIDE(INITRAMFS_BASE = 0);
PROVIDE(INITRAMFS_SIZE = 0);

SECTIONS {
  . = 0x80200000;
  _kernel_start = .;

  .text   : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }

  /* C/C++ global constructor/destructor arrays. */
  .init_array ALIGN(8) : {
    __init_array_start = .;
    *(.init_array .init_array.*)
    __init_array_end = .;
  }

  .fini_array ALIGN(8) : {
    __fini_array_start = .;
    *(.fini_array .fini_array.*)
    __fini_array_end = .;
  }

  .data   : { *(.data .data.*) }
  .bss    : { *(.bss .bss.*) *(COMMON) }
  . = ALIGN(4096);
  _end = .;
}
