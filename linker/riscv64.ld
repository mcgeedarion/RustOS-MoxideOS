OUTPUT_ARCH(riscv)
ENTRY(uefi_start)

/*
 * Initramfs location symbols — default to 0 (no initramfs).
 * OpenSBI / bootloader overwrites these with the physical address and byte
 * length of the CPIO archive before jumping to kernel_main.
 */
PROVIDE(INITRAMFS_BASE = 0);
PROVIDE(INITRAMFS_SIZE = 0);

SECTIONS {
  . = 0x80200000;
  _kernel_start = .;

  /*
   * .text.boot must come first so that _start (the OpenSBI entry point) is
   * the very first instruction executed.  Mark it with
   * #[link_section = ".text.boot"] in Rust.
   */
  .text.boot : { *(.text.boot) }

  .text   : { *(.text   .text.*)   }
  .rodata : { *(.rodata .rodata.*) }

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

  .data : { *(.data .data.*) }

  /*
   * Kernel test registry — populated at link time by #[kernel_test] statics.
   * Only present when the kernel is compiled with --features kmtest.
   */
  .kmtest_registry ALIGN(8) : {
    __kmtest_start = .;
    KEEP(*(.kmtest_registry))
    __kmtest_end = .;
  }

  .bss  : { *(.bss  .bss.*)  *(COMMON) }

  . = ALIGN(4096);
  _end = .;
}
