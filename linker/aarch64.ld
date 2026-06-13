OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
/*
 * Primary entry: efi_main (UEFI application, called by EDK2 firmware).
 * For a future bare-metal path, replace with _start and set . accordingly.
 */
ENTRY(uefi_main)

/*
 * Kernel virtual base — must match va48::KERNEL_BASE in mem_layout.rs.
 * UEFI loads us at an arbitrary physical address; the MMU mapping set up by
 * paging::init_mmu re-maps everything to this virtual base before
 * kernel_main_aarch64() is called.
 */
PROVIDE(_kernel_start = 0xffff000000000000);

/*
 * Initramfs location symbols — default to 0 (no initramfs).
 * Overwritten by the UEFI stub before jumping to kernel_main.
 */
PROVIDE(INITRAMFS_BASE = 0);
PROVIDE(INITRAMFS_SIZE = 0);

SECTIONS {
  /*
   * Load at the kernel virtual base.
   * UEFI firmware identity-maps RAM, so the physical load address is
   * determined at runtime by ExitBootServices(); the VA offset is applied
   * by init_mmu() before we jump to C/Rust kernel code.
   */
  . = 0xffff000000000000;

  /*
   * .text.boot: early exception-vector table and any pre-MMU assembly.
   * Must be the first section so the firmware entry jump lands here.
   * Tag with  #[link_section = ".text.boot"]  in Rust.
   */
  .text.boot ALIGN(4096) : { *(.text.boot) }

  .text ALIGN(4096) : {
    *(.text.efi_main)
    *(.text .text.*)
  }

  .rodata ALIGN(4096) : { *(.rodata .rodata.*) }

  /* C/C++ global ctor/dtor arrays; iterated by run_init_array() at boot. */
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

  .data ALIGN(4096) : { *(.data .data.*) }

  /*
   * Kernel test registry — populated at link time by #[kernel_test] statics.
   * Only present when the kernel is compiled with --features kmtest.
   */
  .kmtest_registry ALIGN(8) : {
    __kmtest_start = .;
    KEEP(*(.kmtest_registry))
    __kmtest_end = .;
  }

  .bss ALIGN(4096) : {
    *(.bss .bss.*)
    *(COMMON)
    /* Boot stack: 64 KiB, 16-byte aligned (AArch64 ABI requires SP % 16 == 0). */
    . = ALIGN(16);
    __BOOT_STACK = .;
    . += 65536;
    __boot_stack_top = .;
  }

  . = ALIGN(4096);
  _end = .;
}
