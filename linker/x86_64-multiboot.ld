OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

/*
 * Multiboot2 / QEMU -kernel entry. UEFI builds keep using x86_64.ld with
 * ENTRY(uefi_start); this script is selected only by x86_64-multiboot.json.
 */
EXTERN(_start)
ENTRY(_start)

/*
 * Expose kernel load address as a linker symbol so Rust code can reference
 * it without hardcoding 0x400000 in pmm.rs.
 */
PROVIDE(_kernel_start = 0x400000);

/*
 * Initramfs location symbols — default to 0 (no initramfs).
 * The multiboot2 boot code overwrites these before jumping to kernel_main.
 */
PROVIDE(INITRAMFS_BASE = 0);
PROVIDE(INITRAMFS_SIZE = 0);

SECTIONS {
  /* Load at 4 MiB physical; identity-mapped by boot.s before entering Rust. */
  . = 0x400000;

  /* Multiboot2 header must appear within the first 32 KiB of the file. */
  .text.boot ALIGN(8) : { KEEP(*(.text.boot)) }

  .text ALIGN(4096) : {
    *(.text._start)
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

  /* Kernel test registry — populated by #[kernel_test] statics. */
  .kmtest_registry ALIGN(8) : {
    __kmtest_start = .;
    KEEP(*(.kmtest_registry))
    __kmtest_end = .;
  }

  .bss ALIGN(4096) : {
    *(.bss .bss.*)
    *(COMMON)
    /* Boot stack: 32 KiB, 16-byte aligned. */
    . = ALIGN(16);
    __BOOT_STACK = .;
    . += 32768;
    __boot_stack_top = .;
  }

  . = ALIGN(4096);
  _end = .;
}
