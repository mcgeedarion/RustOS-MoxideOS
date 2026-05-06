OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
/* UEFI primary entry; _start is the Multiboot2/QEMU fallback. */
ENTRY(uefi_start)

/* Expose kernel load address as a linker symbol so Rust code can reference
 * it directly instead of hardcoding 0x400000 in pmm.rs. */
PROVIDE(_kernel_start = 0x400000);

/*
 * Initramfs location symbols.
 * Defaults to 0 (= no initramfs).  The UEFI stub or Multiboot2 boot code
 * overwrites these with the physical address and byte length of the CPIO
 * archive before jumping to kernel_main.
 */
PROVIDE(INITRAMFS_BASE = 0);
PROVIDE(INITRAMFS_SIZE = 0);

SECTIONS {
  /* Load at 4 MiB physical. Kernel VA = PA (identity mapped by UEFI/QEMU). */
  . = 0x400000;

  /* Multiboot2 header must be in the first 32 KiB of the file. */
  .text.boot ALIGN(8) : {
    *(.text.boot)
  }

  .text ALIGN(4096) : {
    *(.text.uefi_start)
    *(.text._start)
    *(.text .text.*)
  }

  .rodata ALIGN(4096) : { *(.rodata .rodata.*) }

  /* C/C++ global constructor/destructor arrays. run_init_array() in crt0.c
   * iterates __init_array_start..__init_array_end at kernel boot. */
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

  .data   ALIGN(4096) : { *(.data   .data.*  ) }
  .bss    ALIGN(4096) : {
    *(.bss .bss.*)
    *(COMMON)
    /* Boot stack: 32 KiB. */
    . = ALIGN(16);
    __BOOT_STACK = .;
    . += 32768;
    __boot_stack_top = .;
  }
  . = ALIGN(4096);
  _end = .;
}
