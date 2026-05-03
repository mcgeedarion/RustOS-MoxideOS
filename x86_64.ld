OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
/* UEFI primary entry; _start is the Multiboot2/QEMU fallback. */
ENTRY(uefi_start)
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
  .data   ALIGN(4096) : { *(.data   .data.*  ) }
  .bss    ALIGN(4096) : {
    *(.bss .bss.*)
    *(COMMON)
    /* Boot stack lives at the very end of .bss */
    . = ALIGN(16);
    __BOOT_STACK = .;
    . += 16384;
    __boot_stack_top = .;
  }
  . = ALIGN(4096);
  _end = .;
}
