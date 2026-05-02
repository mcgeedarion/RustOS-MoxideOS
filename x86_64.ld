OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(uefi_start)
SECTIONS {
  . = 0xFFFFFFFF80000000;
  .text ALIGN(4096) : AT(ADDR(.text) - 0xFFFFFFFF80000000 + 0x400000) {
    *(.text.uefi_start)
    *(.text .text.*)
  }
  .rodata ALIGN(4096) : { *(.rodata .rodata.*) }
  .data ALIGN(4096) : { *(.data .data.*) }
  .bss ALIGN(4096) : { *(.bss .bss.*) *(COMMON) }
  . = ALIGN(4096);
  _end = .;
}
