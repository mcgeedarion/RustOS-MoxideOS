OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
  . = 0x80200000;
  _kernel_start = .;

  .text   : { *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }

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

  .data   : { *(.data .data.*) }
  .bss    : { *(.bss .bss.*) *(COMMON) }
  . = ALIGN(4096);
  _end = .;
}
