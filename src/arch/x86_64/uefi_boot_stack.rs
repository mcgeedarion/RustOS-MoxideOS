#![cfg(target_os = "uefi")]
#![allow(dead_code)]
#![allow(non_upper_case_globals)]

#[repr(align(16))]
struct BootStackStorage([u8; 32768]);

#[used]
#[no_mangle]
#[link_section = ".bss$rustos_boot_stack"]
static mut __boot_stack_bottom: BootStackStorage = BootStackStorage([0u8; 32768]);

#[used]
#[no_mangle]
#[link_section = ".bss$rustos_boot_stack_top"]
pub static __boot_stack_top: [u8; 0] = [];
