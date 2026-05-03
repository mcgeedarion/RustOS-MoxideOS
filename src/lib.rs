#![no_std]
#![feature(abi_x86_interrupt, naked_functions, alloc_error_handler, core_intrinsics)]
#![allow(dead_code, unused_variables, unused_imports)]
extern crate alloc;

pub mod acpi;
pub mod allocator;
pub mod arch;
pub mod block;
pub mod console;
pub mod drivers;
pub mod dt;
pub mod elf;
pub mod fs;
pub mod gdbstub;
pub mod input;
pub mod loader;
pub mod mm;
pub mod net;
pub mod panic;
pub mod proc;
pub mod rand;
pub mod security;
pub mod shell;
pub mod sync;
pub mod syscall;
pub mod uaccess;
pub mod utils;
pub mod wayland;
