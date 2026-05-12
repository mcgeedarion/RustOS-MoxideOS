//! rustos kernel crate root.

#![no_std]
#![feature(alloc_error_handler)]
#![feature(naked_functions)]
#![feature(asm_const)]
#![allow(dead_code, unused_imports, unused_variables, unused_mut,
         unused_assignments, non_camel_case_types)]

extern crate alloc;

pub mod acpi;
pub mod allocator;
pub mod arch;
pub mod block;
pub mod console;
pub mod crt;
pub mod drivers;
pub mod drm;
pub mod dt;
pub mod elf;
pub mod fs;
pub mod gdbstub;
pub mod initramfs;
pub mod input;
pub mod io_uring;
pub mod ipc;
pub mod loader;
pub mod mm;
pub mod net;
pub mod panic;
pub mod proc;
pub mod rand;
pub mod security;
pub mod shell;
pub mod smp;
pub mod sync;
pub mod syscall;
pub mod time;
pub mod tty;
pub mod uaccess;
pub mod utils;
pub mod wayland;

pub use kernel_main::kernel_main;
mod kernel_main;
