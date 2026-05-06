#![no_std]
#![feature(naked_functions, alloc_error_handler, core_intrinsics)]
// abi_x86_interrupt is declared locally in src/arch/x86_64/idt.rs via
// #![feature(abi_x86_interrupt)] at the crate level only when building for
// x86_64. It is NOT declared here because cfg_attr cannot gate #![feature]
// on a per-arch basis in a way rustc accepts for bare-metal targets.
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]
#![allow(dead_code, unused_variables, unused_imports)]
extern crate alloc;

pub mod allocator;
pub mod arch;
pub mod block;
pub mod console;
pub mod drivers;
pub mod dt;
pub mod elf;
pub mod fs;
pub mod gdbstub;
pub mod initramfs;
pub mod input;
pub mod kernel_main;
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

// acpi is x86-only (ACPI tables are not present on RISC-V QEMU virt).
#[cfg(target_arch = "x86_64")]
pub mod acpi;

/// Wayland compositor subsystem.
/// Enabled with `--features wayland` or `features = ["wayland"]` in Cargo.toml.
#[cfg(feature = "wayland")]
pub mod wayland;
