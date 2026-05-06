#![no_std]
#![feature(naked_functions, alloc_error_handler, core_intrinsics)]
// abi_x86_interrupt is only valid on x86_64 — gate it so RISC-V builds cleanly.
#[cfg(target_arch = "x86_64")]
extern crate core; // pulls in the feature without a separate #![feature] on riscv
// We conditionally enable abi_x86_interrupt only when compiling for x86_64.
// Rust does not support per-target #![feature] in lib.rs, so we use a
// build-script or cfg_attr workaround. The cleanest approach is to move the
// x86 interrupt ABI usage inside src/arch/x86_64/ where the feature is
// declared locally. For now, gate the feature attr with cfg_attr:
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
