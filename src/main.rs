//! Kernel binary crate root.
//!
//! ## Boot paths
//!
//! | Arch    | Boot mechanism      | Entry file                              |
//! |---------|---------------------|-----------------------------------------|
//! | x86_64  | UEFI                | `arch/x86_64/uefi_entry.rs`             |
//! | x86_64  | Multiboot2 / QEMU   | `arch/x86_64/multiboot2_entry.rs`       |
//! | riscv64 | SBI                 | `arch/riscv64/boot.rs`                  |
//! | aarch64 | UEFI                | `arch/aarch64/uefi_entry.rs`            |
//!
//! Every path converges on `kernel_main()` in `kernel_main.rs`.

#![no_std]
#![no_main]

// Pull the kernel library crate into the final executable so its exported boot
// symbols (`uefi_start`, `kernel_main`, architecture modules, panic handler, and
// allocator hooks) are linked into the artifact that xtask converts to EFI.
extern crate rustos_kernel;
