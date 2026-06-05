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
extern crate rustos;
