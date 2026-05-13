//! Early-boot and init-process support.
//!
//! ## Modules
//!
//!   `crt`        — C runtime stub (`crt0.c`): sets up the initial stack
//!                  frame and calls `main` for user-space ELF binaries.
//!
//!   `initramfs`  — CPIO initramfs parser and in-memory VFS mount.
//!                  `initramfs::mount_initramfs()` is called during boot
//!                  before the scheduler starts.
//!
//!   `loader`     — High-level ELF loader: walks program headers, maps
//!                  PT_LOAD segments into a fresh address space, and sets
//!                  up the auxiliary vector (`auxv`) for the dynamic linker.
//!
//!   `schemes`    — Registers all built-in kernel schemes (file:, net:,
//!                  blk:, proc:, dev:, pipe:, null:) into SCHEME_TABLE.
//!                  Called from kernel_main after NIC + DHCP init.

pub mod crt;
pub mod initramfs;
pub mod loader;
pub mod schemes;
