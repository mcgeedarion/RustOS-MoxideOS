//! Early-boot and init-process support.
//!
//! | Module      | Role                                                         |
//! |-------------|--------------------------------------------------------------|
//! | `crt`       | C runtime stub: sets up the initial stack frame and calls    |
//! |             | `main` for user-space ELF binaries.                          |
//! | `initramfs` | CPIO initramfs parser and in-memory VFS mount.               |
//! |             | `mount_initramfs()` is called during boot before the         |
//! |             | scheduler starts.                                            |
//! | `loader`    | High-level ELF loader: maps PT_LOAD segments into a fresh    |
//! |             | address space and sets up the auxiliary vector for the       |
//! |             | dynamic linker.                                              |
//! | `schemes`   | Registers all built-in kernel schemes into `SCHEME_TABLE`.   |
//! |             | Called from `kernel_main` after NIC + DHCP init.             |

pub mod crt;
pub mod initramfs;
pub mod loader;
pub mod schemes;
