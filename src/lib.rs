//! rustos kernel crate root.

#![no_std]
#![feature(alloc_error_handler)]
#![feature(naked_functions)]
#![feature(asm_const)]
#![allow(dead_code, unused_imports, unused_variables, unused_mut,
         unused_assignments, non_camel_case_types)]

extern crate alloc;

// ── Canonical subsystem modules ──────────────────────────────────────────────
//
// Organised by kernel layer (outermost = most dependent on others):
//
//   arch        — Architecture-specific code (x86_64, riscv64)
//   firmware    — Platform firmware interfaces (ACPI, Device Tree)
//   mm          — Memory management (PMM, heap, slab, mmap, swap, allocator)
//   sync        — Synchronisation primitives (spinlock, mutex, condvar)
//   drivers     — Hardware drivers (virtio, NIC, AHCI, NVMe, PCIe, USB, …)
//   display     — Display stack (DRM/KMS object model + Wayland compositor)
//   fs          — Filesystem layer (VFS, ext2, FAT32, initramfs mount)
//   net         — Network stack (TCP/UDP/IP, DHCP, DNS, sockets)
//   block       — Block layer (I/O scheduler, bio abstraction)
//   tty         — TTY/PTY subsystem (ldisc, termios, pts)
//   input       — Input event subsystem
//   console     — Kernel console (printk destination)
//   proc        — Process management (scheduler, exec, wait, signals, namespaces)
//   syscall     — Syscall dispatch table
//   ipc         — IPC (pipes, FIFOs, System V IPC, POSIX MQ)
//   io_uring    — io_uring async I/O ring
//   time        — Timekeeping (clocksource, timerfd, itimers)
//   smp         — SMP / multi-core bringup
//   security    — Security hardening (ASLR, stack canaries, seccomp)
//   shell       — Built-in kernel debug shell
//   init        — Early-boot: initramfs, ELF loader, crt0
//   exec        — Executable format parsers (ELF-64)
//   debug       — Debugging infrastructure (GDB stub)
//   kernel      — Core kernel utilities (panic, rand, uaccess, utils)

pub mod arch;
pub mod block;
pub mod console;
pub mod debug;
pub mod display;
pub mod drivers;
pub mod exec;
pub mod firmware;
pub mod fs;
pub mod init;
pub mod io_uring;
pub mod ipc;
pub mod kernel;
pub mod mm;
pub mod net;
pub mod proc;
pub mod security;
pub mod shell;
pub mod smp;
pub mod sync;
pub mod syscall;
pub mod time;
pub mod tty;
pub mod input;

// ── Legacy top-level aliases (backward compat) ───────────────────────────────
//
// The modules below are kept at their original paths so that all existing
// `crate::foo` references in kernel_main.rs and elsewhere continue to compile
// without modification. They will be removed once all call-sites are updated
// to use the new paths above.
//
//   Old path            New canonical path
//   crate::acpi      →  crate::firmware::acpi
//   crate::allocator →  crate::mm::allocator
//   crate::crt       →  crate::init::crt
//   crate::drm       →  crate::display::drm
//   crate::dt        →  crate::firmware::dt
//   crate::elf       →  crate::exec::elf
//   crate::gdbstub   →  crate::debug::gdbstub
//   crate::initramfs →  crate::init::initramfs
//   crate::loader    →  crate::init::loader
//   crate::panic     →  crate::kernel::panic
//   crate::rand      →  crate::kernel::rand
//   crate::uaccess   →  crate::kernel::uaccess
//   crate::utils     →  crate::kernel::utils
//   crate::wayland   →  crate::display::wayland

pub mod acpi;
pub mod allocator;
pub mod crt;
pub mod drm;
pub mod dt;
pub mod elf;
pub mod gdbstub;
pub mod initramfs;
pub mod loader;
pub mod panic;
pub mod rand;
pub mod uaccess;
pub mod utils;
pub mod wayland;

pub use kernel_main::kernel_main;
mod kernel_main;
