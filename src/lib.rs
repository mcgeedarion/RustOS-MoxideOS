//! RustOS kernel crate root.

#![no_std]
#![feature(alloc_error_handler)]
#![feature(naked_functions)]
#![feature(asm_const)]

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
pub mod input;
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

// ── Legacy top-level aliases (backward compat) ───────────────────────────────
//
// Kept so that existing `crate::foo` references compile unchanged.
// Migrate call-sites to the canonical paths and delete these.
//
//   Old path            Canonical path
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

#[deprecated(since = "0.1.0", note = "use `crate::mm::allocator`")]
pub mod allocator;
#[deprecated(since = "0.1.0", note = "use `crate::init::crt`")]
pub mod crt;
#[deprecated(since = "0.1.0", note = "use `crate::display::drm`")]
pub mod drm;
#[deprecated(since = "0.1.0", note = "use `crate::firmware::dt`")]
pub mod dt;
#[deprecated(since = "0.1.0", note = "use `crate::exec::elf`")]
pub mod elf;
#[deprecated(since = "0.1.0", note = "use `crate::debug::gdbstub`")]
pub mod gdbstub;
#[deprecated(since = "0.1.0", note = "use `crate::init::initramfs`")]
pub mod initramfs;
#[deprecated(since = "0.1.0", note = "use `crate::init::loader`")]
pub mod loader;
#[deprecated(since = "0.1.0", note = "use `crate::kernel::panic`")]
pub mod panic;
#[deprecated(since = "0.1.0", note = "use `crate::kernel::rand`")]
pub mod rand;
#[deprecated(since = "0.1.0", note = "use `crate::kernel::uaccess`")]
pub mod uaccess;
#[deprecated(since = "0.1.0", note = "use `crate::kernel::utils`")]
pub mod utils;
#[deprecated(since = "0.1.0", note = "use `crate::display::wayland`")]
pub mod wayland;

pub use kernel_main::kernel_main;
mod kernel_main;
