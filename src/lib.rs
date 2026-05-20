//! RustOS kernel crate root.

#![no_std]
#![feature(alloc_error_handler)]
#![feature(naked_functions)]
#![feature(asm_const)]
// ── Clippy complexity gates ──────────────────────────────────────────────────
//
// These lints are intentionally set at the crate root so they apply
// globally.  They will surface the known high-complexity functions
// (dispatch_with_rip, sys_ptrace_impl, sys_clone3, bpf_run) during
// normal `cargo clippy` runs, making complexity regressions visible
// in CI before they are merged.
//
// Rationale per lint:
//   cognitive_complexity  — catches functions with deeply nested
//                           conditionals / match arms (the primary issue
//                           in the syscall dispatcher).
//   too_many_arguments    — flags functions with more than 7 parameters;
//                           dispatch_with_rip (8 params) is the first
//                           violation.
//   match_same_arms       — warns when two match arms have identical
//                           bodies (NR 118 / NR 119 duplication).
//   large_enum_variant    — prevents accidentally large enum variants
//                           from inflating stack usage in the hot dispatch
//                           path.
#![deny(clippy::cognitive_complexity)]
#![deny(clippy::too_many_arguments)]
#![warn(clippy::match_same_arms)]
#![warn(clippy::large_enum_variant)]

extern crate alloc;

// ── Canonical subsystem modules ──────────────────────────────────────────────
//
// Organised by kernel layer (outermost = most dependent on others):
//
//   core        — Zero-dependency foundation (error types, panic, cpu-local,
//                 intrusive collections).  Everything may depend on this.
//   arch        — Architecture-specific code (x86_64, riscv64)
//   firmware    — Platform firmware interfaces (ACPI, Device Tree)
//   device      — Hardware-neutral bus manager (PCI, future: platform, USB)
//   irq         — Interrupt controllers (PLIC, CLINT; arch-gated)
//   mm          — Memory management (PMM, heap, slab, mmap, swap, allocator)
//   sync        — Synchronisation primitives (spinlock, mutex, condvar)
//   drivers     — Hardware drivers (virtio, NIC, AHCI, NVMe, PCIe, USB, …)
//   display     — Display stack (DRM/KMS object model + Wayland compositor)
//   fs          — Filesystem layer (VFS, ext2, FAT32, initramfs mount)
//   net         — Network stack (TCP/UDP/IP, DHCP, DNS, sockets)
//   block       — Block layer (I/O scheduler, bio abstraction)
//   tty         — TTY/PTY subsystem (ldisc, termios, pts)
//   input       — Input event subsystem  [cfg(feature = "input_events")]
//   console     — Kernel console (printk destination)
//   proc        — Process management (scheduler, exec, wait, signals, namespaces)
//   syscall     — Syscall dispatch table
//   ipc         — IPC (pipes, FIFOs, System V IPC, POSIX MQ)
//   io_uring    — io_uring async I/O ring
//   time        — Timekeeping (clocksource, timerfd, itimers)
//   smp         — SMP / multi-core bringup
//   security    — Security hardening (ASLR, stack canaries, seccomp, cgroups)
//   shell       — Built-in kernel debug shell
//   init        — Early-boot: initramfs, ELF loader, crt0
//   exec        — Executable format parsers (ELF-64)
//   debug       — Debugging infrastructure  [cfg(feature = "gdbstub")]
//   kernel      — Core kernel utilities (panic, rand, uaccess, utils)

pub mod core;
pub mod arch;
pub mod block;
pub mod console;
pub mod device;
pub mod display;
pub mod drivers;
pub mod exec;
pub mod firmware;
pub mod fs;
pub mod init;
pub mod io_uring;
pub mod ipc;
pub mod irq;
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

// Feature-gated subsystems — only compiled when the matching flag is set.
#[cfg(feature = "input_events")]
pub mod input;

#[cfg(feature = "gdbstub")]
pub mod debug;

pub use kernel_main::kernel_main;
mod kernel_main;
