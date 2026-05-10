#![no_std]
#![feature(naked_functions, alloc_error_handler, core_intrinsics)]
// abi_x86_interrupt is declared locally in src/arch/x86_64/idt.rs via
// #![feature(abi_x86_interrupt)] at the crate level only when building for
// x86_64. It is NOT declared here because cfg_attr cannot gate #![feature]
// on a per-arch basis in a way rustc accepts for bare-metal targets.
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]
// NOTE: do NOT add #![allow(dead_code)] or #![allow(unused_variables)] here.
// Use targeted per-item or per-module suppressions instead so that rustc
// keeps reporting real dead-code and unused-variable warnings everywhere else.
extern crate alloc;

// ── Core kernel — always compiled in every build ──────────────────────────────
//
// These modules form the stable, fully functional base kernel. Every subsystem
// listed here must compile cleanly with zero WIP stubs in the call path.
pub mod allocator;
pub mod arch;
pub mod block;
pub mod console;
pub mod drivers;
pub mod dt;
pub mod elf;
pub mod fs;
pub mod initramfs;
pub mod kernel_main;
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
pub mod uaccess;
pub mod utils;

// ── Architecture-specific (always compiled, arch-gated) ───────────────────────
// ACPI tables are only present on x86_64; RISC-V uses device-tree (src/dt.rs).
#[cfg(target_arch = "x86_64")]
pub mod acpi;

// ── Feature-gated WIP subsystems ─────────────────────────────────────────────
//
// RULE: any module with unimplemented stubs, missing syscall wiring, or
// incomplete capability enforcement MUST live behind a feature flag.
// The default build must compile and run without any of these.
//
// To add a new WIP subsystem:
//   1. Add a named feature to Cargo.toml [features] with a status comment.
//   2. Gate the mod declaration below with #[cfg(feature = "<name>")].
//   3. Do NOT add the feature to `default = [...]`.

/// GDB remote serial protocol stub.
///
/// Not yet implemented — no GDB RSP framing or packet handling exists.
/// Gated to avoid polluting the default build with a dead placeholder and
/// masking legitimate dead-code warnings in the rest of the kernel.
///
/// Enable: `cargo build --features gdbstub`
#[cfg(feature = "gdbstub")]
pub mod gdbstub;

/// Linux /dev/input evdev routing layer.
///
/// `dispatch_key` and `dispatch_mouse` are no-op stubs. Routing to
/// /dev/input/eventN device nodes is not wired.
///
/// Enable: `cargo build --features input_events`
#[cfg(feature = "input_events")]
pub mod input;

/// System V IPC + POSIX message queues.
///
/// Data structures, locking, and syscall logic are complete.
/// CAP_IPC_OWNER capability enforcement is a stub (always grants access).
/// Wire into the syscall table by enabling this feature and calling
/// `ipc::msg::sys_msgget` / `ipc::sem::sys_semget` / etc. from
/// `src/syscall/dispatch.rs`.
///
/// Enable: `cargo build --features sysv_ipc`
#[cfg(feature = "sysv_ipc")]
pub mod ipc;

/// Linux namespace isolation (PID / Mount / Net / UTS / User).
///
/// All five namespace types are implemented in src/security/ns/.
/// Missing: setns(2) syscall dispatch and /proc/self/ns nsfs inodes.
/// The NsSet type is used internally by security::ns regardless of
/// this feature; this gate only controls crate-root visibility.
///
/// Enable: `cargo build --features namespaces`
#[cfg(feature = "namespaces")]
pub mod ns {
    //! Re-export of `security::ns` at the crate root for external consumers.
    pub use crate::security::ns::*;
}

/// cgroups v1 resource controllers (cpu, memory, pids).
///
/// Hierarchy, knob read/write, memory charging, and pids fork-limit are
/// complete. Missing: /sys/fs/cgroup cgroupfs VFS mount and the
/// per-task charge hooks in sys_mmap / sys_fork.
/// The cgroups API is available internally via `security::cgroups`
/// regardless of this gate; the gate controls crate-root visibility.
///
/// Enable: `cargo build --features cgroups`
#[cfg(feature = "cgroups")]
pub mod cgroups {
    //! Re-export of `security::cgroups` at the crate root for external consumers.
    pub use crate::security::cgroups::*;
}

/// Wayland compositor subsystem (in-kernel Wayland protocol server).
///
/// The kernel retains only a thin vblank pass-through
/// (`compositor::vblank_notify`). All compositor logic lives in the
/// privileged userspace process at `userspace/wayland/compositor.c`.
///
/// Enable: `cargo build --features wayland`
#[cfg(feature = "wayland")]
pub mod wayland;
