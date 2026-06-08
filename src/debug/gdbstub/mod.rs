// GDB stub — canonical implementation lives here.
// src/debug/gdbstub/ re-exports from this module via `pub use
// crate::gdbstub::*` in the shim at src/debug/gdbstub/mod.rs (which is kept for
// backward compat).

pub mod breakpoints;
pub mod rsp;
pub mod rsp_aarch64;
pub mod rsp_riscv;
pub mod rsp_x86_64;
pub mod serial;
pub mod session;
pub mod target;

/// Minimal trap-register marker used by architecture exception handlers.
///
/// The concrete register layout is architecture-specific; handlers pass their
/// native interrupt frame pointer through this opaque type until the full GDB
/// stop-reply path is wired.
#[repr(C)]
pub struct SavedRegs {
    _private: [u8; 0],
}

/// Architecture trap handoff placeholder.
///
/// Breakpoint/watchpoint handling is still routed through the generic
/// exception path elsewhere; this no-op keeps the build graph wired while the
/// concrete GDB session integration is completed.
pub fn gdb_trap(_regs: *mut SavedRegs, _pid: usize) {}
