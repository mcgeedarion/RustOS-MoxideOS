//! GDB remote serial protocol (RSP) stub.
//!
//! Enabled via `cargo build --features gdbstub`.
//!
//! # Integration
//!
//! Call [`gdb_trap`] from any INT3 / debug-exception handler, passing a
//! pointer to the interrupted register frame:
//!
//! ```ignore
//! // inside your #[naked] trap handler, after saving all registers:
//! #[cfg(feature = "gdbstub")]
//! crate::gdbstub::gdb_trap(regs as *mut crate::gdbstub::SavedRegs);
//! ```
//!
//! The stub blocks on COM1 (x86_64) or SBI console (RISC-V) until GDB
//! sends a `D` (detach) or `k` (kill) packet, then returns so the kernel
//! can resume normal execution.

pub mod serial;
pub mod rsp;

pub use rsp::SavedRegs;

/// Entry point called from a breakpoint / debug exception handler.
///
/// Blocks until GDB detaches. Modifies `regs` in-place so that the
/// interrupted context is updated with any register writes GDB sent.
///
/// # Safety
/// `regs` must point to the live, writable register save area on the
/// interrupted kernel/user stack frame. The pointer must remain valid
/// for the entire duration of the GDB session.
pub unsafe fn gdb_trap(regs: *mut SavedRegs) {
    rsp::run_session(regs);
}
