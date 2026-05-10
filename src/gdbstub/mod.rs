//! GDB remote serial protocol (RSP) stub — x86_64.
//!
//! Enabled via `cargo build --features gdbstub`.
//!
//! # Integration
//!
//! Call [`gdb_trap`] from any INT3 / debug-exception handler, passing a
//! pointer to the interrupted register frame and the current PID:
//!
//! ```ignore
//! // Inside your #[naked] trap handler, after saving all registers:
//! #[cfg(feature = "gdbstub")]
//! crate::gdbstub::gdb_trap(
//!     regs as *mut crate::gdbstub::SavedRegs,
//!     crate::proc::scheduler::current_pid(),
//! );
//! ```
//!
//! The stub blocks on COM1 (x86_64) until GDB sends a `D` (detach) or
//! `k` (kill) packet, then returns so the kernel can resume normal
//! execution.
//!
//! # RISC-V
//!
//! RISC-V support is a planned follow-up.  The SavedRegs layout and
//! register numbering are x86_64-specific; `cfg(target_arch = "x86_64")`
//! gates compilation in lib.rs.

pub mod serial;
pub mod rsp;

pub use rsp::SavedRegs;

/// Entry point called from a breakpoint or debug-exception handler.
///
/// Blocks until GDB detaches.  Modifies `regs` in-place so that the
/// interrupted context is updated with any register writes GDB issued.
///
/// `stopped_pid` identifies the task that triggered the trap and is used
/// in `?`, `qC`, and thread-stop-reply packets.  Pass
/// `crate::proc::scheduler::current_pid()` from the trap handler.
///
/// # Safety
/// `regs` must point to the live, writable register save area on the
/// interrupted kernel/user stack frame.  The pointer must remain valid
/// for the entire duration of the GDB session.
pub unsafe fn gdb_trap(regs: *mut SavedRegs, stopped_pid: u32) {
    rsp::run_session(regs, stopped_pid);
}
