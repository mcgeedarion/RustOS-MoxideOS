//! GDB Remote Serial Protocol (RSP) stub.
//!
//! Enabled via `cargo build --features gdbstub`.
//!
//! ## Architecture support
//!
//! | Arch    | Status   | Entry point          | Serial I/O       |
//! |---------|----------|----------------------|------------------|
//! | x86_64  | Complete | `gdb_trap`           | COM1 (raw UART)  |
//! | RISC-V  | Complete | `gdb_trap_rv`        | SBI console      |
//!
//! ## x86_64 integration
//!
//! Call [`gdb_trap`] from your `#DB` / `#BP` exception handler:
//!
//! ```ignore
//! #[cfg(all(feature = "gdbstub", target_arch = "x86_64"))]
//! crate::gdbstub::gdb_trap(
//!     regs as *mut crate::gdbstub::SavedRegs,
//!     crate::proc::scheduler::current_pid(),
//! );
//! ```
//!
//! ## RISC-V integration
//!
//! Call [`gdb_trap_rv`] from the breakpoint exception path in
//! `arch/riscv64/trap.rs` (exception code 3 = Breakpoint):
//!
//! ```ignore
//! #[cfg(all(feature = "gdbstub", target_arch = "riscv64"))]
//! crate::gdbstub::gdb_trap_rv(
//!     frame as *mut crate::gdbstub::RvSavedRegs,
//!     crate::proc::scheduler::current_pid(),
//! );
//! ```
//!
//! `RvSavedRegs` is layout-compatible with `TrapFrame` — cast directly.

pub mod serial;

#[cfg(target_arch = "x86_64")]
pub mod rsp;

#[cfg(target_arch = "riscv64")]
pub mod rsp_riscv;

// ── x86_64 re-exports ────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub use rsp::SavedRegs;

/// Entry point from a breakpoint or debug-exception handler (x86_64).
///
/// Blocks on COM1 until GDB detaches or kills.  Modifies `regs` in-place
/// so the interrupted context reflects any register writes GDB issued.
///
/// # Safety
/// `regs` must point to the live, writable x86_64 register save frame.
#[cfg(target_arch = "x86_64")]
pub unsafe fn gdb_trap(regs: *mut SavedRegs, stopped_pid: u32) {
    rsp::run_session(regs, stopped_pid);
}

// ── RISC-V re-exports ────────────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
pub use rsp_riscv::SavedRegs as RvSavedRegs;

/// Entry point from the RISC-V breakpoint exception handler (exception code 3).
///
/// Blocks on SBI console until GDB detaches or kills.  Modifies `regs`
/// in-place — sepc and sstatus changes are reflected when the trap handler
/// `sret`s back to the interrupted context.
///
/// # Safety
/// `regs` must be a valid pointer to the live `TrapFrame` on the kernel stack.
/// `RvSavedRegs` is `#[repr(C)]` and layout-compatible with `TrapFrame`.
#[cfg(target_arch = "riscv64")]
pub unsafe fn gdb_trap_rv(regs: *mut RvSavedRegs, stopped_pid: u32) {
    rsp_riscv::run_session(regs, stopped_pid);
}
