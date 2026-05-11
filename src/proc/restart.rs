//! Restartable-syscall bookkeeping.
//!
//! ## Protocol
//!
//!   1. A syscall that can block (nanosleep, clock_nanosleep, futex WAIT, …)
//!      detects EINTR from signal delivery.
//!   2. Before returning -EINTR to userspace it calls `set_restart` with
//!      the syscall number, the adjusted argument registers, and leaves
//!      `sepc_ecall` as 0 — the trap handler stamps the real value in
//!      `check_and_deliver_with_sepc`.
//!   3. `signal::check_and_deliver_with_sepc` inspects the pending signal's
//!      SA_RESTART flag.  If set, it calls `apply_restart(frame)` to replay
//!      the syscall by rewinding sepc to the ecall instruction address and
//!      restoring the original (possibly adjusted) argument registers.
//!   4. `gdbstub::rsp_riscv` calls `get_restart(pid)` on `g`/`p` packets so
//!      that a stopped task reports the pre-restart register view rather than
//!      the mid-EINTR scratch state.
//!
//! ## Cleanup
//!
//!   `clear_restart(pid)` is called from `exit::do_exit` and `exec::do_execve`
//!   so stale blocks never leak across process lifetimes.

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex;

/// Frozen register state for a restartable syscall.
///
/// Only the registers that change between the original ecall and the restart
/// need to be stored.  Callee-saved registers (s0–s11) are preserved by the
/// scheduler context switch and are never touched by this machinery.
#[derive(Clone, Copy, Debug)]
pub struct RestartBlock {
    /// The ecall instruction address (sepc *before* the +4 advance).
    /// Restoring this makes the CPU re-execute the ecall on sret.
    /// Stamped by `check_and_deliver_with_sepc` after the syscall returns.
    pub sepc_ecall: usize,

    /// The original syscall number (a7).  Stored so the GDB register snapshot
    /// can report it correctly even if the live frame's a7 was clobbered.
    pub nr: usize,

    /// Possibly-adjusted syscall arguments a0–a5.
    /// For nanosleep / clock_nanosleep these carry the *remaining* timeout so
    /// the restarted sleep is not longer than the original requested duration.
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
}

static RESTART_BLOCKS: Mutex<BTreeMap<usize, RestartBlock>> =
    Mutex::new(BTreeMap::new());

/// Store a restart block for `pid`.  Called by the syscall that returns -EINTR.
/// Any previous block for this pid is overwritten.
pub fn set_restart(pid: usize, rb: RestartBlock) {
    RESTART_BLOCKS.lock().insert(pid, rb);
}

/// Retrieve and *consume* the restart block for `pid`.
/// Returns `None` if no restart is pending.
pub fn take_restart(pid: usize) -> Option<RestartBlock> {
    RESTART_BLOCKS.lock().remove(&pid)
}

/// Peek at the restart block without consuming it.
/// Used by the GDB RSP register-snapshot (`g`/`p`) path.
pub fn get_restart(pid: usize) -> Option<RestartBlock> {
    RESTART_BLOCKS.lock().get(&pid).copied()
}

/// Discard any pending restart block for `pid`.
/// Call from `do_exit`, `do_execve`, and `SIGKILL` delivery.
pub fn clear_restart(pid: usize) {
    RESTART_BLOCKS.lock().remove(&pid);
}

/// Rewind `frame` to re-execute the syscall identified by the pending
/// `RestartBlock` for `pid`.
///
/// Consumes the block.  Returns `true` if a restart was applied,
/// `false` if no block was pending.
///
/// # Safety
/// `frame` must be the live supervisor trap frame for `pid` on the current CPU.
#[cfg(target_arch = "riscv64")]
pub unsafe fn apply_restart(
    pid:   usize,
    frame: &mut crate::arch::riscv64::trap::TrapFrame,
) -> bool {
    let rb = match take_restart(pid) {
        Some(rb) => rb,
        None     => return false,
    };
    // Rewind PC to the ecall instruction so the CPU re-executes it on sret.
    frame.sepc = rb.sepc_ecall;
    // Restore the syscall number and (possibly adjusted) argument registers.
    frame.a7 = rb.nr;
    frame.a0 = rb.a0;
    frame.a1 = rb.a1;
    frame.a2 = rb.a2;
    frame.a3 = rb.a3;
    frame.a4 = rb.a4;
    frame.a5 = rb.a5;
    true
}
