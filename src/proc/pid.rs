//! Global PID allocator shim.
//!
//! Thin wrapper around `crate::proc::scheduler::next_pid` so that callers
//! that prefer the `crate::proc::pid::alloc_pid` form (e.g. `proc::exec`)
//! get a stable path. The PID-namespace-aware allocator lives in
//! `crate::security::ns::pid_ns::PidNamespace::{alloc_pid, free_pid}`.

/// Allocate a fresh global PID. Returns a monotonically-increasing value
/// from the scheduler's PID counter. Wraps after `u32::MAX`; collisions are
/// the caller's responsibility (none of the current callers handle them).
#[inline]
pub fn alloc_pid() -> usize {
    crate::proc::scheduler::next_pid() as usize
}

/// Release a PID that was previously allocated via [`alloc_pid`].
///
/// The current scheduler PID counter is monotonic and does not reclaim
/// integers, so this is a no-op. Kept so that callers can express intent
/// symmetrically; replace with a real free-list when the counter becomes
/// reusable.
#[inline]
pub fn free_pid(_pid: usize) {
    // GUESS: scheduler::next_pid is monotonic — no free-list to update.
}
