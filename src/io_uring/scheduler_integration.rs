//! Legacy scheduler compatibility hook for io_uring.
//!
//! ## Why this module exists
//!
//! This module exists only so old boot loops can still call [`scheduler_tick`].
//! After the move to [`WaitQueue`]-based wakeups, `IoUringRing::post_cqe()`
//! wakes any task blocked in `io_uring_enter(... IORING_ENTER_GETEVENTS)`
//! directly — no per-tick drain of a `WakerTable` is required.
//!
//! **Do not add polling logic here.** New completion paths must call
//! [`IoUringRing::post_cqe`] (or, from interrupt/bottom-half context,
//! [`post_cqe_from_irq`]) instead.
//!
//! ## Boot sequence
//!
//!   1. Call [`io_uring::ring::init`] after the allocator is up.
//!   2. The idle loop no longer needs to call [`scheduler_tick`], but may still
//!      do so — it is now a no-op.
//!
//! ## IRQ-driven completions
//!
//! When a virtio-blk or NVMe IRQ fires it should call [`post_cqe_from_irq`]
//! rather than reaching into `IoUringRing` directly. See that function for
//! interrupt-safety constraints.

use crate::io_uring::ring;

// ──────────────────────────────────────────────────────────────────────────────
// Legacy boot-loop hook
// ──────────────────────────────────────────────────────────────────────────────

/// Legacy no-op tick retained for boot-loop compatibility.
///
/// IRQ-driven `post_cqe()` wakes `cq_wq` directly; no scheduler polling is
/// needed here.  This function will be removed once all call sites are updated.
///
/// **Do not add polling here.**
#[deprecated(note = "io_uring wakeups are WaitQueue-driven; this tick hook is a no-op")]
#[inline]
pub fn scheduler_tick() {}

// ──────────────────────────────────────────────────────────────────────────────
// IRQ / bottom-half completion API
// ──────────────────────────────────────────────────────────────────────────────

/// Complete an io_uring operation from an interrupt or bottom-half context.
///
/// Posts a CQE to the ring identified by `ring_idx` and wakes any task blocked
/// in `io_uring_enter(IORING_ENTER_GETEVENTS)` on that ring.
///
/// # Interrupt-safety
///
/// | Context              | Safe to call? | Notes                                      |
/// |----------------------|---------------|--------------------------------------------|
/// | Hard IRQ             | **No**        | `with_ring` acquires a spin-lock that may  |
/// |                      |               | already be held; this can deadlock.        |
/// |                      |               | Enqueue to a bottom-half/tasklet instead.  |
/// | Softirq / bottom-half | **Yes**      | Lock contention is bounded; no sleep.      |
/// | Scheduler / task ctx  | **Yes**      | Normal path.                               |
///
/// # Returns
///
/// `true` if the CQE was posted successfully; `false` if `ring_idx` is invalid
/// or the ring's completion queue overflowed.
///
/// # TODO
///
/// Before wiring real IRQ handlers, audit whether `WaitQueue::wake` (which
/// calls `scheduler::wake_pid`) is safe from softirq context on all target
/// architectures (x86_64 / RISC-V / AArch64).
pub fn post_cqe_from_irq(ring_idx: usize, user_data: u64, res: i32, flags: u32) -> bool {
    ring::with_ring(ring_idx, |r| r.post_cqe(user_data, res, flags)).unwrap_or(false)
}
