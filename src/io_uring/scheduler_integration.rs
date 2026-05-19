// src/io_uring/scheduler_integration.rs
//
// Scheduler hook for io_uring.
//
// ## Current role
//
// With the move to WaitQueue-based wakeups, `post_cqe()` directly wakes
// any task sleeping in `io_uring_enter` GETEVENTS.  No per-tick drain of a
// WakerTable is required.
//
// This file is retained as a hook for future IRQ-driven completions:
// when a virtio-blk or NVMe IRQ fires, it calls `io_uring::post_cqe()`
// from interrupt context, and `cq_wq.wake()` fires immediately.
//
// ## Boot sequence
//
//   1. Call `io_uring::init()` after the allocator is up.
//   2. The idle loop no longer needs to call `scheduler_tick()`, but
//      may still do so — it is now a no-op.

/// No-op tick — kept for boot-loop compatibility.
///
/// IRQ-driven post_cqe() wakes cq_wq directly; no polling is needed here.
pub fn scheduler_tick() {}
