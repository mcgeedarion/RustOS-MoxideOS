// src/io_uring/scheduler_integration.rs
//
// Hook that the task scheduler calls every tick to drive async I/O forward.
//
// Placement in the boot/scheduler tick:
//
//   loop {
//       scheduler::run_ready_tasks();
//       io_uring::scheduler_tick();   // ← add this line
//       arch::wait_for_interrupt();   // hlt on x86
//   }
//
// The tick:
//   1. Processes all pending SQEs (dispatches opcodes, fills CQEs).
//   2. Drains the CQ and wakes every Future that has a matching CQE.
//   3. Woken futures are re-queued by the executor and will run on the next
//      pass of `run_ready_tasks()`.

use crate::io_uring;

/// Drive io_uring forward — called once per scheduler tick.
///
/// This is cheap when the rings are empty (two atomic loads, no work).
pub fn scheduler_tick() {
    if let Err(e) = io_uring::poll_completions() {
        log::error!("[io_uring] poll_completions error: {:?}", e);
    }
}

// ── Integration checklist ────────────────────────────────────────────────────
//
// Boot sequence (main/boot.rs or equivalent):
//   [ ] Call io_uring::init() after the allocator is up.
//   [ ] Add scheduler_tick() to the idle loop (see above).
//
// Network stack:
//   [ ] When accept queue gets a new connection, call io_uring::push_cqe()
//       with the matching listen_fd's token and the new fd as `res`.
//   [ ] When a non-blocking connect completes (interface is up), push the CQE.
//   [ ] When recv data arrives for a socket, push the CQE with bytes read.
//
// VFS:
//   [ ] On block read completion (DMA/IRQ), push_cqe with bytes transferred.
//   [ ] On block write completion, push_cqe with bytes written.
