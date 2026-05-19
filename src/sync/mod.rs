//! Kernel synchronisation primitives.
//!
//! ## The single async coherence invariant
//!
//! **Subsystems MUST NOT call `scheduler::wake_pid()` directly.**
//!
//! Subsystems publish readiness via `WaitQueue::wake(mask)`.
//! The scheduler exclusively owns task state transitions.
//!
//! That boundary prevents async model fragmentation: every blocking path
//! (blocking read/write, poll, select, epoll, io_uring enter, futex,
//! nanosleep, wait4) funnels through the same machinery:
//!
//! ```text
//! blocking syscall
//!         │
//!         ▼
//! wait_on(src.wait_queue(), mask, cancel, deadline)
//!         │
//!         ▼
//! src.poll(mask)           ← lock-free AtomicU32 readiness check
//!         │
//!         ▼
//! WaitQueue::wait(…)       ← ONE scheduler sleep; zero spin loops
//! ```
//!
//! ## Contents
//!
//! | Module          | Purpose                                              |
//! |-----------------|------------------------------------------------------|
//! | `wait_queue`    | [`WaitQueue`] — universal sleep/wake primitive       |
//! | `poll_source`   | [`PollSource`] trait + [`wait_on`] + [`PollTable`]   |
//! | `cancel`        | [`CancellationToken`] — unified cancellation         |
//! | `futex`         | `futex(2)` wait-queue table (will migrate to WQ)     |
//! | `mutex`         | Kernel mutex                                         |
//! | `spinlock`      | Raw spinlock                                         |
//!
//! [`WaitQueue`]:          wait_queue::WaitQueue
//! [`PollSource`]:         poll_source::PollSource
//! [`wait_on`]:            poll_source::wait_on
//! [`PollTable`]:          poll_source::PollTable
//! [`CancellationToken`]:  cancel::CancellationToken

pub mod cancel;
pub mod futex;
pub mod mutex;
pub mod poll_source;
pub mod spinlock;
pub mod wait_queue;
