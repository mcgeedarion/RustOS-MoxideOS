//! Kernel synchronisation primitives.
//!
//! ## Contents
//!
//! - `futex`:      sleep/wake wait-queue table backing the `futex(2)` syscall.
//! - `mutex`:      simple kernel mutex (placeholder).
//! - `spinlock`:   raw spinlock.
//! - `wait_queue`: universal blocking primitive — the ONE wait/wake substrate.
//! - `poll_source`: PollSource trait — the ONE readiness abstraction.
//!
//! ## Invariant
//!
//! **Subsystems MUST NOT call `scheduler::wake_pid()` directly.**
//! Subsystems publish readiness via `WaitQueue::wake(mask)`.
//! The scheduler exclusively owns task state transitions.
//! Every violation is findable with `grep -r 'wake_pid' src/`.

pub mod futex;
pub mod mutex;
pub mod poll_source;
pub mod spinlock;
pub mod wait_queue;

pub use mutex::Mutex;
pub use poll_source::{wait_any, wait_on, PollSource};
pub use wait_queue::{CancelReason, CancellationToken, ReadyMask, WaitQueue, WakeReason};
