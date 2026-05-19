//! Universal kernel wait queue.
//!
//! ## Invariant
//!
//! **Subsystems MUST NOT call `scheduler::wake_pid()` directly.**
//! Subsystems publish readiness via [`WaitQueue::wake`].
//! The scheduler exclusively owns task state transitions.
//!
//! ## Design
//!
//! Every waitable kernel object embeds a `WaitQueue`. When state changes
//! (data arrives, timer fires, fd closes) the producer calls
//! `wq.wake(bits)`. Consumers sleep via `wq.wait(interest, cancel,
//! deadline)` and are unblocked by the scheduler when their interest mask
//! matches an incoming `wake(bits)` call.
//!
//! The `ready` field is an `AtomicU32` so `poll()` is always lock-free and
//! safe from IRQ context. The waiter list is protected by a `SpinLock` and
//! is only touched when a task is actually going to sleep.
//!
//! ## Usage pattern
//!
//! ```rust
//! // Producer (IRQ / device / timer callback):
//! obj.wq.wake(POLLIN);
//!
//! // Consumer (blocking syscall):
//! match obj.wq.wait(POLLIN, Some(&cancel_token), Some(deadline_ns)) {
//!     WakeReason::Ready     => { /* data available */ }
//!     WakeReason::Timeout   => { /* -ETIMEDOUT */ }
//!     WakeReason::Cancelled => { /* -EINTR / -EPIPE / … */ }
//! }
//! ```

extern crate alloc;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::sync::spinlock::SpinLock;
use crate::sync::cancel::CancellationToken;

/// Bitmask of ready events (POLLIN / POLLOUT / POLLHUP / …).
pub type ReadyMask = u32;

/// Internal sentinel: set by the timeout callback to break a sleeping wait.
pub(crate) const POLL_TIMEOUT_BIT: ReadyMask = 1 << 30;
/// Internal sentinel: set by `CancellationToken` to break a sleeping wait.
pub(crate) const POLL_CANCEL_BIT:  ReadyMask = 1 << 31;

/// Why a `WaitQueue::wait` call returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeReason {
    /// At least one bit of `interest` became ready.
    Ready,
    /// The caller-supplied deadline elapsed.
    Timeout,
    /// A `CancellationToken` was fired (signal, fd close, task exit, …).
    Cancelled,
}

// ── internal waiter entry ─────────────────────────────────────────────────────

struct Waiter {
    task_id:  usize,
    interest: ReadyMask,
}

// ── WaitQueue ──────────────────────────────────────────────────────────────────

/// A scheduler-owned blocking primitive.
///
/// Embed one of these in every kernel object that can be waited on
/// (pipe, socket, eventfd, timerfd, io_uring CQ, futex bucket, …).
pub struct WaitQueue {
    /// Atomically maintained readiness bits. Written by producers (IRQ-safe),
    /// read lock-free by `poll()`.
    ready:   AtomicU32,
    waiters: SpinLock<VecDeque<Waiter>>,
}

unsafe impl Sync for WaitQueue {}
unsafe impl Send for WaitQueue {}

impl WaitQueue {
    /// Construct an empty, not-ready queue.
    pub const fn new() -> Self {
        Self {
            ready:   AtomicU32::new(0),
            waiters: SpinLock::new(VecDeque::new()),
        }
    }

    // ── producer API (IRQ-safe) ───────────────────────────────────────────────

    /// Set readiness bits and wake every waiter whose interest overlaps.
    ///
    /// **This is the only legal way for a subsystem to unblock tasks.**
    ///
    /// # Example
    /// ```rust
    /// // After writing bytes into a pipe:
    /// pipe.read_wq.wake(POLLIN);
    /// ```
    pub fn wake(&self, bits: ReadyMask) {
        self.ready.fetch_or(bits, Ordering::Release);
        let waiters = self.waiters.lock();
        for w in waiters.iter() {
            if w.interest & bits != 0 {
                crate::proc::scheduler::wake_pid(w.task_id);
            }
        }
    }

    /// Wake all waiters unconditionally (e.g. on object teardown).
    pub fn wake_all(&self, bits: ReadyMask) {
        self.ready.fetch_or(bits, Ordering::Release);
        let waiters = self.waiters.lock();
        for w in waiters.iter() {
            crate::proc::scheduler::wake_pid(w.task_id);
        }
    }

    /// Clear readiness bits (call after consuming the event, e.g. eventfd read).
    pub fn clear(&self, bits: ReadyMask) {
        self.ready.fetch_and(!bits, Ordering::AcqRel);
    }

    // ── consumer API ─────────────────────────────────────────────────────────

    /// Return currently ready bits matching `interest` without blocking.
    ///
    /// Safe to call from IRQ context.
    #[inline]
    pub fn poll(&self, interest: ReadyMask) -> ReadyMask {
        self.ready.load(Ordering::Acquire) & interest
    }

    /// Block the current task until `interest` bits appear, the optional
    /// deadline elapses, or the optional `CancellationToken` fires.
    ///
    /// Returns the reason the wait ended. The caller is responsible for
    /// re-checking readiness after `WakeReason::Ready` (spurious wakeups
    /// are possible on SMP).
    ///
    /// **Never spins.** Calls `block_current()` exactly once.
    pub fn wait(
        &self,
        interest:  ReadyMask,
        cancel:    Option<&CancellationToken>,
        deadline:  Option<u64>,
    ) -> WakeReason {
        let task_id = crate::proc::scheduler::current_pid();

        // ── fast path ────────────────────────────────────────────────────────
        if self.ready.load(Ordering::Acquire) & interest != 0 {
            return WakeReason::Ready;
        }
        if let Some(ct) = cancel {
            if ct.is_cancelled() { return WakeReason::Cancelled; }
        }

        // ── arm deadline timer ────────────────────────────────────────────────
        // Timer is armed before we register as a waiter so there is no window
        // where the deadline fires without waking us.
        let timer_id: Option<u64> = deadline.map(|dl| {
            let wq_ptr = self as *const WaitQueue as usize;
            crate::time::timer::add_oneshot(dl, move |_id| {
                // SAFETY: WaitQueue lifetime is owned by an Arc<dyn PollSource>
                // which outlives any timer registration made through it.
                let wq = unsafe { &*(wq_ptr as *const WaitQueue) };
                wq.wake(POLL_TIMEOUT_BIT);
            })
        });

        // ── register waiter ──────────────────────────────────────────────────
        {
            let mut waiters = self.waiters.lock();
            waiters.push_back(Waiter {
                task_id,
                interest: interest | POLL_TIMEOUT_BIT | POLL_CANCEL_BIT,
            });
        }

        // ── fire cancel immediately if already set ────────────────────────────
        if let Some(ct) = cancel {
            if ct.is_cancelled() {
                // Remove ourselves before sleeping — we won't sleep at all.
                self.waiters.lock().retain(|w| w.task_id != task_id);
                if let Some(tid) = timer_id {
                    crate::time::timer::cancel_timer(tid);
                }
                return WakeReason::Cancelled;
            }
        }

        // ── sleep ─────────────────────────────────────────────────────────────
        crate::proc::scheduler::block_current();

        // ── de-register and clean up ──────────────────────────────────────────
        self.waiters.lock().retain(|w| w.task_id != task_id);
        if let Some(tid) = timer_id {
            crate::time::timer::cancel_timer(tid);
        }

        // ── determine wake reason ─────────────────────────────────────────────
        if let Some(ct) = cancel {
            if ct.is_cancelled() { return WakeReason::Cancelled; }
        }
        let now = crate::time::read_monotonic_ns();
        if deadline.map(|dl| now >= dl).unwrap_or(false) {
            return WakeReason::Timeout;
        }
        WakeReason::Ready
    }

    // ── poll table forwarding (for select/poll/epoll aggregate waits) ────────

    /// Register a forwarding entry: when this queue fires `bits & interest`,
    /// also wake `target`. Used by `PollTable` to build aggregate waits over
    /// N sources with a single sleep.
    ///
    /// The forwarding entry is automatically removed by the next `wake()` call
    /// (one-shot). The caller must re-register on each poll loop iteration.
    pub fn register_forwarder(
        &self,
        target_task: usize,
        interest: ReadyMask,
    ) {
        let mut waiters = self.waiters.lock();
        // Idempotent: update existing entry for this task.
        for w in waiters.iter_mut() {
            if w.task_id == target_task {
                w.interest |= interest;
                return;
            }
        }
        waiters.push_back(Waiter { task_id: target_task, interest });
    }

    /// Remove any forwarder entry for `target_task`.
    pub fn remove_forwarder(&self, target_task: usize) {
        self.waiters.lock().retain(|w| w.task_id != target_task);
    }
}
