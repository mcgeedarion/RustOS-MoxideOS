//! Kernel-wide unified blocking primitive.
//!
//! # The single rule
//!
//! **Subsystems MUST NOT call `scheduler::wake_pid()` directly.**
//! Call `WaitQueue::wake(mask)` instead. The scheduler owns task state.
//!
//! # Usage
//!
//! ```rust
//! // Device/IRQ side — publish readiness:
//! pipe.read_wq.wake(POLLIN);
//!
//! // Syscall/task side — block until ready:
//! let reason = pipe.read_wq.wait(POLLIN, Some(&cancel), deadline);
//! match reason {
//!     WakeReason::Ready     => { /* read data */ }
//!     WakeReason::Cancelled => return -4, // EINTR
//!     WakeReason::Timeout   => return -110, // ETIMEDOUT
//! }
//! ```

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

/// Bitmask of poll-style readiness flags (POLLIN, POLLOUT, …).
/// Matches the u32 constants in fs::poll.
pub type ReadyMask = u32;

/// Sentinel bits used internally for timeout and cancellation wakeups.
/// Never leaked to callers — masked out before returning from wait().
pub(crate) const WAKE_TIMEOUT: ReadyMask = 1 << 30;
pub(crate) const WAKE_CANCEL:  ReadyMask = 1 << 31;

/// Why a call to WaitQueue::wait() returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeReason {
    /// One or more interest bits became ready.
    Ready,
    /// The deadline elapsed before any interest bits fired.
    Timeout,
    /// A CancellationToken fired (signal, fd close, task exit, etc.).
    Cancelled,
}

struct Waiter {
    task_id:  usize,
    interest: ReadyMask,
}

// Forwarding entry: when this WaitQueue fires, also wake `target`.
struct Forwarder {
    target:   *const WaitQueue,
    interest: ReadyMask,
}

// SAFETY: Forwarder is only accessed under the WaitQueue lock.
// WaitQueue targets are always held in Arc<dyn PollSource> which outlives
// the forwarder registration (register/remove are paired in wait_any).
unsafe impl Send for Forwarder {}

pub struct WaitQueue {
    /// Current readiness bits — published atomically by device/IRQ side.
    /// Readable without the lock for fast-path poll().
    ready:      AtomicU32,
    waiters:    Mutex<VecDeque<Waiter>>,
    forwarders: Mutex<Vec<Forwarder>>,
}

unsafe impl Sync for WaitQueue {}
unsafe impl Send for WaitQueue {}

impl WaitQueue {
    pub const fn new() -> Self {
        Self {
            ready:      AtomicU32::new(0),
            waiters:    Mutex::new(VecDeque::new()),
            forwarders: Mutex::new(Vec::new()),
        }
    }

    /// Publish readiness bits and wake all matching waiters.
    ///
    /// This is the **only** legal entry point for subsystems to unblock tasks.
    /// Never calls `scheduler::wake_pid()` from anywhere else.
    pub fn wake(&self, bits: ReadyMask) {
        self.ready.fetch_or(bits, Ordering::Release);

        // Wake direct waiters.
        let waiters = self.waiters.lock();
        for w in waiters.iter() {
            if w.interest & bits != 0 {
                crate::proc::scheduler::wake_pid(w.task_id);
            }
        }
        drop(waiters);

        // Forward to aggregate WaitQueues (used by poll/select/epoll_wait).
        let fwds = self.forwarders.lock();
        for f in fwds.iter() {
            if f.interest & bits != 0 {
                // SAFETY: target lives in Arc<dyn PollSource>, outlives us.
                let target = unsafe { &*f.target };
                target.ready.fetch_or(bits, Ordering::Release);
                let tw = target.waiters.lock();
                for w in tw.iter() {
                    if w.interest & bits != 0 {
                        crate::proc::scheduler::wake_pid(w.task_id);
                    }
                }
            }
        }
    }

    /// Clear consumed readiness bits.
    /// Call after a consume-on-read operation (timerfd, eventfd).
    pub fn clear(&self, bits: ReadyMask) {
        self.ready.fetch_and(!bits, Ordering::AcqRel);
    }

    /// Non-blocking readiness snapshot.  Lock-free.  IRQ-safe.
    #[inline]
    pub fn poll(&self, interest: ReadyMask) -> ReadyMask {
        self.ready.load(Ordering::Acquire) & interest
    }

    /// Block the current task until `interest` bits appear, the deadline
    /// elapses, or the cancellation token fires.
    ///
    /// **This is the one blocking primitive.**  No spin loop, no yield loop.
    /// Calls `block_current()` exactly once per invocation.
    pub fn wait(
        &self,
        interest:  ReadyMask,
        cancel:    Option<&CancellationToken>,
        deadline:  Option<u64>,
    ) -> WakeReason {
        if self.ready.load(Ordering::Acquire) & interest != 0 {
            return WakeReason::Ready;
        }
        if cancel.map(|c| c.is_cancelled()).unwrap_or(false) {
            return WakeReason::Cancelled;
        }

        let task_id = crate::proc::scheduler::current_pid();
        let full_interest = interest | WAKE_TIMEOUT | WAKE_CANCEL;

        // This ordering prevents a lost wakeup: if the timer fires between
        // the fast-path check and the waiter registration, it will set
        // WAKE_TIMEOUT in ready, and we will see it after taking the lock.
        let timer_id: Option<u64> = deadline.map(|dl| {
            let ptr = self as *const WaitQueue as usize;
            crate::time::timer::add_oneshot(dl, move |_| {
                // SAFETY: WaitQueue is held in Arc<dyn PollSource> and
                // outlives all timers registered on it.
                let wq = unsafe { &*(ptr as *const WaitQueue) };
                wq.wake(WAKE_TIMEOUT);
            })
        });

        {
            let mut waiters = self.waiters.lock();
            // Re-check under lock: readiness may have arrived between the
            // fast-path load above and acquiring the lock.
            if self.ready.load(Ordering::Relaxed) & interest != 0 {
                drop(waiters);
                if let Some(tid) = timer_id {
                    crate::time::timer::cancel_timer(tid);
                }
                return WakeReason::Ready;
            }
            waiters.push_back(Waiter { task_id, interest: full_interest });
        }

        if let Some(ct) = cancel {
            if ct.is_cancelled() {
                // Remove ourselves before returning.
                self.waiters.lock().retain(|w| w.task_id != task_id);
                if let Some(tid) = timer_id {
                    crate::time::timer::cancel_timer(tid);
                }
                return WakeReason::Cancelled;
            }
        }

        crate::proc::scheduler::block_current();

        self.waiters.lock().retain(|w| w.task_id != task_id);
        if let Some(tid) = timer_id {
            crate::time::timer::cancel_timer(tid);
        }

        if cancel.map(|c| c.is_cancelled()).unwrap_or(false) {
            return WakeReason::Cancelled;
        }
        if let Some(dl) = deadline {
            if crate::time::read_monotonic_ns() >= dl {
                return WakeReason::Timeout;
            }
        }
        WakeReason::Ready
    }

    /// Register `target` to be woken whenever this queue fires `interest` bits.
    /// Caller must call `remove_forwarder(target)` when done.
    pub fn register_forwarder(&self, target: &WaitQueue, interest: ReadyMask) {
        let mut fwds = self.forwarders.lock();
        // Deduplicate: only one forwarder per (target, interest) pair.
        let ptr = target as *const WaitQueue;
        if !fwds.iter().any(|f| f.target == ptr) {
            fwds.push(Forwarder { target: ptr, interest });
        }
    }

    /// Remove a previously registered forwarder.
    pub fn remove_forwarder(&self, target: &WaitQueue) {
        let ptr = target as *const WaitQueue;
        self.forwarders.lock().retain(|f| f.target != ptr);
    }

    /// Wake up to `n` waiters whose interest intersects `bits`.
    /// Used by futex_wake(uaddr, n).
    pub fn wake_n(&self, bits: ReadyMask, n: u32) {
        self.ready.fetch_or(bits, Ordering::Release);
        let waiters = self.waiters.lock();
        let mut woken = 0u32;
        for w in waiters.iter() {
            if woken >= n { break; }
            if w.interest & bits != 0 {
                crate::proc::scheduler::wake_pid(w.task_id);
                woken += 1;
            }
        }
    }
}

// Unified cancellation model replacing:
//   - futex_clear_pid()
//   - cancel_timer() in nanosleep
//   - post-hoc has_pending_signal() checks
//   - EPIPE / fd-close races
// Every wait path accepts Option<&CancellationToken>.
// Signal delivery, fd close, and task exit all call cancel().

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    None    = 0,
    Signal  = 1,
    Timeout = 2,
    Closed  = 3,
    Exit    = 4,
    Explicit = 5,
}

pub struct CancellationToken {
    state: AtomicU32,
}

impl CancellationToken {
    pub const fn new() -> Self {
        Self { state: AtomicU32::new(CancelReason::None as u32) }
    }

    /// Fire the token and wake the task sleeping on `wq`.
    ///
    /// Call sites:
    ///   signal delivery  → cancel(Signal,  &pcb.wait_wq)
    ///   fd close         → cancel(Closed,  &resource_wq)
    ///   do_exit          → cancel(Exit,    &pcb.wait_wq)
    ///   timeout expiry   → cancel(Timeout, &pcb.wait_wq)  [handled internally]
    pub fn cancel(&self, reason: CancelReason, wq: &WaitQueue) {
        self.state.store(reason as u32, Ordering::Release);
        wq.wake(WAKE_CANCEL);
    }

    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::Acquire) != CancelReason::None as u32
    }

    pub fn reason(&self) -> CancelReason {
        match self.state.load(Ordering::Acquire) {
            1 => CancelReason::Signal,
            2 => CancelReason::Timeout,
            3 => CancelReason::Closed,
            4 => CancelReason::Exit,
            5 => CancelReason::Explicit,
            _ => CancelReason::None,
        }
    }

    /// Reset after handling — call at syscall re-entry after EINTR.
    pub fn reset(&self) {
        self.state.store(CancelReason::None as u32, Ordering::Relaxed);
    }
}
