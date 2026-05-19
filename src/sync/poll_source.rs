//! `PollSource` — the universal readiness abstraction.
//!
//! Every kernel object that can be waited on implements this trait.
//! `fd_ready()` in `fs/poll.rs` dispatches through it. `select`, `poll`,
//! `epoll`, `io_uring POLL_ADD`, and blocking `read`/`write` all call
//! `wait_on()` rather than open-coding their own sleep loops.
//!
//! ## Implementing `PollSource`
//!
//! ```rust
//! use crate::sync::poll_source::{PollSource, ReadyMask};
//! use crate::sync::wait_queue::WaitQueue;
//! use crate::fs::poll::{POLLIN, POLLOUT, POLLHUP};
//!
//! pub struct Pipe { /* … */ pub read_wq: WaitQueue }
//!
//! impl PollSource for PipeReadEnd {
//!     fn poll(&self, interest: ReadyMask) -> ReadyMask {
//!         let mut r = 0;
//!         if interest & POLLIN  != 0 && self.has_data() { r |= POLLIN; }
//!         if interest & POLLHUP != 0 && !self.write_open { r |= POLLHUP; }
//!         r
//!     }
//!     fn wait_queue(&self) -> &WaitQueue { &self.pipe.read_wq }
//! }
//! ```
//!
//! ## The golden rule
//!
//! A `PollSource` implementation MUST NOT call `scheduler::wake_pid()`.
//! It MUST call `self.wait_queue().wake(bits)` instead.

extern crate alloc;
use alloc::sync::Arc;
use crate::sync::wait_queue::{WaitQueue, ReadyMask, WakeReason};
use crate::sync::cancel::CancellationToken;

/// Implemented by every waitable kernel object.
pub trait PollSource: Send + Sync {
    /// Return the subset of `interest` that is currently ready.
    ///
    /// Must be non-blocking and safe to call from any context.
    fn poll(&self, interest: ReadyMask) -> ReadyMask;

    /// Return a reference to this object's `WaitQueue`.
    ///
    /// Callers sleep on this queue when `poll()` returns 0.
    fn wait_queue(&self) -> &WaitQueue;
}

// ── wait_on ───────────────────────────────────────────────────────────────────

/// Block until `src` becomes ready for `interest`, deadline, or cancel.
///
/// This is the **only** function that blocking syscalls should use for
/// I/O waiting. It replaces every open-coded `while !ready { spin_loop() }`
/// in `sys_poll`, `sys_select`, `sys_epoll_wait`, blocking read/write, etc.
///
/// Returns `(ready_mask, reason)`. If `reason != WakeReason::Ready` the
/// caller should return the appropriate errno without inspecting `ready_mask`.
pub fn wait_on(
    src:      &dyn PollSource,
    interest: ReadyMask,
    cancel:   Option<&CancellationToken>,
    deadline: Option<u64>,
) -> (ReadyMask, WakeReason) {
    loop {
        // Check readiness before sleeping — avoids a syscall round-trip
        // when the fd is already ready.
        let ready = src.poll(interest);
        if ready != 0 {
            return (ready, WakeReason::Ready);
        }
        // Check cancellation before sleeping.
        if let Some(ct) = cancel {
            if ct.is_cancelled() {
                return (0, WakeReason::Cancelled);
            }
        }
        // One scheduler sleep — never spins.
        let reason = src.wait_queue().wait(interest, cancel, deadline);
        match reason {
            // Woken by wake(); re-check readiness (SMP spurious wakeup safety).
            WakeReason::Ready => continue,
            other => return (0, other),
        }
    }
}

// ── AlwaysReady ───────────────────────────────────────────────────────────────

/// A trivial `PollSource` for objects that are always readable and writable
/// (regular files, devfs nodes, /dev/null, etc.).
///
/// Its `WaitQueue` is never slept on in practice — `poll()` always
/// returns `interest` immediately.
pub struct AlwaysReady {
    wq:    WaitQueue,
    mask:  ReadyMask,
}

impl AlwaysReady {
    pub fn new(ready_mask: ReadyMask) -> Self {
        use core::sync::atomic::Ordering;
        let s = Self { wq: WaitQueue::new(), mask: ready_mask };
        // Pre-set the ready bits so poll() is always instant.
        s.wq.ready.store(ready_mask, Ordering::Relaxed);
        s
    }
}

impl PollSource for AlwaysReady {
    fn poll(&self, interest: ReadyMask) -> ReadyMask { self.mask & interest }
    fn wait_queue(&self) -> &WaitQueue { &self.wq }
}

// ── PollTable ─────────────────────────────────────────────────────────────────

/// Aggregate N `PollSource`s into one wait.
///
/// Used by `sys_poll`, `sys_select`, and `sys_epoll_wait` to sleep on
/// multiple fds simultaneously. When any source becomes ready it wakes
/// the aggregate queue, which wakes the sleeping task. The task then
/// re-checks all sources to build the result set.
///
/// This is the kernel equivalent of Linux's `poll_table` /
/// `wait_queue_entry_t` forwarding mechanism.
///
/// ## Usage
///
/// ```rust
/// let mut table = PollTable::new();
/// for src in sources.iter() {
///     table.register(src.as_ref());
/// }
/// table.aggregate_wq.wait(POLLIN, Some(&cancel), deadline);
/// // then re-poll all sources
/// ```
pub struct PollTable {
    pub aggregate_wq: WaitQueue,
    registered:       alloc::vec::Vec<*const WaitQueue>,
    task_id:          usize,
}

// SAFETY: PollTable is used exclusively by one task. The raw pointers point
// to WaitQueues owned by Arc<dyn PollSource> with lifetimes longer than the
// PollTable (they live in the fd table).
unsafe impl Send for PollTable {}
unsafe impl Sync for PollTable {}

impl PollTable {
    pub fn new() -> Self {
        Self {
            aggregate_wq: WaitQueue::new(),
            registered:   alloc::vec::Vec::new(),
            task_id:      crate::proc::scheduler::current_pid(),
        }
    }

    /// Register `src`'s wait queue as a forwarder to this table's aggregate
    /// queue. When `src` fires, this task is woken.
    pub fn register(&mut self, src: &dyn PollSource, interest: ReadyMask) {
        let wq = src.wait_queue() as *const WaitQueue;
        src.wait_queue().register_forwarder(self.task_id, interest);
        self.registered.push(wq);
    }
}

impl Drop for PollTable {
    fn drop(&mut self) {
        for wq_ptr in self.registered.drain(..) {
            // SAFETY: pointers are valid for the duration of the PollTable.
            unsafe { (*wq_ptr).remove_forwarder(self.task_id); }
        }
    }
}
