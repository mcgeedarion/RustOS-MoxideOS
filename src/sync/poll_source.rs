//! PollSource — the single readiness abstraction.
//!
//! Every waitable kernel object implements this trait, replacing the
//! `if pipe … if socket … if eventfd …` dispatch chain in `fs::poll::fd_ready`.
//!
//! # Pattern
//!
//! ```text
//! blocking syscall
//!         |
//!         v
//! wait_on(fd.poll_source(), mask, cancel, deadline)
//!         |
//!         v
//! src.poll(mask)              ← lock-free readiness check
//!         |
//!   if 0  v
//! src.wait_queue().wait(...)  ← one scheduler sleep
//! ```
//!
//! Implementors: pipe, socket, eventfd, timerfd, tty/input, io_uring CQ,
//! pidfd (process exit), futex wait-queues.

extern crate alloc;
use crate::sync::wait_queue::{CancellationToken, ReadyMask, WaitQueue, WakeReason};
use alloc::sync::Arc;
use alloc::vec::Vec;

pub trait PollSource: Send + Sync {
    /// Return the immediately-ready subset of `interest`. Must not block.
    /// Called lock-free from IRQ-safe context.
    fn poll(&self, interest: ReadyMask) -> ReadyMask;

    /// The WaitQueue to sleep on when `poll()` returns 0.
    fn wait_queue(&self) -> &WaitQueue;
}

/// Block until `src` has bits matching `interest`, deadline, or cancel.
///
/// Returns `(ready_bits, reason)`.
/// On Timeout or Cancelled, ready_bits is 0.
///
/// This is the canonical entry point for all blocking read/write/accept/etc.
pub fn wait_on(
    src: &dyn PollSource,
    interest: ReadyMask,
    cancel: Option<&CancellationToken>,
    deadline: Option<u64>,
) -> (ReadyMask, WakeReason) {
    loop {
        let ready = src.poll(interest);
        if ready != 0 {
            return (ready, WakeReason::Ready);
        }
        let reason = src.wait_queue().wait(interest, cancel, deadline);
        match reason {
            // Re-check poll() — guards against spurious wakeups and the
            // case where two tasks race to consume the same readiness event.
            WakeReason::Ready => continue,
            WakeReason::Timeout => return (0, WakeReason::Timeout),
            WakeReason::Cancelled => return (0, WakeReason::Cancelled),
        }
    }
}

/// Sleep until ANY of `sources` has ready bits matching its mask.
///
/// Used by `sys_poll`, `sys_select`, `sys_epoll_wait` to watch N fds with
/// exactly one scheduler sleep instead of a busy-poll loop.
///
/// Each element is `(source, interest_mask)`.
/// Returns as soon as any source fires, times out, or is cancelled.
pub fn wait_any(
    sources: &[(Arc<dyn PollSource>, ReadyMask)],
    cancel: Option<&CancellationToken>,
    deadline: Option<u64>,
) -> WakeReason {
    if sources.is_empty() {
        // Pure timeout wait (e.g. poll(NULL, 0, timeout_ms)).
        let agg = WaitQueue::new();
        return agg.wait(0, cancel, deadline);
    }

    // 1. Check all sources without blocking.
    for (src, mask) in sources {
        if src.poll(*mask) != 0 {
            return WakeReason::Ready;
        }
    }

    // 2. Build one shared aggregate WaitQueue. All source WaitQueues forward their
    //    wakeups here.
    let agg = WaitQueue::new();

    // 3. Register forwarder on every source's WaitQueue.
    let aggregate_mask: ReadyMask = sources.iter().fold(0, |acc, (_, m)| acc | m);
    for (src, mask) in sources {
        src.wait_queue().register_forwarder(&agg, *mask);
    }

    // 4. ONE scheduler sleep.
    let reason = agg.wait(aggregate_mask, cancel, deadline);

    // 5. Remove forwarders — must always run, even on cancel/timeout.
    for (src, _) in sources {
        src.wait_queue().remove_forwarder(&agg);
    }

    reason
}

/// PollSource for objects that are always readable and writable
/// (regular VFS files, devfs nodes).
/// Never blocks; wait_queue() is a no-op queue that is never slept on.
pub struct AlwaysReady {
    wq: WaitQueue,
}

impl AlwaysReady {
    pub const fn new() -> Self {
        Self {
            wq: WaitQueue::new(),
        }
    }
}

impl PollSource for AlwaysReady {
    fn poll(&self, interest: ReadyMask) -> ReadyMask {
        use crate::fs::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
        let mut r = 0;
        if interest & (POLLIN | POLLRDNORM) != 0 {
            r |= POLLIN | POLLRDNORM;
        }
        if interest & (POLLOUT | POLLWRNORM) != 0 {
            r |= POLLOUT | POLLWRNORM;
        }
        r
    }
    fn wait_queue(&self) -> &WaitQueue {
        &self.wq
    }
}
