//! Unified kernel cancellation token.
//!
//! Every wait path accepts an `Option<&CancellationToken>`. Cancellation
//! sources — signals, fd close, task exit, explicit cancel — all funnel
//! through this single type instead of each subsystem having its own
//! "interrupted" flag.
//!
//! ## Usage
//!
//! ```rust
//! // In Pcb (one token per task):
//! pub cancel_token: CancellationToken,
//!
//! // Signal delivery:
//! pcb.cancel_token.cancel(CancelReason::Signal);
//! pcb.cancel_token.wake_waiter();   // optional fast-path nudge
//!
//! // Blocking syscall:
//! let cancel = current_task_cancel_token();
//! match wq.wait(POLLIN, Some(cancel), deadline) {
//!     WakeReason::Cancelled => {
//!         cancel.reset();
//!         return -EINTR;
//!     }
//!     _ => { … }
//! }
//! ```
//!
//! ## Replaces
//!
//! | Old mechanism                          | New call                                    |
//! |----------------------------------------|---------------------------------------------|
//! | `futex_clear_pid(pid)` on exit         | `pcb.cancel_token.cancel(Exit)`             |
//! | `cancel_timer(tid)` in nanosleep       | handled internally by `WaitQueue::wait`     |
//! | `has_pending_signal()` in wait.rs      | `pcb.cancel_token.cancel(Signal)` from delivery |
//! | EPIPE / fd-close races in pipe         | `pipe.cancel_token.cancel(Closed)` on close |

use core::sync::atomic::{AtomicU32, Ordering};

/// The reason a `CancellationToken` was fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CancelReason {
    Signal    = 1,
    Timeout   = 2,
    Closed    = 3,
    TaskExit  = 4,
    Explicit  = 5,
}

impl CancelReason {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Signal),
            2 => Some(Self::Timeout),
            3 => Some(Self::Closed),
            4 => Some(Self::TaskExit),
            5 => Some(Self::Explicit),
            _ => None,
        }
    }

    /// Map to the standard POSIX errno to return to userspace.
    pub fn errno(self) -> isize {
        match self {
            Self::Signal   => -4,   // EINTR
            Self::Timeout  => -110, // ETIMEDOUT
            Self::Closed   => -32,  // EPIPE
            Self::TaskExit => -4,   // EINTR
            Self::Explicit => -125, // ECANCELED
        }
    }
}

/// A per-task (or per-operation) atomic cancellation flag.
///
/// Zero means "not cancelled". Non-zero encodes a [`CancelReason`].
pub struct CancellationToken {
    state: AtomicU32,
}

impl CancellationToken {
    pub const fn new() -> Self {
        Self { state: AtomicU32::new(0) }
    }

    /// Fire the token with the given reason.
    ///
    /// After this call any `WaitQueue::wait` holding a reference to this
    /// token will return `WakeReason::Cancelled` on the next scheduler
    /// wakeup. The caller should also call `wake_pid` on the waiting task
    /// (signal delivery already does this).
    pub fn cancel(&self, reason: CancelReason) {
        // Only set if not already cancelled (first writer wins).
        let _ = self.state.compare_exchange(
            0,
            reason as u32,
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }

    /// Returns `true` if the token has been cancelled for any reason.
    #[inline]
    pub fn is_cancelled(&self) -> bool {
        self.state.load(Ordering::Acquire) != 0
    }

    /// Returns the cancellation reason, if set.
    #[inline]
    pub fn reason(&self) -> Option<CancelReason> {
        CancelReason::from_u32(self.state.load(Ordering::Acquire))
    }

    /// Map the reason to its errno, or 0 if not cancelled.
    #[inline]
    pub fn errno(&self) -> isize {
        self.reason().map(|r| r.errno()).unwrap_or(0)
    }

    /// Reset the token (must be called before the next blocking operation).
    #[inline]
    pub fn reset(&self) {
        self.state.store(0, Ordering::Release);
    }
}
