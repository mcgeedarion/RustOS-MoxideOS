// src/io_uring/token.rs
//
// Monotonic token allocator.
//
// Every submitted SQE needs a unique u64 `user_data` so the waker table
// can map the matching CQE back to the correct Future.
//
// We use a simple fetch-and-increment counter.  The counter wraps at u64::MAX
// (practically never in a kernel context).  Token 0 is reserved for "no token"
// so callers can use it as a sentinel.

use core::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// Allocate the next unique token.
#[inline]
pub fn next() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Peek at the next token without consuming it (useful for tests).
#[inline]
pub fn peek() -> u64 {
    COUNTER.load(Ordering::Relaxed)
}
