// src/io_uring/token.rs

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
