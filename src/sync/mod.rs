//! Kernel synchronisation primitives.
//!
//! ## Contents
//!
//! - `futex`:    sleep/wake wait-queue table backing the `futex(2)` syscall.
//! - `mutex`:    simple kernel mutex (placeholder).
//! - `spinlock`: raw spinlock (placeholder).

pub mod futex;
pub mod mutex;
pub mod spinlock;
