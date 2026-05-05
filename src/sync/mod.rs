//! Kernel synchronisation primitives.
//!
//! ## Contents
//!
//! - `futex`: sleep/wake wait-queue table backing the `futex(2)` syscall.
//!   This is the core primitive that musl pthreads, malloc, and condvars
//!   all depend on.  See `futex.rs` for the full design commentary.

pub mod futex;
