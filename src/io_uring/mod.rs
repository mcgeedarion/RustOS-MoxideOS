// src/io_uring/mod.rs
// io_uring subsystem for RustOS.
// The implementation lives in ring.rs (per-ring structs, global ring table,
// WaitQueue-based wakeup) and syscall.rs (sys_io_uring_setup / _enter /
// _register). This file re-exports the public surface and owns the shared error
// type.

pub mod cqe;
pub mod ops;
pub mod ring;
pub mod ring_buf;
pub mod ring_pub;
pub mod scheduler_integration;
pub mod sqe;
pub mod syscall;

pub use ring::{
    alloc_ring, cq_wq_for, free_ring, init, ring_idx_for_fd, with_ring, with_ring_mut, IoUringCqe,
    IoUringParams, IoUringRing, IoUringSqe,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoUringError {
    /// The submission queue is full; caller should poll completions first.
    SqFull,
    /// The completion queue overflowed (entries were dropped).
    CqOverflow,
    /// An SQE contained an unsupported or unknown opcode.
    UnknownOpcode(u8),
    /// The operation resulted in an OS-level error (negated errno).
    OsError(i32),
    /// Ring index is invalid or not yet initialised.
    InvalidRing,
}

/// Compatibility namespace for callers that probe epoll-backed io_uring fds.
pub mod epoll {
    pub fn is_epoll_fd(_fd: usize) -> bool {
        false
    }
}
