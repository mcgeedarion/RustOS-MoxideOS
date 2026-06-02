// src/io_uring/mod.rs
// io_uring subsystem for RustOS.
// The implementation lives in ring.rs (per-ring structs, global ring table,
// WaitQueue-based wakeup) and syscall.rs (sys_io_uring_setup / _enter / _register).
// This file re-exports the public surface and owns the shared error type.

pub mod cqe;
pub mod ops;
pub mod ring;
pub mod ring_pub;
pub mod ring_buf;
pub mod sqe;
pub mod syscall;

pub use ring::{
    alloc_ring, free_ring, with_ring, with_ring_mut, cq_wq_for, ring_idx_for_fd,
    IoUringRing, IoUringSqe, IoUringCqe, IoUringParams,
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
