// src/io_uring/cqe.rs
// Completion Queue Entry (CQE).
// Linux io_uring_cqe layout: { user_data: u64, res: i32, flags: u32 }
// We carry that layout verbatim so it is compatible with any future
// pass-through to a real kernel.

use crate::io_uring::IoUringError;

/// One entry in the completion queue.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Cqe {
    /// Token echoed from the matching SQE — keys the waker table.
    pub user_data: u64,

    /// Result of the operation.
    ///
    /// Non-negative → success, value is operation-specific (bytes
    /// transferred, new fd from accept, 0 for connect/close, …).
    /// Negative → negated errno (e.g. -EAGAIN = -11, -ECONNREFUSED = -111).
    pub res: i32,

    /// CQE flags (IORING_CQE_F_*).  Currently unused; always 0.
    pub flags: u32,
}

impl Cqe {
    /// Return a zero-initialised CQE (const so it can seed static arrays).
    #[inline]
    pub const fn zeroed() -> Self {
        Cqe {
            user_data: 0,
            res: 0,
            flags: 0,
        }
    }

    /// Returns `Ok(res as usize)` for success, or maps the negated errno to
    /// an `IoUringError` for failure.
    #[inline]
    pub fn result(&self) -> Result<usize, IoUringError> {
        if self.res >= 0 {
            Ok(self.res as usize)
        } else {
            Err(IoUringError::OsError(self.res))
        }
    }

    /// Returns the raw `res` field without interpretation.
    #[inline]
    pub fn raw_result(&self) -> i32 {
        self.res
    }

    /// True when the `res` field indicates the operation would block
    /// (EAGAIN / EWOULDBLOCK = -11).
    #[inline]
    pub fn would_block(&self) -> bool {
        self.res == -11
    }

    /// True when the operation succeeded.
    #[inline]
    pub fn is_ok(&self) -> bool {
        self.res >= 0
    }
}

// Negated Linux errno values most relevant to network / file I/O.
// Prefixed `E_` to avoid collision with any future `std::io::ErrorKind` mirror.

pub mod errno {
    pub const E_AGAIN: i32 = -11; // EAGAIN / EWOULDBLOCK
    pub const E_INTR: i32 = -4; // EINTR
    pub const E_INVAL: i32 = -22; // EINVAL
    pub const E_BADF: i32 = -9; // EBADF
    pub const E_NOBUFS: i32 = -105; // ENOBUFS
    pub const E_CONNREFUSED: i32 = -111; // ECONNREFUSED
    pub const E_CONNRESET: i32 = -104; // ECONNRESET
    pub const E_TIMEDOUT: i32 = -110; // ETIMEDOUT
    pub const E_ADDRINUSE: i32 = -98; // EADDRINUSE
    pub const E_PIPE: i32 = -32; // EPIPE
    pub const E_NOMEM: i32 = -12; // ENOMEM
    pub const E_NOSYS: i32 = -38; // ENOSYS (opcode not implemented)
}
