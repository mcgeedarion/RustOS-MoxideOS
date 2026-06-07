// src/io_uring/cqe.rs

use crate::io_uring::IoUringError;

/// One entry in the completion queue.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Cqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

impl Cqe {
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
