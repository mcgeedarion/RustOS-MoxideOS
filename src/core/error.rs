//! Kernel-wide error type.

use core::fmt;

/// Top-level kernel error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KernelError {
    /// Physical or virtual memory exhausted.
    OutOfMemory,
    BadAlignment,
    BadAddress,
    Overflow,

    /// Caller supplied an invalid argument.
    InvalidArgument,
    PermissionDenied,
    NotFound,
    AlreadyExists,

    /// An underlying hardware or firmware operation failed.
    IoError,
    DeviceNotReady,
    Timeout,

    /// A lock or resource is currently held by another owner.
    WouldBlock,
    Deadlock,

    /// The subsystem or object has not been initialised yet.
    NotInitialised,
    InvalidState,
    InternalError,

    /// Wrap a raw POSIX errno for syscall return paths.
    Errno(i32),
}

impl KernelError {
    /// Convert to a negative POSIX errno value suitable for a syscall return.
    #[inline]
    pub const fn to_errno(self) -> i64 {
        match self {
            Self::OutOfMemory => -12,     // ENOMEM
            Self::BadAlignment => -22,    // EINVAL
            Self::BadAddress => -14,      // EFAULT
            Self::Overflow => -75,        // EOVERFLOW
            Self::InvalidArgument => -22, // EINVAL
            Self::PermissionDenied => -1, // EPERM
            Self::NotFound => -2,         // ENOENT
            Self::AlreadyExists => -17,   // EEXIST
            Self::IoError => -5,          // EIO
            Self::DeviceNotReady => -6,   // ENXIO
            Self::Timeout => -110,        // ETIMEDOUT
            Self::WouldBlock => -11,      // EAGAIN
            Self::Deadlock => -35,        // EDEADLK
            Self::NotInitialised => -22,  // EINVAL
            Self::InvalidState => -22,    // EINVAL
            Self::InternalError => -5,    // EIO  (generic)
            Self::Errno(e) => -(e as i64),
        }
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::BadAlignment => write!(f, "bad alignment"),
            Self::BadAddress => write!(f, "bad address"),
            Self::Overflow => write!(f, "arithmetic overflow"),
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::NotFound => write!(f, "not found"),
            Self::AlreadyExists => write!(f, "already exists"),
            Self::IoError => write!(f, "I/O error"),
            Self::DeviceNotReady => write!(f, "device not ready"),
            Self::Timeout => write!(f, "timeout"),
            Self::WouldBlock => write!(f, "would block"),
            Self::Deadlock => write!(f, "deadlock"),
            Self::NotInitialised => write!(f, "not initialised"),
            Self::InvalidState => write!(f, "invalid state"),
            Self::InternalError => write!(f, "internal kernel error"),
            Self::Errno(e) => write!(f, "errno {e}"),
        }
    }
}

/// Convenience alias — every subsystem `use crate::core::KResult`.
pub type KResult<T> = Result<T, KernelError>;
