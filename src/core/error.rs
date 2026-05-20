//! Kernel-wide error type.
//!
//! [`KernelError`] is the single error enum that all kernel subsystems
//! should return.  Using one type avoids the "error tower" problem where
//! every layer defines its own error and callers must `.map_err` at every
//! boundary.
//!
//! The variants are coarse-grained on purpose: fine-grained context lives
//! in the call-site log or in the debug payload carried by some variants.

use core::fmt;

/// Top-level kernel error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KernelError {
    // ── Resource errors ──────────────────────────────────────────────────
    /// Physical or virtual memory exhausted.
    OutOfMemory,
    /// Address is not aligned to the required boundary.
    BadAlignment,
    /// Address or range falls outside a valid region.
    BadAddress,
    /// Integer or pointer arithmetic would overflow.
    Overflow,

    // ── Argument / permission errors ─────────────────────────────────────
    /// Caller supplied an invalid argument.
    InvalidArgument,
    /// Operation is not permitted for the calling context.
    PermissionDenied,
    /// The requested resource does not exist.
    NotFound,
    /// The resource already exists.
    AlreadyExists,

    // ── Device / I/O errors ───────────────────────────────────────────────
    /// An underlying hardware or firmware operation failed.
    IoError,
    /// A device is not ready or not present.
    DeviceNotReady,
    /// A timeout elapsed before the operation completed.
    Timeout,

    // ── Concurrency errors ────────────────────────────────────────────────
    /// A lock or resource is currently held by another owner.
    WouldBlock,
    /// A deadlock was detected or is imminent.
    Deadlock,

    // ── State / protocol errors ───────────────────────────────────────────
    /// The subsystem or object has not been initialised yet.
    NotInitialised,
    /// An operation was attempted in an invalid state.
    InvalidState,
    /// Internal kernel invariant violated (should trigger a panic in debug).
    InternalError,

    // ── POSIX errno shim ──────────────────────────────────────────────────
    /// Wrap a raw POSIX errno for syscall return paths.
    Errno(i32),
}

impl KernelError {
    /// Convert to a negative POSIX errno value suitable for a syscall return.
    #[inline]
    pub const fn to_errno(self) -> i64 {
        match self {
            Self::OutOfMemory       => -12,  // ENOMEM
            Self::BadAlignment      => -22,  // EINVAL
            Self::BadAddress        => -14,  // EFAULT
            Self::Overflow          => -75,  // EOVERFLOW
            Self::InvalidArgument   => -22,  // EINVAL
            Self::PermissionDenied  => -1,   // EPERM
            Self::NotFound          => -2,   // ENOENT
            Self::AlreadyExists     => -17,  // EEXIST
            Self::IoError           => -5,   // EIO
            Self::DeviceNotReady    => -6,   // ENXIO
            Self::Timeout           => -110, // ETIMEDOUT
            Self::WouldBlock        => -11,  // EAGAIN
            Self::Deadlock          => -35,  // EDEADLK
            Self::NotInitialised    => -22,  // EINVAL
            Self::InvalidState      => -22,  // EINVAL
            Self::InternalError     => -5,   // EIO  (generic)
            Self::Errno(e)          => -(e as i64),
        }
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfMemory      => write!(f, "out of memory"),
            Self::BadAlignment     => write!(f, "bad alignment"),
            Self::BadAddress       => write!(f, "bad address"),
            Self::Overflow         => write!(f, "arithmetic overflow"),
            Self::InvalidArgument  => write!(f, "invalid argument"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::NotFound         => write!(f, "not found"),
            Self::AlreadyExists    => write!(f, "already exists"),
            Self::IoError          => write!(f, "I/O error"),
            Self::DeviceNotReady   => write!(f, "device not ready"),
            Self::Timeout          => write!(f, "timeout"),
            Self::WouldBlock       => write!(f, "would block"),
            Self::Deadlock         => write!(f, "deadlock"),
            Self::NotInitialised   => write!(f, "not initialised"),
            Self::InvalidState     => write!(f, "invalid state"),
            Self::InternalError    => write!(f, "internal kernel error"),
            Self::Errno(e)         => write!(f, "errno {e}"),
        }
    }
}

/// Convenience alias — every subsystem `use crate::core::KResult`.
pub type KResult<T> = Result<T, KernelError>;
