//! Errno constants and conversion helpers for the syscall layer.
//!
//! The kernel is no_std and does not link libc, so we define the errno
//! values used in the syscall dispatcher directly.  All constants are
//! `i32` (the POSIX type) because that is what negative isize return
//! values are derived from.
//!
//! ## Usage
//!
//! ```rust
//! use crate::syscall::errno::{EINVAL, EFAULT, efault, einval};
//!
//! // As a literal:
//! return -(EINVAL as isize);
//!
//! // Via the convenience helper (preferred in dispatch code):
//! return efault();
//! ```

// ── Standard POSIX errno values ─────────────────────────────────────────────
pub const EPERM:    i32 = 1;
pub const ENOENT:   i32 = 2;
pub const ESRCH:    i32 = 3;
pub const EINTR:    i32 = 4;
pub const EIO:      i32 = 5;
pub const EBADF:    i32 = 9;
pub const ENOMEM:   i32 = 12;
pub const EFAULT:   i32 = 14;
pub const EBUSY:    i32 = 16;
pub const ENODEV:   i32 = 19;
pub const EINVAL:   i32 = 22;
pub const ENOSPC:   i32 = 28;
pub const EPIPE:    i32 = 32;
pub const EMSGSIZE: i32 = 90;
pub const ENOSYS:   i32 = 38;
pub const EOVERFLOW: i32 = 75;

// ── Convenience isize helpers (used in dispatch return positions) ─────────
//
// These inline functions avoid the repetitive `-(EXXX as isize)` cast
// pattern throughout the dispatcher.  Each is named after its errno.

#[inline(always)]
pub const fn eperm()    -> isize { -(EPERM    as isize) }
#[inline(always)]
pub const fn efault()   -> isize { -(EFAULT   as isize) }
#[inline(always)]
pub const fn einval()   -> isize { -(EINVAL   as isize) }
#[inline(always)]
pub const fn enosys()   -> isize { -(ENOSYS   as isize) }
#[inline(always)]
pub const fn enomem()   -> isize { -(ENOMEM   as isize) }
#[inline(always)]
pub const fn emsgsize() -> isize { -(EMSGSIZE as isize) }
#[inline(always)]
pub const fn ebadf()    -> isize { -(EBADF    as isize) }
