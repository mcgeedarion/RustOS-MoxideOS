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

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const ESRCH: i32 = 3;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const EACCES: i32 = 13;
pub const EBADF: i32 = 9;
pub const ECHILD: i32 = 10;
pub const ENOMEM: i32 = 12;
pub const EFAULT: i32 = 14;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const ENODEV: i32 = 19;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const ENFILE: i32 = 23;
pub const EMFILE: i32 = 24;
pub const ENOSPC: i32 = 28;
pub const EPIPE: i32 = 32;
pub const ERANGE: i32 = 34;
pub const ENOSYS: i32 = 38;
pub const EMSGSIZE: i32 = 90;
pub const EOVERFLOW: i32 = 75;
pub const ENOTSUP: i32 = 95;

// These inline functions avoid the repetitive `-(EXXX as isize)` cast
// pattern throughout the dispatcher.  Each is named after its errno.

#[inline(always)]
pub const fn eperm() -> isize {
    -(EPERM as isize)
}
#[inline(always)]
pub const fn enoent() -> isize {
    -(ENOENT as isize)
}
#[inline(always)]
pub const fn esrch() -> isize {
    -(ESRCH as isize)
}
#[inline(always)]
pub const fn eio() -> isize {
    -(EIO as isize)
}
#[inline(always)]
pub const fn eacces() -> isize {
    -(EACCES as isize)
}
#[inline(always)]
pub const fn ebadf() -> isize {
    -(EBADF as isize)
}
#[inline(always)]
pub const fn enomem() -> isize {
    -(ENOMEM as isize)
}
#[inline(always)]
pub const fn efault() -> isize {
    -(EFAULT as isize)
}
#[inline(always)]
pub const fn einval() -> isize {
    -(EINVAL as isize)
}
#[inline(always)]
pub const fn erange() -> isize {
    -(ERANGE as isize)
}
#[inline(always)]
pub const fn enosys() -> isize {
    -(ENOSYS as isize)
}
#[inline(always)]
pub const fn emsgsize() -> isize {
    -(EMSGSIZE as isize)
}
#[inline(always)]
pub const fn enotsup() -> isize {
    -(ENOTSUP as isize)
}
