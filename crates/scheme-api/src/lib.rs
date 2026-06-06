//! `scheme-api` — types shared between the kernel and userspace driver
//! processes.
//!
//! This crate is `no_std` by default so it can be linked into the kernel.
//! Enable the `std` feature for userspace consumers and host-side tests.
//!
//! # Overview
//!
//! A *scheme* is a named resource namespace, accessed via URLs of the form
//! `scheme:path`.  The kernel's `SchemeTable` routes `open`/`read`/`write`
//! calls to the appropriate handler.  For in-kernel schemes the handler is a
//! native Rust struct; for userspace drivers it is an `IpcProxyScheme` that
//! forwards these `SchemeRequest` messages over an `IpcEndpoint`.

#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use bitflags::bitflags;

/// A scheme-local file handle.  Opaque to the kernel; meaning is defined
/// by each individual scheme handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SchemeFileId(pub u64);

/// A kernel IPC endpoint handle.  Kernel-allocated; identifies a message
/// queue that can be passed across process boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct IpcEndpoint(pub u64);

/// Authorisation token returned by `sys_driver_bind`.  Encodes (pid, bdf)
/// so the kernel can validate ownership without a table lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DriverHandle(pub u64);

bitflags! {
    /// Flags for the `open` system call / scheme `open` method.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OpenFlags: u32 {
        const READ       = 0b0000_0001;
        const WRITE      = 0b0000_0010;
        const CREATE     = 0b0000_0100;
        const TRUNCATE   = 0b0000_1000;
        const APPEND     = 0b0001_0000;
        const NON_BLOCK  = 0b0010_0000;
        const DIRECTORY  = 0b0100_0000;
        const EXCLUSIVE  = 0b1000_0000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SeekWhence {
    /// Seek from the start of the resource.
    Start = 0,
    /// Seek relative to the current position.
    Current = 1,
    /// Seek from the end.
    End = 2,
}

/// Error codes returned by scheme handlers and propagated back to callers
/// as errno values by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SchemeError {
    /// No scheme registered under this name.
    NoSuchScheme = 1,
    /// The requested path does not exist within the scheme.
    NotFound = 2,
    /// Caller lacks permission.
    PermissionDenied = 3,
    /// An argument was invalid (bad offset, null pointer, etc.).
    InvalidArg = 4,
    /// The operation would block and `O_NONBLOCK` was set.
    WouldBlock = 5,
    /// Generic I/O error.
    Io = 6,
    /// The driver process has exited or is unreachable.
    Unreachable = 7,
    /// Any other unclassified error.
    Other = 0xFF,
}

impl SchemeError {
    /// Convert to a POSIX-compatible negative errno value.
    pub fn to_errno(self) -> i64 {
        match self {
            SchemeError::NoSuchScheme => -2,      // ENOENT
            SchemeError::NotFound => -2,          // ENOENT
            SchemeError::PermissionDenied => -13, // EACCES
            SchemeError::InvalidArg => -22,       // EINVAL
            SchemeError::WouldBlock => -11,       // EAGAIN
            SchemeError::Io => -5,                // EIO
            SchemeError::Unreachable => -111,     // ECONNREFUSED
            SchemeError::Other => -1,             // EPERM
        }
    }
}

/// A request sent *from* the kernel proxy *to* a userspace driver scheme.
#[derive(Debug)]
pub enum SchemeRequest {
    Open {
        path: String,
        flags: OpenFlags,
    },
    Read {
        fd: SchemeFileId,
        len: usize,
    },
    Write {
        fd: SchemeFileId,
        data: Vec<u8>,
    },
    Ioctl {
        fd: SchemeFileId,
        cmd: u64,
        arg: usize,
    },
    Seek {
        fd: SchemeFileId,
        offset: i64,
        whence: SeekWhence,
    },
    Close {
        fd: SchemeFileId,
    },
}

/// A response sent *from* the userspace driver *to* the kernel proxy.
#[derive(Debug)]
pub enum SchemeResponse {
    /// `open` succeeded; carries the driver-local file id.
    Fd(SchemeFileId),
    /// `read` succeeded; carries the raw bytes.
    Data(Vec<u8>),
    /// `write` / `ioctl` succeeded; carries the count/return value.
    Count(usize),
    /// `seek` succeeded; carries the new file position.
    SeekPos(i64),
    /// Generic success (e.g. `close`).
    Ok,
    /// The operation failed.
    Err(SchemeError),
}

/// Message posted to a driver's IPC endpoint when its subscribed IRQ fires.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IrqNotification {
    /// Sentinel byte `0xFF` distinguishing IRQ notifications from scheme
    /// requests (whose first byte is always < `0x80`).
    pub tag: u8,
    pub irq: u32,
    pub timestamp_ns: u64,
}

/// Parse a scheme URL of the form `"scheme:path"` and return
/// `Some((scheme, path))`, or `None` if the input is not a scheme URL.
///
/// The scheme part must be non-empty; the path part may be empty.
///
/// ```
/// # use scheme_api::parse_scheme_url;
/// assert_eq!(parse_scheme_url("blk:vda"),     Some(("blk", "vda")));
/// assert_eq!(parse_scheme_url("net:"),         Some(("net", "")));
/// assert_eq!(parse_scheme_url("/etc/passwd"),  None);
/// assert_eq!(parse_scheme_url("nocolon"),      None);
/// ```
pub fn parse_scheme_url(url: &str) -> Option<(&str, &str)> {
    if url.starts_with('/') {
        return None;
    }
    let (scheme, path) = url.split_once(':')?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return None;
    }
    Some((scheme, path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trip() {
        assert_eq!(parse_scheme_url("file:/etc"), Some(("file", "/etc")));
        assert_eq!(parse_scheme_url("blk:"), Some(("blk", "")));
        assert_eq!(parse_scheme_url("/dev/null"), None);
        assert_eq!(parse_scheme_url(""), None);
    }

    #[test]
    fn open_flags_round_trip() {
        let f = OpenFlags::READ | OpenFlags::WRITE;
        assert!(f.contains(OpenFlags::READ));
        assert!(f.contains(OpenFlags::WRITE));
        assert!(!f.contains(OpenFlags::CREATE));
    }
}
