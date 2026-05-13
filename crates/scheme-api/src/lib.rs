//! scheme-api — shared types for the RustOS scheme-based VFS.
//!
//! This crate is `no_std` so it can be linked into both the kernel
//! (which has no std) and userspace driver binaries (which may opt in
//! to std via the `std` feature flag).
//!
//! # Scheme URL model
//!
//! Every resource in RustOS is addressed as `<scheme>:<path>`, e.g.:
//!   - `file:/etc/passwd`
//!   - `blk:vda`          (virtio-blk block device)
//!   - `net:eth0`         (virtio-net / e1000e NIC)
//!   - `tcp:10.0.0.1:80`  (TCP connection, handled by in-kernel net stack)
//!   - `tty:0`            (serial/tty)
//!   - `proc:1234/maps`   (in-kernel procfs)

#![no_std]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Core identifiers
// ---------------------------------------------------------------------------

/// Opaque handle returned by `sys_driver_bind`.  Kernel-assigned, process-local.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct DriverHandle(pub u64);

/// Opaque endpoint token that the kernel uses to deliver IRQ notifications
/// and to forward scheme requests to a userspace scheme server.
/// Created by `sys_ipc_endpoint_create` and passed to `sys_irq_subscribe`
/// or `sys_scheme_register`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct IpcEndpoint(pub u64);

/// Per-scheme file-descriptor token.  Scheme servers hand these back in
/// response to `SchemeRequest::Open`; the kernel stores them in the
/// per-process fd table alongside the owning scheme's endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SchemeFileId(pub u64);

// ---------------------------------------------------------------------------
// Open flags (subset sufficient for drivers; extend as needed)
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct OpenFlags: u32 {
        const READ      = 1 << 0;
        const WRITE     = 1 << 1;
        const NONBLOCK  = 1 << 2;
        const CREATE    = 1 << 3;
        const TRUNCATE  = 1 << 4;
    }
}

// ---------------------------------------------------------------------------
// IPC message types
// ---------------------------------------------------------------------------

/// A request sent from the kernel (on behalf of a user process) to a
/// userspace scheme server over its `IpcEndpoint`.
#[derive(Debug)]
pub enum SchemeRequest {
    /// Open `path` with `flags`; returns `SchemeFileId` on success.
    Open {
        path: String,
        flags: OpenFlags,
    },
    /// Read up to `len` bytes from `fd`.
    Read {
        fd: SchemeFileId,
        len: usize,
    },
    /// Write `data` to `fd`.
    Write {
        fd: SchemeFileId,
        data: Vec<u8>,
    },
    /// Device-specific control command.
    Ioctl {
        fd: SchemeFileId,
        cmd: u64,
        arg: usize,
    },
    /// Seek to `offset` relative to `whence`.
    Seek {
        fd: SchemeFileId,
        offset: i64,
        whence: SeekWhence,
    },
    /// Close `fd` and release driver-side resources.
    Close {
        fd: SchemeFileId,
    },
}

/// Response from the scheme server back to the kernel.
#[derive(Debug)]
pub enum SchemeResponse {
    /// Newly-opened file handle.
    Fd(SchemeFileId),
    /// Data payload (answer to `Read`).
    Data(Vec<u8>),
    /// Byte count written / ioctl result.
    Count(usize),
    /// Seek position after the operation.
    SeekPos(i64),
    /// Success with no payload.
    Ok,
    /// Scheme-level error.
    Err(SchemeError),
}

/// Notification posted to a driver process when its subscribed IRQ fires.
#[derive(Debug, Clone, Copy)]
pub struct IrqNotification {
    /// IRQ number that fired.
    pub irq: u32,
    /// Monotonic timestamp (nanoseconds since boot) of the interrupt.
    pub timestamp_ns: u64,
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SchemeError {
    /// Path / scheme prefix not found.
    NoSuchScheme     = 1,
    /// File or resource within the scheme not found.
    NotFound         = 2,
    /// Caller lacks required capability.
    PermissionDenied = 3,
    /// Invalid argument.
    InvalidArg       = 4,
    /// Resource is temporarily unavailable (try again).
    WouldBlock       = 5,
    /// I/O error.
    Io               = 6,
    /// Scheme server is not responding.
    Unreachable      = 7,
    /// Catch-all.
    Other            = 255,
}

impl core::fmt::Display for SchemeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoSuchScheme     => write!(f, "no such scheme"),
            Self::NotFound         => write!(f, "not found"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::InvalidArg       => write!(f, "invalid argument"),
            Self::WouldBlock       => write!(f, "would block"),
            Self::Io               => write!(f, "I/O error"),
            Self::Unreachable      => write!(f, "scheme server unreachable"),
            Self::Other            => write!(f, "unknown scheme error"),
        }
    }
}

// ---------------------------------------------------------------------------
// Seek whence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SeekWhence {
    Start   = 0,
    Current = 1,
    End     = 2,
}

// ---------------------------------------------------------------------------
// URL parsing helper
// ---------------------------------------------------------------------------

/// Split `"scheme:path"` into `("scheme", "path")`.
///
/// Returns `None` if there is no `:` separator.  The path portion may be
/// empty (e.g. `"blk:"` is valid and means the root of the blk scheme).
pub fn parse_scheme_url(url: &str) -> Option<(&str, &str)> {
    url.split_once(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normal_url() {
        let (scheme, path) = parse_scheme_url("file:/etc/os-release").unwrap();
        assert_eq!(scheme, "file");
        assert_eq!(path, "/etc/os-release");
    }

    #[test]
    fn parse_bare_scheme() {
        let (scheme, path) = parse_scheme_url("blk:").unwrap();
        assert_eq!(scheme, "blk");
        assert_eq!(path, "");
    }

    #[test]
    fn parse_missing_colon() {
        assert!(parse_scheme_url("nocolon").is_none());
    }
}
