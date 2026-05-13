//! SchemeTable — global registry of scheme handlers.
//!
//! # What is a scheme?
//!
//! Borrowed from Redox OS.  A *scheme* is a named namespace that provides
//! resource access via a URL-like syntax:  `<scheme>:<path>`.  Examples:
//!
//! ```text
//! tcp:192.168.0.1:80   → open a TCP connection
//! blk:0/0              → block device 0, partition 0
//! tty:0                → serial console 0
//! file:/etc/passwd     → ordinary VFS file (the kernel's own driver)
//! ```
//!
//! # Registration
//!
//! Scheme drivers (kernel subsystems or future userspace servers) call
//! `SCHEME_TABLE.register(name, handler)` at init time.  `name` is the bare
//! string without the trailing colon (e.g., `"tcp"`, not `"tcp:"`).
//!
//! # Routing
//!
//! `open_url(url, flags)` strips the scheme prefix from a URL, looks up the
//! handler, and calls `handler.open(path_after_colon, flags)` →
//! `(Arc<dyn Scheme>, SchemeFileId)`.  This is used by `proc_fd_open` to
//! replace ad-hoc scheme dispatch.
//!
//! # Introspection
//!
//! `list()` returns a sorted `Vec<String>` of all registered scheme names.
//! This is consumed by `/proc/schemes` (see `procfs.rs`).

extern crate alloc;
use alloc::{
    collections::BTreeMap,
    string::String,
    sync::Arc,
    vec::Vec,
};
use spin::RwLock;

use scheme_api::{OpenFlags, SchemeError, SchemeFileId};

// ---------------------------------------------------------------------------
// Scheme trait
// ---------------------------------------------------------------------------

/// Trait that every scheme handler must implement.
///
/// Methods that a handler does not support may return `Err(SchemeError::InvalidArg)`
/// or `Err(SchemeError::Other)`.  The default implementations below do exactly
/// that so that minimal handlers only need to implement `open`, `read`, and
/// `close`.
pub trait Scheme: Send + Sync {
    /// Open the resource at `path` (the part of the URL after the colon).
    ///
    /// Returns an opaque file-ID that is passed to every subsequent I/O call.
    fn open(
        &self,
        path:  &str,
        flags: OpenFlags,
    ) -> Result<SchemeFileId, SchemeError>;

    /// Read up to `buf.len()` bytes starting at the current seek position.
    fn read(
        &self,
        fid: SchemeFileId,
        buf: &mut [u8],
    ) -> Result<usize, SchemeError> {
        let _ = (fid, buf);
        Err(SchemeError::InvalidArg)
    }

    /// Write `buf` at the current seek position.
    fn write(
        &self,
        fid: SchemeFileId,
        buf: &[u8],
    ) -> Result<usize, SchemeError> {
        let _ = (fid, buf);
        Err(SchemeError::InvalidArg)
    }

    /// Reposition the file offset.
    ///
    /// `whence` follows POSIX semantics: 0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END.
    fn seek(
        &self,
        fid:    SchemeFileId,
        offset: i64,
        whence: u8,
    ) -> Result<u64, SchemeError> {
        let _ = (fid, offset, whence);
        Err(SchemeError::InvalidArg)
    }

    /// Perform a device-specific control operation.
    fn ioctl(
        &self,
        fid: SchemeFileId,
        cmd: u64,
        arg: usize,
    ) -> Result<usize, SchemeError> {
        let _ = (fid, cmd, arg);
        Err(SchemeError::InvalidArg)
    }

    /// Release resources associated with `fid`.
    fn close(
        &self,
        fid: SchemeFileId,
    ) -> Result<(), SchemeError>;
}

// ---------------------------------------------------------------------------
// SchemeTable
// ---------------------------------------------------------------------------

pub struct SchemeTable {
    inner: RwLock<BTreeMap<String, Arc<dyn Scheme>>>,
}

impl SchemeTable {
    pub const fn new() -> Self {
        Self { inner: RwLock::new(BTreeMap::new()) }
    }

    // ── Registration ────────────────────────────────────────────────────────────

    /// Register a scheme handler under `name`.
    ///
    /// `name` must not include the trailing colon (e.g., `"tcp"`, not `"tcp:"`).
    /// Re-registering an existing name overwrites the previous handler.
    pub fn register(&self, name: &str, handler: Arc<dyn Scheme>) {
        self.inner.write().insert(String::from(name), handler);
    }

    /// Remove a previously-registered scheme handler.
    ///
    /// No-op if the name is not registered.
    pub fn deregister(&self, name: &str) {
        self.inner.write().remove(name);
    }

    // ── Introspection ────────────────────────────────────────────────────────────

    /// Return all registered scheme names in sorted (BTree) order.
    ///
    /// This is the backing API for `/proc/schemes`.  The read lock is held
    /// only for the duration of the `collect()`.
    pub fn list(&self) -> Vec<String> {
        self.inner.read().keys().cloned().collect()
    }

    /// Returns `true` if `name` is currently registered.
    pub fn contains(&self, name: &str) -> bool {
        self.inner.read().contains_key(name)
    }

    /// Look up `name` and return a cloned `Arc` to the handler, if present.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Scheme>> {
        self.inner.read().get(name).map(Arc::clone)
    }

    // ── URL routing ──────────────────────────────────────────────────────────────

    /// Parse `url` as `<scheme>:<path>`, look up the handler, and call
    /// `handler.open(path, flags)`.
    ///
    /// # Errors
    ///
    /// * `SchemeError::NoSuchScheme` — no colon in `url`, or no handler
    ///   registered under the extracted scheme name.
    /// * Any error forwarded from `handler.open()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (scheme, fid) =
    ///     SCHEME_TABLE.open_url("tcp:192.168.0.1:80", OpenFlags::RDWR)?;
    /// ```
    pub fn open_url(
        &self,
        url:   &str,
        flags: OpenFlags,
    ) -> Result<(Arc<dyn Scheme>, SchemeFileId), SchemeError> {
        // Split at the first colon.  URLs must have the form `<scheme>:<rest>`.
        let colon = url.find(':').ok_or(SchemeError::NoSuchScheme)?;
        let scheme_name = &url[..colon];
        let path        = &url[colon + 1..];

        // Clone the Arc while holding the read lock, then release it before
        // calling into the handler (which may block on IPC).
        let handler = self
            .inner
            .read()
            .get(scheme_name)
            .map(Arc::clone)
            .ok_or(SchemeError::NoSuchScheme)?;

        let fid = handler.open(path, flags)?;
        Ok((handler, fid))
    }
}

// ---------------------------------------------------------------------------
// Global instance
// ---------------------------------------------------------------------------

/// Kernel-wide scheme registry.  Initialised at boot time.
///
/// Drivers register themselves during their `init()` call:
///
/// ```ignore
/// use crate::fs::scheme_table::SCHEME_TABLE;
///
/// SCHEME_TABLE.register("tcp",  Arc::new(TcpScheme::new()));
/// SCHEME_TABLE.register("blk",  Arc::new(BlkScheme::new()));
/// SCHEME_TABLE.register("tty",  Arc::new(TtyScheme::new()));
/// ```
pub static SCHEME_TABLE: SchemeTable = SchemeTable::new();

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use scheme_api::{OpenFlags, SchemeError, SchemeFileId};

    struct EchoScheme;
    impl Scheme for EchoScheme {
        fn open(&self, _: &str, _: OpenFlags) -> Result<SchemeFileId, SchemeError> {
            Ok(SchemeFileId(99))
        }
        fn close(&self, _: SchemeFileId) -> Result<(), SchemeError> { Ok(()) }
    }

    #[test]
    fn register_and_list() {
        let t = SchemeTable::new();
        t.register("blk",  Arc::new(EchoScheme));
        t.register("file", Arc::new(EchoScheme));
        t.register("tcp",  Arc::new(EchoScheme));

        let names = t.list();
        // BTreeMap iterates in sorted order.
        assert_eq!(names, ["blk", "file", "tcp"]);
    }

    #[test]
    fn open_url_routes_correctly() {
        let t = SchemeTable::new();
        t.register("tcp", Arc::new(EchoScheme));

        let result = t.open_url("tcp:127.0.0.1:8080", OpenFlags::RDWR);
        assert!(result.is_ok());
        let (_scheme, fid) = result.unwrap();
        assert_eq!(fid.0, 99);
    }

    #[test]
    fn open_url_unknown_scheme_returns_error() {
        let t = SchemeTable::new();
        let err = t.open_url("unknown:foo", OpenFlags::RDONLY).unwrap_err();
        assert!(matches!(err, SchemeError::NoSuchScheme));
    }

    #[test]
    fn open_url_no_colon_returns_error() {
        let t = SchemeTable::new();
        let err = t.open_url("nocolon", OpenFlags::RDONLY).unwrap_err();
        assert!(matches!(err, SchemeError::NoSuchScheme));
    }

    #[test]
    fn deregister_removes_handler() {
        let t = SchemeTable::new();
        t.register("net", Arc::new(EchoScheme));
        assert!(t.contains("net"));
        t.deregister("net");
        assert!(!t.contains("net"));
        let names = t.list();
        assert!(!names.contains(&String::from("net")));
    }
}
