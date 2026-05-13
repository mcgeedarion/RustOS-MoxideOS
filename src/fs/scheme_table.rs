//! Scheme table — the kernel-side registry that maps URL scheme prefixes
//! (e.g. `"file"`, `"blk"`, `"net"`, `"tcp"`, `"tty"`, `"proc"`) to
//! `Arc<dyn Scheme>` handlers.
//!
//! # How it fits into the VFS
//!
//! `sys_open(path, flags)` is the single entry point.  We first try to
//! parse `path` as a scheme URL (`scheme:rest`).  If it has a colon we
//! look up the scheme and dispatch through `SchemeTable::open`.  If it
//! does *not* contain a colon we fall back to the legacy POSIX path
//! resolver in `vfs_ops.rs` — this preserves full backward compatibility
//! while we migrate subsystems one by one.
//!
//! In-kernel schemes (tty, proc, initramfs) implement `Scheme` directly.
//! Userspace driver schemes are represented by `IpcProxyScheme` instances
//! that forward requests over the registered `IpcEndpoint`.

use alloc::{
    string::String,
    sync::Arc,
    collections::BTreeMap,
};
use spin::RwLock;

use scheme_api::{
    OpenFlags, SchemeError, SchemeFileId,
    parse_scheme_url,
};

// ---------------------------------------------------------------------------
// The `Scheme` trait — implemented by every scheme handler
// ---------------------------------------------------------------------------

/// Every resource namespace implements this trait.
///
/// Methods mirror the POSIX file-descriptor interface so that the fd
/// table can hold scheme fds alongside regular pipe/socket fds without
/// any special-casing.
pub trait Scheme: Send + Sync {
    /// Open a resource at `path` inside this scheme.  Returns a
    /// scheme-local file id that the kernel stores in the fd table.
    fn open(&self, path: &str, flags: OpenFlags)
        -> Result<SchemeFileId, SchemeError>;

    /// Read up to `buf.len()` bytes from `fd`.  Returns bytes read.
    fn read(&self, fd: SchemeFileId, buf: &mut [u8])
        -> Result<usize, SchemeError>;

    /// Write `buf` to `fd`.  Returns bytes written.
    fn write(&self, fd: SchemeFileId, buf: &[u8])
        -> Result<usize, SchemeError>;

    /// Device-specific control.
    fn ioctl(&self, fd: SchemeFileId, cmd: u64, arg: usize)
        -> Result<usize, SchemeError>;

    /// Reposition the file offset.  Default: unsupported.
    fn seek(&self, _fd: SchemeFileId, _offset: i64, _whence: u8)
        -> Result<i64, SchemeError>
    {
        Err(SchemeError::InvalidArg)
    }

    /// Close `fd` and release any driver-side resources.
    fn close(&self, fd: SchemeFileId) -> Result<(), SchemeError>;
}

// ---------------------------------------------------------------------------
// SchemeTable
// ---------------------------------------------------------------------------

/// Global scheme registry.
///
/// Use the `SCHEME_TABLE` static below; do not construct directly.
pub struct SchemeTable {
    inner: RwLock<BTreeMap<String, Arc<dyn Scheme>>>,
}

impl SchemeTable {
    pub const fn new() -> Self {
        Self {
            inner: RwLock::new(BTreeMap::new()),
        }
    }

    // ------------------------------------------------------------------
    // Registration
    // ------------------------------------------------------------------

    /// Register a scheme handler.
    ///
    /// # Panics
    /// Panics if `name` contains a `':'` (scheme names must be bare words).
    pub fn register(&self, name: &str, handler: Arc<dyn Scheme>) {
        assert!(!name.contains(':'), "scheme name must not contain ':'  (got {:?})", name);
        let mut guard = self.inner.write();
        guard.insert(String::from(name), handler);
        log::info!("[scheme] registered scheme \"{}\"\n", name);
    }

    /// Remove a scheme (called when a driver process exits).
    pub fn unregister(&self, name: &str) {
        let mut guard = self.inner.write();
        if guard.remove(name).is_some() {
            log::info!("[scheme] unregistered scheme \"{}\"\n", name);
        }
    }

    // ------------------------------------------------------------------
    // Dispatch
    // ------------------------------------------------------------------

    /// Route an `open` call by scheme prefix.
    ///
    /// `url` must be of the form `"scheme:path"`.  Returns
    /// `(Arc<dyn Scheme>, SchemeFileId)` so the caller can store both in
    /// the process fd table and later dispatch `read`/`write`/`close`
    /// without another table lookup.
    pub fn open(
        &self,
        url: &str,
        flags: OpenFlags,
    ) -> Result<(Arc<dyn Scheme>, SchemeFileId), SchemeError> {
        let (scheme_name, path) =
            parse_scheme_url(url).ok_or(SchemeError::InvalidArg)?;

        let handler = {
            let guard = self.inner.read();
            guard
                .get(scheme_name)
                .cloned()
                .ok_or(SchemeError::NoSuchScheme)?
        };

        let fid = handler.open(path, flags)?;
        Ok((handler, fid))
    }

    /// List registered scheme names (for debugging / `/proc/schemes`).
    pub fn list(&self) -> alloc::vec::Vec<String> {
        self.inner.read().keys().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// The kernel-wide scheme registry.  Initialised at boot in `kernel_main`.
pub static SCHEME_TABLE: SchemeTable = SchemeTable::new();

// ---------------------------------------------------------------------------
// Helper: is this path a scheme URL?
// ---------------------------------------------------------------------------

/// Returns `true` if `path` looks like a scheme URL (`"word:..."`).
///
/// A leading `/` means it is a classic POSIX path and should go through
/// the legacy VFS path resolver instead.
pub fn is_scheme_url(path: &str) -> bool {
    if path.starts_with('/') {
        return false;
    }
    // Must have a colon with only valid identifier chars before it.
    path.split_once(':')
        .map(|(prefix, _)| !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_scheme_url_positive() {
        assert!(is_scheme_url("file:/etc/passwd"));
        assert!(is_scheme_url("blk:vda"));
        assert!(is_scheme_url("tcp:127.0.0.1:80"));
        assert!(is_scheme_url("net:"));
    }

    #[test]
    fn is_scheme_url_negative() {
        assert!(!is_scheme_url("/etc/passwd"));
        assert!(!is_scheme_url("nocolon"));
        assert!(!is_scheme_url(""));
    }
}
