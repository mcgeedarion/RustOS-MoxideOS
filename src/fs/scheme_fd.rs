//! SchemeFdStore — maps kernel backing-fd numbers to (Arc<dyn Scheme>, SchemeFileId)
//! so that read / write / close / seek can dispatch without re-hitting the
//! scheme table or re-parsing the URL.
//!
//! # Design
//!
//! When `proc_fd_open` resolves a scheme URL it:
//! 1. Calls `SCHEME_TABLE.open(url, flags)` → `(Arc<dyn Scheme>, SchemeFileId)`.
//! 2. Allocates a *synthetic* backing-fd number (a plain `usize` from an
//!    atomic counter — no underlying VFS inode is needed).
//! 3. Inserts `(scheme, fid)` into `SCHEME_FD_STORE` keyed by that backing fd.
//! 4. Stores the backing fd in the process `FdEntry` as usual.
//!
//! All subsequent I/O on the user-visible fd flows through
//! `scheme_fd_read` / `scheme_fd_write` / `scheme_fd_seek` / `scheme_fd_ioctl`.
//! `close_backing` calls `scheme_fd_close` which forwards to the scheme handler
//! and removes the entry from the store.
//!
//! # Thread-safety
//!
//! The store is protected by a `spin::Mutex`. Each operation holds the lock
//! only long enough to clone the `Arc` and copy the `SchemeFileId`, then
//! releases it before calling into the scheme handler. This means multiple
//! kernel threads can issue concurrent scheme I/O without holding the global
//! lock during the (potentially blocking) driver IPC round-trip.

extern crate alloc;
use alloc::{
    collections::BTreeMap,
    sync::Arc,
};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use scheme_api::{SchemeFileId, SchemeError};
use super::scheme_table::Scheme;

// ---------------------------------------------------------------------------
// Synthetic backing-fd allocator
// ---------------------------------------------------------------------------
//
// Regular VFS fds come from the ramfs/ext2 file tables (small integers).
// We place scheme backing-fds in a high range (starting at 0x8000_0000) so
// they never collide with real VFS fds. The counter only increases; the
// reclaimed fd numbers from `remove` are *not* reused (fine for the
// expected number of open scheme fds per session).

static SCHEME_FD_COUNTER: AtomicUsize = AtomicUsize::new(0x8000_0000);

/// Allocate a fresh synthetic backing-fd number for a scheme fd.
pub fn alloc_scheme_backing_fd() -> usize {
    SCHEME_FD_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// SchemeFdStore
// ---------------------------------------------------------------------------

struct SchemeFdEntry {
    scheme: Arc<dyn Scheme>,
    fid:    SchemeFileId,
}

struct SchemeFdStore {
    map: Mutex<BTreeMap<usize, SchemeFdEntry>>,
}

impl SchemeFdStore {
    const fn new() -> Self {
        Self { map: Mutex::new(BTreeMap::new()) }
    }

    fn insert(&self, backing_fd: usize, scheme: Arc<dyn Scheme>, fid: SchemeFileId) {
        self.map.lock().insert(backing_fd, SchemeFdEntry { scheme, fid });
    }

    /// Clone the (scheme, fid) pair for `backing_fd`, if present.
    fn get(&self, backing_fd: usize) -> Option<(Arc<dyn Scheme>, SchemeFileId)> {
        let guard = self.map.lock();
        guard.get(&backing_fd).map(|e| (Arc::clone(&e.scheme), e.fid))
    }

    fn remove(&self, backing_fd: usize) -> Option<(Arc<dyn Scheme>, SchemeFileId)> {
        self.map.lock().remove(&backing_fd).map(|e| (e.scheme, e.fid))
    }

    /// Returns true iff `backing_fd` is a scheme fd.
    fn contains(&self, backing_fd: usize) -> bool {
        self.map.lock().contains_key(&backing_fd)
    }
}

static SCHEME_FD_STORE: SchemeFdStore = SchemeFdStore::new();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Register a newly-opened scheme fd.
///
/// Called from `proc_fd_open` after `SCHEME_TABLE.open` succeeds.
pub fn scheme_fd_register(backing_fd: usize, scheme: Arc<dyn Scheme>, fid: SchemeFileId) {
    SCHEME_FD_STORE.insert(backing_fd, scheme, fid);
}

/// Returns `true` if `backing_fd` belongs to a scheme.
pub fn is_scheme_fd(backing_fd: usize) -> bool {
    SCHEME_FD_STORE.contains(backing_fd)
}

// ---------------------------------------------------------------------------
// I/O dispatch
// ---------------------------------------------------------------------------

/// Read up to `buf.len()` bytes from the scheme fd.
///
/// Returns the byte count on success, or a negative errno on error.
pub fn scheme_fd_read(backing_fd: usize, buf: &mut [u8]) -> isize {
    let (scheme, fid) = match SCHEME_FD_STORE.get(backing_fd) {
        Some(pair) => pair,
        None       => return -9,  // EBADF
    };
    match scheme.read(fid, buf) {
        Ok(n)  => n as isize,
        Err(e) => scheme_error_to_errno(e),
    }
}

/// Write `buf` to the scheme fd.
///
/// Returns bytes written on success, or a negative errno on error.
pub fn scheme_fd_write(backing_fd: usize, buf: &[u8]) -> isize {
    let (scheme, fid) = match SCHEME_FD_STORE.get(backing_fd) {
        Some(pair) => pair,
        None       => return -9,
    };
    match scheme.write(fid, buf) {
        Ok(n)  => n as isize,
        Err(e) => scheme_error_to_errno(e),
    }
}

/// Reposition the scheme fd's offset.
///
/// Returns the new absolute position on success, or a negative errno.
pub fn scheme_fd_seek(backing_fd: usize, offset: i64, whence: u8) -> isize {
    let (scheme, fid) = match SCHEME_FD_STORE.get(backing_fd) {
        Some(pair) => pair,
        None       => return -9,
    };
    match scheme.seek(fid, offset, whence) {
        Ok(pos) => pos as isize,
        Err(e)  => scheme_error_to_errno(e),
    }
}

/// Issue an ioctl on the scheme fd.
///
/// Returns the result value on success, or a negative errno.
pub fn scheme_fd_ioctl(backing_fd: usize, cmd: u64, arg: usize) -> isize {
    let (scheme, fid) = match SCHEME_FD_STORE.get(backing_fd) {
        Some(pair) => pair,
        None       => return -9,
    };
    match scheme.ioctl(fid, cmd, arg) {
        Ok(n)  => n as isize,
        Err(e) => scheme_error_to_errno(e),
    }
}

/// Close a scheme fd — forwards to the scheme handler and removes the entry
/// from the store.
///
/// Called from `close_backing` in `process_fd.rs`.
pub fn scheme_fd_close(backing_fd: usize) {
    if let Some((scheme, fid)) = SCHEME_FD_STORE.remove(backing_fd) {
        // Best-effort: log but do not panic if the driver is already gone.
        if let Err(e) = scheme.close(fid) {
            log::warn!("[scheme] close({:#x}) error: {:?}\n", backing_fd, e);
        }
    }
}

// ---------------------------------------------------------------------------
// Errno translation
// ---------------------------------------------------------------------------

#[inline]
fn scheme_error_to_errno(e: SchemeError) -> isize {
    match e {
        SchemeError::NoSuchScheme    => -2,   // ENOENT
        SchemeError::NotFound        => -2,   // ENOENT
        SchemeError::PermissionDenied => -13, // EACCES
        SchemeError::InvalidArg      => -22,  // EINVAL
        SchemeError::WouldBlock      => -11,  // EAGAIN
        SchemeError::Io              => -5,   // EIO
        SchemeError::Unreachable     => -5,   // EIO
        SchemeError::Other           => -5,   // EIO
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use scheme_api::{OpenFlags, SchemeError, SchemeFileId};
    use crate::fs::scheme_table::Scheme;

    struct DummyScheme;
    impl Scheme for DummyScheme {
        fn open(&self, _: &str, _: OpenFlags) -> Result<SchemeFileId, SchemeError> {
            Ok(SchemeFileId(42))
        }
        fn read(&self, _: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
            buf[0] = b'X'; Ok(1)
        }
        fn write(&self, _: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
            Ok(buf.len())
        }
        fn ioctl(&self, _: SchemeFileId, _: u64, _: usize) -> Result<usize, SchemeError> {
            Ok(0)
        }
        fn close(&self, _: SchemeFileId) -> Result<(), SchemeError> { Ok(()) }
    }

    #[test]
    fn insert_lookup_remove() {
        let bfd = 0x9000_0001_usize;
        let scheme: Arc<dyn Scheme> = Arc::new(DummyScheme);
        scheme_fd_register(bfd, Arc::clone(&scheme), SchemeFileId(7));

        assert!(is_scheme_fd(bfd));

        let mut buf = [0u8; 4];
        assert_eq!(scheme_fd_read(bfd, &mut buf), 1);
        assert_eq!(buf[0], b'X');

        scheme_fd_close(bfd);
        assert!(!is_scheme_fd(bfd));
        // After close, read should return EBADF.
        assert_eq!(scheme_fd_read(bfd, &mut buf), -9);
    }
}
