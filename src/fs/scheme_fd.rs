//! SchemeFdStore — maps kernel backing-fd numbers to (Arc<dyn Scheme>,

extern crate alloc;
use crate::core::fast_hash::KernelFastMap;
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use super::scheme_table::Scheme;
use scheme_api::{SchemeError, SchemeFileId};

///
static SCHEME_FD_COUNTER: AtomicUsize = AtomicUsize::new(0x8000_0000);
static FREE_SCHEME_FDS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Allocate a fresh synthetic backing-fd number for a scheme fd.
pub fn alloc_scheme_backing_fd() -> usize {
    if let Some(fd) = FREE_SCHEME_FDS.lock().pop() {
        return fd;
    }
    SCHEME_FD_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Return a synthetic backing-fd to the free list.
pub fn free_scheme_backing_fd(fd: usize) {
    FREE_SCHEME_FDS.lock().push(fd);
}

struct SchemeFdEntry {
    scheme: Arc<dyn Scheme>,
    fid: SchemeFileId,
    refs: usize,
}

struct SchemeFdStore {
    map: Mutex<KernelFastMap<usize, SchemeFdEntry>>,
}

impl SchemeFdStore {
    const fn new() -> Self {
        // Fast map is safe here: keys are kernel-assigned synthetic backing fd
        // numbers and no user-visible output depends on iteration order.
        Self {
            map: Mutex::new(KernelFastMap::new()),
        }
    }

    fn insert(&self, backing_fd: usize, scheme: Arc<dyn Scheme>, fid: SchemeFileId) {
        self.map.lock().insert(
            backing_fd,
            SchemeFdEntry {
                scheme,
                fid,
                refs: 1,
            },
        );
    }

    /// Clone the (scheme, fid) pair for `backing_fd`, if present.
    fn get(&self, backing_fd: usize) -> Option<(Arc<dyn Scheme>, SchemeFileId)> {
        let guard = self.map.lock();
        guard
            .get(&backing_fd)
            .map(|e| (Arc::clone(&e.scheme), e.fid))
    }

    fn dup(&self, backing_fd: usize) -> bool {
        let mut guard = self.map.lock();
        if let Some(entry) = guard.get_mut(&backing_fd) {
            entry.refs = entry.refs.saturating_add(1);
            true
        } else {
            false
        }
    }

    fn close_ref(&self, backing_fd: usize) -> Option<(Arc<dyn Scheme>, SchemeFileId)> {
        let mut guard = self.map.lock();
        let entry = guard.get_mut(&backing_fd)?;
        if entry.refs > 1 {
            entry.refs -= 1;
            return None;
        }
        guard.remove(&backing_fd).map(|e| (e.scheme, e.fid))
    }

    /// Returns true iff `backing_fd` is a scheme fd.
    fn contains(&self, backing_fd: usize) -> bool {
        self.map.lock().contains_key(&backing_fd)
    }
}

static SCHEME_FD_STORE: SchemeFdStore = SchemeFdStore::new();

/// Register a newly-opened scheme fd.
pub fn scheme_fd_register(backing_fd: usize, scheme: Arc<dyn Scheme>, fid: SchemeFileId) {
    SCHEME_FD_STORE.insert(backing_fd, scheme, fid);
}

/// Returns `true` if `backing_fd` belongs to a scheme.
pub fn is_scheme_fd(backing_fd: usize) -> bool {
    SCHEME_FD_STORE.contains(backing_fd)
}

/// Clone the registered scheme/fid pair for compatibility callers that need
/// to translate a synthetic backing fd back to a scheme-local file id.
pub fn scheme_fd_get_fid(backing_fd: usize) -> Option<(Arc<dyn Scheme>, SchemeFileId)> {
    SCHEME_FD_STORE.get(backing_fd)
}

/// Increment the reference count for a duplicated process-local fd.
pub fn scheme_fd_dup(backing_fd: usize) -> bool {
    SCHEME_FD_STORE.dup(backing_fd)
}

/// Read up to `buf.len()` bytes from the scheme fd.
pub fn scheme_fd_read(backing_fd: usize, buf: &mut [u8]) -> isize {
    let (scheme, fid) = match SCHEME_FD_STORE.get(backing_fd) {
        Some(pair) => pair,
        None => return -9, // EBADF
    };
    match scheme.read(fid, buf) {
        Ok(n) => n as isize,
        Err(e) => scheme_error_to_errno(e),
    }
}

/// Write `buf` to the scheme fd.
pub fn scheme_fd_write(backing_fd: usize, buf: &[u8]) -> isize {
    let (scheme, fid) = match SCHEME_FD_STORE.get(backing_fd) {
        Some(pair) => pair,
        None => return -9,
    };
    match scheme.write(fid, buf) {
        Ok(n) => n as isize,
        Err(e) => scheme_error_to_errno(e),
    }
}

/// Reposition the scheme fd's offset.
pub fn scheme_fd_seek(backing_fd: usize, offset: i64, whence: u8) -> isize {
    let (scheme, fid) = match SCHEME_FD_STORE.get(backing_fd) {
        Some(pair) => pair,
        None => return -9,
    };
    match scheme.seek(fid, offset, whence) {
        Ok(pos) => pos as isize,
        Err(e) => scheme_error_to_errno(e),
    }
}

/// Issue an ioctl on the scheme fd.
pub fn scheme_fd_ioctl(backing_fd: usize, cmd: u64, arg: usize) -> isize {
    let (scheme, fid) = match SCHEME_FD_STORE.get(backing_fd) {
        Some(pair) => pair,
        None => return -9,
    };
    match scheme.ioctl(fid, cmd, arg) {
        Ok(n) => n as isize,
        Err(e) => scheme_error_to_errno(e),
    }
}

/// Close a scheme fd — forwards to the scheme handler, removes the entry
pub fn scheme_fd_close(backing_fd: usize) {
    if let Some((scheme, fid)) = SCHEME_FD_STORE.close_ref(backing_fd) {
        // Best-effort: log but do not panic if the driver is already gone.
        if let Err(e) = scheme.close(fid) {
            log::warn!("[scheme] close({:#x}) error: {:?}\n", backing_fd, e);
        }
        free_scheme_backing_fd(backing_fd);
    }
}

#[inline]
fn scheme_error_to_errno(e: SchemeError) -> isize {
    match e {
        SchemeError::NoSuchScheme => -2,      // ENOENT
        SchemeError::NotFound => -2,          // ENOENT
        SchemeError::PermissionDenied => -13, // EACCES
        SchemeError::InvalidArg => -22,       // EINVAL
        SchemeError::WouldBlock => -11,       // EAGAIN
        SchemeError::Io => -5,                // EIO
        SchemeError::Unreachable => -5,       // EIO
        SchemeError::Other => -5,             // EIO
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::scheme_table::Scheme;
    use alloc::sync::Arc;
    use scheme_api::{OpenFlags, SchemeError, SchemeFileId};

    struct DummyScheme;
    impl Scheme for DummyScheme {
        fn open(&self, _: &str, _: OpenFlags) -> Result<SchemeFileId, SchemeError> {
            Ok(SchemeFileId(42))
        }
        fn read(&self, _: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
            buf[0] = b'X';
            Ok(1)
        }
        fn write(&self, _: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
            Ok(buf.len())
        }
        fn ioctl(&self, _: SchemeFileId, _: u64, _: usize) -> Result<usize, SchemeError> {
            Ok(0)
        }
        fn close(&self, _: SchemeFileId) -> Result<(), SchemeError> {
            Ok(())
        }
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
        assert_eq!(scheme_fd_read(bfd, &mut buf), -9);
    }

    #[test]
    fn fd_numbers_are_recycled_after_close() {
        let a = alloc_scheme_backing_fd();
        let b = alloc_scheme_backing_fd();
        assert_ne!(a, b, "each allocation must be unique");

        free_scheme_backing_fd(a);
        free_scheme_backing_fd(b);

        // Free list is LIFO, so b comes back first.
        assert_eq!(alloc_scheme_backing_fd(), b);
        assert_eq!(alloc_scheme_backing_fd(), a);
    }
}
