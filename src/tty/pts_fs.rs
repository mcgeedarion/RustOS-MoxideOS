//! `/dev/pts` virtual filesystem (devpts).
//!
//! Maintains a registry of all live slave PTY device nodes.
//! The VFS layer calls `pts_open(idx)` when userspace opens `/dev/pts/<n>`.
//!
//! ## Mount / directory layout
//!
//!   /dev/ptmx          — always present, opens a new PTY master (posix_openpt)
//!   /dev/pts/          — directory; contains one entry per live slave
//!   /dev/pts/0         — slave for PTY pair 0
//!   /dev/pts/1         — slave for PTY pair 1
//!   …
//!
//! ## File operations on /dev/ptmx
//!
//!   open  → posix_openpt() → fd wrapping PtyMaster
//!   ioctl → pty_ioctl (TIOCGPTN / TIOCSPTLCK)
//!
//! ## File operations on /dev/pts/<n>
//!
//!   open  → pts_open(n) → fd wrapping PtySlave (requires unlockpt)
//!   read  → PtyPair::slave_read
//!   write → PtyPair::slave_write
//!   ioctl → pty_ioctl

extern crate alloc;
use alloc::{
    collections::BTreeSet,
    string::{String, ToString},
};
use spin::Mutex;

/// Set of currently live slave indices (for directory listing).
static LIVE_SLAVES: Mutex<Option<BTreeSet<u32>>> = Mutex::new(None);

pub fn init() {
    *LIVE_SLAVES.lock() = Some(BTreeSet::new());
}

/// Register a new slave node (called by `tty::alloc_pty`).
pub fn register_slave(idx: u32) {
    if let Some(set) = LIVE_SLAVES.lock().as_mut() {
        set.insert(idx);
    }
}

/// Remove a slave node (called by `tty::free_pty`).
pub fn unregister_slave(idx: u32) {
    if let Some(set) = LIVE_SLAVES.lock().as_mut() {
        set.remove(&idx);
    }
}

/// Returns true if slave `idx` exists (used by VFS open path).
pub fn slave_exists(idx: u32) -> bool {
    LIVE_SLAVES
        .lock()
        .as_ref()
        .map_or(false, |s| s.contains(&idx))
}

/// Enumerate all live slave indices (for /dev/pts directory listing).
pub fn list_slaves() -> alloc::vec::Vec<u32> {
    LIVE_SLAVES
        .lock()
        .as_ref()
        .map_or_else(alloc::vec::Vec::new, |s| s.iter().copied().collect())
}

/// Resolve `/dev/pts/<n>` path to a slave index.  Returns None if the
/// path doesn't match the prefix or the index is out of range.
pub fn resolve_path(path: &str) -> Option<u32> {
    let rest = path.strip_prefix("/dev/pts/")?;
    let idx: u32 = rest.parse().ok()?;
    if slave_exists(idx) {
        Some(idx)
    } else {
        None
    }
}

/// Called from VFS open when `path == "/dev/ptmx"` or `path == "/dev/pts/<n>"`.
///
/// Returns `PtsFd` describing which side to open, or an error.
pub enum PtsFd {
    /// Open the master side; caller receives `(slave_idx, Arc<PtyPair>)`.
    Master {
        slave_idx: u32,
        pair: alloc::sync::Arc<crate::tty::pty::PtyPair>,
    },
    /// Open the slave side; caller receives `Arc<PtyPair>`.
    Slave {
        pair: alloc::sync::Arc<crate::tty::pty::PtyPair>,
    },
}

pub fn vfs_open(path: &str) -> Result<PtsFd, isize> {
    if path == "/dev/ptmx" {
        let (idx, pair) = crate::tty::pty::posix_openpt()?;
        return Ok(PtsFd::Master {
            slave_idx: idx,
            pair,
        });
    }
    if let Some(idx) = resolve_path(path) {
        let pair = crate::tty::lookup_pty(idx).ok_or(-6isize)?; // ENXIO
        if pair.is_locked() {
            return Err(-5);
        } // EIO — slave locked
        pair.slave_open
            .store(true, core::sync::atomic::Ordering::SeqCst);
        return Ok(PtsFd::Slave { pair });
    }
    Err(-2) // ENOENT
}

/// Generate a /proc-style directory listing for /dev/pts.
pub fn readdir() -> alloc::vec::Vec<String> {
    let slaves = list_slaves();
    let mut entries = alloc::vec![String::from("."), String::from("..")];
    for idx in slaves {
        entries.push(idx.to_string());
    }
    entries
}
