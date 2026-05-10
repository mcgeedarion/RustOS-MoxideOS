//! VFS dentry/stat cache — path → (fstype, ino, KStat).
//!
//! ## Design
//! 512-slot direct-mapped cache keyed on FNV-1a(path) % 512.
//! Each slot stores the full path string so collisions are detected
//! and stale entries are never returned.
//!
//! ## Invalidation
//! Any write-side vfs_ops function (create, unlink, write_all, rename,
//! truncate, chmod, chown) calls `dcache::invalidate(path)` before
//! returning, keeping the cache coherent for the common single-node case.
//!
//! ## Thread safety
//! A single `spin::Mutex` guards the whole table.  Cache operations are
//! O(1) and hold the lock for only a few dozen cycles, so contention is
//! negligible.

extern crate alloc;
use alloc::string::String;
use spin::Mutex;
use crate::fs::mount::FsType;
use crate::fs::vfs_ops::KStat;

const DCACHE_SIZE: usize = 512;

#[derive(Clone)]
pub struct DcacheEntry {
    pub path:   String,
    pub fstype: FsType,
    pub ino:    u64,
    pub stat:   KStat,
}

struct Dcache {
    slots: [Option<DcacheEntry>; DCACHE_SIZE],
}

impl Dcache {
    const fn new() -> Self {
        // Option<DcacheEntry> is not Copy so we cannot use [None; N] directly
        // in a const context with a non-Copy type.  Use a workaround: we
        // declare the array as MaybeUninit and initialise in init().
        // Simpler: since spin::Mutex::new is const, we just wrap an
        // Option<Box<Dcache>> — but that requires alloc in const.  Instead
        // we rely on the fact that our Dcache is only ever behind the Mutex
        // which is lazily initialised via DCACHE.lock().  We use a Vec-based
        // backing store initialised on first lock via LazyDcache below.
        Dcache { slots: [const { None }; DCACHE_SIZE] }
    }
}

static DCACHE: Mutex<Dcache> = Mutex::new(Dcache::new());

// FNV-1a 64-bit hash, truncated to cache index.
fn slot(path: &str) -> usize {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in path.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    (h as usize) % DCACHE_SIZE
}

/// Look up `path` in the cache.  Returns a clone of the entry on hit.
pub fn lookup(path: &str) -> Option<DcacheEntry> {
    let cache = DCACHE.lock();
    let s = slot(path);
    match &cache.slots[s] {
        Some(e) if e.path == path => Some(e.clone()),
        _ => None,
    }
}

/// Insert or replace the entry for `path`.
pub fn insert(path: &str, fstype: FsType, ino: u64, stat: KStat) {
    let mut cache = DCACHE.lock();
    let s = slot(path);
    cache.slots[s] = Some(DcacheEntry {
        path:   String::from(path),
        fstype,
        ino,
        stat,
    });
}

/// Remove the entry for `path` if present (e.g. after unlink/rename/write).
pub fn invalidate(path: &str) {
    let mut cache = DCACHE.lock();
    let s = slot(path);
    if let Some(e) = &cache.slots[s] {
        if e.path == path {
            cache.slots[s] = None;
        }
    }
}
