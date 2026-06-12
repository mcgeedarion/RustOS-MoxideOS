//! Minimal devfs implementation.
//!
//! Provides:
//! - A static major/minor dispatch table (`DEVFS_TABLE`) mapping `(major, minor)` to `Arc<dyn
//!   FileOps>`.
//! - `register_char_device(major, minor, ops)` — called by subsystems to publish their devices.
//! - `devfs_open(path)` — resolves a `/dev/…` path to a `FileOps`.
//! - `init_devfs()` — creates `/dev/input/` VFS entries and registers `EventNode`s for every device
//!   in `InputDeviceRegistry`.
//!
//! # Major numbers used
//!
//! | Major | Subsystem        | Nodes                     |
//! |------:|:-----------------|:--------------------------|
//! |    13 | input (evdev)    | `/dev/input/event0` …     |
//!
//! Others (DRM = 226, tty = 4, …) follow the same pattern and can be wired
//! in their own subsystem init functions.

#![allow(dead_code)]

use crate::fs::vfs_ops::FileOps;
use crate::input::{device_count, EventNode};
use alloc::sync::Arc;

const MAX_MAJOR: usize = 256;
const MAX_MINOR: usize = 256;

/// A single cell in the dispatch table.  `None` until a device is registered.
type DevCell = Option<Arc<dyn FileOps + Send + Sync>>;

/// Two-level table: DEVFS_TABLE[major][minor].
struct DevfsTable {
    majors: [Option<alloc::boxed::Box<[DevCell; MAX_MINOR]>>; MAX_MAJOR],
}

impl DevfsTable {
    const fn empty_majors() -> [Option<alloc::boxed::Box<[DevCell; MAX_MINOR]>>; MAX_MAJOR] {
        // Can't const-init Box<[…; 256]> easily; we initialise lazily in
        // register_char_device instead.  This just provides the None array.
        [const { None }; MAX_MAJOR]
    }

    fn get(&self, major: usize, minor: usize) -> Option<Arc<dyn FileOps + Send + Sync>> {
        self.majors.get(major)?.as_ref()?.get(minor)?.clone()
    }

    fn set(&mut self, major: usize, minor: usize, ops: Arc<dyn FileOps + Send + Sync>) {
        if self.majors[major].is_none() {
            let boxed: alloc::boxed::Box<[DevCell; MAX_MINOR]> =
                alloc::boxed::Box::new([const { None }; MAX_MINOR]);
            self.majors[major] = Some(boxed);
        }
        if let Some(ref mut row) = self.majors[major] {
            row[minor] = Some(ops);
        }
    }
}

// SAFETY: DEVFS_TABLE is mutated only during single-threaded init.
static mut DEVFS_TABLE: DevfsTable = DevfsTable {
    majors: [const { None }; MAX_MAJOR],
};

/// Register a character device at (major, minor).
pub fn register_char_device(major: usize, minor: usize, ops: Arc<dyn FileOps + Send + Sync>) {
    unsafe { DEVFS_TABLE.set(major, minor, ops) }
}

/// Resolve a `/dev/input/eventN` path to its `FileOps`.
pub fn devfs_open(path: &str) -> Option<Arc<dyn FileOps + Send + Sync>> {
    let rel = path
        .strip_prefix("/dev/input/event")
        .or_else(|| path.strip_prefix("input/event"))
        .or_else(|| path.strip_prefix("event"))?;

    let minor: usize = rel.parse().ok()?;
    unsafe { DEVFS_TABLE.get(INPUT_MAJOR, minor) }
}

/// Input subsystem major number (matches Linux).
pub const INPUT_MAJOR: usize = 13;

/// Initialise the devfs layer.
pub fn init() {
    let count = device_count();
    for minor in 0..count {
        let node = Arc::new(EventNode::new(minor)) as Arc<dyn FileOps + Send + Sync>;
        register_char_device(INPUT_MAJOR, minor, node);
        log::info!("devfs: registered /dev/input/event{}", minor);
    }

    crate::fs::vfs::ensure_dir("/dev/input");
}

// ===== GUESS: fd -> device FileOps lookup =====
pub fn get_dev_fd(_fd: i32) -> Option<alloc::sync::Arc<dyn FileOps + Send + Sync>> {
    // GUESS: we don't currently store a per-fd kind tag distinguishing
    // devfs entries from regular file entries. Treat all fds as
    // non-devfs to preserve existing branch behaviour in callers.
    None
}

// ===== GUESS: stat alias for devfs entries =====
pub fn stat(_path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    // GUESS: cannot resolve without a devfs path map. Surface ENOENT
    // so VFS dispatchers fall through to the next FS.
    Err(-2)
}

/// Concrete `dev:` scheme adapter.
///
/// The implementation lives in `url_dispatch` so all filesystem URL handlers
/// share the same fd-table and flag-handling helpers.
pub use crate::fs::url_dispatch::DevFs;
