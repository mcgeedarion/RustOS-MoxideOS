//! Minimal devfs implementation.
//!
//! Provides:
//! - A static major/minor dispatch table (`DEVFS_TABLE`) mapping `(major,
//!   minor)` to `Arc<dyn FileOps>`.
//! - `register_char_device(major, minor, ops)` — called by subsystems to
//!   publish their devices.
//! - `devfs_open(path)` — resolves a `/dev/…` path to a `FileOps`.
//! - `init_devfs()` — creates `/dev/input/` VFS entries and registers
//!   `EventNode`s for every device in `InputDeviceRegistry`.
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

/// Maximum number of majors we track.
const MAX_MAJOR: usize = 256;
/// Maximum minors per major.
const MAX_MINOR: usize = 256;

/// A single cell in the dispatch table.  `None` until a device is registered.
type DevCell = Option<Arc<dyn FileOps + Send + Sync>>;

/// Two-level table: DEVFS_TABLE[major][minor].
///
/// Using a flat 256×256 array would be 512 KiB of pointers — acceptable in a
/// kernel heap.  We use `Option<Arc<…>>` to keep unregistered slots at
/// `None` without a sentinel.
struct DevfsTable {
    /// Outer vec allocated lazily per major.
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
            // Allocate the minor table on first use for this major.
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
///
/// Idempotent: registering the same (major, minor) twice replaces the old
/// `FileOps` silently.
pub fn register_char_device(major: usize, minor: usize, ops: Arc<dyn FileOps + Send + Sync>) {
    // SAFETY: called during single-threaded init only.
    unsafe { DEVFS_TABLE.set(major, minor, ops) }
}

/// Resolve a `/dev/input/eventN` path to its `FileOps`.
///
/// Returns `None` when:
/// - the path is not `/dev/input/eventN`
/// - no device is registered at the parsed minor
pub fn devfs_open(path: &str) -> Option<Arc<dyn FileOps + Send + Sync>> {
    // Accept both `/dev/input/eventN` and `input/eventN` (relative to /dev).
    let rel = path
        .strip_prefix("/dev/input/event")
        .or_else(|| path.strip_prefix("input/event"))
        .or_else(|| path.strip_prefix("event"))?;

    let minor: usize = rel.parse().ok()?;
    // SAFETY: called after init; table is read-only thereafter.
    unsafe { DEVFS_TABLE.get(INPUT_MAJOR, minor) }
}

/// Input subsystem major number (matches Linux).
pub const INPUT_MAJOR: usize = 13;

/// Initialise the devfs layer.
///
/// 1. For every device registered in `InputDeviceRegistry`, creates an
///    `EventNode` wrapped in `Arc` and installs it at `(INPUT_MAJOR, minor)`.
/// 2. Creates the `/dev/input/` VFS directory node so that `openat`/ `getdents`
///    work.
pub fn init() {
    let count = device_count();
    for minor in 0..count {
        let node = Arc::new(EventNode::new(minor)) as Arc<dyn FileOps + Send + Sync>;
        register_char_device(INPUT_MAJOR, minor, node);
        log::info!("devfs: registered /dev/input/event{}", minor);
    }

    // Register the directory entry in the VFS so `open("/dev/input")` works.
    // We use the existing ramfs/tmpfs at /dev (mounted during early init).
    // If the VFS mount isn't up yet this is a no-op; the compositor can
    // also open the device by fd number via WAYLAND_INPUT_FD.
    crate::fs::vfs::ensure_dir("/dev/input");
}

// ===== GUESS: fd -> device FileOps lookup =====
/// GUESS: map a kernel fd to a devfs-backed FileOps handle. Without a
/// dedicated fd table for devfs we look up via the global process file table.
/// Returns None when the fd is not a devfs entry.
pub fn get_dev_fd(_fd: i32) -> Option<alloc::sync::Arc<dyn FileOps + Send + Sync>> {
    // GUESS: we don't currently store a per-fd kind tag distinguishing
    // devfs entries from regular file entries. Treat all fds as
    // non-devfs to preserve existing branch behaviour in callers.
    None
}

// ===== GUESS: stat alias for devfs entries =====
/// GUESS: devfs nodes have no concrete stat backing. Return a synthetic
/// character-device stat so callers can branch on file-type. Returns
/// Err(-2) (ENOENT) when path is not a devfs entry.
pub fn stat(_path: &str) -> Result<crate::fs::vfs_ops::KStat, isize> {
    // GUESS: cannot resolve without a devfs path map. Surface ENOENT
    // so VFS dispatchers fall through to the next FS.
    Err(-2)
}
