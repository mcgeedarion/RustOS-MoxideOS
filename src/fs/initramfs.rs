//! VFS bridge: mount the CPIO initramfs into the ramfs tree.
//!
//! Call `mount_initramfs()` once, after `heap::init()` and before the first
//! `open(2)` or `execve` that needs to reach a file inside the initramfs.
//! The function is idempotent — a second call is a no-op.
//!
//! The function walks the CPIO archive (via `initramfs::load()`) and for
//! each entry:
//!   * directory  → `vfs::mkdir(path)`
//!   * regular file → `vfs::create_file(path, data)`
//!   * symlink    → `vfs::symlink(target, path)` (if the VFS supports it)
//!
//! The CPIO "TRAILER!!!" entry signals end-of-archive and terminates the
//! walk.  Paths starting with "." are normalised to absolute paths.

extern crate alloc;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::fs::vfs;
use crate::initramfs;

/// Set once `mount_initramfs()` completes successfully.
static MOUNTED: AtomicBool = AtomicBool::new(false);

/// Walk the CPIO initramfs and create corresponding VFS entries.
///
/// Idempotent: returns immediately if already mounted.
pub fn mount_initramfs() {
    if MOUNTED.load(Ordering::Acquire) {
        return;
    }

    let handle = initramfs::load();

    for entry in handle.entries() {
        // Skip the end-of-archive marker.
        if entry.name == "TRAILER!!!" {
            continue;
        }
        // Skip the synthetic "." root entry.
        if entry.name == "." || entry.name.is_empty() {
            continue;
        }

        // Normalise path: "./foo" → "/foo", "foo" → "/foo".
        let path: String = if entry.name.starts_with('/') {
            entry.name.into()
        } else if let Some(rest) = entry.name.strip_prefix("./") {
            alloc::format!("/{rest}")
        } else {
            alloc::format!("/{}", entry.name)
        };

        // S_IFMT mask (Linux inode mode field upper 4 bits):
        //   0o140000 = socket   (skip)
        //   0o120000 = symlink
        //   0o100000 = regular file
        //   0o060000 = block device (skip)
        //   0o040000 = directory
        //   0o020000 = char device  (skip)
        //   0o010000 = FIFO        (skip)
        let mode = entry.mode;
        let file_type = mode & 0o170000;

        match file_type {
            // ── directory ───────────────────────────────────────────────
            0o040000 => {
                vfs::mkdir(&path);
            }

            // ── regular file ─────────────────────────────────────────────
            0o100000 => {
                // Ensure parent directory exists first.
                if let Some(parent) = parent_of(&path) {
                    vfs::mkdir(&parent);
                }
                vfs::create_file(&path, entry.data);
            }

            // ── symbolic link ─────────────────────────────────────────────
            0o120000 => {
                // The symlink target is stored in the file data as a
                // NUL-terminated (or plain) string.
                let target_bytes = entry.data;
                let target_len = target_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(target_bytes.len());
                if let Ok(target) = core::str::from_utf8(&target_bytes[..target_len]) {
                    // vfs::symlink(target, linkpath) — best-effort.
                    #[cfg(feature = "vfs_symlink")]
                    vfs::symlink(target, &path);
                    // Without VFS symlink support, create a regular file
                    // containing the target path so at least readlink works.
                    #[cfg(not(feature = "vfs_symlink"))]
                    vfs::create_file(&path, target_bytes);
                }
            }

            // ── everything else: skip ──────────────────────────────────────
            _ => {}
        }
    }

    MOUNTED.store(true, Ordering::Release);
    crate::println!(
        "initramfs: mounted {} entries into VFS",
        count_entries(&handle)
    );
}

// ── helpers ───────────────────────────────────────────────────────────────

/// Return the parent directory path of `path`, or None for top-level entries.
fn parent_of(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    let last_slash = trimmed.rfind('/')?;
    if last_slash == 0 {
        return None;
    } // parent is root
    Some(trimmed[..last_slash].into())
}

/// Count non-trailer, non-dot entries in the archive (for the log message).
fn count_entries(handle: &initramfs::InitramfsHandle<'_>) -> usize {
    handle
        .entries()
        .filter(|e| e.name != "TRAILER!!!" && e.name != "." && !e.name.is_empty())
        .count()
}
