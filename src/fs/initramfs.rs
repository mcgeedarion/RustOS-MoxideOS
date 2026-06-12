//! VFS bridge: mount the CPIO initramfs into the ramfs tree.

extern crate alloc;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::fs::{vfs, vfs_ops};
use crate::initramfs;

/// Set once `mount_initramfs()` completes successfully.
static MOUNTED: AtomicBool = AtomicBool::new(false);

/// Walk the CPIO initramfs and create corresponding VFS entries.
pub fn mount_initramfs() {
    if MOUNTED.load(Ordering::Acquire) {
        return;
    }

    if !initramfs::has_initramfs_range() {
        crate::kprintln!("initramfs: none provided — continuing with ramfs only");
        MOUNTED.store(true, Ordering::Release);
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

        let mode = entry.mode;
        let file_type = mode & 0o170000;

        match file_type {
            0o040000 => {
                let _ = vfs_ops::mkdir(&path);
            },

            0o100000 => {
                // Ensure parent directory exists first.
                if let Some(parent) = parent_of(&path) {
                    let _ = vfs_ops::mkdir(&parent);
                }
                let _ = vfs::create_file(&path, entry.data);
            },

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
                    let _ = vfs::create_file(&path, target_bytes);
                }
            },

            _ => {},
        }
    }

    MOUNTED.store(true, Ordering::Release);
    crate::kprintln!(
        "initramfs: mounted {} entries into VFS",
        count_entries(&handle)
    );
}

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
