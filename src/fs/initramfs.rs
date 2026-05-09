//! VFS bridge: populate a ramfs mount from the CPIO initramfs.
//!
//! After the PMM and heap are up, `mount_initramfs()` walks every entry in
//! the CPIO archive and inserts it into a freshly-mounted ramfs instance.
//! The resulting VFS tree is then available to `open(2)` / `execve(2)`.
//!
//! Callers should do:
//! ```
//! fs::initramfs::mount_initramfs();
//! ```
//! before the first `execve`.

use crate::{
    fs::ramfs,
    initramfs as cpio,
};

/// Walk the CPIO archive and create the corresponding VFS nodes in a ramfs.
///
/// Directories are created first (in archive order), then regular files and
/// symlinks.  Hard-link pairs (nlink > 1) are represented as independent
/// copies — true hard-link accounting would require inode deduplication which
/// is not yet implemented in ramfs.
pub fn mount_initramfs() {
    let archive = cpio::load();

    let mut dirs_seen  = 0usize;
    let mut files_seen = 0usize;
    let mut links_seen = 0usize;

    for entry in archive.entries() {
        let path = entry.name; // already stripped of leading "./" and "/"

        if entry.is_dir() {
            if path.is_empty() { continue; } // skip the "."/"" root entry
            match ramfs::mkdir(path, entry.permissions()) {
                Ok(())  => dirs_seen  += 1,
                Err(e)  => crate::println!("initramfs: mkdir {:?} failed: {:?}", path, e),
            }
        } else if entry.is_symlink() {
            // symlink target is stored as the file data
            if let Ok(target) = core::str::from_utf8(entry.data) {
                match ramfs::symlink(path, target) {
                    Ok(())  => links_seen += 1,
                    Err(e)  => crate::println!("initramfs: symlink {:?} -> {:?} failed: {:?}", path, target, e),
                }
            }
        } else if entry.is_file() {
            match ramfs::create_file(path, entry.permissions(), entry.data) {
                Ok(())  => files_seen += 1,
                Err(e)  => crate::println!("initramfs: create {:?} failed: {:?}", path, e),
            }
        }
    }

    crate::println!(
        "initramfs: mounted {} dirs, {} files, {} symlinks",
        dirs_seen, files_seen, links_seen,
    );
}
