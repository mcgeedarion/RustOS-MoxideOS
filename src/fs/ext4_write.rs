//! Ext4 **write path** — create, unlink, mkdir, rename, write, truncate,
//! fsync, and extended attributes.
//!
//! This module works on the same in-memory image loaded by `ext4::mount()`
//! and flushes dirty blocks back to the virtio-blk device via
//! `virtio_blk::write_sectors`.
//!
//! # Design
//! All mutating operations hold the `FS` mutex for the duration of the call
//! so there are no partial-write windows visible to readers.
//!
//! The journal (if present) is intentionally bypassed.  We mark the
//! superblock `s_state` as `EXT4_ERROR_FS` on mount and clear it on a
//! clean unmount.  If the kernel crashes mid-write the host e2fsck can
//! recover.  A proper jbd2 journal is future work.

extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::string::ToString;
use spin::Mutex;

use crate::fs::ext4::{
    mount as ext4_mount,
    stat,
    file_size,
    readdir_raw,
    sys_stat,
    Ext4Stat,
};

// ── errno shorthand ────────────────────────────────────────────────────────
const ENOENT: i32 = -2;
const EIO:    i32 = -5;
const EEXIST: i32 = -17;
const ENOTEMPTY: i32 = -39;
const ENOSPC: i32 = -28;
const EINVAL: i32 = -22;
const EROFS:  i32 = -30;
const EPERM:  i32 = -1;

// ── dirty-block tracker ────────────────────────────────────────────────────
//
// We keep a list of block numbers that have been modified since the last
// flush.  flush_dirty() writes each one back to the block device in order.

static DIRTY: Mutex<Vec<u64>> = Mutex::new(Vec::new());

fn mark_dirty(blkno: u64) {
    let mut d = DIRTY.lock();
    if !d.contains(&blkno) { d.push(blkno); }
}

/// Write all dirty blocks back to the virtio-blk device.
/// Called by sys_fsync and on clean unmount.
pub fn flush_dirty() -> i32 {
    use crate::fs::ext4; // re-use FS lock via raw access

    let blknos: Vec<u64> = {
        let mut d = DIRTY.lock();
        let out = d.clone();
        d.clear();
        out
    };

    for blkno in blknos {
        if write_block(blkno).is_err() { return EIO; }
    }
    0
}

// Write a single block (identified by blkno) from the in-memory image to
// the block device.
fn write_block(blkno: u64) -> Result<(), ()> {
    // We need the block size and the raw data slice.
    // Acquire the FS read-lock long enough to copy the block.
    let (block_size, block_data) = {
        // SAFETY: we only read here
        let guard = unsafe {
            // Access the private FS static via the public ext4 module.
            // Because Rust doesn't expose private statics across modules we
            // do this via a dedicated helper added to ext4.rs.
            crate::fs::ext4::copy_block(blkno)
        };
        match guard { Some(v) => v, None => return Err(()) }
    };

    let lba_start = (blkno * (block_size / 512) as u64);
    let sectors   = block_size / 512;
    let mut off   = 0usize;
    let mut lba   = lba_start;
    while off < block_data.len() {
        let chunk = &block_data[off..off + 512];
        crate::drivers::virtio_blk::write_sector(lba, chunk).map_err(|_| ())?;
        off += 512;
        lba += 1;
    }
    Ok(())
}

// ── bitmap helpers ─────────────────────────────────────────────────────────

/// Allocate a free bit in a bitmap block; return bit index or None.
fn alloc_bit(data: &mut Vec<u8>, blk_off: usize, count: usize) -> Option<usize> {
    for i in 0..count {
        let byte = blk_off + i / 8;
        let bit  = i % 8;
        if byte < data.len() && data[byte] & (1 << bit) == 0 {
            data[byte] |= 1 << bit;
            return Some(i);
        }
    }
    None
}

fn free_bit(data: &mut Vec<u8>, blk_off: usize, idx: usize) {
    let byte = blk_off + idx / 8;
    let bit  = idx % 8;
    if byte < data.len() {
        data[byte] &= !(1 << bit);
    }
}

// ── public write API ───────────────────────────────────────────────────────

/// Write `buf` to the file at `path` starting at `offset`.
/// Creates the file if it does not exist (O_CREAT | O_WRONLY semantics).
/// Returns bytes written or a negative errno.
pub fn write(path: &str, buf: &[u8], offset: u64) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.write_file(path, buf, offset))
        .unwrap_or(EIO)
}

/// Truncate or extend the file at `path` to exactly `len` bytes.
pub fn truncate(path: &str, len: u64) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.truncate_file(path, len))
        .unwrap_or(EIO)
}

/// Create a new empty regular file.
pub fn create(path: &str, mode: u16) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.create_file(path, mode))
        .unwrap_or(EIO)
}

/// Remove a regular file or empty directory.
pub fn unlink(path: &str) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.unlink_path(path, false))
        .unwrap_or(EIO)
}

/// Remove an empty directory.
pub fn rmdir(path: &str) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.unlink_path(path, true))
        .unwrap_or(EIO)
}

/// Create a new directory.
pub fn mkdir(path: &str, mode: u16) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.mkdir_path(path, mode))
        .unwrap_or(EIO)
}

/// Rename / move a path.
pub fn rename(old: &str, new: &str) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.rename_path(old, new))
        .unwrap_or(EIO)
}

/// Hard-link `old` as `new`.
pub fn link(old: &str, new: &str) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.link_path(old, new))
        .unwrap_or(EIO)
}

/// Create a symlink `path` → `target`.
pub fn symlink(target: &str, path: &str) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.symlink_path(target, path))
        .unwrap_or(EIO)
}

/// Change file permissions.
pub fn chmod(path: &str, mode: u16) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.chmod_path(path, mode))
        .unwrap_or(EIO)
}

/// Change file owner.
pub fn chown(path: &str, uid: u32, gid: u32) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.chown_path(path, uid, gid))
        .unwrap_or(EIO)
}

/// Update atime/mtime.
pub fn utimens(path: &str, atime_ns: u64, mtime_ns: u64) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.utimens_path(path, atime_ns, mtime_ns))
        .unwrap_or(EIO)
}

/// Flush dirty blocks to the block device.
pub fn fsync(_path: &str) -> i32 {
    flush_dirty()
}

// ── xattr ──────────────────────────────────────────────────────────────────

/// Get the value of extended attribute `name` on `path`.
/// Returns the raw byte value or a negative errno.
pub fn getxattr(path: &str, name: &str) -> Result<Vec<u8>, i32> {
    crate::fs::ext4::with_fs(|fs| fs.getxattr_path(path, name))
        .unwrap_or(Err(EIO))
}

/// Set extended attribute `name` = `value` on `path`.
pub fn setxattr(path: &str, name: &str, value: &[u8], flags: u32) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.setxattr_path(path, name, value, flags))
        .unwrap_or(EIO)
}

/// List the names of all extended attributes on `path`.
pub fn listxattr(path: &str) -> Result<Vec<String>, i32> {
    crate::fs::ext4::with_fs(|fs| fs.listxattr_path(path))
        .unwrap_or(Err(EIO))
}

/// Remove extended attribute `name` from `path`.
pub fn removexattr(path: &str, name: &str) -> i32 {
    crate::fs::ext4::with_fs_mut(|fs| fs.removexattr_path(path, name))
        .unwrap_or(EIO)
}
