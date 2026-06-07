//! Ext4 write API surface.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

const EIO: i32 = -5;
const EROFS: i32 = -30;
const ENOTSUP: i32 = -95;

/// Write all dirty ext4 blocks back to the block device.
pub fn flush_dirty() -> i32 {
    0
}

/// Write `buf` to the file at `path` starting at `offset`.
pub fn write(_path: &str, _buf: &[u8], _offset: u64) -> i32 {
    EROFS
}

/// Truncate or extend the file at `path` to exactly `len` bytes.
pub fn truncate(_path: &str, _len: u64) -> i32 {
    EROFS
}

/// Create a new empty regular file.
pub fn create(_path: &str, _mode: u16) -> i32 {
    EROFS
}

/// Remove a regular file or empty directory.
pub fn unlink(_path: &str) -> i32 {
    EROFS
}

/// Remove an empty directory.
pub fn rmdir(_path: &str) -> i32 {
    EROFS
}

/// Create a new directory.
pub fn mkdir(_path: &str, _mode: u16) -> i32 {
    EROFS
}

/// Rename / move a path.
pub fn rename(_old: &str, _new: &str) -> i32 {
    EROFS
}

/// Hard-link `old` as `new`.
pub fn link(_old: &str, _new: &str) -> i32 {
    EROFS
}

/// Create a symlink `path` -> `target`.
pub fn symlink(_target: &str, _path: &str) -> i32 {
    EROFS
}

/// Change file permissions.
pub fn chmod(_path: &str, _mode: u16) -> i32 {
    EROFS
}

/// Change file owner.
pub fn chown(_path: &str, _uid: u32, _gid: u32) -> i32 {
    EROFS
}

/// Update atime/mtime.
pub fn utimens(_path: &str, _atime_ns: u64, _mtime_ns: u64) -> i32 {
    EROFS
}

/// Flush dirty blocks to the block device.
pub fn fsync(_path: &str) -> i32 {
    flush_dirty()
}

/// Get the value of extended attribute `name` on `path`.
pub fn getxattr(_path: &str, _name: &str) -> Result<Vec<u8>, i32> {
    Err(ENOTSUP)
}

/// Set extended attribute `name` = `value` on `path`.
pub fn setxattr(_path: &str, _name: &str, _value: &[u8], _flags: u32) -> i32 {
    EROFS
}

/// List the names of all extended attributes on `path`.
pub fn listxattr(_path: &str) -> Result<Vec<String>, i32> {
    Err(ENOTSUP)
}

/// Remove extended attribute `name` from `path`.
pub fn removexattr(_path: &str, _name: &str) -> i32 {
    EROFS
}
