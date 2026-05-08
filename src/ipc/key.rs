//! IPC key management.
//!
//! `ftok(path, proj_id)` converts a filesystem path + project ID into a
//! `key_t`.  On Linux the formula is:
//!
//!   key = (proj_id & 0xFF) << 24
//!       | (major(st_dev) & 0xFF) << 16
//!       | (minor(st_dev) & 0xFF) << 8
//!       | (st_ino & 0xFF)
//!
//! Since we don't have real device numbers yet, we hash the path bytes
//! and combine with `proj_id`.  Programs using `IPC_PRIVATE` (key = 0)
//! bypass this entirely.

/// Kernel-internal `ftok` approximation.
/// Real implementation should use `vfs_stat(path).st_dev / st_ino`.
pub fn ftok(path: &[u8], proj_id: u8) -> i32 {
    let mut h: u32 = 0x1505;
    for &b in path {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    ((proj_id as u32) << 24 | (h & 0x00FF_FFFF)) as i32
}
