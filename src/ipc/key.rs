//! IPC key management (`ftok`).
//!
//! On Linux the formula for `ftok(path, proj_id)` is:
//!
//! ```text
//! key = (proj_id & 0xFF) << 24
//!     | (major(st_dev) & 0xFF) << 16
//!     | (minor(st_dev) & 0xFF) << 8
//!     | (st_ino & 0xFF)
//! ```
//!
//! Until real device numbers are available we hash the path bytes and
//! combine with `proj_id`.  Callers using `IPC_PRIVATE` (key = 0) bypass
//! this entirely.

/// Kernel-internal `ftok` approximation.
/// Replace with `vfs_stat(path).st_dev / st_ino` once VFS stat is stable.
pub fn ftok(path: &[u8], proj_id: u8) -> i32 {
    let mut h: u32 = 0x1505;
    for &b in path {
        h = h.wrapping_mul(31).wrapping_add(b as u32);
    }
    ((proj_id as u32) << 24 | (h & 0x00FF_FFFF)) as i32
}
