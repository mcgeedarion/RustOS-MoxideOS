//! Compatibility shim for older callsites using `crate::drivers::virtio_blk`.
//!
//! Prefer `crate::block::virtio_blk` for the raw VirtIO block driver or
//! `crate::drivers::block` for multi-sector helpers.

extern crate alloc;

pub use crate::block::virtio_blk::*;

const SECTOR_SIZE: usize = 512;

#[inline]
fn required_len(count: u32) -> Option<usize> {
    (count as usize).checked_mul(SECTOR_SIZE)
}

/// Multi-sector read helper. Returns `false` if `buf` is too small or I/O fails.
#[inline]
pub fn read_sectors(lba: u64, count: u32, buf: &mut [u8]) -> bool {
    let Some(len) = required_len(count) else {
        return false;
    };

    if buf.len() < len {
        return false;
    }

    crate::drivers::block::read_sectors(lba, count, buf)
}

/// Multi-sector write helper. Returns `false` if `buf` is too small or I/O fails.
#[inline]
pub fn write_sectors(lba: u64, count: u32, buf: &[u8]) -> bool {
    let Some(len) = required_len(count) else {
        return false;
    };

    if buf.len() < len {
        return false;
    }

    crate::drivers::block::write_sectors(lba, count, buf)
}

/// Read `count` sectors into a freshly allocated buffer.
/// Returns `None` if overflow, allocation failure, or I/O error.
#[inline]
pub fn read_sectors_vec(lba: u64, count: u32) -> Option<alloc::vec::Vec<u8>> {
    let len = required_len(count)?;
    let mut buf = alloc::vec![0u8; len];

    if read_sectors(lba, count, &mut buf) {
        Some(buf)
    } else {
        None
    }
}

/// Returns `true` only after `virtio_blk_init` has completed successfully.
#[inline]
pub fn is_present() -> bool {
    crate::block::virtio_blk::is_present()
}
