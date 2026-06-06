//! virtio-blk driver re-export.
//!
//! Canonical driver path for block callsites:
//! `crate::drivers::virtio_blk::*`.

pub use crate::block::virtio_blk::*;

// ===== GUESS: multi-sector helpers + is_present probe =====

/// GUESS: alias to the multi-sector helper in `drivers::block`.
#[inline]
pub fn read_sectors(lba: u64, count: u32, buf: &mut [u8]) -> bool {
    crate::drivers::block::read_sectors(lba, count, buf)
}

/// GUESS: alias to the multi-sector helper in `drivers::block`.
#[inline]
pub fn write_sectors(lba: u64, count: u32, buf: &[u8]) -> bool {
    crate::drivers::block::write_sectors(lba, count, buf)
}

/// GUESS: Vec-returning convenience.
#[inline]
pub fn read_sectors_vec(lba: u64, count: u32) -> alloc::vec::Vec<u8> {
    crate::drivers::block::read_sectors_vec(lba, count)
}

/// GUESS: presence probe. We don't track init state across the static
/// driver — return true to allow FS init to attempt I/O and fail gracefully.
#[inline]
pub fn is_present() -> bool { true }

