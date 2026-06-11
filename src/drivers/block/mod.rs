//! Block and storage drivers.
//!
//! ## Modules
//!   ahci — AHCI SATA controller
//!   nvme — NVMe host controller
//!
//! For the VirtIO block device, use `crate::block::virtio_blk` directly
//! or the multi-sector helpers (`read_sectors`, `write_sectors`,
//! `read_sectors_vec`, `write_sectors_raw`) exported from this module.

pub mod ahci;
pub mod nvme;

extern crate alloc;

const SECTOR_SIZE: usize = 512;

#[inline]
fn required_len(count: u32) -> Option<usize> {
    (count as usize).checked_mul(SECTOR_SIZE)
}

/// Read `count` 512-byte sectors starting at `lba` into `buf`.
/// Returns `false` if `buf` is too small, `count` overflows, or any sector read fails.
pub fn read_sectors(lba: u64, count: u32, buf: &mut [u8]) -> bool {
    let Some(len) = required_len(count) else {
        return false;
    };

    if buf.len() < len {
        return false;
    }

    for i in 0..count as usize {
        let off = i * SECTOR_SIZE;
        let mut tmp = [0u8; SECTOR_SIZE];

        if !crate::block::virtio_blk::read_sector(lba + i as u64, &mut tmp) {
            return false;
        }

        buf[off..off + SECTOR_SIZE].copy_from_slice(&tmp);
    }

    true
}

/// Write `count` 512-byte sectors starting at `lba` from `buf`.
/// Returns `false` if `buf` is too small, `count` overflows, or any sector write fails.
pub fn write_sectors(lba: u64, count: u32, buf: &[u8]) -> bool {
    let Some(len) = required_len(count) else {
        return false;
    };

    if buf.len() < len {
        return false;
    }

    for i in 0..count as usize {
        let off = i * SECTOR_SIZE;
        let mut tmp = [0u8; SECTOR_SIZE];
        tmp.copy_from_slice(&buf[off..off + SECTOR_SIZE]);

        if !crate::block::virtio_blk::write_sector(lba + i as u64, &tmp) {
            return false;
        }
    }

    true
}

/// Read `count` sectors into a freshly allocated buffer.
/// Returns `None` on overflow, allocation, or I/O failure.
pub fn read_sectors_vec(lba: u64, count: u32) -> Option<alloc::vec::Vec<u8>> {
    let len = required_len(count)?;
    let mut v = alloc::vec![0u8; len];

    if read_sectors(lba, count, &mut v) {
        Some(v)
    } else {
        None
    }
}

/// Write a byte slice to disk starting at `lba`.
/// `data` must be a non-zero multiple of 512 bytes; returns an error otherwise.
pub fn write_sectors_raw(lba: u64, data: &[u8]) -> Result<(), &'static str> {
    if data.is_empty() || data.len() % SECTOR_SIZE != 0 {
        return Err("unaligned block write");
    }

    let count = (data.len() / SECTOR_SIZE) as u32;

    if write_sectors(lba, count, data) {
        Ok(())
    } else {
        Err("block write failed")
    }
}
