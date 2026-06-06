//! Block and storage drivers.
//!
//! ## Modules
//!   ahci       — AHCI SATA controller
//!   nvme       — NVMe host controller
//!   virtio_blk — VirtIO block device

pub mod ahci;
pub mod nvme;
pub mod virtio_blk;

// ===== GUESS: multi-sector helpers wrapping virtio_blk's single-sector API =====

/// GUESS: read `count` 512-byte sectors starting at `lba` into `buf`.
/// Buf must be at least `count * 512` bytes.
pub fn read_sectors(lba: u64, count: u32, buf: &mut [u8]) -> bool {
    const SS: usize = 512;
    for i in 0..count as usize {
        let off = i * SS;
        let mut tmp = [0u8; SS];
        if !crate::block::virtio_blk::read_sector(lba + i as u64, &mut tmp) {
            return false;
        }
        buf[off..off + SS].copy_from_slice(&tmp);
    }
    true
}

/// GUESS: write `count` 512-byte sectors starting at `lba` from `buf`.
pub fn write_sectors(lba: u64, count: u32, buf: &[u8]) -> bool {
    const SS: usize = 512;
    for i in 0..count as usize {
        let off = i * SS;
        let mut tmp = [0u8; SS];
        tmp.copy_from_slice(&buf[off..off + SS]);
        if !crate::block::virtio_blk::write_sector(lba + i as u64, &tmp) {
            return false;
        }
    }
    true
}

/// GUESS: convenience returning the read bytes as a Vec.
pub fn read_sectors_vec(lba: u64, count: u32) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec![0u8; count as usize * 512];
    let _ = read_sectors(lba, count, &mut v);
    v
}
