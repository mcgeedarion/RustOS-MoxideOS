//! x86_64 boot-time memory discovery.
//!
//! Converts UEFI memory information into the common
//! `mm::boot_memory::Regions` description that the PMM consumes.

use crate::mm::boot_memory::{Region, RegionKind, Regions};
use crate::mm::memmap::{BootSource, BOOT_SOURCE, UEFI_DESC_SIZE, UEFI_MMAP_BUF, UEFI_MMAP_SIZE};

/// Build a `Regions` description from the current boot source.
///
/// This mirrors the logic in `mm::memmap` but returns a structured
/// representation instead of calling into `pmm` directly.
pub fn discover() -> Regions {
    match unsafe { BOOT_SOURCE } {
        BootSource::Uefi => discover_uefi(),
        BootSource::Unknown => Regions::new(),
    }
}

fn discover_uefi() -> Regions {
    let mut regions = Regions::new();
    let buf = unsafe { &UEFI_MMAP_BUF[..UEFI_MMAP_SIZE] };
    let dsz = unsafe { UEFI_DESC_SIZE };
    if dsz == 0 {
        return regions;
    }
    let mut off = 0usize;
    const EFI_CONVENTIONAL: u32 = 7;
    while off + dsz <= buf.len() {
        let mem_type = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let phys: u64 = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap());
        let npages: u64 = u64::from_le_bytes(buf[off + 24..off + 32].try_into().unwrap());
        if mem_type == EFI_CONVENTIONAL {
            regions.push(Region {
                start: phys,
                length: npages * 4096,
                kind: RegionKind::Usable,
            });
        }
        off += dsz;
    }
    regions
}
