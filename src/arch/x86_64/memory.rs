//! x86_64 boot-time memory discovery.
//!
//! Converts UEFI / Multiboot2 memory information into the common
//! `mm::boot_memory::Regions` description that the PMM consumes.

use crate::mm::boot_memory::{Region, RegionKind, Regions};
use crate::mm::memmap::{BootSource, BOOT_SOURCE, MB2_INFO_PA, UEFI_DESC_SIZE, UEFI_MMAP_BUF, UEFI_MMAP_SIZE};

/// Build a `Regions` description from the current boot source.
///
/// This mirrors the logic in `mm::memmap` but returns a structured
/// representation instead of calling into `pmm` directly.
pub fn discover() -> Regions {
    match unsafe { BOOT_SOURCE } {
        BootSource::Uefi       => discover_uefi(),
        BootSource::Multiboot2 => discover_multiboot2(),
        BootSource::Unknown    => Regions::new(),
    }
}

fn discover_uefi() -> Regions {
    let mut regions = Regions::new();
    let buf  = unsafe { &UEFI_MMAP_BUF[..UEFI_MMAP_SIZE] };
    let dsz  = unsafe { UEFI_DESC_SIZE };
    if dsz == 0 { return regions; }
    let mut off = 0usize;
    const EFI_CONVENTIONAL: u32 = 7;
    while off + dsz <= buf.len() {
        let mem_type = u32::from_le_bytes(buf[off..off+4].try_into().unwrap());
        let phys:   u64 = u64::from_le_bytes(buf[off+8..off+16].try_into().unwrap());
        let npages: u64 = u64::from_le_bytes(buf[off+24..off+32].try_into().unwrap());
        if mem_type == EFI_CONVENTIONAL {
            regions.push(Region {
                start:  phys,
                length: npages * 4096,
                kind:   RegionKind::Usable,
            });
        }
        off += dsz;
    }
    regions
}

fn discover_multiboot2() -> Regions {
    let mut regions = Regions::new();
    let info_pa = unsafe { MB2_INFO_PA };
    if info_pa == 0 { return regions; }

    // The multiboot2 parsing logic in mm::memmap uses a helper phys_to_virt.
    // Here we replicate only what we need to obtain the memory map.
    #[cfg(target_arch = "x86_64")]
    fn phys_to_virt(pa: u64) -> usize {
        crate::arch::x86_64::mem_layout::higher_half::phys_to_virt(pa)
    }

    let info_va = phys_to_virt(info_pa);
    const MB2_TAG_MMAP:  u32 = 6;
    const MB2_TAG_END:   u32 = 0;
    const MB2_MEM_AVAIL: u32 = 1;
    const MB2_MAX_INFO_SIZE: usize = 65536;

    let raw_total = unsafe { (info_va as *const u32).read_unaligned() } as usize;
    let total_size = raw_total.min(MB2_MAX_INFO_SIZE);
    let mut off = 8usize;
    while off + 8 <= total_size {
        let tag_va   = info_va + off;
        let tag_type = unsafe { (tag_va as *const u32).read_unaligned() };
        let tag_size = unsafe { ((tag_va + 4) as *const u32).read_unaligned() } as usize;
        if tag_size < 8 { break; }
        if tag_type == MB2_TAG_END { break; }
        if tag_type == MB2_TAG_MMAP {
            let entry_size = unsafe { ((tag_va + 8) as *const u32).read_unaligned() } as usize;
            if entry_size == 0 { off += (tag_size + 7) & !7; continue; }
            let entries_off = 16usize;
            let entries_end = tag_size;
            let mut e = entries_off;
            while e + entry_size <= entries_end {
                let ev    = tag_va + e;
                let base  = unsafe { (ev as *const u64).read_unaligned() };
                let len   = unsafe { ((ev + 8) as *const u64).read_unaligned() };
                let mtype = unsafe { ((ev + 16) as *const u32).read_unaligned() };
                if mtype == MB2_MEM_AVAIL {
                    regions.push(Region {
                        start:  base,
                        length: len,
                        kind:   RegionKind::Usable,
                    });
                }
                e += entry_size;
            }
        }
        off += (tag_size + 7) & !7;
    }

    regions
}
