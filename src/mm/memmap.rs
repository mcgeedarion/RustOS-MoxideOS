//! Boot memory map consumer — Phase 2.
//!
//! Reads the memory map provided by the bootloader and feeds usable
//! ranges to pmm_add_region().  Called once during kernel_main, after
//! heap_init() and before any large allocation.
//!
//! ## Supported map formats
//!   1. UEFI memory map  — stored by uefi_entry.rs in UEFI_MMAP.
//!   2. Multiboot2 mmap  — EBX pointer stored by _start in MB2_INFO_PA.
//!
//! ## Physical-to-virtual translation
//!
//! All arch-specific PA → VA translation is delegated to the arch
//! `mem_layout` module.  No local copy of PHYS_OFFSET lives here.

/// How this kernel instance was booted.
#[derive(Clone, Copy, PartialEq)]
pub enum BootSource {
    Uefi,
    Multiboot2,
    Unknown,
}

pub static mut BOOT_SOURCE: BootSource = BootSource::Unknown;

#[cfg(target_arch = "x86_64")]
#[inline]
fn phys_to_virt(pa: u64) -> usize {
    crate::arch::x86_64::mem_layout::higher_half::phys_to_virt(pa)
}

#[cfg(target_arch = "riscv64")]
#[inline]
fn phys_to_virt(pa: u64) -> usize {
    // RISC-V: PHYS_OFFSET is determined by the linker script (not a fixed
    // constant).  Read KERNEL_PHYS_BASE, which the linker exports, and
    // use it as the physmap window base.
    extern "C" {
        static KERNEL_PHYS_BASE: usize;
    }
    unsafe { pa as usize + KERNEL_PHYS_BASE }
}

// ── UEFI memory map ───────────────────────────────────────────────────────────

pub static mut UEFI_MMAP_BUF: [u8; 8192] = [0u8; 8192];
pub static mut UEFI_MMAP_SIZE: usize = 0;
pub static mut UEFI_DESC_SIZE: usize = 0;

const EFI_CONVENTIONAL: u32 = 7;

fn ingest_uefi() {
    let buf = unsafe { &UEFI_MMAP_BUF[..UEFI_MMAP_SIZE] };
    let dsz = unsafe { UEFI_DESC_SIZE };
    if dsz == 0 {
        return;
    }
    let mut off = 0usize;
    while off + dsz <= buf.len() {
        let mem_type = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap());
        let phys: u64 = u64::from_le_bytes(buf[off + 8..off + 16].try_into().unwrap());
        let npages: u64 = u64::from_le_bytes(buf[off + 24..off + 32].try_into().unwrap());
        if mem_type == EFI_CONVENTIONAL {
            crate::mm::pmm::pmm_add_region(phys as usize, (npages * 4096) as usize);
        }
        off += dsz;
    }
}

// ── Multiboot2 memory map ─────────────────────────────────────────────────────

pub static mut MB2_INFO_PA: u64 = 0;

const MB2_TAG_MMAP: u32 = 6;
const MB2_TAG_END: u32 = 0;
const MB2_MEM_AVAIL: u32 = 1;
const MB2_MAX_INFO_SIZE: usize = 65536;

fn ingest_multiboot2() {
    let info_pa = unsafe { MB2_INFO_PA };
    if info_pa == 0 {
        return;
    }
    let info_va = phys_to_virt(info_pa);
    let raw_total = unsafe { (info_va as *const u32).read_unaligned() } as usize;
    let total_size = raw_total.min(MB2_MAX_INFO_SIZE);
    let mut off = 8usize;
    while off + 8 <= total_size {
        let tag_va = info_va + off;
        let tag_type = unsafe { (tag_va as *const u32).read_unaligned() };
        let tag_size = unsafe { ((tag_va + 4) as *const u32).read_unaligned() } as usize;
        if tag_size < 8 {
            break;
        }
        if tag_type == MB2_TAG_END {
            break;
        }
        if tag_type == MB2_TAG_MMAP {
            let entry_size = unsafe { ((tag_va + 8) as *const u32).read_unaligned() } as usize;
            if entry_size == 0 {
                off += (tag_size + 7) & !7;
                continue;
            }
            let entries_off = 16usize;
            let entries_end = tag_size;
            let mut e = entries_off;
            while e + entry_size <= entries_end {
                let ev = tag_va + e;
                let base = unsafe { (ev as *const u64).read_unaligned() };
                let len = unsafe { ((ev + 8) as *const u64).read_unaligned() };
                let mtype = unsafe { ((ev + 16) as *const u32).read_unaligned() };
                if mtype == MB2_MEM_AVAIL {
                    crate::mm::pmm::pmm_add_region(base as usize, len as usize);
                }
                e += entry_size;
            }
        }
        off += (tag_size + 7) & !7;
    }
}

// ── Public API ────────────────────────────────────────────────────────────────

pub fn memmap_init() {
    match unsafe { BOOT_SOURCE } {
        BootSource::Uefi => ingest_uefi(),
        BootSource::Multiboot2 => ingest_multiboot2(),
        BootSource::Unknown => {}
    }
    crate::log::kprintln!(
        "pmm: {} MiB total, {} MiB free",
        crate::mm::pmm::total_pages() * 4 / 1024,
        crate::mm::pmm::free_pages() * 4 / 1024,
    );
}
