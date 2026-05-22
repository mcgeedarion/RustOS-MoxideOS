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
pub enum BootSource { Uefi, Multiboot2, Unknown }

pub static mut BOOT_SOURCE: BootSource = BootSource::Unknown;

#[cfg(target_arch = "x86_64")]
#[inline]
fn phys_to_virt(pa: u64) -> usize {
    crate::arch::x86_64::mem_layout::higher_half::phys_to_virt(pa)
}

#[cfg(target_arch = "riscv64")]
#[inline]
fn phys_to_virt(pa: u64) -> usize {
    extern "C" { static KERNEL_PHYS_BASE: usize; }
    unsafe { pa as usize + KERNEL_PHYS_BASE }
}

// UEFI / Multiboot2 ingestion now lives in arch-specific memory
// discovery (arch::<arch>::memory::discover) which returns
// `mm::boot_memory::Regions`. This module remains as a thin
// compatibility layer if needed by existing callers.

pub fn memmap_init() {
    crate::log::kprintln!(
        "pmm: {} MiB total, {} MiB free",
        crate::mm::pmm::total_pages() * 4 / 1024,
        crate::mm::pmm::free_pages()  * 4 / 1024,
    );
}
