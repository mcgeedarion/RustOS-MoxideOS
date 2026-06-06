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

// ====================================================================
// Bootloader hand-off state (populated by the architecture entry stub).
//
// GUESS: these were previously declared somewhere outside the tree (the
// arch/x86_64/uefi_entry.rs and _start paths reference them through the
// `crate::mm::memmap::*` path). The fields below are the minimum shape
// required by `arch::x86_64::memory::discover_*` and by the read sites
// in this file. UEFI_MMAP_BUF is intentionally large enough for the
// typical mid-firmware map (~96 descriptors of 48 bytes each).
// ====================================================================

/// Maximum number of bytes of UEFI memory map the bootloader is
/// allowed to stash here. Sized for ~96 descriptors of up to 64 B each.
pub const UEFI_MMAP_MAX: usize = 8192;

/// Buffer that holds the UEFI memory map between the firmware hand-off
/// and `discover_uefi()`. Written by `arch::x86_64::uefi_entry`.
pub static mut UEFI_MMAP_BUF: [u8; UEFI_MMAP_MAX] = [0; UEFI_MMAP_MAX];

/// Number of bytes actually populated in [`UEFI_MMAP_BUF`].
pub static mut UEFI_MMAP_SIZE: usize = 0;

/// Size of a single UEFI memory descriptor (varies with firmware
/// version). `0` means "no UEFI map was provided".
pub static mut UEFI_DESC_SIZE: usize = 0;

/// Physical address of the Multiboot2 information structure stashed by
/// the `_start` asm path. `0` means the boot was not Multiboot2.
pub static mut MB2_INFO_PA: u64 = 0;

#[cfg(target_arch = "x86_64")]
#[inline]
fn phys_to_virt(pa: u64) -> usize {
    crate::arch::x86_64::mem_layout::higher_half::phys_to_virt(pa)
}

#[cfg(target_arch = "riscv64")]
#[inline]
fn phys_to_virt(pa: u64) -> usize {
    extern "C" {
        static KERNEL_PHYS_BASE: usize;
    }
    unsafe { pa as usize + KERNEL_PHYS_BASE }
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn phys_to_virt(pa: u64) -> usize {
    crate::arch::aarch64::mem_layout::va48::phys_to_virt(pa as usize)
}

// UEFI / Multiboot2 ingestion now lives in arch-specific memory
// discovery (arch::<arch>::memory::discover) which returns
// `mm::boot_memory::Regions`. This module remains as a thin
// compatibility layer if needed by existing callers.

pub fn memmap_init() {
    crate::log::kprintln!(
        "pmm: {} MiB total, {} MiB free",
        crate::mm::pmm::total_pages() * 4 / 1024,
        crate::mm::pmm::free_pages() * 4 / 1024,
    );
}
