//! Physical ↔ virtual address translation.
//!
//! We use a fixed kernel virtual-memory layout:
//!
//!   PHYS_OFFSET is the base virtual address at which all of physical memory
//!   is mapped ("direct map" / "physmap").  This is architecture-specific:
//!
//!   ARM64    — 0xFFFF_0000_0000_0000  (top of canonical VA range)
//!   RISC-V   — 0xFFFF_FFD8_0000_0000  (SV48 direct map)
//!   x86_64   — 0xFFFF_8880_0000_0000  (Linux-compatible direct map)
//!
//! These match the paging setup in `arch/*/mm/` so the functions below are
//! zero-overhead inline arithmetic.

// Require a 64-bit target; avoids silent truncation of the PHYS_OFFSET constants.
const _: () = assert!(
    core::mem::size_of::<usize>() == 8,
    "RustOS requires a 64-bit target (usize must be 8 bytes)"
);

cfg_if::cfg_if! {
    if #[cfg(target_arch = "aarch64")] {
        pub const PHYS_OFFSET: usize = 0xFFFF_0000_0000_0000;
    } else if #[cfg(target_arch = "riscv64")] {
        pub const PHYS_OFFSET: usize = 0xFFFF_FFD8_0000_0000;
    } else if #[cfg(target_arch = "x86_64")] {
        pub const PHYS_OFFSET: usize = 0xFFFF_8880_0000_0000;
    } else {
        compile_error!("unsupported architecture: add PHYS_OFFSET for this target");
    }
}

// ---------------------------------------------------------------------------
// Core translations
// ---------------------------------------------------------------------------

/// Convert a kernel virtual address in the direct map to its physical address.
///
/// # Panics (debug)
/// Panics in debug builds if `vaddr` is below `PHYS_OFFSET` (would underflow).
#[inline(always)]
pub fn virt_to_phys(vaddr: usize) -> usize {
    debug_assert!(
        vaddr >= PHYS_OFFSET,
        "virt_to_phys: vaddr {:#x} is below PHYS_OFFSET {:#x}",
        vaddr,
        PHYS_OFFSET
    );
    vaddr.wrapping_sub(PHYS_OFFSET)
}

/// Convert a physical address to its kernel virtual address in the direct map.
///
/// # Panics (debug)
/// Panics in debug builds if the addition would overflow (paddr too large).
#[inline(always)]
pub fn phys_to_virt(paddr: usize) -> usize {
    debug_assert!(
        paddr.checked_add(PHYS_OFFSET).is_some(),
        "phys_to_virt: overflow for paddr {:#x}",
        paddr
    );
    paddr.wrapping_add(PHYS_OFFSET)
}

// ---------------------------------------------------------------------------
// Alignment helpers
// ---------------------------------------------------------------------------

/// Round `addr` down to the nearest multiple of `align`.
///
/// `align` must be a power of two.
#[inline(always)]
pub const fn align_down(addr: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two(), "align must be a power of two");
    addr & !(align - 1)
}

/// Round `addr` up to the nearest multiple of `align`.
///
/// `align` must be a power of two.  Returns `None` on overflow.
#[inline(always)]
pub const fn align_up(addr: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two(), "align must be a power of two");
    let mask = align - 1;
    addr.checked_add(mask).map(|a| a & !mask)
}

/// Returns `true` if `addr` is aligned to `align` bytes.
///
/// `align` must be a power of two.
#[inline(always)]
pub const fn is_aligned(addr: usize, align: usize) -> bool {
    addr & (align - 1) == 0
}

/// Returns the offset of `addr` within its containing page (4 KiB).
#[inline(always)]
pub const fn page_offset(addr: usize) -> usize {
    addr & 0xFFF
}

// ---------------------------------------------------------------------------
// Raw-pointer helpers (virtual addresses only)
// ---------------------------------------------------------------------------

/// Interpret a kernel virtual address as a raw const pointer to `T`.
///
/// # Safety
/// The caller must ensure that `vaddr` is a valid, correctly aligned virtual
/// address for a live object of type `T`.
#[inline(always)]
pub unsafe fn virt_as_ptr<T>(vaddr: usize) -> *const T {
    vaddr as *const T
}

/// Interpret a kernel virtual address as a raw mut pointer to `T`.
///
/// # Safety
/// The caller must ensure that `vaddr` is a valid, correctly aligned virtual
/// address for a uniquely-owned live object of type `T`.
#[inline(always)]
pub unsafe fn virt_as_mut_ptr<T>(vaddr: usize) -> *mut T {
    vaddr as *mut T
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_phys_virt() {
        let phys: usize = 0x0010_0000; // 1 MiB
        assert_eq!(virt_to_phys(phys_to_virt(phys)), phys);
    }

    #[test]
    fn round_trip_virt_phys() {
        let virt = phys_to_virt(0x0020_0000); // 2 MiB mapped
        assert_eq!(phys_to_virt(virt_to_phys(virt)), virt);
    }

    #[test]
    fn align_down_page() {
        assert_eq!(align_down(0x1234_5678, 0x1000), 0x1234_5000);
        assert_eq!(align_down(0x1000, 0x1000), 0x1000);
    }

    #[test]
    fn align_up_page() {
        assert_eq!(align_up(0x1234_5001, 0x1000), Some(0x1234_6000));
        assert_eq!(align_up(0x1000, 0x1000), Some(0x1000));
    }

    #[test]
    fn is_aligned_checks() {
        assert!(is_aligned(0x2000, 0x1000));
        assert!(!is_aligned(0x2001, 0x1000));
    }

    #[test]
    fn page_offset_checks() {
        assert_eq!(page_offset(0x1234_5ABC), 0xABC);
        assert_eq!(page_offset(0x1234_5000), 0x000);
    }
}
