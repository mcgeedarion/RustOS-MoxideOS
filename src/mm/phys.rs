//! Physical ↔ virtual address translation.
//!
//! We use a fixed kernel virtual-memory layout:
//!
//!   PHYS_OFFSET is the base virtual address at which all of physical memory
//!   is mapped ("direct map" / "physmap").  This is architecture-specific:
//!
//!   x86_64   — 0xFFFF_8880_0000_0000  (Linux-compatible direct map)
//!   RISC-V   — 0xFFFF_FFD8_0000_0000  (SV48 direct map)
//!   ARM64    — 0xFFFF_0000_0000_0000  (top of canonical VA range)
//!
//! These match the paging setup in `arch/*/mm/` so the functions below are
//! zero-overhead inline arithmetic.

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        pub const PHYS_OFFSET: usize = 0xFFFF_8880_0000_0000;
    } else if #[cfg(target_arch = "riscv64")] {
        pub const PHYS_OFFSET: usize = 0xFFFF_FFD8_0000_0000;
    } else if #[cfg(target_arch = "aarch64")] {
        pub const PHYS_OFFSET: usize = 0xFFFF_0000_0000_0000;
    } else {
        compile_error!("unsupported architecture: add PHYS_OFFSET for this target");
    }
}

/// Convert a kernel virtual address in the direct map to its physical address.
#[inline(always)]
pub fn virt_to_phys(vaddr: usize) -> usize {
    vaddr - PHYS_OFFSET
}

/// Convert a physical address to its kernel virtual address in the direct map.
#[inline(always)]
pub fn phys_to_virt(paddr: usize) -> usize {
    paddr + PHYS_OFFSET
}
