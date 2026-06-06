//! Boot‑time memory description that is architecture‑agnostic.
//!
//! This module defines the simple types that carry the physical memory map
//! from the arch‑specific discovery code into the generic PMM.

use alloc::vec::Vec;

/// Describes what a physical region is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionKind {
    /// Normal RAM that can be allocated for frames.
    Usable,
    /// Reserved by firmware / hardware; not available for allocation.
    Reserved,
    /// Memory‑mapped I/O region.
    Mmio,
    /// Where the kernel image itself resides.
    KernelImage,
    /// Bootloader / firmware region (e.g. UEFI boot services).
    Bootloader,
    /// Initramfs / early‑userspace blob.
    InitRamFs,
}

/// A single contiguous physical region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    /// Physical start address (inclusive).
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
    /// What this region is used for.
    pub kind: RegionKind,
}

impl Region {
    /// Returns the end address (exclusive).
    #[inline(always)]
    pub const fn end(&self) -> u64 {
        self.start + self.length
    }

    /// True if the region is usable for frame allocation.
    #[inline(always)]
    pub const fn is_usable(&self) -> bool {
        matches!(self.kind, RegionKind::Usable)
    }
}

/// A collection of regions discovered at boot time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Regions {
    inner: Vec<Region>,
}

impl Regions {
    /// Create an empty collection.
    pub const fn new() -> Self {
        Self { inner: Vec::new() }
    }

    /// Push a region onto the collection.
    pub fn push(&mut self, region: Region) {
        self.inner.push(region);
    }

    /// Iterator over the regions.
    pub fn iter(&self) -> core::slice::Iter<'_, Region> {
        self.inner.iter()
    }

    /// Total amount of usable RAM (in bytes).
    pub fn total_usable(&self) -> u64 {
        self.iter()
            .filter(|r| r.is_usable())
            .map(|r| r.length)
            .sum()
    }

    /// Convert into the owned Vec.
    pub fn into_inner(self) -> Vec<Region> {
        self.inner
    }
}
