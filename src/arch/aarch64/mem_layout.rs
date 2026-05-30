//! AArch64 memory-layout and architectural constants.
//!
//! RustOS ARM64 intentionally targets the same baseline hardware class as the
//! experimental ReactOS ARM64 port: UEFI firmware, Armv8-A or newer CPUs, and a
//! GICv2 or GICv3 interrupt controller.  This module keeps those baseline
//! assumptions explicit and centralised.

/// Human-readable baseline requirement for diagnostics and docs.
pub const BASELINE: &str = "UEFI + Armv8-A+ + GICv2/GICv3";

pub mod page {
    pub const SIZE: usize = 4096;
    pub const SHIFT: usize = 12;
    pub const MASK: usize = SIZE - 1;
    pub const TABLE_ENTRIES: usize = 512;
    pub const BLOCK_1G: usize = 1 << 30;
    pub const BLOCK_2M: usize = 1 << 21;

    #[inline]
    pub const fn align_up(n: usize) -> usize {
        (n + MASK) & !MASK
    }
    #[inline]
    pub const fn align_down(n: usize) -> usize {
        n & !MASK
    }
}

/// 48-bit VA layout using 4 KiB translation granules (four table levels).
pub mod va48 {
    pub const VA_BITS: usize = 48;
    pub const USER_TOP: usize = 1usize << 47;
    pub const KERNEL_BASE: usize = 0xffff_0000_0000_0000;
    pub const PHYS_OFFSET: usize = 0xffff_8000_0000_0000;

    #[inline]
    pub const fn l0_index(va: usize) -> usize {
        (va >> 39) & 0x1ff
    }
    #[inline]
    pub const fn l1_index(va: usize) -> usize {
        (va >> 30) & 0x1ff
    }
    #[inline]
    pub const fn l2_index(va: usize) -> usize {
        (va >> 21) & 0x1ff
    }
    #[inline]
    pub const fn l3_index(va: usize) -> usize {
        (va >> 12) & 0x1ff
    }

    #[inline]
    pub const fn phys_to_virt(pa: usize) -> usize {
        pa + PHYS_OFFSET
    }
    #[inline]
    pub const fn virt_to_phys(va: usize) -> usize {
        va - PHYS_OFFSET
    }
}

/// AArch64 page/table descriptor bits for stage-1 EL1 translation.
pub mod pte {
    pub const VALID: usize = 1 << 0;
    pub const TABLE: usize = 1 << 1;
    pub const BLOCK: usize = 0 << 1;
    pub const PAGE: usize = 1 << 1;

    pub const ATTR_INDEX_SHIFT: usize = 2;
    pub const ATTR_NORMAL: usize = 0 << ATTR_INDEX_SHIFT;
    pub const ATTR_DEVICE_NGNRE: usize = 1 << ATTR_INDEX_SHIFT;
    pub const NS: usize = 1 << 5;
    pub const AP_RW_EL1: usize = 0 << 6;
    pub const AP_RW_EL0: usize = 1 << 6;
    pub const AP_RO_EL1: usize = 2 << 6;
    pub const AP_RO_EL0: usize = 3 << 6;
    pub const SH_INNER: usize = 3 << 8;
    pub const AF: usize = 1 << 10;
    pub const NG: usize = 1 << 11;
    pub const PXN: usize = 1 << 53;
    pub const UXN: usize = 1 << 54;
    pub const ADDR_MASK: usize = 0x0000_ffff_ffff_f000;

    #[inline]
    pub const fn pa_to_desc(pa: usize, flags: usize) -> usize {
        (pa & ADDR_MASK) | flags | VALID
    }
    #[inline]
    pub const fn desc_to_pa(desc: usize) -> usize {
        desc & ADDR_MASK
    }
}

/// MAIR_EL1 attribute encodings used by `paging::init_mmu`.
pub mod mair {
    pub const NORMAL_WB_RA_WA: u64 = 0xff;
    pub const DEVICE_NGNRE: u64 = 0x04;
    pub const VALUE: u64 = NORMAL_WB_RA_WA | (DEVICE_NGNRE << 8);
}

/// TCR_EL1 configuration: 4 KiB granule, 48-bit TTBR0/TTBR1 VA, inner WBWA.
pub mod tcr {
    pub const T0SZ_48: u64 = 64 - 48;
    pub const T1SZ_48: u64 = (64 - 48) << 16;
    pub const IRGN0_WBWA: u64 = 1 << 8;
    pub const ORGN0_WBWA: u64 = 1 << 10;
    pub const SH0_INNER: u64 = 3 << 12;
    pub const TG0_4K: u64 = 0 << 14;
    pub const IRGN1_WBWA: u64 = 1 << 24;
    pub const ORGN1_WBWA: u64 = 1 << 26;
    pub const SH1_INNER: u64 = 3 << 28;
    pub const TG1_4K: u64 = 2 << 30;
    pub const IPS_48BIT: u64 = 5 << 32;
    pub const VALUE: u64 = T0SZ_48
        | T1SZ_48
        | IRGN0_WBWA
        | ORGN0_WBWA
        | SH0_INNER
        | TG0_4K
        | IRGN1_WBWA
        | ORGN1_WBWA
        | SH1_INNER
        | TG1_4K
        | IPS_48BIT;
}

pub mod sctlr {
    pub const M: u64 = 1 << 0;
    pub const C: u64 = 1 << 2;
    pub const I: u64 = 1 << 12;
}

/// QEMU `virt` defaults used as fallback when ACPI/DT has not supplied GIC MMIO.
pub mod gic {
    pub const GICV2_DIST_BASE: usize = 0x0800_0000;
    pub const GICV2_CPU_BASE: usize = 0x0801_0000;
    pub const GICV3_DIST_BASE: usize = 0x0800_0000;
    pub const GICV3_REDIST_BASE: usize = 0x080a_0000;
    pub const MIN_SPI: u32 = 32;
}

pub mod uart {
    /// QEMU `virt` PL011 UART base; UEFI console is preferred during boot.
    pub const PL011_BASE: usize = 0x0900_0000;
    pub const DR: usize = 0x00;
    pub const FR: usize = 0x18;
    pub const FR_TXFF: u32 = 1 << 5;
    pub const FR_RXFE: u32 = 1 << 4;
}
