//! Platform CPU topology: returns the list of secondary CPU MPIDR values.
//!
//! On AArch64 the CPU topology is discovered from either:
//!   1. ACPI MADT  — GIC CPU Interface entries (type 0x0B for GICv2, type 0x0C
//!      for GICv3 redistributor)
//!   2. Device Tree — `cpu` nodes under `/cpus` with `reg` property
//!
//! We support MADT first (UEFI path), then fall back to a hard-coded
//! QEMU virt 4-CPU default for development/testing when neither is
//! available.
//!
//! ## MPIDR format (Armv8-A)
//!
//!   [39:32] Aff3   [23:16] Aff2   [15:8] Aff1   [7:0] Aff0
//!
//! For a flat single-cluster layout (QEMU virt) only Aff0 varies (0..N-1).

#![allow(dead_code)]

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// MPIDR of the boot CPU, recorded by early arch init.
static BOOT_MPIDR: AtomicUsize = AtomicUsize::new(0);

/// Record the BSP's MPIDR so we can exclude it from the secondary list.
pub fn set_boot_mpidr(mpidr: u64) {
    BOOT_MPIDR.store(mpidr as usize, Ordering::Relaxed);
}

/// Return the MPIDR values of all secondary (non-boot) CPUs.
///
/// Tries ACPI MADT first, then a QEMU-virt fallback.
pub fn secondary_mpidrs() -> Vec<u64> {
    let boot = BOOT_MPIDR.load(Ordering::Relaxed) as u64;

    let mut from_madt = Vec::new();
    unsafe {
        crate::firmware::acpi::walk_madt(|hdr, ptr| {
            let mpidr = match hdr.kind {
                // Type 0x0B: GIC CPU Interface (GICv2)
                0x0B => {
                    // struct: type(1) len(1) _rsvd(2) cpu_interface_number(4)
                    //         uid(4) flags(4) parking_protocol_version(4)
                    //         performance_interrupt_gsiv(4) parked_address(8)
                    //         base_address(8) gic_v2m_base(8) vgic_maint(4)
                    //         gicr_base(8) mpidr(8) efficiency_class(1) ...
                    // MPIDR is at byte offset 56 from the entry start.
                    if hdr.len >= 76 {
                        let m = (ptr.add(56) as *const u64).read_unaligned();
                        Some(m)
                    } else {
                        None
                    }
                },
                // Type 0x0C: GIC Redistributor / GICv3 per-CPU interface
                // This entry type doesn't carry MPIDR directly;
                // skip — rely on type 0x0B entries or DTB.
                _ => None,
            };
            if let Some(m) = mpidr {
                from_madt.push(m);
            }
        });
    }

    if from_madt.len() > 1 {
        // Filter out the boot CPU and de-duplicate.
        from_madt.retain(|&m| m != boot);
        from_madt.dedup();
        return from_madt;
    }

    // CPU count can be overridden by calling set_cpu_count() from DTB parsing.
    let count = CPU_COUNT.load(Ordering::Relaxed);
    if count <= 1 {
        return Vec::new();
    }
    (0..count as u64)
        .filter(|&aff0| aff0 != (boot & 0xff))
        .map(|aff0| aff0)
        .collect()
}

/// Logical CPU count, set by DTB/ACPI parsing.  Default = 1 (uniprocessor).
static CPU_COUNT: AtomicUsize = AtomicUsize::new(1);

/// Set the total CPU count (called from DTB or ACPI MADT enumeration).
pub fn set_cpu_count(n: usize) {
    CPU_COUNT.store(n, Ordering::Relaxed);
}

/// Return the total CPU count.
pub fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Relaxed)
}
