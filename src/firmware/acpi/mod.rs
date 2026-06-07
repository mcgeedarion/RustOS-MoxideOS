//! ACPI table parser: RSDP → RSDT/XSDT → MADT → interrupt routing.
//!
//! ## Why we care
//!
//! On UEFI systems the firmware hands us a pointer to the RSDP.  From there we
//! locate the MADT so we can discover LAPIC/IOAPIC information (x86_64) or any
//! other tables we may want later.
//!
//! Power management tables (FADT, DSDT) are parsed by the `power` sub-module.
//! S3 sleep / resume is handled by `sleep`.
//! CPU frequency scaling (`_PSS`/`_PPC`) is in `cpufreq`.
//! Battery information (`_BIF`/`_BST`) is in `battery`.
//! PCIe ACPI-mediated hot-plug (GPE + Notify) is in `hotplug`.
//! NUMA topology (SRAT + SLIT) is in `numa`.

pub mod battery;
pub mod cpufreq;
pub mod hotplug;
pub mod numa;
pub mod power;
pub mod sleep;

use core::mem::size_of;
use core::slice;

use crate::println;

#[repr(C, packed)]
pub struct RsdpV1 {
    sig: [u8; 8],
    csum: u8,
    oem_id: [u8; 6],
    rev: u8,
    rsdt_phys: u32,
}

#[repr(C, packed)]
pub struct RsdpV2 {
    v1: RsdpV1,
    len: u32,
    xsdt_phys: u64,
    ext_csum: u8,
    _rsvd: [u8; 3],
}

#[repr(C, packed)]
pub struct SdtHeader {
    pub sig: [u8; 4],
    pub len: u32,
    pub rev: u8,
    pub csum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_rev: u32,
    pub creator_id: u32,
    pub creator_rev: u32,
}

#[repr(C, packed)]
pub struct Madt {
    pub hdr: SdtHeader,
    pub lapic_addr: u32,
    pub flags: u32,
}

#[repr(C, packed)]
pub struct MadtEntryHdr {
    pub kind: u8,
    pub len: u8,
}

pub enum AcpiRoot {
    Rsdt(*const SdtHeader),
    Xsdt(*const SdtHeader),
}

static mut ACPI_ROOT: Option<AcpiRoot> = None;

fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, b| acc.wrapping_add(*b)) == 0
}

unsafe fn sig_eq<const N: usize>(ptr: *const u8, sig: &[u8; N]) -> bool {
    slice::from_raw_parts(ptr, N) == sig
}

pub unsafe fn init(rsdp_phys: usize) {
    if rsdp_phys == 0 {
        println!("acpi: no rsdp");
        return;
    }

    let v1 = &*(rsdp_phys as *const RsdpV1);
    if !sig_eq(v1.sig.as_ptr(), b"RSD PTR ") {
        println!("acpi: bad rsdp sig");
        return;
    }
    if !checksum_ok(slice::from_raw_parts(
        rsdp_phys as *const u8,
        size_of::<RsdpV1>(),
    )) {
        println!("acpi: rsdp v1 checksum failed");
        return;
    }

    if v1.rev >= 2 {
        let v2 = &*(rsdp_phys as *const RsdpV2);
        let len = core::ptr::addr_of!(v2.len).read_unaligned() as usize;
        let xsdt_phys = core::ptr::addr_of!(v2.xsdt_phys).read_unaligned();
        if checksum_ok(slice::from_raw_parts(rsdp_phys as *const u8, len)) && xsdt_phys != 0 {
            ACPI_ROOT = Some(AcpiRoot::Xsdt(xsdt_phys as usize as *const SdtHeader));
            println!("acpi: xsdt @ {:#x}", xsdt_phys);
            return;
        }
    }

    let rsdt_phys = core::ptr::addr_of!(v1.rsdt_phys).read_unaligned();
    if rsdt_phys != 0 {
        ACPI_ROOT = Some(AcpiRoot::Rsdt(rsdt_phys as usize as *const SdtHeader));
        println!("acpi: rsdt @ {:#x}", rsdt_phys);
    }
}

pub unsafe fn find_table(sig: &[u8; 4]) -> Option<*const SdtHeader> {
    let root = ACPI_ROOT.as_ref()?;
    match *root {
        AcpiRoot::Rsdt(hdr) => {
            let hdr_ref = &*hdr;
            let total = hdr_ref.len as usize;
            let entries_bytes = total - size_of::<SdtHeader>();
            let n = entries_bytes / 4;
            let base = (hdr as usize + size_of::<SdtHeader>()) as *const u32;
            for i in 0..n {
                let phys = *base.add(i) as usize;
                let th = &*(phys as *const SdtHeader);
                if &th.sig == sig {
                    return Some(phys as *const SdtHeader);
                }
            }
        },
        AcpiRoot::Xsdt(hdr) => {
            let hdr_ref = &*hdr;
            let total = hdr_ref.len as usize;
            let entries_bytes = total - size_of::<SdtHeader>();
            let n = entries_bytes / 8;
            let base = (hdr as usize + size_of::<SdtHeader>()) as *const u64;
            for i in 0..n {
                let phys = *base.add(i) as usize;
                let th = &*(phys as *const SdtHeader);
                if &th.sig == sig {
                    return Some(phys as *const SdtHeader);
                }
            }
        },
    }
    None
}

pub unsafe fn madt() -> Option<&'static Madt> {
    let p = find_table(b"APIC")? as *const Madt;
    Some(&*p)
}

pub unsafe fn walk_madt(mut f: impl FnMut(&MadtEntryHdr, *const u8)) {
    let m = match madt() {
        Some(m) => m,
        None => return,
    };
    let start = (m as *const Madt as usize) + size_of::<Madt>();
    let end = (m as *const Madt as usize) + (m.hdr.len as usize);
    let mut p = start;
    while p + size_of::<MadtEntryHdr>() <= end {
        let h = &*(p as *const MadtEntryHdr);
        if h.len < size_of::<MadtEntryHdr>() as u8 || p + h.len as usize > end {
            break;
        }
        f(h, p as *const u8);
        p += h.len as usize;
    }
}

/// Return the physical base address of the PCIe ECAM window from the MCFG
/// table, if present.
///
/// The MCFG body starts at offset 44 from the table start:
///   36 bytes SdtHeader + 8 bytes reserved = 44.
/// The first MCFG allocation structure begins there with:
///   [0..8]  Base Address (u64)
///   [8..10] PCI Segment Group Number
///   [10]    Start PCI Bus
///   [11]    End PCI Bus
///   [12..16] Reserved
pub fn mcfg_base() -> Option<usize> {
    unsafe {
        let mcfg = find_table(b"MCFG")?;
        let body = (mcfg as usize + 44) as *const u64;
        let base = body.read_unaligned();
        if base == 0 {
            None
        } else {
            Some(base as usize)
        }
    }
}

/// Return the number of logical CPUs found in the MADT, or 1 if unknown.
pub fn cpu_count() -> usize {
    let mut count = 0usize;
    unsafe {
        walk_madt(|hdr, _| {
            // Type 0 = Local APIC (x86), type 0x0B = GIC CPU Interface (arm64)
            if hdr.kind == 0 || hdr.kind == 0x0B {
                count += 1;
            }
        });
    }
    if count == 0 {
        1
    } else {
        count
    }
}

/// Return the base address of the PCIe ECAM region from MCFG, if present.
/// Alias kept for x86_64 callers that used `pcie_ecam_base()`.
pub fn pcie_ecam_base() -> Option<u64> {
    mcfg_base().map(|b| b as u64)
}

/// Convenience: initialise all ACPI sub-systems after the RSDP has been found.
///
/// Call order:
/// 1. `init(rsdp_phys)`       — root table discovery
/// 2. `power::init()`         — FADT/DSDT, SCI IRQ
/// 3. `sleep::init()`         — FACS, S3 wakeup vector
/// 4. `cpufreq::init()`       — _PSS / _PPC P-state table
/// 5. `battery::init()`       — _BIF / _BST battery info
/// 6. `hotplug::init()`       — GPE hot-plug handler
/// 7. `numa::init()`          — SRAT + SLIT topology
pub unsafe fn init_all(rsdp_phys: usize) {
    init(rsdp_phys);
    power::init();
    sleep::init();
    cpufreq::init();
    battery::init();
    hotplug::init();
    numa::init();
}

/// Convenience wrapper used by x86_64 kernel_main.
pub unsafe fn acpi_init(rsdp_phys: usize) {
    init(rsdp_phys);
}
