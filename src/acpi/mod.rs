//! ACPI table parser: RSDP → RSDT/XSDT → MADT → interrupt routing.
//!
//! ## What this does
//!   1. Locates the RSDP in the EBDA / BIOS ROM / UEFI config table.
//!   2. Parses RSDT or XSDT to find the MADT (APIC table).
//!   3. Walks MADT entries to discover:
//!      - Local APICs  (which CPU cores are present)
//!      - I/O APICs    (hardware interrupt routing base)
//!      - Interrupt source overrides (IRQ remapping)
//!   4. Exposes a flat [CpuInfo; MAX_CPUS] and [IoApic; MAX_IOAPICS] array
//!      readable at any time after acpi_init() is called.
//!
//! ## Scope
//!   We only parse what we need for SMP boot and interrupt routing.
//!   DSDT/SSDT/AML bytecode execution is deliberately out of scope.

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

// ─── RSDP ────────────────────────────────────────────────────────────────────

/// ACPI 1.0 RSDP (20 bytes).  ACPI 2.0 extends it to 36 bytes.
#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],   // "RSD PTR "
    checksum:  u8,
    oem_id:    [u8; 6],
    revision:  u8,        // 0 = ACPI 1.0, 2 = ACPI 2.0+
    rsdt_addr: u32,
    // ACPI 2.0+ only:
    length:    u32,
    xsdt_addr: u64,
    ext_checksum: u8,
    _reserved: [u8; 3],
}

/// SDT common header (8 bytes).
#[repr(C, packed)]
struct SdtHeader {
    signature: [u8; 4],
    length:    u32,
    revision:  u8,
    checksum:  u8,
    oem_id:    [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id:   u32,
    creator_rev:  u32,
}

// ─── MADT entry types ────────────────────────────────────────────────────────

const MADT_TYPE_LOCAL_APIC:    u8 = 0;
const MADT_TYPE_IO_APIC:       u8 = 1;
const MADT_TYPE_IRQ_OVERRIDE:  u8 = 2;
const MADT_TYPE_LOCAL_X2APIC:  u8 = 9;

#[repr(C, packed)]
struct MadtLocalApic  { _hdr: [u8;2], acpi_uid: u8, apic_id: u8, flags: u32 }
#[repr(C, packed)]
struct MadtIoApic     { _hdr: [u8;2], id: u8, _res: u8, addr: u32, gsi_base: u32 }
#[repr(C, packed)]
struct MadtIrqOverride{ _hdr: [u8;2], bus: u8, irq: u8, gsi: u32, flags: u16 }
#[repr(C, packed)]
struct MadtX2Apic     { _hdr: [u8;2], _res: u16, x2id: u32, flags: u32, uid: u32 }

// ─── Public result types ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct CpuInfo {
    pub apic_id:  u32,
    pub acpi_uid: u32,
    pub enabled:  bool,
}

#[derive(Clone, Copy, Debug)]
pub struct IoApicInfo {
    pub id:       u8,
    pub mmio_pa:  u32,   // MMIO physical address
    pub gsi_base: u32,   // Global System Interrupt base
}

#[derive(Clone, Copy, Debug)]
pub struct IrqOverride {
    pub irq: u8,         // legacy ISA IRQ
    pub gsi: u32,        // actual GSI at the I/O APIC
    pub flags: u16,      // polarity / trigger mode
}

#[derive(Default)]
struct AcpiData {
    cpus:      Vec<CpuInfo>,
    ioapics:   Vec<IoApicInfo>,
    overrides: Vec<IrqOverride>,
    initialized: bool,
}

static ACPI: Mutex<AcpiData> = Mutex::new(AcpiData {
    cpus:      Vec::new(),
    ioapics:   Vec::new(),
    overrides: Vec::new(),
    initialized: false,
});

// ─── Initialisation ───────────────────────────────────────────────────────────

/// Find and parse ACPI tables.  Call once during early kernel init,
/// after the PMM is up (we need identity-mapped physical memory access).
///
/// `rsdp_pa` is the physical address of the RSDP, typically supplied by
/// the bootloader (UEFI: from EFI_SYSTEM_TABLE.ConfigurationTable;
/// Multiboot2: from the ACPI tag; fallback: scan EBDA / BIOS ROM).
/// Pass 0 to trigger the legacy BIOS scan.
pub fn acpi_init(rsdp_pa: u64) {
    let rsdp_va = if rsdp_pa != 0 {
        rsdp_pa as usize
    } else {
        match scan_for_rsdp() {
            Some(va) => va,
            None     => { log!("ACPI: RSDP not found"); return; }
        }
    };

    let rsdp = unsafe { &*(rsdp_va as *const Rsdp) };
    if &rsdp.signature != b"RSD PTR " {
        log!("ACPI: bad RSDP signature");
        return;
    }

    let mut acpi = ACPI.lock();

    // Prefer XSDT (ACPI 2.0+) over RSDT.
    if rsdp.revision >= 2 && rsdp.xsdt_addr != 0 {
        parse_xsdt(rsdp.xsdt_addr as usize, &mut acpi);
    } else {
        parse_rsdt(rsdp.rsdt_addr as usize, &mut acpi);
    }

    acpi.initialized = true;
    log!("ACPI: {} CPUs, {} I/O APICs, {} IRQ overrides",
         acpi.cpus.len(), acpi.ioapics.len(), acpi.overrides.len());
}

// ─── Accessors ────────────────────────────────────────────────────────────────

pub fn cpu_count() -> usize {
    ACPI.lock().cpus.len()
}

pub fn with_cpus<F: FnMut(CpuInfo)>(mut f: F) {
    for cpu in ACPI.lock().cpus.iter() { f(*cpu); }
}

pub fn with_ioapics<F: FnMut(IoApicInfo)>(mut f: F) {
    for io in ACPI.lock().ioapics.iter() { f(*io); }
}

/// Map a legacy ISA IRQ to its real GSI (accounting for overrides).
pub fn isa_irq_to_gsi(irq: u8) -> u32 {
    let acpi = ACPI.lock();
    for ov in acpi.overrides.iter() {
        if ov.irq == irq { return ov.gsi; }
    }
    irq as u32  // 1:1 if no override
}

// ─── RSDT / XSDT walking ─────────────────────────────────────────────────────

fn parse_rsdt(va: usize, acpi: &mut AcpiData) {
    let hdr    = unsafe { &*(va as *const SdtHeader) };
    let length = unsafe { core::ptr::read_unaligned(&hdr.length) } as usize;
    let entries = (length - core::mem::size_of::<SdtHeader>()) / 4;
    for i in 0..entries {
        let ptr_va = va + core::mem::size_of::<SdtHeader>() + i * 4;
        let table_pa = unsafe { (ptr_va as *const u32).read_unaligned() } as usize;
        try_parse_table(table_pa, acpi);
    }
}

fn parse_xsdt(va: usize, acpi: &mut AcpiData) {
    let hdr    = unsafe { &*(va as *const SdtHeader) };
    let length = unsafe { core::ptr::read_unaligned(&hdr.length) } as usize;
    let entries = (length - core::mem::size_of::<SdtHeader>()) / 8;
    for i in 0..entries {
        let ptr_va = va + core::mem::size_of::<SdtHeader>() + i * 8;
        let table_pa = unsafe { (ptr_va as *const u64).read_unaligned() } as usize;
        try_parse_table(table_pa, acpi);
    }
}

fn try_parse_table(va: usize, acpi: &mut AcpiData) {
    if va < 0x1000 { return; }
    let hdr = unsafe { &*(va as *const SdtHeader) };
    match &hdr.signature {
        b"APIC" => parse_madt(va, acpi),
        _       => {} // FADT, HPET, MCFG etc. — not needed yet
    }
}

// ─── MADT parser ─────────────────────────────────────────────────────────────

fn parse_madt(va: usize, acpi: &mut AcpiData) {
    let hdr    = unsafe { &*(va as *const SdtHeader) };
    let length = unsafe { core::ptr::read_unaligned(&hdr.length) } as usize;
    // MADT has an 8-byte prefix after the SDT header:
    //   local_apic_addr: u32,  flags: u32
    let body_start = va + core::mem::size_of::<SdtHeader>() + 8;
    let body_end   = va + length;

    let mut off = body_start;
    while off + 2 <= body_end {
        let entry_type = unsafe { *(off as *const u8) };
        let entry_len  = unsafe { *((off + 1) as *const u8) } as usize;
        if entry_len < 2 { break; }

        match entry_type {
            MADT_TYPE_LOCAL_APIC => {
                if entry_len >= core::mem::size_of::<MadtLocalApic>() {
                    let e = unsafe { &*(off as *const MadtLocalApic) };
                    let flags = unsafe { core::ptr::read_unaligned(&e.flags) };
                    if flags & 1 != 0 { // processor enabled
                        acpi.cpus.push(CpuInfo {
                            apic_id:  e.apic_id as u32,
                            acpi_uid: e.acpi_uid as u32,
                            enabled:  true,
                        });
                    }
                }
            }
            MADT_TYPE_IO_APIC => {
                if entry_len >= core::mem::size_of::<MadtIoApic>() {
                    let e = unsafe { &*(off as *const MadtIoApic) };
                    acpi.ioapics.push(IoApicInfo {
                        id:       e.id,
                        mmio_pa:  unsafe { core::ptr::read_unaligned(&e.addr) },
                        gsi_base: unsafe { core::ptr::read_unaligned(&e.gsi_base) },
                    });
                }
            }
            MADT_TYPE_IRQ_OVERRIDE => {
                if entry_len >= core::mem::size_of::<MadtIrqOverride>() {
                    let e = unsafe { &*(off as *const MadtIrqOverride) };
                    acpi.overrides.push(IrqOverride {
                        irq:   e.irq,
                        gsi:   unsafe { core::ptr::read_unaligned(&e.gsi) },
                        flags: unsafe { core::ptr::read_unaligned(&e.flags) },
                    });
                }
            }
            MADT_TYPE_LOCAL_X2APIC => {
                if entry_len >= core::mem::size_of::<MadtX2Apic>() {
                    let e = unsafe { &*(off as *const MadtX2Apic) };
                    let flags = unsafe { core::ptr::read_unaligned(&e.flags) };
                    if flags & 1 != 0 {
                        acpi.cpus.push(CpuInfo {
                            apic_id:  unsafe { core::ptr::read_unaligned(&e.x2id) },
                            acpi_uid: unsafe { core::ptr::read_unaligned(&e.uid) },
                            enabled:  true,
                        });
                    }
                }
            }
            _ => {}
        }
        off += entry_len;
    }
}

// ─── RSDP legacy scan ─────────────────────────────────────────────────────────

/// Scan the EBDA and BIOS ROM for the "RSD PTR " signature.
/// Returns the virtual address (= physical address in identity-mapped kernel).
fn scan_for_rsdp() -> Option<usize> {
    // 1. EBDA: read segment from BIOS data area at 0x40E, then scan first 1 KiB.
    let ebda_seg = unsafe { (0x40E as *const u16).read_unaligned() } as usize;
    let ebda_va  = ebda_seg << 4;
    if let Some(va) = scan_range(ebda_va, ebda_va + 1024) { return Some(va); }
    // 2. BIOS ROM 0xE0000..0xFFFFF
    scan_range(0xE_0000, 0x10_0000)
}

fn scan_range(start: usize, end: usize) -> Option<usize> {
    let mut va = start;
    while va + 8 <= end {
        if unsafe { core::slice::from_raw_parts(va as *const u8, 8) } == b"RSD PTR " {
            return Some(va);
        }
        va += 16; // RSDP is always 16-byte aligned
    }
    None
}

/// Stub log macro for inside acpi module (no console dep at early boot).
macro_rules! log {
    ($fmt:literal $(, $arg:expr)*) => {{
        // Writes to serial port 0x3F8 directly during early init.
        let msg = alloc::format!(concat!($fmt, "\r\n") $(, $arg)*);
        for b in msg.bytes() {
            unsafe {
                while crate::arch::x86_64::serial::serial_ready() == 0 {}
                crate::arch::x86_64::serial::serial_write(b);
            }
        }
    }}
}
