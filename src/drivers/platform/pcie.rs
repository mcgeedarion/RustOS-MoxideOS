//! PCIe bus enumerator — Phase 1 (ECAM + MSI-X).
//!
//! ## PCI configuration space access
//!   Legacy port I/O (CONFIG_ADDRESS / CONFIG_DATA) is x86-only.
//!   This driver uses ECAM (Enhanced Configuration Access Mechanism):
//!     addr = ecam_base | (bus << 20) | (dev << 15) | (fn << 12) | offset
//!   `ecam_base` comes from the firmware memory map (ACPI MCFG or device-tree).
//!
//! ## Enumeration
//!   Scans bus 0..=255, device 0..=31, function 0..=7.
//!   Records every live endpoint in a global `Vec<PciDevice>`.
//!
//! ## MSI-X
//!   Locates capability 0x11 in the capability list and enables the MSI-X
//!   table; individual vector setup is done via `msix_configure`.

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

// ─────────────────────────────────────────────────────────────────────────────
// PCI config-space register offsets
// ─────────────────────────────────────────────────────────────────────────────

const PCI_VENDOR:      u16 = 0x00;
const PCI_DEVICE:      u16 = 0x02;
const PCI_COMMAND:     u16 = 0x04;
const PCI_CLASS:       u16 = 0x0A;
const PCI_HDR_TYPE:    u16 = 0x0E;
const PCI_BAR0:        u16 = 0x10;
const PCI_CAP_PTR:     u16 = 0x34;
const PCI_STATUS:      u16 = 0x06;

const CMD_BUS_MASTER:  u16 = 1 << 2;
const CMD_MEM_SPACE:   u16 = 1 << 1;
const STATUS_CAP_LIST: u16 = 1 << 4;

const CAP_MSIX:        u8  = 0x11;

// ─────────────────────────────────────────────────────────────────────────────
// ECAM access
// ─────────────────────────────────────────────────────────────────────────────

static ECAM_BASE: Mutex<u64> = Mutex::new(0);

/// Call once at boot with the ECAM base from ACPI MCFG / device-tree.
pub fn set_ecam_base(base: u64) {
    *ECAM_BASE.lock() = base;
}

#[inline]
fn ecam_addr(bus: u8, dev: u8, func: u8, off: u16) -> usize {
    let base = *ECAM_BASE.lock() as usize;
    base | ((bus as usize) << 20)
         | ((dev  as usize) << 15)
         | ((func as usize) << 12)
         | (off as usize)
}

#[inline]
pub fn cfg_read32(bus: u8, dev: u8, func: u8, off: u16) -> u32 {
    unsafe { read_volatile(ecam_addr(bus, dev, func, off) as *const u32) }
}

#[inline]
pub fn cfg_read16(bus: u8, dev: u8, func: u8, off: u16) -> u16 {
    unsafe { read_volatile(ecam_addr(bus, dev, func, off) as *const u16) }
}

#[inline]
pub fn cfg_read8(bus: u8, dev: u8, func: u8, off: u16) -> u8 {
    unsafe { read_volatile(ecam_addr(bus, dev, func, off) as *const u8) }
}

#[inline]
pub fn cfg_write32(bus: u8, dev: u8, func: u8, off: u16, val: u32) {
    unsafe { write_volatile(ecam_addr(bus, dev, func, off) as *mut u32, val); }
}

#[inline]
pub fn cfg_write16(bus: u8, dev: u8, func: u8, off: u16, val: u16) {
    unsafe { write_volatile(ecam_addr(bus, dev, func, off) as *mut u16, val); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Device descriptor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PciDevice {
    pub bus:      u8,
    pub dev:      u8,
    pub func:     u8,
    pub vendor:   u16,
    pub device:   u16,
    pub class:    u16,
    /// BAR0 base address (MMIO, 64-bit decoded).
    pub bar0:     u64,
    /// Index of the MSI-X capability in the cap list, or 0 if absent.
    pub msix_cap: u8,
}

static DEVICES: Mutex<Vec<PciDevice>> = Mutex::new(Vec::new());

// ─────────────────────────────────────────────────────────────────────────────
// Enumeration
// ─────────────────────────────────────────────────────────────────────────────

pub fn enumerate() {
    let mut devs = DEVICES.lock();
    devs.clear();

    for bus in 0u8..=255 {
        for dev in 0u8..32 {
            for func in 0u8..8 {
                let vid = cfg_read16(bus, dev, func, PCI_VENDOR);
                if vid == 0xFFFF { continue; }

                let did   = cfg_read16(bus, dev, func, PCI_DEVICE);
                let class = cfg_read16(bus, dev, func, PCI_CLASS);
                let hdr   = cfg_read8(bus, dev, func, PCI_HDR_TYPE);

                // Decode BAR0 (support 64-bit).
                let bar0_lo = cfg_read32(bus, dev, func, PCI_BAR0) & !0xF;
                let bar0_hi = if cfg_read32(bus, dev, func, PCI_BAR0) & 0x4 != 0 {
                    cfg_read32(bus, dev, func, PCI_BAR0 + 4) as u64
                } else { 0 };
                let bar0 = bar0_lo as u64 | (bar0_hi << 32);

                // Enable bus-master + memory decode.
                let cmd = cfg_read16(bus, dev, func, PCI_COMMAND);
                cfg_write16(bus, dev, func, PCI_COMMAND,
                    cmd | CMD_BUS_MASTER | CMD_MEM_SPACE);

                // Walk capability list for MSI-X.
                let mut msix_cap = 0u8;
                let status = cfg_read16(bus, dev, func, PCI_STATUS);
                if status & STATUS_CAP_LIST != 0 {
                    let mut ptr = cfg_read8(bus, dev, func, PCI_CAP_PTR) & !3;
                    for _ in 0..48 {
                        if ptr == 0 { break; }
                        let cap_id = cfg_read8(bus, dev, func, ptr as u16);
                        if cap_id == CAP_MSIX { msix_cap = ptr; break; }
                        ptr = cfg_read8(bus, dev, func, ptr as u16 + 1);
                    }
                }

                devs.push(PciDevice { bus, dev, func, vendor: vid, device: did,
                    class, bar0, msix_cap });

                // Single-function device — skip remaining functions.
                if hdr & 0x80 == 0 && func == 0 { break; }
            }
        }
    }
}

/// Return a snapshot of all enumerated PCI devices.
pub fn devices() -> Vec<PciDevice> {
    DEVICES.lock().clone()
}

/// Find the first device matching (vendor, device_id).
pub fn find(vendor: u16, device_id: u16) -> Option<PciDevice> {
    DEVICES.lock().iter()
        .find(|d| d.vendor == vendor && d.device == device_id)
        .cloned()
}

// ─────────────────────────────────────────────────────────────────────────────
// MSI-X
// ─────────────────────────────────────────────────────────────────────────────

/// Enable MSI-X and configure vector `vec_idx` to deliver to `lapic_id`
/// at `vector` with `data`.
///
/// `d.msix_cap` must be non-zero (i.e., the device must have MSI-X).
pub fn msix_configure(d: &PciDevice, vec_idx: usize, lapic_id: u32,
                      vector: u8, _data: u32)
{
    if d.msix_cap == 0 { return; }
    let cap = d.msix_cap as u16;

    // Read table BIR and offset.
    let table_dw = cfg_read32(d.bus, d.dev, d.func, cap + 4);
    let bir      = (table_dw & 0x7) as u8;
    let offset   = (table_dw & !0x7) as usize;

    // Resolve BAR for BIR (only BAR0 supported here).
    let bar_base = if bir == 0 { d.bar0 } else { return };
    let table_base = bar_base as usize + offset;

    // Each MSI-X table entry is 16 bytes: addr_lo, addr_hi, data, ctrl.
    let entry = (table_base + vec_idx * 16) as *mut u32;
    unsafe {
        let addr = 0xFEE0_0000u32 | (lapic_id << 12);
        write_volatile(entry,       addr);
        write_volatile(entry.add(1), 0);
        write_volatile(entry.add(2), vector as u32);
        write_volatile(entry.add(3), 0); // unmask
    }

    // Enable MSI-X in message control.
    let mc = cfg_read16(d.bus, d.dev, d.func, cap + 2);
    cfg_write16(d.bus, d.dev, d.func, cap + 2, mc | 0x8000);
}
