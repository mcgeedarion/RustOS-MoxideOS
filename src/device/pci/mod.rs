//! PCI subsystem — types, canonical registry, and public helpers.
//!
//! ## Scan ownership
//! The PCI bus scan is performed **once** by `crate::arch::x86_64::pci::init()`
//! (Type-1 I/O-port access).  That function populates both its own legacy
//! fixed-array registry *and* `DEVICES` here via `register_device()`.  There
//! is no second scan; `enumerate.rs` has been removed.
//!
//! ## `class` field encoding
//! `PciDevice::class` stores `(class_byte << 8) | subclass_byte` so that
//! common comparisons like `d.class == 0x0106` (AHCI) work naturally.

pub mod bus;
pub mod ecam;
pub mod msix;

pub use bus::PciBus;

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

pub(crate) const PCI_VENDOR: u16 = 0x00;
pub(crate) const PCI_DEVICE: u16 = 0x02;
pub(crate) const PCI_COMMAND: u16 = 0x04;
pub(crate) const PCI_STATUS: u16 = 0x06;
pub(crate) const PCI_CLASS: u16 = 0x0A;
pub(crate) const PCI_HDR_TYPE: u16 = 0x0E;
pub(crate) const PCI_BAR0: u16 = 0x10;
pub(crate) const PCI_CAP_PTR: u16 = 0x34;

pub(crate) const CMD_BUS_MASTER: u16 = 1 << 2;
pub(crate) const CMD_MEM_SPACE: u16 = 1 << 1;
pub(crate) const STATUS_CAP_LIST: u16 = 1 << 4;

pub(crate) const CAP_MSIX: u8 = 0x11;

/// A single PCI function discovered during bus enumeration.
///
/// `class` encodes `(class_byte << 8) | subclass_byte`, e.g. `0x0106` = AHCI.
#[derive(Clone, Debug)]
pub struct PciDevice {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    /// `(class_byte << 8) | subclass_byte`
    pub class: u16,
    /// BAR0–BAR5 base addresses (MMIO, 64-bit decoded, cached at scan time).
    /// I/O BARs, absent BARs, and the upper dword of a consumed 64-bit pair
    /// are stored as 0.
    pub bars: [u64; 6],
    /// Config-space byte offset of the MSI-X capability record, or 0.
    pub msix_cap: u8,
}

pub static DEVICES: Mutex<Vec<PciDevice>> = Mutex::new(Vec::new());

/// Return a snapshot of every enumerated PCI device.
pub fn devices() -> Vec<PciDevice> {
    DEVICES.lock().clone()
}

/// Encode a PCI bus/device/function tuple as the userspace-driver BDF token.
#[inline]
pub const fn encode_bdf(bus: u8, dev: u8, func: u8) -> u32 {
    ((bus as u32) << 16) | ((dev as u32) << 8) | func as u32
}

/// Decode the userspace-driver BDF token into `(bus, device, function)`.
#[inline]
pub const fn decode_bdf(bdf: u32) -> (u8, u8, u8) {
    ((bdf >> 16) as u8, (bdf >> 8) as u8, bdf as u8)
}

/// Find a device by encoded bus/device/function.
pub fn find_by_bdf(bdf: u32) -> Option<PciDevice> {
    let (bus, dev, func) = decode_bdf(bdf);
    DEVICES
        .lock()
        .iter()
        .find(|d| d.bus == bus && d.dev == dev && d.func == func)
        .cloned()
}

/// Find the first device matching `(vendor, device_id)`.
pub fn find(vendor: u16, device_id: u16) -> Option<PciDevice> {
    DEVICES
        .lock()
        .iter()
        .find(|d| d.vendor == vendor && d.device == device_id)
        .cloned()
}

/// Find the first device matching `(class_byte, subclass_byte)`.
///
/// Matches against the combined `class` field: `(class_byte << 8) |
/// subclass_byte`.
pub fn find_by_class_sub(class: u8, subclass: u8) -> Option<PciDevice> {
    let target = (class as u16) << 8 | subclass as u16;
    DEVICES.lock().iter().find(|d| d.class == target).cloned()
}

/// Find the first device matching `(class_byte, subclass_byte, prog_if)`.
///
/// `prog_if` is not stored in the canonical struct, so this bridges into
/// the arch-level registry which retains the full triple.
/// Returns a canonical `PciDevice` (with `bars` and `msix_cap`) on match.
pub fn find_by_class_progif(class: u8, subclass: u8, prog_if: u8) -> Option<PciDevice> {
    crate::arch::x86_64::pci::find_class_progif(class, subclass, prog_if).map(|d| PciDevice {
        bus: d.bus,
        dev: d.dev,
        func: d.func,
        vendor: d.vendor,
        device: d.device,
        class: (d.class as u16) << 8 | d.subclass as u16,
        bars: d.bars,
        msix_cap: d.msix_cap,
    })
}
