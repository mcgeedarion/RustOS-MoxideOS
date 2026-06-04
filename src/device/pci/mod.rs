//! PCI subsystem — types, registry, and public re-exports.

pub mod bus;
pub mod ecam;
pub mod enumerate;
pub mod msix;

pub use bus::PciBus;

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

pub(crate) const PCI_VENDOR:      u16 = 0x00;
pub(crate) const PCI_DEVICE:      u16 = 0x02;
pub(crate) const PCI_COMMAND:     u16 = 0x04;
pub(crate) const PCI_STATUS:      u16 = 0x06;
pub(crate) const PCI_CLASS:       u16 = 0x0A;
pub(crate) const PCI_HDR_TYPE:    u16 = 0x0E;
pub(crate) const PCI_BAR0:        u16 = 0x10;
pub(crate) const PCI_CAP_PTR:     u16 = 0x34;

pub(crate) const CMD_BUS_MASTER:  u16 = 1 << 2;
pub(crate) const CMD_MEM_SPACE:   u16 = 1 << 1;
pub(crate) const STATUS_CAP_LIST: u16 = 1 << 4;

pub(crate) const CAP_MSIX:        u8  = 0x11;

/// A single PCI function discovered during bus enumeration.
#[derive(Clone, Debug)]
pub struct PciDevice {
    pub bus:      u8,
    pub dev:      u8,
    pub func:     u8,
    pub vendor:   u16,
    pub device:   u16,
    pub class:    u16,
    /// BAR0–BAR5 base addresses (MMIO, 64-bit decoded).
    /// Index = BAR number (0–5). I/O BARs and the upper half of 64-bit
    /// BARs are stored as 0.
    pub bars:     [u64; 6],
    /// Offset of the MSI-X capability record, or 0 if not present.
    pub msix_cap: u8,
}

pub(crate) static DEVICES: Mutex<Vec<PciDevice>> = Mutex::new(Vec::new());

/// Return a snapshot of every enumerated PCI device.
pub fn devices() -> Vec<PciDevice> {
    DEVICES.lock().clone()
}

/// Find the first device matching `(vendor, device_id)`.
pub fn find(vendor: u16, device_id: u16) -> Option<PciDevice> {
    DEVICES.lock()
        .iter()
        .find(|d| d.vendor == vendor && d.device == device_id)
        .cloned()
}
