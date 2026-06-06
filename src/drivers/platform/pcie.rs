//! PCIe platform driver — thin shim over `crate::device::pci`.
//!
//! All real logic (ECAM access, bus enumeration, MSI-X) now lives in
//! `crate::device::pci`.  This module exists solely to keep the
//! legacy `crate::drivers::platform::pcie::*` public API surface
//! intact so that existing call-sites continue to compile unchanged.
//!
//! New code should import from `crate::device::pci` directly.

use crate::device::pci::{
    self as pci_bus,
    ecam,
};
pub use crate::device::pci::PciDevice;

// Legacy class-tuple constants + class lookup live in the x86_64 PCI
// driver. Re-export so callers can use the `drivers::pcie::*` path.
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::pci::{
    PCI_CLASS_STORAGE_AHCI,
    PCI_CLASS_STORAGE_NVME,
    PCI_CLASS_NETWORK_ETH,
    find_device_by_class,
};
use crate::device::pci::msix::msix_configure as _msix_configure;

extern crate alloc;
use alloc::vec::Vec;

/// Initialise ECAM base address.  Delegates to `PciBus::init`.
///
/// # Safety
/// `base` must map a valid ECAM region.
pub unsafe fn set_ecam_base(base: u64) {
    ecam::set_base(base);
}

#[inline]
pub fn cfg_read32(bus: u8, dev: u8, func: u8, off: u16) -> u32 {
    ecam::cfg_read32(bus, dev, func, off)
}

#[inline]
pub fn cfg_read16(bus: u8, dev: u8, func: u8, off: u16) -> u16 {
    ecam::cfg_read16(bus, dev, func, off)
}

#[inline]
pub fn cfg_read8(bus: u8, dev: u8, func: u8, off: u16) -> u8 {
    ecam::cfg_read8(bus, dev, func, off)
}

#[inline]
pub fn cfg_write32(bus: u8, dev: u8, func: u8, off: u16, val: u32) {
    ecam::cfg_write32(bus, dev, func, off, val)
}

#[inline]
pub fn cfg_write16(bus: u8, dev: u8, func: u8, off: u16, val: u16) {
    ecam::cfg_write16(bus, dev, func, off, val)
}

// PciDevice is already brought into scope at the top via `use crate::device::pci::PciDevice;`
// (it is public by virtue of being defined in a pub module and re-exporting it
//  here as a second `pub use` would shadow itself; downstream callers can use
//  either `crate::drivers::platform::pcie::PciDevice` (via the `use` above) or
//  `crate::device::pci::PciDevice` directly).

/// Run full bus enumeration.  Delegates to `PciBus::rescan()`.
pub fn enumerate() {
    crate::device::pci::bus::PciBus::rescan();
}

/// Return a snapshot of all discovered devices.
pub fn devices() -> Vec<PciDevice> {
    pci_bus::devices()
}

/// Find the first device matching `(vendor, device_id)`.
pub fn find(vendor: u16, device_id: u16) -> Option<PciDevice> {
    pci_bus::find(vendor, device_id)
}

/// Configure an MSI-X vector.  Delegates to `device::pci::msix`.
pub fn msix_configure(
    d:        &PciDevice,
    vec_idx:  usize,
    lapic_id: u32,
    vector:   u8,
    data:     u32,
) {
    _msix_configure(d, vec_idx, lapic_id, vector, data);
}
