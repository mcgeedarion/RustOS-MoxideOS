//! `PciBus` — the primary bus-manager API consumed by drivers.
//!
//! # Design
//!
//! Drivers **never** call ECAM helpers or touch `DEVICES` directly.  Instead
//! they use `PciBus` as a capability token:
//!
//! ```rust,ignore
//! use crate::device::pci::PciBus;
//!
//! // Boot path:
//! PciBus::init(ecam_base);
//!
//! // Driver probe:
//! if let Some(dev) = PciBus::find(VIRTIO_VENDOR, VIRTIO_NET_DEVICE) {
//!     driver_init(dev);
//! }
//! ```
//!
//! `PciBus` is a zero-sized type; it carries no state itself — all state lives
//! in the module-level statics in `ecam` and the `DEVICES` registry.

extern crate alloc;
use alloc::vec::Vec;

use super::ecam::set_base;
use super::enumerate::scan_all;
use super::{devices, find, PciDevice};

/// Zero-sized token representing the PCI bus manager.
///
/// All methods are associated functions so no instance is required.
pub struct PciBus;

impl PciBus {
    /// Initialise ECAM and enumerate all PCI devices.
    ///
    /// Call **once** at boot after the firmware memory map is available.
    /// Subsequent calls are harmless (they re-enumerate).
    ///
    /// # Safety
    /// `ecam_base` must point to a valid ECAM window mapped in the kernel's
    /// address space.
    pub unsafe fn init(ecam_base: u64) {
        set_base(ecam_base);
        scan_all();
    }

    /// Return a snapshot of all discovered PCI devices.
    pub fn all() -> Vec<PciDevice> {
        devices()
    }

    /// Find the first device matching `(vendor, device_id)`.
    ///
    /// Returns `None` if no device matches or the bus has not been
    /// enumerated yet.
    pub fn find(vendor: u16, device_id: u16) -> Option<PciDevice> {
        find(vendor, device_id)
    }

    /// Iterate all devices and call `probe` for each one.
    ///
    /// This is the canonical driver-probe entry point.  `probe` returns
    /// `true` if it claimed the device (purely informational for now;
    /// callers may use it for logging).
    pub fn probe_all<F>(mut probe: F)
    where
        F: FnMut(&PciDevice) -> bool,
    {
        for dev in devices() {
            probe(&dev);
        }
    }

    /// Re-run bus enumeration (e.g., after a hot-plug event).
    pub fn rescan() {
        scan_all();
    }
}
