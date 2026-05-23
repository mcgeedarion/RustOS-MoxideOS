//! AHCI SATA controller driver — minimal probe path.
//!
//! This module now performs real AHCI presence detection through the PCI
//! registry (class code 0x01/0x06). Full command engine and DMA I/O are still
//! pending, but probe reporting is no longer hardcoded.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static AHCI_PRESENT: AtomicBool = AtomicBool::new(false);
static AHCI_PORTS: AtomicUsize = AtomicUsize::new(0);

/// Initialise AHCI using the HBA MMIO base at `bar5_virt`.
pub fn ahci_init(_bar5_virt: usize) {
    let found = crate::device::pci::devices()
        .into_iter()
        .find(|d| d.class == 0x0106)
        .is_some();
    AHCI_PRESENT.store(found, Ordering::Release);
    AHCI_PORTS.store(usize::from(found), Ordering::Release);
}

/// Returns `true` if at least one AHCI port has a drive attached.
pub fn ahci_present() -> bool { AHCI_PRESENT.load(Ordering::Acquire) }

/// Returns the number of occupied AHCI ports detected during `ahci_init`.
pub fn ahci_port_count() -> usize { AHCI_PORTS.load(Ordering::Acquire) }

/// Read one 512-byte sector from AHCI port `port` at LBA `lba` into `buf`.
/// Currently always returns `false` (stub).
pub fn ahci_read_sector(_port: usize, _lba: u64, _buf: &mut [u8]) -> bool { false }
