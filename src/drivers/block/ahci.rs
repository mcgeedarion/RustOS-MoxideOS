//! AHCI SATA controller driver — stub.
//!
//! A full AHCI implementation is pending.  These stubs allow kernel_main
//! to compile and fall through to the NVMe probe on real hardware.

/// Initialise AHCI using the HBA MMIO base at `bar5_virt`.
/// Currently a no-op stub; returns immediately without touching hardware.
pub fn ahci_init(_bar5_virt: usize) {}

/// Returns `true` if at least one AHCI port has a drive attached.
/// Currently always returns `false` (stub).
pub fn ahci_present() -> bool { false }

/// Returns the number of occupied AHCI ports detected during `ahci_init`.
/// Currently always returns `0` (stub).
pub fn ahci_port_count() -> usize { 0 }

/// Read one 512-byte sector from AHCI port `port` at LBA `lba` into `buf`.
/// Currently always returns `false` (stub).
pub fn ahci_read_sector(_port: usize, _lba: u64, _buf: &mut [u8]) -> bool { false }
