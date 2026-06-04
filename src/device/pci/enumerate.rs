//! REMOVED — PCI enumeration is now performed exclusively by
//! `crate::arch::x86_64::pci::init()` which populates both the legacy
//! fixed-array registry and `crate::device::pci::DEVICES` in a single
//! Type-1 I/O-port scan.
//!
//! This file is intentionally empty.  It will be deleted in a follow-up
//! cleanup commit once all `mod enumerate` references are removed.
