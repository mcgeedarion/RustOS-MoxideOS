//! Device bus manager subsystem.
//!
//! This crate provides a hardware-neutral bus abstraction used by all
//! device drivers.  Drivers **probe** from the bus manager; they never
//! perform raw bus enumeration themselves.
//!
//! ## Hierarchy
//!
//! ```text
//! src/device/
//! ├── mod.rs          — subsystem root (you are here)
//! └── pci/
//!     ├── mod.rs      — PciDevice + DEVICES registry
//!     ├── ecam.rs     — ECAM MMIO helpers
//!     ├── enumerate.rs — full bus scan
//!     ├── bus.rs      — PciBus manager
//!     └── msix.rs     — MSI-X vector configuration
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use crate::device::pci::PciBus;
//!
//! // Once at boot, after firmware gives us the ECAM base:
//! PciBus::init(ecam_base);
//!
//! // Driver probe site:
//! if let Some(dev) = PciBus::find(0x1AF4, 0x1041) {
//!     // virtio-net found — proceed with driver init
//! }
//! ```

pub mod pci;
pub use pci::PciBus;
