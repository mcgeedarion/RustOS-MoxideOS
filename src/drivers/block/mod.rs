//! Block and storage drivers.
//!
//! ## Modules
//!   ahci       — AHCI SATA controller
//!   nvme       — NVMe host controller
//!   virtio_blk — VirtIO block device

pub mod ahci;
pub mod nvme;
pub mod virtio_blk;
