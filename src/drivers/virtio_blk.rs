//! virtio-blk driver — delegates to `crate::block::virtio_blk`.
//!
//! The full virtqueue implementation (descriptor ring, available/used rings,
//! MMIO register layout, read_sector / write_sector) lives in
//! `src/block/virtio_blk.rs`.  This module re-exports it so driver consumers
//! can use `crate::drivers::virtio_blk::*` consistently with other drivers.

pub use crate::block::virtio_blk::*;
