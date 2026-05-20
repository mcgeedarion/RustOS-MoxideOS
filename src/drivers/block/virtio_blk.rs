//! virtio-blk driver — delegates to `crate::block::virtio_blk`.
//!
//! The full virtqueue implementation (descriptor ring, available/used rings,
//! MMIO register layout, read_sector / write_sector) lives in
//! `src/block/virtio_blk.rs`.  This shim re-exports the public surface so
//! that drivers consumers can reach it via `crate::drivers::block::virtio_blk`.

pub use crate::block::virtio_blk::*;
