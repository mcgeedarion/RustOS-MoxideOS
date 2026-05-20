//! virtio-blk driver re-export.
//!
//! The full virtqueue implementation lives in `src/block/virtio_blk.rs`.
//! This module re-exports it so consumers can use
//! `crate::drivers::net::virtio_blk::*` or `crate::drivers::virtio_blk::*`.

pub use crate::block::virtio_blk::*;
