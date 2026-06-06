//! VirtIO infrastructure: MMIO transport and split virtqueue.
//!
//! Re-exports consumed by `drivers::block::virtio_blk`.

pub mod mmio;
pub mod virtqueue;

pub use mmio::VirtioMmio;
pub use virtqueue::{VirtqDesc, Virtqueue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
