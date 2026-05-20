//! Driver subsystems.
//!
//! ## Subsystems
//!   gpu/      — DRM/KMS, framebuffer, GOP, VGA, virtio-gpu, AMD GEM
//!   input/    — evdev, HID, keyboard, mouse, USB, Bluetooth, virtio-input
//!   net/      — e1000e, NIC abstraction, virtio-net (PCIe + MMIO)
//!   block/    — AHCI, NVMe, virtio-blk
//!   platform/ — CLINT, GPIO, PCIe ECAM, PLIC, TTY shim

pub mod block;
pub mod gpu;
pub mod input;
pub mod net;
pub mod platform;
