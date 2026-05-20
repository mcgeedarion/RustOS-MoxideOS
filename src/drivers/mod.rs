//! Driver subsystems.
//!
//! ## Subsystems
//!   gpu/      — DRM/KMS, framebuffer, GOP, VGA, virtio-gpu, AMD GEM
//!   input/    — evdev, HID, keyboard, mouse, USB, Bluetooth, virtio-input
//!   net/      — e1000e, NIC abstraction, virtio-net (PCIe + MMIO)
//!   block/    — AHCI, NVMe, virtio-blk
//!   platform/ — GPIO, PCIe ECAM, TTY shim
//!
//! Interrupt controllers (PLIC, CLINT) live in `crate::irq::riscv64`.

pub mod block;
pub mod gpu;
pub mod input;
pub mod net;
pub mod platform;
