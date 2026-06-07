//! Driver subsystems.
//!
//! ## Subsystems
//!   gpu/      — DRM/KMS, framebuffer, GOP, VGA, virtio-gpu, AMD GEM
//!   input/    — evdev, HID, keyboard, mouse, USB, Bluetooth, virtio-input
//!   net/      — e1000e, NIC abstraction, virtio-net (PCIe + MMIO)
//!   block/    — AHCI, NVMe, virtio-blk
//!   platform/ — GPIO, PCIe ECAM
//!   virtio/   — MMIO transport and split virtqueue (shared by all virtio
//! drivers)
//!
//! Terminal semantics (line discipline, PTY, termios) live in `crate::tty`.
//! Interrupt controllers (PLIC, CLINT) live in `crate::irq::riscv64`.

pub mod block;
pub mod gpu;
// Compatibility re-exports for older call sites that imported GPU drivers
// directly from `crate::drivers::*`.
#[cfg(target_arch = "x86_64")]
pub use gpu::vga;
pub use gpu::{drm, gop, virtio_gpu};
pub mod input;
pub mod net;
// Compatibility re-export for `crate::drivers::nic::*` callers.
pub use net::nic;
pub mod platform;
// GUESS: callers use crate::drivers::pcie; canonical home is platform::pcie.
pub use platform::pcie;
pub mod virtio;
pub mod virtio_blk;
