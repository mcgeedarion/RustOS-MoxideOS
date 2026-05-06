//! Kernel device driver submodules.
//!
//! New drivers: add `pub mod <name>;` here and create `src/drivers/<name>.rs`.

pub mod ahci;
pub mod amdgpu_gem;
pub mod clint;
pub mod drm;
pub mod evdev;
pub mod gop;
pub mod gpio;
pub mod gpu;
pub mod hid;
pub mod keyboard;
pub mod mouse;
pub mod pcie;
pub mod tty;
pub mod usb;
pub mod virtio_blk;
pub mod virtio_input;
pub mod virtio_net;
