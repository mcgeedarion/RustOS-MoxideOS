//! Driver modules.
//!
//! ## Always compiled
//!   gop          — UEFI GOP framebuffer capture (pre-ExitBootServices)
//!   drm          — DRM/KMS stub backed by the GOP linear framebuffer
//!   ahci         — AHCI SATA controller
//!   pcie         — PCIe ECAM enumeration
//!   virtio_blk   — VirtIO block device
//!   virtio_net   — VirtIO network device (stub)
//!   virtio_input — VirtIO input device (stub)
//!   evdev        — evdev input event layer (stub)
//!   keyboard     — PS/2 / USB keyboard (stub)
//!   mouse        — PS/2 / USB mouse (stub)
//!   hid          — USB HID (stub)
//!   usb          — USB host controller (stub)
//!   clint        — RISC-V CLINT timer
//!   gpio         — GPIO (stub)
//!   tty          — TTY driver shim (real impl in shell/tty.rs)
//!   gpu          — Generic GPU placeholder
//!
//! ## Feature-gated
//!   amdgpu_gem   — AMD GEM/TTM memory manager; requires feature "amdgpu"

pub mod ahci;
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

#[cfg(feature = "amdgpu")]
pub mod amdgpu_gem;
