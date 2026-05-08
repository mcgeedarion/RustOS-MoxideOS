//! Driver modules.
//!
//! ## Always compiled
//!   gop           — UEFI GOP framebuffer capture (pre-ExitBootServices)
//!   drm           — DRM/KMS stub backed by GOP or virtio-gpu
//!   framebuffer   — Unified FB abstraction (virtio-gpu > GOP fallback)
//!   virtio_gpu    — VirtIO GPU device (virtio-gpu-pci, device ID 0x1050)
//!   ahci          — AHCI SATA controller
//!   nvme          — NVMe host controller
//!   pcie          — PCIe ECAM enumeration
//!   e1000e        — Intel e1000e Gigabit Ethernet
//!   nic           — NIC abstraction layer (send_frame / rx_poll_all)
//!   virtio_blk    — VirtIO block device
//!   virtio_net    — VirtIO network device
//!   virtio_input  — VirtIO input device
//!   evdev         — evdev input event layer
//!   keyboard      — PS/2 / USB keyboard
//!   mouse         — PS/2 / USB mouse
//!   hid           — USB HID
//!   usb           — USB xHCI host controller
//!   clint         — RISC-V CLINT timer
//!   gpio          — GPIO (stub)
//!   tty           — TTY driver shim (real impl in shell/tty.rs)
//!   gpu           — Generic GPU placeholder (superseded by virtio_gpu)
//!
//! ## Feature-gated
//!   amdgpu_gem    — AMD GEM/TTM memory manager; requires feature "amdgpu"

pub mod ahci;
pub mod clint;
pub mod drm;
pub mod e1000e;
pub mod evdev;
pub mod framebuffer;
pub mod gop;
pub mod gpio;
pub mod gpu;
pub mod hid;
pub mod keyboard;
pub mod mouse;
pub mod nic;
pub mod nvme;
pub mod pcie;
pub mod tty;
pub mod usb;
pub mod virtio_blk;
pub mod virtio_gpu;
pub mod virtio_input;
pub mod virtio_net;

#[cfg(feature = "amdgpu")]
pub mod amdgpu_gem;
