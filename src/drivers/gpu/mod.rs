//! GPU and display drivers.
//!
//! ## Modules
//!   gpu           — GPU HAL, backend registry, GpuDevice trait
//!   drm           — DRM/KMS stub
//!   framebuffer   — Unified framebuffer abstraction
//!   gop           — UEFI GOP capture (pre-ExitBootServices)
//!   virtio_gpu    — VirtIO GPU device (virtio-gpu-pci, device ID 0x1050)
//!   vga           — VGA text mode 80×25 [x86_64 only]
//!   amdgpu_gem    — AMD GEM/TTM memory manager [feature = "amdgpu"]

pub mod drm;
pub mod framebuffer;
pub mod gop;
pub mod gpu;
pub mod virtio_gpu;

#[cfg(target_arch = "x86_64")]
pub mod vga;

#[cfg(feature = "amdgpu")]
pub mod amdgpu_gem;
