//! DRM/KMS (Direct Rendering Manager / Kernel Mode Setting) subsystem.
//!
//! This module provides the kernel-side DRM/KMS infrastructure:
//! - Mode setting (CRTC, encoder, connector management)
//! - Framebuffer allocation and management
//! - GPU/display driver abstraction
//! - GEM (Graphics Execution Manager) buffer objects
//! - Synchronization primitives for GPU work (fences, dma-buf)
//!
//! The Wayland compositor (`crate::display::wayland`) interfaces with this
//! subsystem to perform display output and buffer presentation.
//!
//! Hardware driver stubs: `crate::drivers::drm`, `crate::drivers::virtio_gpu`

pub mod connector;
pub mod crtc;
pub mod encoder;
pub mod framebuffer;
pub mod gem;
pub mod plane;

pub use crate::drm::{
    DisplayMode, DrmDriver, DrmError,
    connector::*, crtc::*, encoder::*, framebuffer::*, gem::*, plane::*,
};
