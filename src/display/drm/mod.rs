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

pub mod connector;
pub mod crtc;
pub mod encoder;
pub mod framebuffer;
pub mod gem;
pub mod plane;

use core::fmt;

/// A display mode descriptor (resolution + refresh rate).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayMode {
    pub hdisplay: u32,
    pub vdisplay: u32,
    /// Vertical refresh rate in Hz
    pub vrefresh: u32,
    pub clock: u32,
}

impl fmt::Display for DisplayMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}x{}@{}Hz", self.hdisplay, self.vdisplay, self.vrefresh)
    }
}

/// Trait that all DRM drivers must implement.
pub trait DrmDriver: Send + Sync {
    /// Return the name of this driver (e.g. "virtio-gpu", "amdgpu").
    fn name(&self) -> &'static str;

    /// Initialize the driver and probe hardware.
    fn init(&mut self) -> Result<(), DrmError>;

    /// Return supported display modes for the given connector index.
    fn get_modes(&self, connector_id: u32) -> &[DisplayMode];

    /// Apply a mode set: attach framebuffer `fb_id` to `crtc_id` with `mode`.
    fn set_mode(
        &mut self,
        crtc_id: u32,
        fb_id: u32,
        connector_ids: &[u32],
        mode: &DisplayMode,
    ) -> Result<(), DrmError>;

    /// Page-flip to a new framebuffer (used for vsync presentation).
    fn page_flip(&mut self, crtc_id: u32, fb_id: u32) -> Result<(), DrmError>;
}

/// Errors produced by the DRM subsystem.
#[derive(Debug)]
pub enum DrmError {
    /// Hardware not found or not supported.
    NoDevice,
    /// Requested mode is not supported by the display.
    InvalidMode,
    /// Framebuffer handle is invalid or has been destroyed.
    InvalidFramebuffer,
    /// The CRTC or connector index is out of range.
    InvalidId,
    /// A hardware or driver-internal error occurred.
    HardwareError(&'static str),
}

impl fmt::Display for DrmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DrmError::NoDevice => write!(f, "DRM: no device found"),
            DrmError::InvalidMode => write!(f, "DRM: invalid display mode"),
            DrmError::InvalidFramebuffer => write!(f, "DRM: invalid framebuffer"),
            DrmError::InvalidId => write!(f, "DRM: invalid CRTC/connector id"),
            DrmError::HardwareError(msg) => write!(f, "DRM: hardware error: {}", msg),
        }
    }
}
