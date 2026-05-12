//! Direct Rendering Manager (DRM) subsystem.
//!
//! Provides kernel-mode setting (KMS) and GPU buffer management (GEM)
//! for display hardware.

pub mod connector;
pub mod crtc;
pub mod encoder;
pub mod framebuffer;
pub mod gem;
pub mod plane;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayMode {
    pub hdisplay: u16,
    pub vdisplay: u16,
    pub refresh: u32,
    pub clock: u32,
    pub hsync_start: u16,
    pub hsync_end: u16,
    pub htotal: u16,
    pub vsync_start: u16,
    pub vsync_end: u16,
    pub vtotal: u16,
    pub flags: u32,
}

pub use connector::Connector;
pub use crtc::Crtc;
pub use encoder::Encoder;
pub use framebuffer::FramebufferDesc;
pub use gem::GemObject;
pub use plane::Plane;

/// DRM device handle.
pub struct DrmDevice {
    pub connectors: alloc::vec::Vec<Connector>,
    pub crtcs: alloc::vec::Vec<Crtc>,
    pub encoders: alloc::vec::Vec<Encoder>,
    pub planes: alloc::vec::Vec<Plane>,
    pub framebuffers: alloc::vec::Vec<FramebufferDesc>,
    pub gem_objects: alloc::vec::Vec<GemObject>,
}

impl DrmDevice {
    pub fn new() -> Self {
        Self {
            connectors: alloc::vec::Vec::new(),
            crtcs: alloc::vec::Vec::new(),
            encoders: alloc::vec::Vec::new(),
            planes: alloc::vec::Vec::new(),
            framebuffers: alloc::vec::Vec::new(),
            gem_objects: alloc::vec::Vec::new(),
        }
    }
}
