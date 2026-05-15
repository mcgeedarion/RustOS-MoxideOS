//! Framebuffer management.
//!
//! A framebuffer wraps a GEM object and describes the pixel layout
//! so the CRTC can scan it out.

pub struct FramebufferDesc {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
    pub depth: u32,
    pub gem_handle: u32,
}

impl FramebufferDesc {
    pub fn new(
        id: u32,
        width: u32,
        height: u32,
        pitch: u32,
        bpp: u32,
        depth: u32,
        gem_handle: u32,
    ) -> Self {
        Self {
            id,
            width,
            height,
            pitch,
            bpp,
            depth,
            gem_handle,
        }
    }

    pub fn size_bytes(&self) -> usize {
        (self.pitch * self.height) as usize
    }

    pub fn stride(&self) -> usize {
        self.pitch as usize
    }
}
