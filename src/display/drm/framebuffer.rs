//! Framebuffer management.
//!
//! Framebuffers wrap a GEM buffer object and add metadata (width, height,
//! pitch, pixel format) needed by the display hardware for scanout.

use super::DrmError;

/// Pixel format (subset of DRM fourcc formats).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Xrgb8888,
    Argb8888,
    Rgb565,
    Xbgr8888,
}

impl PixelFormat {
    /// Bytes per pixel.
    pub fn bpp(self) -> u32 {
        match self {
            PixelFormat::Rgb565 => 2,
            _ => 4,
        }
    }
}

pub struct Framebuffer {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub format: PixelFormat,
    /// Physical base address of the backing buffer.
    pub paddr: u64,
}

impl Framebuffer {
    pub fn new(
        id: u32,
        width: u32,
        height: u32,
        format: PixelFormat,
        paddr: u64,
    ) -> Result<Self, DrmError> {
        if width == 0 || height == 0 {
            return Err(DrmError::InvalidFramebuffer);
        }
        let pitch = width * format.bpp();
        Ok(Self {
            id,
            width,
            height,
            pitch,
            format,
            paddr,
        })
    }

    pub fn size_bytes(&self) -> u64 {
        self.pitch as u64 * self.height as u64
    }
}

/// Public alias for the framebuffer description type. `display::console`
/// imports `FramebufferDesc`; this matches that name without changing
/// callers downstream.
pub type FramebufferDesc = Framebuffer;
