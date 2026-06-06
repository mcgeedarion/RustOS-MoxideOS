//! Kernel framebuffer abstraction.
//!
//! `Framebuffer` is a lightweight descriptor over a DMA-coherent pixel buffer.
//! Drivers and the DRM layer pass `&Framebuffer` references around instead of
//! raw pointers so that pitch, format and dimensions are always available.

use crate::drivers::gpu::drm::GemBo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    Argb8888, // 0xAARRGGBB
    Xrgb8888, // 0x00RRGGBB
    Rgb565,
    Bgr888,
}

impl PixelFormat {
    pub fn bytes_per_pixel(self) -> usize {
        match self {
            PixelFormat::Argb8888 | PixelFormat::Xrgb8888 => 4,
            PixelFormat::Rgb565 => 2,
            PixelFormat::Bgr888 => 3,
        }
    }
}

impl Default for PixelFormat {
    fn default() -> Self {
        PixelFormat::Xrgb8888
    }
}

#[derive(Clone, Debug)]
pub struct Framebuffer {
    pub phys: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32, // bytes per row
    pub format: PixelFormat,
}

impl Framebuffer {
    pub fn new(phys: u64, width: u32, height: u32, format: PixelFormat) -> Self {
        let pitch = width * format.bytes_per_pixel() as u32;
        Self {
            phys,
            width,
            height,
            pitch,
            format,
        }
    }

    pub fn from_gem(bo: &GemBo) -> Self {
        Self {
            phys: bo.phys,
            width: bo.width,
            height: bo.height,
            pitch: bo.pitch,
            format: bo.format,
        }
    }

    /// Size in bytes.
    pub fn size(&self) -> usize {
        (self.pitch * self.height) as usize
    }

    /// Mutable pixel slice (ARGB u32 words).
    /// Only valid for 32-bpp formats.
    pub fn as_u32_slice_mut(&self) -> &'static mut [u32] {
        let n = (self.pitch / 4 * self.height) as usize;
        unsafe { core::slice::from_raw_parts_mut(self.phys as *mut u32, n) }
    }

    /// Byte-level mutable slice.
    pub fn as_byte_slice_mut(&self) -> &'static mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.phys as *mut u8, self.size()) }
    }

    /// Write one ARGB pixel at `(x, y)`.  No bounds check.
    #[inline]
    pub fn put_pixel(&self, x: u32, y: u32, argb: u32) {
        let off = (y * self.pitch / 4 + x) as usize;
        unsafe {
            core::ptr::write_volatile((self.phys as *mut u32).add(off), argb);
        }
    }

    /// Fill the entire framebuffer with `argb`.
    pub fn clear(&self, argb: u32) {
        let px = self.as_u32_slice_mut();
        for p in px.iter_mut() {
            unsafe {
                core::ptr::write_volatile(p, argb);
            }
        }
    }

    /// Blit a `w*h` ARGB pixel rectangle at `(x, y)`.
    pub fn blit(&self, x: u32, y: u32, w: u32, h: u32, pixels: &[u32]) {
        for row in 0..h {
            let dst_off = ((y + row) * self.pitch / 4 + x) as usize;
            let src_off = (row * w) as usize;
            let dst = self.as_u32_slice_mut();
            for col in 0..w as usize {
                if dst_off + col < dst.len() && src_off + col < pixels.len() {
                    unsafe {
                        core::ptr::write_volatile(&mut dst[dst_off + col], pixels[src_off + col]);
                    }
                }
            }
        }
    }
}
