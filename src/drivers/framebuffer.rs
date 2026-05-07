//! Unified framebuffer abstraction.
//!
//! Provides a single `Framebuffer` handle that can be backed by either:
//!   a) The UEFI GOP linear framebuffer (available after ExitBootServices)
//!   b) The virtio-gpu pixel buffer (available after `virtio_gpu::init()`)
//!
//! Precedence: virtio-gpu is preferred over GOP (it is writable and the
//! QEMU window refreshes via explicit flush commands, giving proper vsync
//! semantics).  GOP is used as a fallback on bare-metal or headless builds.
//!
//! ## Usage
//!
//! ```rust
//! use crate::drivers::framebuffer;
//!
//! if let Some(mut fb) = framebuffer::acquire() {
//!     // Fill with solid red (BGRX: B=0, G=0, R=0xFF, X=0)
//!     fb.fill(0x00_FF_00_00);
//!     fb.flush_all();
//! }
//! ```

use super::{virtio_gpu, gop};

// ─────────────────────────────────────────────────────────────────────────────
// Backend selection
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Backend {
    /// virtio-gpu — writable, flushes go through virtio commands.
    VirtioGpu,
    /// UEFI GOP linear framebuffer — writes go directly to VRAM.
    Gop,
}

// ─────────────────────────────────────────────────────────────────────────────
// Framebuffer handle
// ─────────────────────────────────────────────────────────────────────────────

/// A live handle to the kernel framebuffer.  Pixel format is always
/// **BGRX u32** (byte 0 = B, byte 1 = G, byte 2 = R, byte 3 = unused).
pub struct Framebuffer {
    /// Kernel-virtual (= physical for identity-mapped pages) base address.
    pub base:    *mut u32,
    /// Width in pixels.
    pub width:   u32,
    /// Height in pixels.
    pub height:  u32,
    /// Bytes per row (stride).
    pub stride:  u32,
    /// Which hardware backs this handle.
    pub backend: Backend,
}

// SAFETY: the pixel buffer is a global singleton protected by the caller
// (only one Framebuffer is handed out at a time via `acquire()`).
unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    // ── Pixel access ─────────────────────────────────────────────────────

    /// Write a single pixel.  `color` is in BGRX u32 format.
    #[inline]
    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height { return; }
        let offset = (y * (self.stride / 4) + x) as usize;
        unsafe { self.base.add(offset).write_volatile(color); }
    }

    /// Fill the entire framebuffer with `color`.
    pub fn fill(&mut self, color: u32) {
        let words = (self.stride as usize / 4) * self.height as usize;
        for i in 0..words {
            unsafe { self.base.add(i).write_volatile(color); }
        }
    }

    /// Copy a row-major BGRX slice into the framebuffer at `(dst_x, dst_y)`.
    /// `src` must be `w` pixels wide and `h` pixels tall (w * h * 4 bytes).
    pub fn blit(&mut self, dst_x: u32, dst_y: u32, w: u32, h: u32, src: &[u32]) {
        for row in 0..h {
            let sy = dst_y + row;
            if sy >= self.height { break; }
            for col in 0..w {
                let sx = dst_x + col;
                if sx >= self.width { continue; }
                let src_idx = (row * w + col) as usize;
                if src_idx < src.len() {
                    self.put_pixel(sx, sy, src[src_idx]);
                }
            }
        }
    }

    // ── Display sync ─────────────────────────────────────────────────────

    /// Flush a dirty rectangle to the physical display.
    /// For GOP this is a no-op (memory-mapped VRAM is always live).
    /// For virtio-gpu this issues TRANSFER_TO_HOST_2D + RESOURCE_FLUSH.
    pub fn flush(&self, x: u32, y: u32, w: u32, h: u32) {
        if self.backend == Backend::VirtioGpu {
            virtio_gpu::flush(x, y, w, h);
        }
        // GOP: nothing to do — writes to VRAM are immediately visible.
    }

    /// Flush the entire framebuffer.
    pub fn flush_all(&self) {
        self.flush(0, 0, self.width, self.height);
    }

    // ── Convenience colour constructors ──────────────────────────────────

    /// Build a BGRX pixel from R, G, B components (0–255 each).
    #[inline]
    pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
        (r as u32) << 16 | (g as u32) << 8 | (b as u32)
    }

    pub const BLACK:   u32 = 0x0000_0000;
    pub const WHITE:   u32 = 0x00FF_FFFF;
    pub const RED:     u32 = 0x00FF_0000;
    pub const GREEN:   u32 = 0x0000_FF00;
    pub const BLUE:    u32 = 0x0000_00FF;
    pub const MAGENTA: u32 = 0x00FF_00FF;
    pub const CYAN:    u32 = 0x0000_FFFF;
    pub const YELLOW:  u32 = 0x00FF_FF00;
}

// ─────────────────────────────────────────────────────────────────────────────
// acquire()
// ─────────────────────────────────────────────────────────────────────────────

/// Try to obtain a `Framebuffer` handle.  Returns `None` if no display
/// hardware is available.
///
/// Priority: virtio-gpu > GOP.
pub fn acquire() -> Option<Framebuffer> {
    // 1. Prefer virtio-gpu.
    if virtio_gpu::is_present() {
        let (width, height) = virtio_gpu::dimensions()?;
        let base = virtio_gpu::fb_phys()? as *mut u32;
        return Some(Framebuffer {
            base,
            width,
            height,
            stride: width * 4,
            backend: Backend::VirtioGpu,
        });
    }
    // 2. Fall back to UEFI GOP.
    let info = gop::get()?;
    Some(Framebuffer {
        base:    info.fb_phys as *mut u32,
        width:   info.width,
        height:  info.height,
        stride:  info.pixels_per_line * 4,
        backend: Backend::Gop,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// devfs /dev/fb0 helpers  (called from fs/devfs.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Physical base address for /dev/fb0 mmap.
pub fn fb0_phys() -> Option<u64> {
    if virtio_gpu::is_present() { return virtio_gpu::fb_phys(); }
    gop::get().map(|g| g.fb_phys)
}

/// Byte length of /dev/fb0 region.
pub fn fb0_size() -> Option<usize> {
    if virtio_gpu::is_present() {
        let (w, h) = virtio_gpu::dimensions()?;
        return Some(w as usize * h as usize * 4);
    }
    gop::get().map(|g| gop::fb_byte_size(&g))
}

/// Width, height in pixels.
pub fn fb0_dimensions() -> Option<(u32, u32)> {
    if virtio_gpu::is_present() { return virtio_gpu::dimensions(); }
    gop::get().map(|g| (g.width, g.height))
}
