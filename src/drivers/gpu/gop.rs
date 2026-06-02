//! UEFI GOP (Graphics Output Protocol) framebuffer driver.
//!
//! At boot time the UEFI firmware provides a linear framebuffer via GOP.
//! The bootloader records the base address, resolution and pixel format in
//! the boot info structure.  This driver maps that buffer and provides the
//! same `clear` / `blit` / `flush` API as the other GPU backends.
//!
//! ## GOP pixel formats (EFI_GRAPHICS_PIXEL_FORMAT)
//!   0 = PixelRedGreenBlueReserved8BitPerColor  (RGBX)
//!   1 = PixelBlueGreenRedReserved8BitPerColor  (BGRX)
//!   2 = PixelBitMask
//!   3 = PixelBltOnly  (no framebuffer, unsupported)

extern crate alloc;
use spin::Mutex;

use crate::drivers::gpu::framebuffer::{Framebuffer, PixelFormat};
use crate::drivers::gpu::gpu::DisplayInfo;

struct GopState {
    fb:     Framebuffer,
    format: GopPixelFormat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GopPixelFormat {
    RgbX,
    BgrX,
    Unknown,
}

static GOP: Mutex<Option<GopState>> = Mutex::new(None);

/// Initialise from values supplied by the bootloader.
pub fn init(fb_base: u64, width: u32, height: u32, pitch_bytes: u32) {
    let fb = Framebuffer {
        phys:   fb_base,
        width,
        height,
        pitch:  pitch_bytes,
        format: PixelFormat::Xrgb8888,
    };
    *GOP.lock() = Some(GopState { fb, format: GopPixelFormat::BgrX });
}

pub fn is_initialised() -> bool { GOP.lock().is_some() }

pub fn display_info() -> Option<DisplayInfo> {
    GOP.lock().as_ref().map(|g| DisplayInfo {
        width:  g.fb.width,
        height: g.fb.height,
        pitch:  g.fb.pitch,
        bpp:    32,
    })
}

pub fn clear(argb: u32) {
    if let Some(g) = GOP.lock().as_ref() {
        g.fb.clear(argb_to_gopfmt(argb, g.format));
    }
}

pub fn blit(x: u32, y: u32, width: u32, height: u32, pixels: &[u32]) {
    let g = GOP.lock();
    if let Some(g) = g.as_ref() {
        let fmt = g.format;
        // Convert each pixel to GOP native format.
        let conv: alloc::vec::Vec<u32> = pixels.iter().map(|&p| argb_to_gopfmt(p, fmt)).collect();
        g.fb.blit(x, y, width, height, &conv);
    }
}

/// Return the raw framebuffer physical address (for DRM scanout).
pub fn fb_phys() -> Option<u64> {
    GOP.lock().as_ref().map(|g| g.fb.phys)
}

#[inline]
fn argb_to_gopfmt(argb: u32, fmt: GopPixelFormat) -> u32 {
    // Input: 0xAARRGGBB
    let a = (argb >> 24) & 0xFF;
    let r = (argb >> 16) & 0xFF;
    let g = (argb >>  8) & 0xFF;
    let b =  argb        & 0xFF;
    match fmt {
        GopPixelFormat::RgbX => (r << 24) | (g << 16) | (b << 8) | a,
        GopPixelFormat::BgrX => (b << 24) | (g << 16) | (r << 8) | a,
        GopPixelFormat::Unknown => argb,
    }
}
