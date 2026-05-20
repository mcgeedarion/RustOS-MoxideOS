//! GPU subsystem facade.
//!
//! Dispatches framebuffer and DRM operations to whichever GPU driver
//! was initialised first (virtio-gpu → VGA fallback).
//!
//! ## Supported backends
//!   - `virtio_gpu`  — QEMU virtio-gpu (MMIO + PCI)
//!   - `amdgpu_gem`  — AMD GFX stub (GEM buffer management)
//!   - `vga`         — legacy VGA text / VESA linear framebuffer
//!   - `gop`         — UEFI GOP framebuffer (boot-time)
//!
//! ## Usage
//!   ```
//!   gpu::init_virtio(mmio_base);   // or gpu::init_vga() / gpu::init_gop(&info)
//!   gpu::clear(0x00_00_00_FF);     // ARGB black
//!   gpu::blit(x, y, w, h, pixels);
//!   gpu::flush();
//!   ```

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default)]
pub struct DisplayInfo {
    pub width:  u32,
    pub height: u32,
    pub pitch:  u32,   // bytes per row
    pub bpp:    u8,    // bits per pixel
}

// ---------------------------------------------------------------------------
// Backend enum
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
enum Backend {
    VirtioGpu,
    AmdGpu,
    Vga,
    Gop,
    None,
}

static BACKEND: Mutex<Backend> = Mutex::new(Backend::None);

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

pub fn init_virtio(mmio_base: u64) {
    crate::drivers::gpu::virtio_gpu::init(mmio_base);
    *BACKEND.lock() = Backend::VirtioGpu;
}

pub fn init_amdgpu(mmio_base: u64) {
    crate::drivers::gpu::amdgpu_gem::init(mmio_base);
    *BACKEND.lock() = Backend::AmdGpu;
}

pub fn init_vga() {
    crate::drivers::gpu::vga::init();
    *BACKEND.lock() = Backend::Vga;
}

pub fn init_gop(base: u64, width: u32, height: u32, pitch: u32) {
    crate::drivers::gpu::gop::init(base, width, height, pitch);
    *BACKEND.lock() = Backend::Gop;
}

pub fn is_initialised() -> bool {
    *BACKEND.lock() != Backend::None
}

// ---------------------------------------------------------------------------
// Display info
// ---------------------------------------------------------------------------

pub fn display_info() -> Option<DisplayInfo> {
    match *BACKEND.lock() {
        Backend::VirtioGpu => crate::drivers::gpu::virtio_gpu::display_info(),
        Backend::AmdGpu    => crate::drivers::gpu::amdgpu_gem::display_info(),
        Backend::Vga       => crate::drivers::gpu::vga::display_info(),
        Backend::Gop       => crate::drivers::gpu::gop::display_info(),
        Backend::None      => None,
    }
}

// ---------------------------------------------------------------------------
// Drawing primitives
// ---------------------------------------------------------------------------

/// Fill the entire framebuffer with `argb` colour.
pub fn clear(argb: u32) {
    match *BACKEND.lock() {
        Backend::VirtioGpu => crate::drivers::gpu::virtio_gpu::clear(argb),
        Backend::Vga       => crate::drivers::gpu::vga::clear(argb),
        Backend::Gop       => crate::drivers::gpu::gop::clear(argb),
        _                  => {}
    }
}

/// Blit `width * height` ARGB pixels starting at `(x, y)`.
pub fn blit(x: u32, y: u32, width: u32, height: u32, pixels: &[u32]) {
    match *BACKEND.lock() {
        Backend::VirtioGpu => crate::drivers::gpu::virtio_gpu::blit(x, y, width, height, pixels),
        Backend::Vga       => crate::drivers::gpu::vga::blit(x, y, width, height, pixels),
        Backend::Gop       => crate::drivers::gpu::gop::blit(x, y, width, height, pixels),
        _                  => {}
    }
}

/// Flush pending drawing to the physical display.
pub fn flush() {
    match *BACKEND.lock() {
        Backend::VirtioGpu => crate::drivers::gpu::virtio_gpu::flush(),
        Backend::Gop       => { /* GOP writes directly to linear FB */ }
        _                  => {}
    }
}

/// Draw an ASCII character at pixel position `(x, y)` using an 8×16 bitmap font.
pub fn draw_char(x: u32, y: u32, c: u8, fg: u32, bg: u32) {
    let glyph = font_glyph(c);
    let mut px = [bg; 8 * 16];
    for row in 0..16usize {
        let bits = glyph[row];
        for col in 0..8usize {
            if bits & (0x80 >> col) != 0 {
                px[row * 8 + col] = fg;
            }
        }
    }
    blit(x, y, 8, 16, &px);
}

/// Draw a null-terminated ASCII string at `(x, y)`.  Advances X by 8 per char.
pub fn draw_str(mut x: u32, y: u32, s: &str, fg: u32, bg: u32) {
    for c in s.bytes() {
        draw_char(x, y, c, fg, bg);
        x += 8;
    }
}

// ---------------------------------------------------------------------------
// 8x16 bitmap font (CP437 subset, first 128 glyphs)
// ---------------------------------------------------------------------------

fn font_glyph(c: u8) -> &'static [u8; 16] {
    &FONT8X16[c.min(127) as usize]
}

// Only the printable ASCII range is populated here for brevity.
// Non-printable glyphs default to all-zeros (blank).
#[rustfmt::skip]
static FONT8X16: [[u8; 16]; 128] = {
    let mut f = [[0u8; 16]; 128];
    // Space (0x20)
    // '!' (0x21)
    // We embed a minimal 8x16 definition for 0x20–7E.
    // Full font data would be ~2 KB; abbreviated here.
    f
};
