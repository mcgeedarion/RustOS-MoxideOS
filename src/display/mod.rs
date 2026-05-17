//! Display subsystem: DRM/KMS object model, Wayland compositor,
//! PSF2 font renderer, and framebuffer text console.
//!
//! ## Layers
//!
//!   `drm`     — DRM/KMS objects (CRTC, encoder, connector, plane, GEM).
//!               This is the kernel-side mode-setting abstraction layer.
//!               The hardware driver stubs live in `crate::drivers::drm`
//!               and `crate::drivers::virtio_gpu`.
//!
//!   `wayland` — In-kernel Wayland compositor and server.
//!               Surfaces are presented to the display via the DRM layer.
//!
//!   `font`    — Zero-copy PSF2 bitmap font parser and glyph rasteriser.
//!               Reads an embedded `*.psf` blob and writes XRGB8888 pixels.
//!
//!   `console` — Scrolling framebuffer text console.
//!               Evdev key events (as ASCII bytes) are fed in via
//!               [`console::Console::feed_char`]; dirty cells are flushed
//!               to the DRM framebuffer via [`console::Console::flush`].

pub mod drm;
pub mod wayland;
pub mod font;
pub mod console;
