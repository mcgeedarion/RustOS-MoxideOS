//! Display subsystem: DRM/KMS object model and Wayland compositor.
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

pub mod drm;
pub mod wayland;
