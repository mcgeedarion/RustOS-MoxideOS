//! In-kernel Wayland compositor and server.
//!
//! Surfaces are presented to the display via `crate::display::drm`.
//!
//! ## Kernel responsibilities
//!
//! This module is intentionally thin. The Wayland compositor runs as a
//! privileged userspace process (`/usr/bin/rustos-compositor`). The kernel
//! retains only:
//!
//!   - `compositor::vblank_notify` — vblank ISR pass-through to the compositor process via
//!     `crate::drivers::drm::deliver_vblank_event`.
//!   - `server` — architecture documentation; no public API.

pub mod compositor;
pub mod server;
