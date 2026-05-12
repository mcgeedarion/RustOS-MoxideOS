//! In-kernel Wayland compositor and server.
//!
//! Surfaces are presented to the display via `crate::display::drm`.

pub use crate::wayland::{compositor, server};

pub mod compositor {
    pub use crate::wayland::compositor::*;
}

pub mod server {
    pub use crate::wayland::server::*;
}
