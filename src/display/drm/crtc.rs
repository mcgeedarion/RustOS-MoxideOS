//! CRTC (Cathode Ray Tube Controller) management.
//!
//! A CRTC scans out a framebuffer to one or more encoders. It controls
//! the display timing and resolution.

use super::DisplayMode;

pub struct Crtc {
    pub id: u32,
    pub mode: Option<DisplayMode>,
    pub enabled: bool,
    pub x: u32,
    pub y: u32,
}

impl Crtc {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            mode: None,
            enabled: false,
            x: 0,
            y: 0,
        }
    }

    pub fn set_mode(&mut self, mode: DisplayMode) {
        self.mode = Some(mode);
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.mode = None;
        self.enabled = false;
    }
}
