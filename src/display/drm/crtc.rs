//! CRTC (CRT Controller) management.
//!
//! A CRTC scans out a framebuffer to one or more encoders. Each active
//! display pipeline requires exactly one CRTC.

use super::{DisplayMode, DrmError};

/// Represents a single CRTC instance.
pub struct Crtc {
    pub id: u32,
    pub active: bool,
    pub current_mode: Option<DisplayMode>,
    pub current_fb: Option<u32>,
}

impl Crtc {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            active: false,
            current_mode: None,
            current_fb: None,
        }
    }

    pub fn set_mode(&mut self, mode: DisplayMode, fb_id: u32) -> Result<(), DrmError> {
        self.current_mode = Some(mode);
        self.current_fb = Some(fb_id);
        self.active = true;
        Ok(())
    }

    pub fn disable(&mut self) {
        self.active = false;
        self.current_mode = None;
        self.current_fb = None;
    }
}
