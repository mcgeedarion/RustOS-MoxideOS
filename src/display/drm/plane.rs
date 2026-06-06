//! Plane management.
//!
//! Planes represent hardware compositing layers. The primary plane
//! displays the main framebuffer; overlay planes can composite
//! additional surfaces (cursors, video, UI layers) without CPU blending.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneType {
    Primary,
    Cursor,
    Overlay,
}

pub struct Plane {
    pub id: u32,
    pub plane_type: PlaneType,
    /// Bitmask of CRTC indices this plane can be used with.
    pub possible_crtcs: u32,
    pub fb_id: Option<u32>,
}

impl Plane {
    pub fn new(id: u32, plane_type: PlaneType, possible_crtcs: u32) -> Self {
        Self {
            id,
            plane_type,
            possible_crtcs,
            fb_id: None,
        }
    }

    pub fn attach_fb(&mut self, fb_id: u32) {
        self.fb_id = Some(fb_id);
    }

    pub fn detach_fb(&mut self) {
        self.fb_id = None;
    }
}
