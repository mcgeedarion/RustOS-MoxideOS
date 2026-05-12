//! Plane management.
//!
//! A plane represents a hardware layer that can be composited by the
//! display engine. Primary planes show framebuffers; overlay planes
//! can be used for hardware cursor or video overlay.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaneType {
    Primary,
    Overlay,
    Cursor,
}

pub struct Plane {
    pub id: u32,
    pub plane_type: PlaneType,
    pub crtc_id: Option<u32>,
    pub fb_id: Option<u32>,
}

impl Plane {
    pub fn new(id: u32, plane_type: PlaneType) -> Self {
        Self { id, plane_type, crtc_id: None, fb_id: None }
    }

    pub fn attach(&mut self, crtc_id: u32, fb_id: u32) {
        self.crtc_id = Some(crtc_id);
        self.fb_id = Some(fb_id);
    }
}
