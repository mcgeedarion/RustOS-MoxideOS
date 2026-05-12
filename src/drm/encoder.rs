//! Encoder management.
//!
//! Encoders convert the pixel data from a CRTC into a signal suitable
//! for a particular connector type (HDMI, DisplayPort, LVDS, etc.).

/// Encoder output type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderType {
    None,
    Dac,
    Tmds,  // HDMI / DVI
    Lvds,
    Tvdac,
    Virtual,
    Dsi,
    Dp,    // DisplayPort
}

pub struct Encoder {
    pub id: u32,
    pub encoder_type: EncoderType,
    /// Bitmask of CRTC indices this encoder can be driven by.
    pub possible_crtcs: u32,
}

impl Encoder {
    pub fn new(id: u32, encoder_type: EncoderType, possible_crtcs: u32) -> Self {
        Self { id, encoder_type, possible_crtcs }
    }
}
