//! Encoder management.
//!
//! An encoder converts pixel data from a CRTC to the format required
//! by a connector (e.g., TMDS for HDMI, LVDS for panels).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderType {
    None,
    Dac,
    Tmds,
    Lvds,
    TvDac,
    Virtual,
    Dsi,
    Dpmst,
    Dp,
}

pub struct Encoder {
    pub id: u32,
    pub encoder_type: EncoderType,
    pub crtc_id: Option<u32>,
}

impl Encoder {
    pub fn new(id: u32, encoder_type: EncoderType) -> Self {
        Self {
            id,
            encoder_type,
            crtc_id: None,
        }
    }

    pub fn attach_crtc(&mut self, crtc_id: u32) {
        self.crtc_id = Some(crtc_id);
    }
}
