//! PSF2 (PC Screen Font v2) bitmap font renderer.
//!
//! Parses an in-memory PSF2 blob and rasterises individual glyphs
//! directly into a caller-supplied pixel buffer.
//!
//! ## Usage
//! ```rust
//! // Embed a PSF2 font at compile time:
//! static FONT_BYTES: &[u8] = include_bytes!("../../assets/font.psf");
//! let font = Psf2Font::parse(FONT_BYTES).unwrap();
//! font.draw_glyph(b'A', buf, x, y, pitch, 0x00FF_FFFF);
//! ```

/// Magic number at offset 0 of every PSF2 file.
pub const PSF2_MAGIC: u32 = 0x864A_B572;

/// Raw PSF2 file header — all fields little-endian.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Psf2Header {
    pub magic:        u32,
    pub version:      u32,
    pub header_size:  u32,  // bytes before glyph data
    pub flags:        u32,  // bit 0: has unicode table
    pub glyph_count:  u32,
    pub bytes_per_glyph: u32,
    pub height:       u32,  // pixels per glyph
    pub width:        u32,  // pixels per glyph
}

/// A validated, zero-copy view into a PSF2 font blob.
pub struct Psf2Font<'a> {
    pub header: Psf2Header,
    /// Slice of every glyph's bitmap data, tightly packed.
    glyphs: &'a [u8],
}

#[derive(Debug)]
pub enum Psf2Error {
    TooShort,
    BadMagic,
    BadVersion,
    GlyphDataOverflow,
}

impl<'a> Psf2Font<'a> {
    /// Parse a PSF2 blob.  Returns an error if the header is invalid
    /// or the file is too short to contain all declared glyphs.
    pub fn parse(data: &'a [u8]) -> Result<Self, Psf2Error> {
        if data.len() < core::mem::size_of::<Psf2Header>() {
            return Err(Psf2Error::TooShort);
        }

        // SAFETY: we just verified `data` is long enough for the header.
        let hdr: Psf2Header = unsafe {
            core::ptr::read_unaligned(data.as_ptr() as *const Psf2Header)
        };

        if hdr.magic != PSF2_MAGIC {
            return Err(Psf2Error::BadMagic);
        }
        if hdr.version != 0 {
            return Err(Psf2Error::BadVersion);
        }

        let glyph_start = hdr.header_size as usize;
        let glyph_total = (hdr.glyph_count as usize)
            .checked_mul(hdr.bytes_per_glyph as usize)
            .ok_or(Psf2Error::GlyphDataOverflow)?;

        let glyph_end = glyph_start
            .checked_add(glyph_total)
            .ok_or(Psf2Error::GlyphDataOverflow)?;

        if data.len() < glyph_end {
            return Err(Psf2Error::TooShort);
        }

        Ok(Self { header: hdr, glyphs: &data[glyph_start..glyph_end] })
    }

    /// Width of a single glyph in pixels.
    #[inline]
    pub fn width(&self) -> u32 { self.header.width }

    /// Height of a single glyph in pixels.
    #[inline]
    pub fn height(&self) -> u32 { self.header.height }

    /// Bytes per glyph row (rounded up to the nearest whole byte).
    #[inline]
    pub fn bytes_per_row(&self) -> u32 {
        (self.header.width + 7) / 8
    }

    /// Return the bitmap slice for glyph index `index`, or `None` if
    /// `index` is out of range.
    pub fn glyph_bitmap(&self, index: u32) -> Option<&[u8]> {
        if index >= self.header.glyph_count {
            return None;
        }
        let bpg  = self.header.bytes_per_glyph as usize;
        let off  = index as usize * bpg;
        Some(&self.glyphs[off..off + bpg])
    }

    /// Draw glyph for ASCII/Latin-1 codepoint `ch` at pixel position
    /// `(dst_x, dst_y)` into a 32-bpp `XRGB8888` pixel buffer.
    ///
    /// * `pixels`  — mutable slice of `u32` covering the full framebuffer.
    /// * `pitch`   — number of `u32` elements per horizontal scan line
    ///               (i.e. `fb_width` or `fb_pitch / 4`).
    /// * `fg`      — foreground colour as `0x00RRGGBB`.
    /// * `bg`      — background colour; pass `None` to skip background
    ///               pixels (transparent blending).
    pub fn draw_glyph(
        &self,
        ch: u8,
        pixels: &mut [u32],
        dst_x: usize,
        dst_y: usize,
        pitch: usize,
        fg: u32,
        bg: Option<u32>,
    ) {
        // Clamp to the font's glyph table; unmapped bytes use glyph 0.
        let index = if (ch as u32) < self.header.glyph_count { ch as u32 } else { 0 };
        let bitmap = match self.glyph_bitmap(index) {
            Some(b) => b,
            None    => return,
        };

        let bpr = self.bytes_per_row() as usize;
        let h   = self.header.height as usize;
        let w   = self.header.width  as usize;

        for row in 0..h {
            let row_bytes = &bitmap[row * bpr..(row + 1) * bpr];
            let base = (dst_y + row) * pitch + dst_x;

            for col in 0..w {
                let byte_idx = col / 8;
                let bit_idx  = 7 - (col % 8);  // MSB-first
                let set = (row_bytes[byte_idx] >> bit_idx) & 1 != 0;

                let pixel_off = base + col;
                if pixel_off >= pixels.len() {
                    return;
                }

                if set {
                    pixels[pixel_off] = fg;
                } else if let Some(bg_col) = bg {
                    pixels[pixel_off] = bg_col;
                }
            }
        }
    }
}
