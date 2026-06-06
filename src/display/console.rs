//! Framebuffer text console.
//!
//! Wraps a DRM [`FramebufferDesc`] + a mapped pixel buffer and
//! a [`Psf2Font`] to provide a terminal-style scrolling text surface.
//! Evdev key events (translated to ASCII by the input layer) are fed
//! in via [`Console::feed_char`].
//!
//! ## Architecture
//!
//! ```text
//!  evdev  ──► input::KeyEvent ──► Console::feed_char()
//!                                        │
//!                                   echo to cell grid
//!                                        │
//!                               Console::flush() ──► DRM framebuffer
//! ```
//!
//! The console is intentionally dumb: it does not own a DRM device or
//! mode-set.  The caller maps the GEM buffer's physical address and
//! passes the raw `&mut [u32]` slice here.  The compositor (Wayland
//! layer) can later take over by simply replacing or overlaying that
//! buffer.

use crate::display::drm::framebuffer::FramebufferDesc;
use crate::display::font::Psf2Font;

/// Default foreground: bright white.
pub const DEFAULT_FG: u32 = 0x00FF_FFFF;
/// Default background: near-black.
pub const DEFAULT_BG: u32 = 0x001C_1C1C;

/// A single text cell.
#[derive(Clone, Copy)]
struct Cell {
    ch: u8,
    fg: u32,
    bg: u32,
    /// Whether this cell needs to be repainted on the next flush.
    dirty: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self {
            ch: b' ',
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
            dirty: true,
        }
    }
}

/// Scrolling framebuffer console.
///
/// Generic over the font lifetime so it can hold a `Psf2Font<'static>`
/// from an embedded font blob without any allocation.
pub struct Console<'font> {
    font: Psf2Font<'font>,
    fb: FramebufferDesc,
    cols: usize,
    rows: usize,
    /// Column of the text cursor.
    cursor_col: usize,
    /// Row of the text cursor.
    cursor_row: usize,
    /// Flat cell grid, row-major.
    cells: alloc::vec::Vec<Cell>,
    /// Current foreground / background colours (can be changed via escape
    /// sequences or direct API later).
    fg: u32,
    bg: u32,
}

impl<'font> Console<'font> {
    /// Construct a new console.
    ///
    /// `font`  — parsed PSF2 font.  
    /// `fb`    — DRM framebuffer descriptor (used for dimensions/pitch).  
    pub fn new(font: Psf2Font<'font>, fb: FramebufferDesc) -> Self {
        let cols = fb.width as usize / font.width() as usize;
        let rows = fb.height as usize / font.height() as usize;
        let cells = alloc::vec![Cell::default(); cols * rows];
        Self {
            font,
            fb,
            cols,
            rows,
            cursor_col: 0,
            cursor_row: 0,
            cells,
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
        }
    }

    // ------------------------------------------------------------------ //
    //  Public API                                                          //
    // ------------------------------------------------------------------ //

    /// Feed a single byte (ASCII or Latin-1) into the console.
    ///
    /// Call this from the evdev / keyboard input path once per keystroke.
    pub fn feed_char(&mut self, ch: u8) {
        match ch {
            b'\r' | b'\n' => self.newline(),
            0x08 | 0x7F => self.backspace(),
            _ => self.put_char(ch),
        }
    }

    /// Write a UTF-8 string slice one byte at a time.
    pub fn write_str(&mut self, s: &str) {
        for byte in s.bytes() {
            self.feed_char(byte);
        }
    }

    /// Repaint all dirty cells into the provided pixel buffer.
    ///
    /// `pixels` must cover the full framebuffer: `pitch * height` `u32`s.
    /// `pitch`  is the framebuffer stride expressed in **pixels** (i.e.
    ///          `FramebufferDesc::stride() / 4` for 32 bpp).
    pub fn flush(&mut self, pixels: &mut [u32], pitch: usize) {
        let gw = self.font.width() as usize;
        let gh = self.font.height() as usize;

        for row in 0..self.rows {
            for col in 0..self.cols {
                let cell = &mut self.cells[row * self.cols + col];
                if !cell.dirty {
                    continue;
                }
                cell.dirty = false;
                let ch = cell.ch;
                let fg = cell.fg;
                let bg = cell.bg;

                // Fill cell background first.
                let px = col * gw;
                let py = row * gh;
                for dy in 0..gh {
                    let base = (py + dy) * pitch + px;
                    for dx in 0..gw {
                        let off = base + dx;
                        if off < pixels.len() {
                            pixels[off] = bg;
                        }
                    }
                }

                // Overlay glyph.
                self.font.draw_glyph(ch, pixels, px, py, pitch, fg, None);
            }
        }
    }

    /// Force-mark every cell dirty so the next `flush` redraws entirely.
    pub fn invalidate(&mut self) {
        for cell in self.cells.iter_mut() {
            cell.dirty = true;
        }
    }

    /// Move the hardware cursor (if supported) or just update internal state.
    pub fn set_cursor(&mut self, col: usize, row: usize) {
        self.cursor_col = col.min(self.cols.saturating_sub(1));
        self.cursor_row = row.min(self.rows.saturating_sub(1));
    }

    /// Change the active foreground/background colours for subsequent writes.
    pub fn set_colors(&mut self, fg: u32, bg: u32) {
        self.fg = fg;
        self.bg = bg;
    }

    // ------------------------------------------------------------------ //
    //  Internal helpers                                                    //
    // ------------------------------------------------------------------ //

    fn put_char(&mut self, ch: u8) {
        if self.cursor_col >= self.cols {
            self.newline();
        }
        let idx = self.cursor_row * self.cols + self.cursor_col;
        self.cells[idx] = Cell {
            ch,
            fg: self.fg,
            bg: self.bg,
            dirty: true,
        };
        self.cursor_col += 1;
    }

    fn newline(&mut self) {
        self.cursor_col = 0;
        if self.cursor_row + 1 < self.rows {
            self.cursor_row += 1;
        } else {
            self.scroll_up();
        }
    }

    fn backspace(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        } else if self.cursor_row > 0 {
            self.cursor_row -= 1;
            self.cursor_col = self.cols - 1;
        }
        let idx = self.cursor_row * self.cols + self.cursor_col;
        self.cells[idx] = Cell {
            ch: b' ',
            fg: self.fg,
            bg: self.bg,
            dirty: true,
        };
    }

    /// Shift every row up by one; blank the last row.
    fn scroll_up(&mut self) {
        for row in 1..self.rows {
            for col in 0..self.cols {
                let src = self.cells[row * self.cols + col];
                let dst = &mut self.cells[(row - 1) * self.cols + col];
                if dst.ch != src.ch || dst.fg != src.fg || dst.bg != src.bg {
                    *dst = Cell { dirty: true, ..src };
                }
            }
        }
        // Blank the last row.
        let last = (self.rows - 1) * self.cols;
        for col in 0..self.cols {
            self.cells[last + col] = Cell {
                dirty: true,
                ..Cell::default()
            };
        }
        self.cursor_row = self.rows - 1;
    }
}

// ------------------------------------------------------------------ //
//  core::fmt::Write glue so the console can be used with write!()/    //
//  writeln!() macros from the kernel's logging paths.                 //
// ------------------------------------------------------------------ //

use core::fmt;

impl<'font> fmt::Write for Console<'font> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Console::write_str(self, s);
        Ok(())
    }
}
