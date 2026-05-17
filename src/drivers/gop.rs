//! VGA text-mode and Mode 13h pixel-mode driver.
//!
//! ## When this is used
//!   VGA is the last-resort display before UEFI GOP, virtio-gpu, or any
//!   other framebuffer is available.  It is used in two scenarios:
//!
//!   1. **Early boot** — before ExitBootServices and GOP capture, the
//!      firmware still leaves VGA text mode active on x86_64.  The early
//!      console (`early_con`) writes directly to the text buffer at
//!      physical 0xB8000.
//!
//!   2. **Bare-metal fallback** — on machines with no UEFI GOP (very old
//!      hardware or legacy BIOS boot), the kernel can set Mode 13h and
//!      use the linear pixel buffer at 0xA0000 as a 320×200 display.
//!
//! ## Text mode (80×25, mode 0x03)
//!   Buffer:   0xB8000 (identity-mapped)
//!   Format:   u16 per cell — low byte = ASCII, high byte = attribute
//!             Attribute: bits[7:4] = background, bits[3:0] = foreground
//!             Colour indices: 0=black 1=blue 2=green 3=cyan 4=red
//!                             5=magenta 6=brown 7=ltgrey 8=dkgrey
//!                             9=ltblue A=ltgreen B=ltcyan C=ltred
//!                             D=ltmagenta E=yellow F=white
//!   Cursor:   CRT index registers 0x3D4/0x3D5, indices 0x0E (hi) / 0x0F (lo)
//!
//! ## Mode 13h pixel mode (320×200 × 8-bit palette)
//!   Buffer:   0xA0000 (identity-mapped)
//!   Format:   1 byte per pixel, value = palette index (256-colour)
//!   Palette:  programmed via DAC registers 0x3C8 (write index) / 0x3C9 (data,
//!             R then G then B, 6 bits each)
//!
//! ## Public API
//!   Text mode:
//!     text::init()                 — zero buffer, reset cursor
//!     text::put_char(col, row, ch, attr)
//!     text::put_str(col, row, s, attr)
//!     text::scroll_up()
//!     text::clear()
//!     text::set_cursor(col, row)
//!     text::hide_cursor()
//!     COLS, ROWS                   — 80, 25
//!   Pixel mode:
//!     mode13::init()               — set Mode 13h, load default palette
//!     mode13::put_pixel(x, y, idx)
//!     mode13::fill(idx)
//!     mode13::load_palette(pal)    — load 256-entry [u8;3] array (RGB, 6-bit)
//!     W, H                         — 320, 200

// ─────────────────────────────────────────────────────────────────────────────
// I/O port helpers (x86_64 only — this driver is a no-op on RISC-V)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod io {
    #[inline(always)]
    pub unsafe fn inb(port: u16) -> u8 {
        let v: u8;
        core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack));
        v
    }
    #[inline(always)]
    pub unsafe fn outb(port: u16, val: u8) {
        core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
    }
    #[inline(always)]
    pub unsafe fn outw(port: u16, val: u16) {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Text mode  (0xB8000, 80×25)
// ─────────────────────────────────────────────────────────────────────────────

pub mod text {
    #[cfg(target_arch = "x86_64")]
    use super::io;

    // Physical base of VGA text buffer (identity-mapped in kernel page tables).
    const TEXT_PHYS: usize = 0xB8000;

    pub const COLS: usize = 80;
    pub const ROWS: usize = 25;

    // CRT controller I/O ports.
    const CRTC_ADDR: u16 = 0x3D4;
    const CRTC_DATA: u16 = 0x3D5;
    const CRTC_CURSOR_HI: u8 = 0x0E;
    const CRTC_CURSOR_LO: u8 = 0x0F;
    const CRTC_CURSOR_START: u8 = 0x0A;
    const CRTC_CURSOR_END:   u8 = 0x0B;

    /// Default text attribute: white (0xF) on black (0x0).
    pub const ATTR_DEFAULT: u8 = 0x0F;
    /// Bright white on blue — useful for status bars.
    pub const ATTR_HIGHLIGHT: u8 = 0x1F;
    /// Light red on black — errors.
    pub const ATTR_ERROR: u8 = 0x0C;

    /// Colour indices for the attribute nibbles.
    #[allow(dead_code)]
    pub mod colour {
        pub const BLACK:     u8 = 0x0;
        pub const BLUE:      u8 = 0x1;
        pub const GREEN:     u8 = 0x2;
        pub const CYAN:      u8 = 0x3;
        pub const RED:       u8 = 0x4;
        pub const MAGENTA:   u8 = 0x5;
        pub const BROWN:     u8 = 0x6;
        pub const LTGREY:    u8 = 0x7;
        pub const DKGREY:    u8 = 0x8;
        pub const LTBLUE:    u8 = 0x9;
        pub const LTGREEN:   u8 = 0xA;
        pub const LTCYAN:    u8 = 0xB;
        pub const LTRED:     u8 = 0xC;
        pub const LTMAGENTA: u8 = 0xD;
        pub const YELLOW:    u8 = 0xE;
        pub const WHITE:     u8 = 0xF;

        /// Build an attribute byte: `fg | (bg << 4)`.
        #[inline]
        pub const fn attr(fg: u8, bg: u8) -> u8 { fg | (bg << 4) }
    }

    // ── Buffer helpers ────────────────────────────────────────────────────────

    /// Return a mutable pointer to the cell at `(col, row)`.
    #[inline]
    unsafe fn cell(col: usize, row: usize) -> *mut u16 {
        (TEXT_PHYS as *mut u16).add(row * COLS + col)
    }

    /// Pack a character and attribute into a VGA text cell word.
    #[inline]
    const fn pack(ch: u8, attr: u8) -> u16 {
        (attr as u16) << 8 | ch as u16
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Clear the text buffer and move the hardware cursor to (0, 0).
    pub fn init() {
        clear();
        #[cfg(target_arch = "x86_64")]
        unsafe { set_cursor(0, 0); show_cursor(true); }
    }

    /// Clear the entire screen to spaces with `ATTR_DEFAULT`.
    pub fn clear() {
        let blank = pack(b' ', ATTR_DEFAULT);
        for i in 0..(COLS * ROWS) {
            unsafe { (TEXT_PHYS as *mut u16).add(i).write_volatile(blank); }
        }
    }

    /// Write a single character at `(col, row)` with `attr`.
    ///
    /// Out-of-bounds writes are silently ignored.
    #[inline]
    pub fn put_char(col: usize, row: usize, ch: u8, attr: u8) {
        if col >= COLS || row >= ROWS { return; }
        unsafe { cell(col, row).write_volatile(pack(ch, attr)); }
    }

    /// Write an ASCII string starting at `(col, row)`, wrapping at `COLS`.
    /// Returns the column position after the last character written.
    pub fn put_str(col: usize, row: usize, s: &[u8], attr: u8) -> usize {
        let mut c = col;
        let mut r = row;
        for &ch in s {
            if r >= ROWS { break; }
            match ch {
                b'\n' => { c = 0; r += 1; }
                b'\r' => { c = 0; }
                _ => {
                    put_char(c, r, ch, attr);
                    c += 1;
                    if c >= COLS { c = 0; r += 1; }
                }
            }
        }
        c
    }

    /// Scroll the entire screen up by one row; blank the last row.
    pub fn scroll_up() {
        unsafe {
            let base = TEXT_PHYS as *mut u16;
            // Move rows 1..ROWS up to rows 0..ROWS-1.
            for row in 0..(ROWS - 1) {
                for col in 0..COLS {
                    let src = base.add((row + 1) * COLS + col).read_volatile();
                    base.add(row * COLS + col).write_volatile(src);
                }
            }
            // Blank the last row.
            let blank = pack(b' ', ATTR_DEFAULT);
            for col in 0..COLS {
                base.add((ROWS - 1) * COLS + col).write_volatile(blank);
            }
        }
    }

    /// Move the VGA hardware text cursor to `(col, row)`.
    #[cfg(target_arch = "x86_64")]
    pub fn set_cursor(col: usize, row: usize) {
        let pos = (row * COLS + col) as u16;
        unsafe {
            io::outb(CRTC_ADDR, CRTC_CURSOR_HI);
            io::outb(CRTC_DATA, (pos >> 8) as u8);
            io::outb(CRTC_ADDR, CRTC_CURSOR_LO);
            io::outb(CRTC_DATA, (pos & 0xFF) as u8);
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn set_cursor(_col: usize, _row: usize) {}

    /// Show or hide the blinking hardware cursor.
    ///
    /// Hiding is done by setting the cursor-start register bit 5 (disable).
    #[cfg(target_arch = "x86_64")]
    pub fn show_cursor(visible: bool) {
        unsafe {
            io::outb(CRTC_ADDR, CRTC_CURSOR_START);
            let v = io::inb(CRTC_DATA);
            if visible {
                io::outb(CRTC_DATA, v & !0x20);
            } else {
                io::outb(CRTC_DATA, v | 0x20);
            }
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn show_cursor(_visible: bool) {}

    /// Convenience alias.
    #[inline]
    pub fn hide_cursor() { show_cursor(false); }

    /// Read the current hardware cursor position as `(col, row)`.
    #[cfg(target_arch = "x86_64")]
    pub fn cursor_pos() -> (usize, usize) {
        let pos = unsafe {
            io::outb(CRTC_ADDR, CRTC_CURSOR_HI);
            let hi = io::inb(CRTC_DATA) as u16;
            io::outb(CRTC_ADDR, CRTC_CURSOR_LO);
            let lo = io::inb(CRTC_DATA) as u16;
            (hi << 8) | lo
        };
        (pos as usize % COLS, pos as usize / COLS)
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn cursor_pos() -> (usize, usize) { (0, 0) }

    /// Set cursor shape: `scan_start`..`scan_end` (0–15).
    /// Typical underline cursor: `(13, 14)`.  Block cursor: `(0, 15)`.
    #[cfg(target_arch = "x86_64")]
    pub fn set_cursor_shape(scan_start: u8, scan_end: u8) {
        unsafe {
            io::outb(CRTC_ADDR, CRTC_CURSOR_START);
            io::outb(CRTC_DATA, scan_start & 0x1F);
            io::outb(CRTC_ADDR, CRTC_CURSOR_END);
            io::outb(CRTC_DATA, scan_end & 0x1F);
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn set_cursor_shape(_s: u8, _e: u8) {}

    /// Write a `\0`-terminated C-style string for convenience.
    pub fn put_cstr(col: usize, row: usize, s: &[u8], attr: u8) {
        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        put_str(col, row, &s[..end], attr);
    }

    /// Fill a rectangular region `(col, row, w, h)` with `(ch, attr)`.
    pub fn fill_rect(col: usize, row: usize, w: usize, h: usize, ch: u8, attr: u8) {
        let word = pack(ch, attr);
        for r in row..(row + h).min(ROWS) {
            for c in col..(col + w).min(COLS) {
                unsafe { cell(c, r).write_volatile(word); }
            }
        }
    }

    /// Draw a simple single-line box at `(col, row)` of size `(w, h)`.
    ///
    /// Uses CP437 box-drawing characters:
    ///   corners ┌ ┐ └ ┘, horizontals ─, verticals │
    pub fn draw_box(col: usize, row: usize, w: usize, h: usize, attr: u8) {
        if w < 2 || h < 2 { return; }
        // Corners
        put_char(col,         row,         0xDA, attr); // ┌
        put_char(col + w - 1, row,         0xBF, attr); // ┐
        put_char(col,         row + h - 1, 0xC0, attr); // └
        put_char(col + w - 1, row + h - 1, 0xD9, attr); // ┘
        // Top / bottom edges
        for c in (col + 1)..(col + w - 1) {
            put_char(c, row,         0xC4, attr); // ─
            put_char(c, row + h - 1, 0xC4, attr);
        }
        // Side edges
        for r in (row + 1)..(row + h - 1) {
            put_char(col,         r, 0xB3, attr); // │
            put_char(col + w - 1, r, 0xB3, attr);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode 13h  (320×200, 256-colour palette, 0xA0000)
// ─────────────────────────────────────────────────────────────────────────────

pub mod mode13 {
    #[cfg(target_arch = "x86_64")]
    use super::io;

    pub const W: usize = 320;
    pub const H: usize = 200;
    const PIXEL_PHYS: usize = 0xA0000;

    // VGA sequencer / CRTC / GC / AC I/O ports.
    const MISC_WRITE:    u16 = 0x3C2;
    const SEQ_ADDR:      u16 = 0x3C4;
    const CRTC_ADDR:     u16 = 0x3D4;
    const GC_ADDR:       u16 = 0x3CE;
    const AC_ADDR_DATA:  u16 = 0x3C0;
    const AC_READ:       u16 = 0x3C1;
    const INPUT_STATUS1: u16 = 0x3DA;
    const DAC_WRITE_IDX: u16 = 0x3C8;
    const DAC_DATA:      u16 = 0x3C9;

    // ── Mode 13h register tables ──────────────────────────────────────────────
    //
    // These are the register values needed to set standard 320×200×8bpp mode
    // (BIOS mode 13h) from protected/long mode without calling INT 10h.
    // Values sourced from FreeVGA project documentation.

    const MISC: u8 = 0x63;

    const SEQ_REGS: &[(u8, u8)] = &[
        (0x00, 0x03), // reset
        (0x01, 0x01), // clocking mode: 8-dot char
        (0x02, 0x0F), // map mask: enable all planes
        (0x03, 0x00), // character map select
        (0x04, 0x0E), // sequencer memory mode: chain-4
    ];

    const CRTC_REGS: &[(u8, u8)] = &[
        (0x00, 0x5F), // horizontal total
        (0x01, 0x4F), // horizontal display end
        (0x02, 0x50), // start horizontal blanking
        (0x03, 0x82), // end horizontal blanking
        (0x04, 0x54), // start horizontal retrace
        (0x05, 0x80), // end horizontal retrace
        (0x06, 0xBF), // vertical total
        (0x07, 0x1F), // overflow
        (0x08, 0x00), // preset row scan
        (0x09, 0x41), // max scan line (double-scan)
        (0x0A, 0x00), // cursor start
        (0x0B, 0x00), // cursor end
        (0x0C, 0x00), // start address high
        (0x0D, 0x00), // start address low
        (0x0E, 0x00), // cursor location high
        (0x0F, 0x00), // cursor location low
        (0x10, 0x9C), // vertical retrace start
        (0x11, 0x8E), // vertical retrace end
        (0x12, 0x8F), // vertical display end
        (0x13, 0x28), // logical width
        (0x14, 0x40), // underline location
        (0x15, 0x96), // start vertical blanking
        (0x16, 0xB9), // end vertical blanking
        (0x17, 0xA3), // CRTC mode control
        (0x18, 0xFF), // line compare
    ];

    const GC_REGS: &[(u8, u8)] = &[
        (0x00, 0x00), // set/reset
        (0x01, 0x00), // enable set/reset
        (0x02, 0x00), // color compare
        (0x03, 0x00), // data rotate
        (0x04, 0x00), // read map select
        (0x05, 0x40), // graphics mode
        (0x06, 0x05), // misc: graphics mode, A0000-AFFFF
        (0x07, 0x0F), // color don't care
        (0x08, 0xFF), // bit mask
    ];

    const AC_REGS: &[u8; 21] = &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x41, // mode control: 256-colour
        0x00, // overscan colour
        0x0F, // colour plane enable
        0x00, // horizontal pixel panning
        0x00, // colour select
    ];

    // ── Default 256-colour palette  (VGA standard palette) ───────────────────
    //
    // First 16 entries match the EGA/VGA standard.  The rest follow the
    // standard 256-colour layout BIOS mode 13h loads by default.
    // Each entry is [R, G, B], values 0–63 (6-bit DAC).
    //
    // We only define the first 16 here and fill the rest programmatically.

    const EGA16: [[u8; 3]; 16] = [
        [0x00,0x00,0x00], // 0  black
        [0x00,0x00,0x2A], // 1  blue
        [0x00,0x2A,0x00], // 2  green
        [0x00,0x2A,0x2A], // 3  cyan
        [0x2A,0x00,0x00], // 4  red
        [0x2A,0x00,0x2A], // 5  magenta
        [0x2A,0x15,0x00], // 6  brown
        [0x2A,0x2A,0x2A], // 7  light grey
        [0x15,0x15,0x15], // 8  dark grey
        [0x15,0x15,0x3F], // 9  light blue
        [0x15,0x3F,0x15], // 10 light green
        [0x15,0x3F,0x3F], // 11 light cyan
        [0x3F,0x15,0x15], // 12 light red
        [0x3F,0x15,0x3F], // 13 light magenta
        [0x3F,0x3F,0x15], // 14 yellow
        [0x3F,0x3F,0x3F], // 15 white
    ];

    // ── Public API ────────────────────────────────────────────────────────────

    /// Program Mode 13h registers and load the default VGA palette.
    ///
    /// **Only call this on x86_64 bare-metal.**  On a UEFI system that has
    /// already called ExitBootServices and captured GOP, use the GOP
    /// framebuffer instead (`framebuffer::acquire()`).
    #[cfg(target_arch = "x86_64")]
    pub fn init() {
        unsafe { set_mode13h_regs(); }
        load_default_palette();
        fill(0); // clear to black
    }
    #[cfg(not(target_arch = "x86_64"))]
    pub fn init() {} // no-op on RISC-V

    /// Write one pixel at `(x, y)` with palette index `idx`.
    #[inline]
    pub fn put_pixel(x: usize, y: usize, idx: u8) {
        if x >= W || y >= H { return; }
        unsafe {
            ((PIXEL_PHYS + y * W + x) as *mut u8).write_volatile(idx);
        }
    }

    /// Fill the entire 320×200 buffer with palette index `idx`.
    pub fn fill(idx: u8) {
        for i in 0..(W * H) {
            unsafe { (PIXEL_PHYS as *mut u8).add(i).write_volatile(idx); }
        }
    }

    /// Load a custom 256-entry palette.
    ///
    /// `pal` must be a 256×3 array: `[[R, G, B]; 256]` with values 0–63.
    pub fn load_palette(pal: &[[u8; 3]; 256]) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            io::outb(DAC_WRITE_IDX, 0);
            for entry in pal.iter() {
                io::outb(DAC_DATA, entry[0]);
                io::outb(DAC_DATA, entry[1]);
                io::outb(DAC_DATA, entry[2]);
            }
        }
        #[cfg(not(target_arch = "x86_64"))]
        let _ = pal;
    }

    /// Convenience: get a `*mut u8` to the raw pixel buffer.
    ///
    /// # Safety
    /// Caller must ensure Mode 13h is active and no concurrent access.
    #[inline]
    pub unsafe fn raw_buf() -> *mut u8 {
        PIXEL_PHYS as *mut u8
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    #[cfg(target_arch = "x86_64")]
    unsafe fn set_mode13h_regs() {
        // Unlock CRTC registers 0-7 (clear bit 7 of reg 0x11 first).
        io::outb(CRTC_ADDR, 0x11);
        let v = io::inb(CRTC_ADDR + 1);
        io::outb(CRTC_ADDR + 1, v & !0x80);

        // Misc output register.
        io::outb(MISC_WRITE, MISC);

        // Sequencer.
        for &(idx, val) in SEQ_REGS {
            io::outb(SEQ_ADDR,     idx);
            io::outb(SEQ_ADDR + 1, val);
        }

        // CRTC: unlock first, then write all.
        io::outb(CRTC_ADDR, 0x11);
        io::outb(CRTC_ADDR + 1, 0x00); // clear protect bit
        for &(idx, val) in CRTC_REGS {
            io::outb(CRTC_ADDR,     idx);
            io::outb(CRTC_ADDR + 1, val);
        }

        // Graphics controller.
        for &(idx, val) in GC_REGS {
            io::outb(GC_ADDR,     idx);
            io::outb(GC_ADDR + 1, val);
        }

        // Attribute controller: flip to index mode by reading INPUT_STATUS1.
        let _ = io::inb(INPUT_STATUS1);
        for (i, &val) in AC_REGS.iter().enumerate() {
            io::outb(AC_ADDR_DATA, i as u8);
            io::outb(AC_ADDR_DATA, val);
        }
        // Re-enable video output (bit 5 of AC index write = palette source).
        io::outb(AC_ADDR_DATA, 0x20);
    }

    fn load_default_palette() {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            io::outb(DAC_WRITE_IDX, 0);

            // First 16: EGA colours.
            for entry in EGA16.iter() {
                io::outb(DAC_DATA, entry[0]);
                io::outb(DAC_DATA, entry[1]);
                io::outb(DAC_DATA, entry[2]);
            }

            // 16–231: 6×6×6 colour cube.
            for r in 0u8..6 {
                for g in 0u8..6 {
                    for b in 0u8..6 {
                        // Scale 0-5 → 0-63
                        io::outb(DAC_DATA, r * 12 + if r > 0 { 8 } else { 0 });
                        io::outb(DAC_DATA, g * 12 + if g > 0 { 8 } else { 0 });
                        io::outb(DAC_DATA, b * 12 + if b > 0 { 8 } else { 0 });
                    }
                }
            }

            // 232–255: 24-step greyscale (excluding pure black/white already in EGA).
            for i in 0u8..24 {
                let v = i * 2 + 4; // 4, 6, 8 … 50 (6-bit scale)
                io::outb(DAC_DATA, v);
                io::outb(DAC_DATA, v);
                io::outb(DAC_DATA, v);
            }
        }
    }
}
