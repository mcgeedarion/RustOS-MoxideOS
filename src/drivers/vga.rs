//! VGA text mode driver — 80 × 25, 16 colours.
//!
//! ## Usage
//!
//! ```rust
//! // In kernel_main, after serial init, before anything that prints:
//! crate::drivers::vga::init();
//!
//! // Then use the macros:
//! vga_println!("Hello from VGA text mode!");
//! vga_print!("col={} row={}", col, row);
//! ```
//!
//! ## Architecture
//!
//! The VGA text buffer lives at physical address `0xB8000`.  Each cell
//! is two bytes: low byte = ASCII character, high byte = attribute
//! (bits 7:4 = background colour, bits 3:0 = foreground colour).
//!
//! After UEFI `ExitBootServices` the identity map is still in place so
//! `0xB8000` is directly accessible as a raw pointer.  If the kernel
//! later remaps the VGA region it should call `vga::set_base(new_va)`.
//!
//! ## CRTC cursor control
//!
//! The hardware text cursor position is programmed through the VGA CRTC
//! index/data port pair at `0x3D4` / `0x3D5` (colour-card base).
//! Registers 14 (0x0E) and 15 (0x0F) hold the high and low bytes of
//! the linear cursor position (0 = top-left, 1999 = bottom-right).
//!
//! ## Scroll
//!
//! When the cursor reaches row 25, rows 1–24 are `memmove`d up by one
//! row and row 24 is cleared with spaces in the current background colour.
//!
//! ## Safety note
//!
//! All MMIO accesses are through `write_volatile` / `read_volatile` to
//! prevent the compiler from eliding or reordering them.  The global
//! writer is protected by a `spin::Mutex`.

#![cfg(target_arch = "x86_64")]

use core::fmt;
use spin::Mutex;

// ─── dimensions ──────────────────────────────────────────────────────────────

pub const COLS: usize = 80;
pub const ROWS: usize = 25;
const BUF_CELLS: usize = COLS * ROWS;

// ─── colour palette ──────────────────────────────────────────────────────────

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    Black        = 0,
    Blue         = 1,
    Green        = 2,
    Cyan         = 3,
    Red          = 4,
    Magenta      = 5,
    Brown        = 6,
    LightGrey    = 7,
    DarkGrey     = 8,
    LightBlue    = 9,
    LightGreen   = 10,
    LightCyan    = 11,
    LightRed     = 12,
    LightMagenta = 13,
    Yellow       = 14,
    White        = 15,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColorAttr(u8);

impl ColorAttr {
    #[inline]
    pub const fn new(fg: Color, bg: Color) -> Self {
        Self((bg as u8) << 4 | (fg as u8))
    }
}

// ─── VGA cell ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct VgaCell {
    ch:   u8,
    attr: u8,
}

impl VgaCell {
    const fn new(ch: u8, attr: ColorAttr) -> Self {
        Self { ch, attr: attr.0 }
    }
    const fn blank(attr: ColorAttr) -> Self {
        Self::new(b' ', attr)
    }
}

// ─── CRTC helpers (I/O port access) ──────────────────────────────────────────

const CRTC_ADDR: u16 = 0x3D4;
const CRTC_DATA: u16 = 0x3D5;
const CRTC_CURSOR_HI: u8 = 0x0E;
const CRTC_CURSOR_LO: u8 = 0x0F;
const CRTC_CURSOR_START: u8 = 0x0A;
const CRTC_CURSOR_END:   u8 = 0x0B;

#[inline]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nostack, preserves_flags)
    );
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!(
        "in al, dx",
        in("dx") port,
        out("al") val,
        options(nostack, preserves_flags)
    );
    val
}

#[inline]
unsafe fn crtc_write(reg: u8, val: u8) {
    outb(CRTC_ADDR, reg);
    outb(CRTC_DATA, val);
}

#[inline]
unsafe fn crtc_read(reg: u8) -> u8 {
    outb(CRTC_ADDR, reg);
    inb(CRTC_DATA)
}

/// Enable the hardware underline cursor between scan lines `start`–`end`.
/// Pass `start = 0x20` to hide the cursor entirely.
unsafe fn set_cursor_shape(start: u8, end: u8) {
    // Preserve the high bits of cursor-start (blink/disable flags).
    let cs = (crtc_read(CRTC_CURSOR_START) & 0xC0) | (start & 0x1F);
    crtc_write(CRTC_CURSOR_START, cs);
    crtc_write(CRTC_CURSOR_END,   end & 0x1F);
}

unsafe fn move_hw_cursor(pos: u16) {
    crtc_write(CRTC_CURSOR_HI, (pos >> 8) as u8);
    crtc_write(CRTC_CURSOR_LO, (pos & 0xFF) as u8);
}

// ─── VGA BIOS data area probe ─────────────────────────────────────────────────

/// Returns `true` if the VGA BIOS data area at `0x0449` reports a text
/// video mode (modes 0–3 and 7 are standard text modes).
///
/// This is valid after ExitBootServices because the firmware's 1:1 identity
/// map covers the low 1 MiB.  If the kernel no longer identity-maps that
/// region at the time of the call, skip this probe and always return `true`.
pub fn bios_reports_text_mode() -> bool {
    // Physical 0x0449 = BIOS Data Area byte: current video mode.
    let mode = unsafe { core::ptr::read_volatile(0x0449usize as *const u8) };
    matches!(mode, 0..=3 | 7)
}

// ─── VgaWriter ───────────────────────────────────────────────────────────────

pub struct VgaWriter {
    col:   usize,
    row:   usize,
    attr:  ColorAttr,
    /// Base virtual address of the VGA text buffer (default 0xB8000).
    base:  usize,
    /// Whether to update the CRTC hardware cursor after each write.
    hw_cursor: bool,
}

impl VgaWriter {
    const fn new() -> Self {
        Self {
            col:       0,
            row:       0,
            attr:      ColorAttr::new(Color::LightGrey, Color::Black),
            base:      0xB8000,
            hw_cursor: true,
        }
    }

    /// Change the VGA buffer base address (call after remapping the region).
    pub fn set_base(&mut self, va: usize) {
        self.base = va;
    }

    /// Change the foreground/background colour for subsequent writes.
    pub fn set_color(&mut self, attr: ColorAttr) {
        self.attr = attr;
    }

    /// Clear the entire screen with the current background colour.
    pub fn clear(&mut self) {
        let blank = VgaCell::blank(self.attr);
        for i in 0..BUF_CELLS {
            self.write_cell(i, blank);
        }
        self.col = 0;
        self.row = 0;
        self.sync_cursor();
    }

    #[inline]
    fn cell_offset(&self, col: usize, row: usize) -> usize {
        row * COLS + col
    }

    #[inline]
    fn write_cell(&self, offset: usize, cell: VgaCell) {
        // Each cell is 2 bytes; write as a u16 for a single bus cycle.
        let ptr = (self.base + offset * 2) as *mut u16;
        let word = (cell.attr as u16) << 8 | cell.ch as u16;
        unsafe { core::ptr::write_volatile(ptr, word) };
    }

    fn put_char(&mut self, ch: u8) {
        match ch {
            b'\n' => {
                self.col = 0;
                self.row += 1;
            }
            b'\r' => {
                self.col = 0;
            }
            b'\t' => {
                // Advance to next 8-column tab stop.
                self.col = (self.col + 8) & !7;
                if self.col >= COLS {
                    self.col = 0;
                    self.row += 1;
                }
            }
            0x08 => {
                // Backspace: move left, overwrite with space.
                if self.col > 0 {
                    self.col -= 1;
                } else if self.row > 0 {
                    self.row -= 1;
                    self.col = COLS - 1;
                }
                let off = self.cell_offset(self.col, self.row);
                self.write_cell(off, VgaCell::blank(self.attr));
            }
            _ => {
                let off = self.cell_offset(self.col, self.row);
                self.write_cell(off, VgaCell::new(ch, self.attr));
                self.col += 1;
                if self.col >= COLS {
                    self.col = 0;
                    self.row += 1;
                }
            }
        }
        if self.row >= ROWS {
            self.scroll();
            self.row = ROWS - 1;
        }
    }

    fn scroll(&mut self) {
        // Move rows 1..ROWS up by one row.
        for row in 1..ROWS {
            for col in 0..COLS {
                let src = self.cell_offset(col, row);
                let dst = self.cell_offset(col, row - 1);
                let word = unsafe {
                    core::ptr::read_volatile((self.base + src * 2) as *const u16)
                };
                unsafe {
                    core::ptr::write_volatile((self.base + dst * 2) as *mut u16, word)
                };
            }
        }
        // Clear the last row.
        let blank_word = {
            let c = VgaCell::blank(self.attr);
            (c.attr as u16) << 8 | c.ch as u16
        };
        for col in 0..COLS {
            let off = self.cell_offset(col, ROWS - 1);
            unsafe {
                core::ptr::write_volatile((self.base + off * 2) as *mut u16, blank_word)
            };
        }
    }

    fn sync_cursor(&self) {
        if self.hw_cursor {
            let pos = (self.row * COLS + self.col) as u16;
            unsafe { move_hw_cursor(pos) };
        }
    }

    /// Write a raw byte (printable ASCII or control character).
    pub fn write_byte(&mut self, byte: u8) {
        self.put_char(byte);
        self.sync_cursor();
    }

    /// Write a UTF-8 string, converting non-ASCII to `?`.
    pub fn write_str_raw(&mut self, s: &str) {
        for byte in s.bytes() {
            let ch = if byte.is_ascii() { byte } else { b'?' };
            self.put_char(ch);
        }
        self.sync_cursor();
    }
}

impl fmt::Write for VgaWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str_raw(s);
        Ok(())
    }
}

// ─── Global instance ─────────────────────────────────────────────────────────

pub static VGA_WRITER: Mutex<VgaWriter> = Mutex::new(VgaWriter::new());

// ─── Public API ──────────────────────────────────────────────────────────────

/// Initialise the VGA text mode driver.
///
/// - Probes the BIOS Data Area to confirm text mode is active.
/// - Enables an underline hardware cursor (scan lines 14–15 for 16-line font).
/// - Clears the screen.
///
/// Safe to call unconditionally from `kernel_main`; if the probe indicates
/// a graphics mode (GOP took over) the function returns `false` and does
/// nothing, leaving the GOP framebuffer driver in full control.
pub fn init() -> bool {
    if !bios_reports_text_mode() {
        return false;
    }
    let mut w = VGA_WRITER.lock();
    w.clear();
    // Underline cursor at the bottom two scan lines of a 16-line character.
    unsafe { set_cursor_shape(14, 15) };
    w.sync_cursor();
    true
}

/// Update the VGA buffer base virtual address after the kernel has remapped
/// the VGA region to a higher address.
pub fn set_base(va: usize) {
    VGA_WRITER.lock().set_base(va);
}

/// Set the colour attribute for subsequent VGA writes.
pub fn set_color(fg: Color, bg: Color) {
    VGA_WRITER.lock().set_color(ColorAttr::new(fg, bg));
}

/// Clear the screen.
pub fn clear() {
    VGA_WRITER.lock().clear();
}

// ─── Macros ──────────────────────────────────────────────────────────────────

/// Print to the VGA text buffer without a newline.
///
/// Mirrors `serial_print!` in usage.  Silently compiles away on
/// non-x86_64 targets (the cfg gate on the module handles it).
#[macro_export]
macro_rules! vga_print {
    ($($arg:tt)*) => ({
        #[cfg(target_arch = "x86_64")]
        {
            use core::fmt::Write;
            let _ = write!(
                $crate::drivers::vga::VGA_WRITER.lock(),
                $($arg)*
            );
        }
    });
}

/// Print to the VGA text buffer with a trailing newline.
#[macro_export]
macro_rules! vga_println {
    ()          => ($crate::vga_print!("\n"));
    ($($arg:tt)*) => ($crate::vga_print!("{}", format_args!($($arg)*)));
}
