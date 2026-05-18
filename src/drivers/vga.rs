//! VGA text-mode driver — 80×25, 16-colour, x86_64 only.
//!
//! # Overview
//!
//! Drives the legacy VGA text buffer at physical address `0xB8000`.  Each cell
//! is two bytes: `[attribute, ascii]`.  The attribute byte encodes a 4-bit
//! foreground colour, a 3-bit background colour, and a blink/bright-bg bit.
//!
//! ```text
//! bit  7      6  5  4      3  2  1  0
//!      blink  BG BG BG     FG FG FG FG
//! ```
//!
//! # Features
//!
//! * `putc` / `puts` / `core::fmt::Write` integration (`print!` / `println!`).
//! * Hardware cursor driven through VGA CRT registers (`0x3D4`/`0x3D5`).
//! * Newline, carriage-return, tab (8-space), and backspace handling.
//! * Scroll-up by one row when the cursor reaches row 25.
//! * `clear` resets the whole buffer to spaces with the current attribute.
//! * `set_color` updates foreground/background for subsequent writes.
//! * A global `WRITER` singleton protected by a simple spinlock so that
//!   `print!` / `println!` macros are safe to call from any context.
//!
//! # Safety
//!
//! All direct memory-mapped I/O is wrapped in `volatile` read/write helpers so
//! the compiler cannot cache or elide the accesses.  Port I/O for the hardware
//! cursor uses `x86_64::instructions::port::Port` via inline assembly.

use core::fmt;
use core::ptr::{read_volatile, write_volatile};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Physical (identity-mapped) base address of the VGA text buffer.
const VGA_BASE: usize = 0xB8000;

/// Number of text columns.
pub const COLS: usize = 80;

/// Number of text rows.
pub const ROWS: usize = 25;

/// Total cells in the buffer.
const BUFFER_SIZE: usize = COLS * ROWS;

// ── I/O port helpers (inline asm, no external crate needed) ──────────────────

/// Write a byte to an x86 I/O port.
///
/// # Safety
/// The caller must ensure `port` is a valid VGA register address.
#[inline(always)]
unsafe fn outb(port: u16, value: u8) {
    core::arch::asm!(
        "out dx, al",
        in("dx") port,
        in("al") value,
        options(nomem, nostack, preserves_flags)
    );
}

/// Read a byte from an x86 I/O port.
///
/// # Safety
/// The caller must ensure `port` is a valid VGA register address.
#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!(
        "in al, dx",
        out("al") value,
        in("dx") port,
        options(nomem, nostack, preserves_flags)
    );
    value
}

// ── Colour types ─────────────────────────────────────────────────────────────

/// 4-bit VGA colour index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum Color {
    Black        = 0,
    Blue         = 1,
    Green        = 2,
    Cyan         = 3,
    Red          = 4,
    Magenta      = 5,
    Brown        = 6,
    LightGray    = 7,
    DarkGray     = 8,
    LightBlue    = 9,
    LightGreen   = 10,
    LightCyan    = 11,
    LightRed     = 12,
    Pink         = 13,
    Yellow       = 14,
    White        = 15,
}

/// Packed attribute byte: `(bg << 4) | fg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ColorCode(u8);

impl ColorCode {
    /// Create a colour code from a foreground and background colour.
    #[inline]
    pub const fn new(fg: Color, bg: Color) -> Self {
        Self((bg as u8) << 4 | (fg as u8))
    }
}

impl Default for ColorCode {
    fn default() -> Self {
        ColorCode::new(Color::White, Color::Black)
    }
}

// ── Buffer cell ───────────────────────────────────────────────────────────────

/// One VGA text cell: ASCII byte followed by an attribute byte.
///
/// The struct is `repr(C)` so the layout exactly matches hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct ScreenChar {
    ascii:     u8,
    attribute: ColorCode,
}

impl ScreenChar {
    #[inline]
    const fn new(ascii: u8, attribute: ColorCode) -> Self {
        Self { ascii, attribute }
    }

    /// A blank space cell with the given attribute.
    #[inline]
    const fn blank(attribute: ColorCode) -> Self {
        Self::new(b' ', attribute)
    }
}

// ── Low-level volatile buffer access ─────────────────────────────────────────

/// Return a raw pointer to the cell at `(row, col)`.
///
/// # Safety
/// `row` must be `< ROWS` and `col` must be `< COLS`.
#[inline(always)]
unsafe fn cell_ptr(row: usize, col: usize) -> *mut ScreenChar {
    (VGA_BASE as *mut ScreenChar).add(row * COLS + col)
}

/// Volatile-write a cell.
///
/// # Safety
/// Same as [`cell_ptr`].
#[inline(always)]
unsafe fn write_cell(row: usize, col: usize, ch: ScreenChar) {
    write_volatile(cell_ptr(row, col), ch);
}

/// Volatile-read a cell.
///
/// # Safety
/// Same as [`cell_ptr`].
#[inline(always)]
unsafe fn read_cell(row: usize, col: usize) -> ScreenChar {
    read_volatile(cell_ptr(row, col))
}

// ── Hardware cursor ───────────────────────────────────────────────────────────

/// CRT controller index register.
const CRT_INDEX: u16 = 0x3D4;
/// CRT controller data register.
const CRT_DATA:  u16 = 0x3D5;

/// VGA cursor high-byte register index.
const CURSOR_HIGH: u8 = 0x0E;
/// VGA cursor low-byte register index.
const CURSOR_LOW:  u8 = 0x0F;

/// Move the hardware text cursor to `(row, col)`.
///
/// # Safety
/// Port I/O is inherently unsafe.
unsafe fn set_hw_cursor(row: usize, col: usize) {
    let pos = (row * COLS + col) as u16;
    outb(CRT_INDEX, CURSOR_HIGH);
    outb(CRT_DATA,  (pos >> 8) as u8);
    outb(CRT_INDEX, CURSOR_LOW);
    outb(CRT_DATA,  (pos & 0xFF) as u8);
}

/// Enable the hardware blinking cursor (scanlines 14–15, i.e. underline).
///
/// # Safety
/// Port I/O.
pub unsafe fn enable_hw_cursor(cursor_start: u8, cursor_end: u8) {
    outb(CRT_INDEX, 0x0A);
    let cur = inb(CRT_DATA);
    outb(CRT_DATA,  (cur & 0xC0) | cursor_start);
    outb(CRT_INDEX, 0x0B);
    let cur = inb(CRT_DATA);
    outb(CRT_DATA,  (cur & 0xE0) | cursor_end);
}

/// Disable the hardware cursor (set bit 5 of register 0x0A).
///
/// # Safety
/// Port I/O.
pub unsafe fn disable_hw_cursor() {
    outb(CRT_INDEX, 0x0A);
    outb(CRT_DATA,  0x20);
}

// ── Writer ────────────────────────────────────────────────────────────────────

/// VGA text-mode writer.
///
/// Tracks the current cursor position and colour attribute.  All mutation goes
/// through [`write_byte`] so invariants (scroll, cursor sync) are maintained
/// in a single place.
pub struct VgaWriter {
    col:   usize,
    row:   usize,
    color: ColorCode,
}

impl VgaWriter {
    /// Construct a writer starting at the top-left corner with default colours
    /// (white on black).
    pub const fn new() -> Self {
        Self {
            col:   0,
            row:   0,
            color: ColorCode::new(Color::White, Color::Black),
        }
    }

    // ── Colour control ────────────────────────────────────────────────────────

    /// Update the colour attribute for all subsequent writes.
    #[inline]
    pub fn set_color(&mut self, fg: Color, bg: Color) {
        self.color = ColorCode::new(fg, bg);
    }

    /// Return the current [`ColorCode`].
    #[inline]
    pub fn color(&self) -> ColorCode {
        self.color
    }

    // ── Screen control ────────────────────────────────────────────────────────

    /// Clear the entire screen and reset the cursor to `(0, 0)`.
    pub fn clear(&mut self) {
        let blank = ScreenChar::blank(self.color);
        for row in 0..ROWS {
            for col in 0..COLS {
                unsafe { write_cell(row, col, blank) };
            }
        }
        self.col = 0;
        self.row = 0;
        unsafe { set_hw_cursor(0, 0) };
    }

    /// Clear a single row to blank cells.
    fn clear_row(&mut self, row: usize) {
        let blank = ScreenChar::blank(self.color);
        for col in 0..COLS {
            unsafe { write_cell(row, col, blank) };
        }
    }

    // ── Scrolling ─────────────────────────────────────────────────────────────

    /// Scroll the screen up by one row.
    ///
    /// Each row is copied to the row above it; the bottom row is blanked.
    fn scroll_up(&mut self) {
        for row in 1..ROWS {
            for col in 0..COLS {
                let ch = unsafe { read_cell(row, col) };
                unsafe { write_cell(row - 1, col, ch) };
            }
        }
        self.clear_row(ROWS - 1);
    }

    // ── Core write primitive ──────────────────────────────────────────────────

    /// Write a single byte to the screen, advancing the cursor.
    ///
    /// Control characters handled:
    /// - `\n` — newline (move to start of next row, scroll if needed)
    /// - `\r` — carriage return (move to column 0)
    /// - `\t` — tab (advance to next 8-column boundary)
    /// - `\x08` (BS) — move cursor one cell left (does not erase)
    /// - All other bytes are written as printable ASCII; non-printable bytes
    ///   (`< 0x20` or `>= 0x7F`) are substituted with `'?'`.
    pub fn write_byte(&mut self, byte: u8) {
        match byte {
            b'\n' => {
                self.col = 0;
                self.advance_row();
            }
            b'\r' => {
                self.col = 0;
            }
            b'\t' => {
                // Advance to the next 8-column tab stop.
                let next = (self.col + 8) & !7;
                self.col = next.min(COLS);
                if self.col >= COLS {
                    self.col = 0;
                    self.advance_row();
                }
            }
            0x08 => {
                // Backspace: move cursor left without erasing.
                if self.col > 0 {
                    self.col -= 1;
                }
            }
            _ => {
                // Substitute non-printable characters.
                let ascii = if byte.is_ascii_graphic() || byte == b' ' {
                    byte
                } else {
                    b'?'
                };
                let ch = ScreenChar::new(ascii, self.color);
                unsafe { write_cell(self.row, self.col, ch) };
                self.col += 1;
                if self.col >= COLS {
                    self.col = 0;
                    self.advance_row();
                }
            }
        }
        unsafe { set_hw_cursor(self.row, self.col) };
    }

    /// Write every byte of a string slice.
    pub fn write_str_raw(&mut self, s: &str) {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Advance to the next row, scrolling if we are already on the last row.
    #[inline]
    fn advance_row(&mut self) {
        if self.row + 1 < ROWS {
            self.row += 1;
        } else {
            self.scroll_up();
            // row stays at ROWS - 1 after scrolling.
            self.row = ROWS - 1;
        }
    }

    // ── Cursor queries ────────────────────────────────────────────────────────

    /// Current cursor column (0-based).
    #[inline]
    pub fn col(&self) -> usize { self.col }

    /// Current cursor row (0-based).
    #[inline]
    pub fn row(&self) -> usize { self.row }

    /// Move the software (and hardware) cursor to an explicit position.
    ///
    /// Clamps coordinates to the visible buffer; does not scroll.
    pub fn set_cursor(&mut self, row: usize, col: usize) {
        self.row = row.min(ROWS - 1);
        self.col = col.min(COLS - 1);
        unsafe { set_hw_cursor(self.row, self.col) };
    }
}

// ── `core::fmt::Write` ────────────────────────────────────────────────────────

impl fmt::Write for VgaWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str_raw(s);
        Ok(())
    }
}

// ── Global singleton ──────────────────────────────────────────────────────────

/// A minimal spinlock wrapper so `WRITER` can live in a `static`.
///
/// We roll our own rather than pulling in `spin` to keep the dependency tree
/// minimal.  This uses `AtomicBool` with acquire/release ordering.
use core::sync::atomic::{AtomicBool, Ordering};

pub struct VgaSpinlock {
    locked: AtomicBool,
    writer: core::cell::UnsafeCell<VgaWriter>,
}

// SAFETY: The spinlock ensures mutual exclusion.
unsafe impl Sync for VgaSpinlock {}
unsafe impl Send for VgaSpinlock {}

impl VgaSpinlock {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            writer: core::cell::UnsafeCell::new(VgaWriter::new()),
        }
    }

    /// Acquire the lock, spin-waiting if necessary.
    pub fn lock(&self) -> VgaGuard<'_> {
        while self.locked.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            // Spin; hint to the CPU that we are in a busy-wait loop.
            core::hint::spin_loop();
        }
        VgaGuard { lock: self }
    }
}

/// RAII guard returned by [`VgaSpinlock::lock`].
pub struct VgaGuard<'a> {
    lock: &'a VgaSpinlock,
}

impl core::ops::Deref for VgaGuard<'_> {
    type Target = VgaWriter;
    fn deref(&self) -> &VgaWriter {
        unsafe { &*self.lock.writer.get() }
    }
}

impl core::ops::DerefMut for VgaGuard<'_> {
    fn deref_mut(&mut self) -> &mut VgaWriter {
        unsafe { &mut *self.lock.writer.get() }
    }
}

impl Drop for VgaGuard<'_> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

/// Kernel-wide VGA writer singleton.
///
/// Initialised to white-on-black at `(0, 0)`.  Access via [`vga_print!`] /
/// [`vga_println!`], or directly through `WRITER.lock()`.
pub static WRITER: VgaSpinlock = VgaSpinlock::new();

// ── Public macros ─────────────────────────────────────────────────────────────

/// Print a formatted string to the VGA text buffer (no trailing newline).
///
/// ```rust,ignore
/// vga_print!("boot: cpus={}", ncpus);
/// ```
#[macro_export]
macro_rules! vga_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write as _;
        let mut guard = $crate::drivers::vga::WRITER.lock();
        let _ = core::write!(guard, $($arg)*);
    }};
}

/// Print a formatted string to the VGA text buffer, appending a newline.
///
/// ```rust,ignore
/// vga_println!("Hello, {}!", "world");
/// ```
#[macro_export]
macro_rules! vga_println {
    ()            => { $crate::vga_print!("\n") };
    ($($arg:tt)*) => { $crate::vga_print!("{}\n", format_args!($($arg)*)) };
}

// ── Initialisation entry point ────────────────────────────────────────────────

/// Initialise the VGA text-mode driver.
///
/// Clears the screen, enables the hardware underline cursor (scanlines 14–15),
/// and moves the hardware cursor to `(0, 0)`.
///
/// Call once from the BSP during early boot, before any `vga_print!` output.
pub fn init() {
    let mut w = WRITER.lock();
    w.clear();
    // Safety: we are on x86_64 BSP during early init; port I/O is safe here.
    unsafe {
        enable_hw_cursor(14, 15);
        set_hw_cursor(0, 0);
    }
}
