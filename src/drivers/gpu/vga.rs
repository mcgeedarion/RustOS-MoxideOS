//! VGA / VESA framebuffer driver.
//!
//! Two modes are supported:
//!   1. **VGA text mode** (80×25, mode 3)   — available immediately after boot
//!      on x86; writes characters to the 0xB8000 buffer.
//!   2. **VESA LFB** (linear framebuffer)    — set up by the bootloader via
//!      VESA BIOS INT 10h / VBE mode set; base address passed via boot info.
//!
//! If an LFB is available it is used; otherwise text mode is used as fallback.

extern crate alloc;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

use crate::drivers::gpu::framebuffer::{Framebuffer, PixelFormat};
use crate::drivers::gpu::gpu::DisplayInfo;

const VGA_TEXT_BASE: usize = 0xB8000;
const VGA_TEXT_COLS: usize = 80;
const VGA_TEXT_ROWS: usize = 25;
const VGA_TEXT_CELLS: usize = VGA_TEXT_COLS * VGA_TEXT_ROWS;

/// VGA colour attribute byte: bg[7:4] + fg[3:0]
#[allow(dead_code)]
pub mod color {
    pub const BLACK: u8 = 0x0;
    pub const BLUE: u8 = 0x1;
    pub const GREEN: u8 = 0x2;
    pub const CYAN: u8 = 0x3;
    pub const RED: u8 = 0x4;
    pub const MAGENTA: u8 = 0x5;
    pub const BROWN: u8 = 0x6;
    pub const LIGHT_GREY: u8 = 0x7;
    pub const DARK_GREY: u8 = 0x8;
    pub const LIGHT_BLUE: u8 = 0x9;
    pub const LIGHT_GREEN: u8 = 0xA;
    pub const LIGHT_CYAN: u8 = 0xB;
    pub const LIGHT_RED: u8 = 0xC;
    pub const PINK: u8 = 0xD;
    pub const YELLOW: u8 = 0xE;
    pub const WHITE: u8 = 0xF;
    pub fn attr(fg: u8, bg: u8) -> u8 {
        (bg << 4) | (fg & 0xF)
    }
}

const VGA_CRTC_ADDR: u16 = 0x03D4;
const VGA_CRTC_DATA: u16 = 0x03D5;
const VGA_MISC_WRITE: u16 = 0x03C2;
const VGA_SEQ_ADDR: u16 = 0x03C4;
const VGA_SEQ_DATA: u16 = 0x03C5;
const VGA_GC_ADDR: u16 = 0x03CE;
const VGA_GC_DATA: u16 = 0x03CF;
const VGA_AC_ADDR: u16 = 0x03C0;
const VGA_AC_DATA_W: u16 = 0x03C0;
const VGA_AC_DATA_R: u16 = 0x03C1;
const VGA_STAT1: u16 = 0x03DA; // Input Status Register 1 (resets AC flip-flop)

enum VgaMode {
    Text,
    Lfb(Framebuffer),
}

struct VgaState {
    mode: VgaMode,
    col: usize,
    row: usize,
    attr: u8,
}

static VGA: Mutex<Option<VgaState>> = Mutex::new(None);

pub fn init() {
    clear_text_buffer();
    *VGA.lock() = Some(VgaState {
        mode: VgaMode::Text,
        col: 0,
        row: 0,
        attr: color::attr(color::LIGHT_GREY, color::BLACK),
    });
}

pub fn init_lfb(base: u64, width: u32, height: u32, pitch: u32) {
    let fb = Framebuffer {
        phys: base,
        width,
        height,
        pitch,
        format: PixelFormat::Xrgb8888,
    };
    *VGA.lock() = Some(VgaState {
        mode: VgaMode::Lfb(fb),
        col: 0,
        row: 0,
        attr: color::attr(color::LIGHT_GREY, color::BLACK),
    });
}

pub fn is_initialised() -> bool {
    VGA.lock().is_some()
}

pub fn display_info() -> Option<DisplayInfo> {
    VGA.lock().as_ref().map(|v| match &v.mode {
        VgaMode::Text => DisplayInfo {
            width: 80,
            height: 25,
            pitch: 160,
            bpp: 16,
        },
        VgaMode::Lfb(fb) => DisplayInfo {
            width: fb.width,
            height: fb.height,
            pitch: fb.pitch,
            bpp: 32,
        },
    })
}

/// Write a character at the current cursor position and advance.
pub fn putchar(c: u8) {
    let mut g = VGA.lock();
    let st = match g.as_mut() {
        Some(s) => s,
        None => return,
    };
    match c {
        b'\n' => {
            st.col = 0;
            st.row += 1;
        },
        b'\r' => {
            st.col = 0;
        },
        b'\t' => {
            st.col = (st.col + 8) & !7;
        },
        b'\x08' => {
            if st.col > 0 {
                st.col -= 1;
            }
        },
        _ => {
            text_write_at(st.col, st.row, c, st.attr);
            st.col += 1;
        },
    }
    if st.col >= VGA_TEXT_COLS {
        st.col = 0;
        st.row += 1;
    }
    if st.row >= VGA_TEXT_ROWS {
        scroll();
        st.row = VGA_TEXT_ROWS - 1;
    }
    update_cursor(st.col, st.row);
}

/// Write a string to the text buffer.
pub fn print(s: &str) {
    for b in s.bytes() {
        putchar(b);
    }
}

/// Set foreground/background colour attribute.
pub fn set_attr(fg: u8, bg: u8) {
    if let Some(st) = VGA.lock().as_mut() {
        st.attr = color::attr(fg, bg);
    }
}

pub fn clear(argb: u32) {
    let g = VGA.lock();
    if let Some(VgaState {
        mode: VgaMode::Lfb(fb),
        ..
    }) = g.as_ref()
    {
        fb.clear(argb);
    }
}

pub fn blit(x: u32, y: u32, width: u32, height: u32, pixels: &[u32]) {
    let g = VGA.lock();
    if let Some(VgaState {
        mode: VgaMode::Lfb(fb),
        ..
    }) = g.as_ref()
    {
        fb.blit(x, y, width, height, pixels);
    }
}

fn text_write_at(col: usize, row: usize, c: u8, attr: u8) {
    let idx = (row * VGA_TEXT_COLS + col) * 2;
    let base = VGA_TEXT_BASE;
    unsafe {
        write_volatile((base + idx) as *mut u8, c);
        write_volatile((base + idx + 1) as *mut u8, attr);
    }
}

fn clear_text_buffer() {
    for i in 0..VGA_TEXT_CELLS {
        let idx = i * 2;
        unsafe {
            write_volatile((VGA_TEXT_BASE + idx) as *mut u8, b' ');
            write_volatile(
                (VGA_TEXT_BASE + idx + 1) as *mut u8,
                color::attr(color::LIGHT_GREY, color::BLACK),
            );
        }
    }
}

fn scroll() {
    for row in 1..VGA_TEXT_ROWS {
        for col in 0..VGA_TEXT_COLS {
            let src = VGA_TEXT_BASE + ((row * VGA_TEXT_COLS + col) * 2);
            let dst = VGA_TEXT_BASE + (((row - 1) * VGA_TEXT_COLS + col) * 2);
            unsafe {
                let ch = read_volatile(src as *const u8);
                let attr = read_volatile((src + 1) as *const u8);
                write_volatile(dst as *mut u8, ch);
                write_volatile((dst + 1) as *mut u8, attr);
            }
        }
    }
    // Clear last row.
    let row = VGA_TEXT_ROWS - 1;
    for col in 0..VGA_TEXT_COLS {
        let idx = (row * VGA_TEXT_COLS + col) * 2;
        unsafe {
            write_volatile((VGA_TEXT_BASE + idx) as *mut u8, b' ');
            write_volatile(
                (VGA_TEXT_BASE + idx + 1) as *mut u8,
                color::attr(color::LIGHT_GREY, color::BLACK),
            );
        }
    }
}

fn update_cursor(col: usize, row: usize) {
    let pos = (row * VGA_TEXT_COLS + col) as u16;
    unsafe {
        outb(VGA_CRTC_ADDR, 0x0F);
        outb(VGA_CRTC_DATA, (pos & 0xFF) as u8);
        outb(VGA_CRTC_ADDR, 0x0E);
        outb(VGA_CRTC_DATA, ((pos >> 8) & 0xFF) as u8);
    }
}

#[inline]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val);
}

// ===== GUESS: char-level printer for tty fast paths =====
/// GUESS: prints a single char via `putchar`.
#[inline]
pub fn print_char(c: char) {
    putchar(c as u8);
}
