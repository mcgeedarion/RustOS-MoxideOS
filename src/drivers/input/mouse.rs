//! PS/2 mouse driver.
//!
//! Receives 3-byte PS/2 packets from the i8042 auxiliary port and pushes
//! EV_REL (X/Y delta, wheel) and EV_KEY (button) events to evdev.
//!
//! ## PS/2 mouse packet format (standard 3-byte)
//!
//!   Byte 0: YO XO YS XS  1  M  R  L
//!   Byte 1: X movement delta (2’s complement)
//!   Byte 2: Y movement delta (2’s complement, positive = up)

use crate::drivers::input::evdev::{self, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, REL_X, REL_Y};
use spin::Mutex;

struct MouseState {
    buf: [u8; 3],
    phase: usize,
}

static MOUSE: Mutex<MouseState> = Mutex::new(MouseState {
    buf: [0; 3],
    phase: 0,
});

/// Feed one raw PS/2 byte from the mouse into the packet assembler.
/// Call from the IRQ 12 handler (x86) or the i8042 aux interrupt.
pub fn handle_byte(byte: u8) {
    let mut ms = MOUSE.lock();

    // Resync: byte 0 must have bit 3 set.
    if ms.phase == 0 && byte & 0x08 == 0 {
        return;
    }

    ms.buf[ms.phase] = byte;
    ms.phase += 1;

    if ms.phase == 3 {
        ms.phase = 0;
        let b0 = ms.buf[0];
        let b1 = ms.buf[1];
        let b2 = ms.buf[2];
        drop(ms);
        decode_packet(b0, b1, b2);
    }
}

fn decode_packet(b0: u8, b1: u8, b2: u8) {
    // X delta: sign bit in b0 bit 4.
    let xs = (b0 & 0x10) != 0;
    let ys = (b0 & 0x20) != 0;
    let mut dx = b1 as i32;
    let mut dy = b2 as i32;
    if xs {
        dx -= 256;
    }
    if ys {
        dy -= 256;
    }
    // PS/2 Y is inverted vs evdev convention.
    dy = -dy;

    if dx != 0 {
        evdev::push_rel(REL_X, dx);
    }
    if dy != 0 {
        evdev::push_rel(REL_Y, dy);
    }

    // Buttons.
    evdev::push_key(BTN_LEFT, (b0 & 0x01) as i32);
    evdev::push_key(BTN_RIGHT, (b0 & 0x02) as i32 >> 1);
    evdev::push_key(BTN_MIDDLE, (b0 & 0x04) as i32 >> 2);

    evdev::sync();
}
