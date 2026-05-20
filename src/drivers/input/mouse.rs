//! PS/2 mouse driver (Aux port, IRQ 12).
//!
//! Receives 3-byte (standard) or 4-byte (IntelliMouse) packets from the
//! PS/2 aux port and pushes REL_X, REL_Y, REL_WHEEL and BTN_* events
//! into the evdev queue.

use super::evdev::{self, EventType, InputEvent,
                   REL_X, REL_Y, REL_WHEEL,
                   BTN_LEFT, BTN_RIGHT, BTN_MIDDLE};
use spin::Mutex;

// ---------------------------------------------------------------------------
// PS/2 I/O ports (x86)
// ---------------------------------------------------------------------------

const PS2_DATA: u16 = 0x60;
const PS2_CMD:  u16 = 0x64; // also STATUS when read

// Status bits
const STS_OBF:  u8 = 1 << 0; // Output Buffer Full
const STS_IBF:  u8 = 1 << 1; // Input  Buffer Full
const STS_AUX:  u8 = 1 << 5; // Aux (mouse) data in OBF

// Commands
const CMD_WRITE_AUX:   u8 = 0xD4;
const CMD_READ_CFG:    u8 = 0x20;
const CMD_WRITE_CFG:   u8 = 0x60;
const MOUSE_ENABLE:    u8 = 0xF4;
const MOUSE_DEFAULTS:  u8 = 0xF6;
const MOUSE_INTELLIMOUSE: u8 = 0xF3;
const MOUSE_ACK:       u8 = 0xFA;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MouseState {
    packet:     [u8; 4],
    byte_idx:   usize,
    four_byte:  bool,   // IntelliMouse scroll wheel
    prev_btns:  u8,
}

static STATE: Mutex<MouseState> = Mutex::new(MouseState {
    packet: [0; 4], byte_idx: 0, four_byte: false, prev_btns: 0,
});

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Initialise PS/2 mouse.  Must be called after PS/2 controller init.
pub fn init() {
    unsafe {
        // Enable aux port in controller config byte.
        ps2_cmd(CMD_READ_CFG);
        let cfg = ps2_read();
        ps2_cmd(CMD_WRITE_CFG);
        ps2_write(cfg | 0x02); // enable IRQ12

        // Try to enable IntelliMouse (scroll wheel).
        aux_write(MOUSE_DEFAULTS);
        ps2_read(); // ACK
        aux_write(MOUSE_INTELLIMOUSE);
        ps2_read();
        aux_write(200);
        ps2_read();
        aux_write(MOUSE_INTELLIMOUSE);
        ps2_read();
        aux_write(100);
        ps2_read();
        aux_write(80);
        ps2_read();
        aux_write(0xF2); // GET_ID
        ps2_read(); // ACK
        let id = ps2_read();
        STATE.lock().four_byte = id == 3;

        aux_write(MOUSE_ENABLE);
        ps2_read(); // ACK
    }
}

// ---------------------------------------------------------------------------
// IRQ12 handler (call from interrupt dispatcher)
// ---------------------------------------------------------------------------

pub fn irq_handler() {
    let byte = unsafe {
        let s = ps2_status();
        if s & STS_OBF == 0 || s & STS_AUX == 0 { return; }
        ps2_data_read()
    };

    let mut ms = STATE.lock();
    let pkt_len = if ms.four_byte { 4 } else { 3 };
    ms.packet[ms.byte_idx] = byte;
    ms.byte_idx += 1;

    if ms.byte_idx < pkt_len { return; }
    ms.byte_idx = 0;

    // Decode packet.
    let flags = ms.packet[0];
    // Overflow bits: discard corrupted packet.
    if flags & 0xC0 != 0 { return; }

    let dx = ms.packet[1] as i8 as i32
           - if flags & 0x10 != 0 { 256 } else { 0 };
    let dy = ms.packet[2] as i8 as i32
           - if flags & 0x20 != 0 { 256 } else { 0 };
    let dz = if ms.four_byte { ms.packet[3] as i8 as i32 } else { 0 };

    let btns = flags & 0x07;
    let changed = btns ^ ms.prev_btns;
    ms.prev_btns = btns;

    drop(ms);

    if dx != 0 { evdev::push(InputEvent { ev_type: EventType::Relative, code: REL_X, value: dx }); }
    if dy != 0 { evdev::push(InputEvent { ev_type: EventType::Relative, code: REL_Y, value: -dy }); }
    if dz != 0 { evdev::push(InputEvent { ev_type: EventType::Relative, code: REL_WHEEL, value: dz }); }

    for (bit, code) in [(0, BTN_LEFT), (1, BTN_RIGHT), (2, BTN_MIDDLE)] {
        if changed & (1 << bit) != 0 {
            let val = if btns & (1 << bit) != 0 { 1 } else { 0 };
            evdev::push(InputEvent { ev_type: EventType::Key, code, value: val });
        }
    }

    evdev::sync();
}

// ---------------------------------------------------------------------------
// PS/2 helpers
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
unsafe fn ps2_status() -> u8 { x86_in8(PS2_CMD) }
#[cfg(target_arch = "x86_64")]
unsafe fn ps2_data_read() -> u8 { x86_in8(PS2_DATA) }
#[cfg(target_arch = "x86_64")]
unsafe fn ps2_read() -> u8 {
    let mut spin = 0u32;
    while x86_in8(PS2_CMD) & STS_OBF == 0 { core::hint::spin_loop(); spin += 1; if spin > 100_000 { return 0; } }
    x86_in8(PS2_DATA)
}
#[cfg(target_arch = "x86_64")]
unsafe fn ps2_write_port(port: u16, val: u8) {
    let mut spin = 0u32;
    while x86_in8(PS2_CMD) & STS_IBF != 0 { core::hint::spin_loop(); spin += 1; if spin > 100_000 { return; } }
    x86_out8(port, val);
}
#[cfg(target_arch = "x86_64")]
unsafe fn ps2_cmd(cmd: u8) { ps2_write_port(PS2_CMD, cmd); }
#[cfg(target_arch = "x86_64")]
unsafe fn ps2_write(val: u8) { ps2_write_port(PS2_DATA, val); }
#[cfg(target_arch = "x86_64")]
unsafe fn aux_write(val: u8) { ps2_cmd(CMD_WRITE_AUX); ps2_write(val); }

#[cfg(not(target_arch = "x86_64"))]
unsafe fn ps2_status() -> u8 { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn ps2_data_read() -> u8 { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn ps2_read() -> u8 { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn ps2_cmd(_: u8) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn ps2_write(_: u8) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn aux_write(_: u8) {}

#[cfg(target_arch = "x86_64")]
unsafe fn x86_in8(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port);
    val
}
#[cfg(target_arch = "x86_64")]
unsafe fn x86_out8(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val);
}
