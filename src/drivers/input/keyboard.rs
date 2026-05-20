//! PS/2 keyboard driver (i8042 controller).
//!
//! Handles scancode set 1 (XT) which QEMU emits by default.  Translates
//! scancodes to USB HID key codes and pushes EV_KEY events to evdev.
//!
//! ## i8042 ports
//!   0x60  Data register  (R: scancode from device, W: command to device)
//!   0x64  Status/command (R: status byte,           W: controller command)
//!
//! ## Scancode set 1 summary
//!   0x01–7F   key make (press)
//!   0x81–FF   key break (release) = make | 0x80
//!   0xE0 xx   extended key prefix

extern crate alloc;
use crate::drivers::input::evdev;

// ---------------------------------------------------------------------------
// i8042 port constants
// ---------------------------------------------------------------------------

const PS2_DATA:   u16 = 0x60;
const PS2_STATUS: u16 = 0x64;
const PS2_CMD:    u16 = 0x64;

const STATUS_OBF: u8 = 1 << 0; // output buffer full (data ready to read)
const STATUS_IBF: u8 = 1 << 1; // input  buffer full (do not write yet)

// ---------------------------------------------------------------------------
// Scancode set 1 → HID keycode table
// ---------------------------------------------------------------------------

// Index = scancode (0x00..0x7F), value = HID usage id (or 0 = undefined).
#[rustfmt::skip]
static SC1_TO_HID: [u16; 128] = [
 /*00*/ 0,    41,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  45,  46, 42, 43,
 /*10*/ 20,   26,   8,  21,  23,  28,  24,  12,  18,  19,  47,  48,  40, 224,   4,  22,
 /*20*/  7,    9,  10,  11,  13,  14,  15,  51,  52,  53, 225,  49,  29,  27,   6,  25,
 /*30*/  5,   17,  16,  54,  55,  56, 229,  85, 226,  44,  57,  58,  59,  60,  61,  62,
 /*40*/ 63,   64,  65,  66,  67,  83,  71,  95,  96,  97,  86,  92,  93,  94,  87,  89,
 /*50*/ 90,   91,  98,  99,   0,   0,   0,  68,  69,   0,   0,   0,   0,   0,   0,   0,
 /*60*/  0,    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
 /*70*/  0,    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
];

// Extended (E0-prefixed) scancodes → HID.
#[rustfmt::skip]
static SC1_EXT_TO_HID: [u16; 128] = [
 /*00*/ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
 /*10*/ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 88, 228, 0, 0,
 /*20*/ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
 /*30*/ 0, 0, 0, 0, 0, 84, 0, 70, 230, 0, 0, 0, 0, 0, 0, 0,
 /*40*/ 0, 0, 0, 0, 0, 0, 0, 74, 75, 77, 0, 80, 0, 79, 0, 72,
 /*50*/ 73, 78, 0, 76, 0, 81, 0, 82, 0, 0, 0, 0, 0, 0, 0, 0,
 /*60*/ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
 /*70*/ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// ---------------------------------------------------------------------------
// HID keycode → ASCII (printable, unshifted)
// ---------------------------------------------------------------------------

#[rustfmt::skip]
static HID_TO_ASCII: [u8; 256] = [
  0,  0,  0,  0, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', b'i', b'j', b'k', b'l',
  b'm', b'n', b'o', b'p', b'q', b'r', b's', b't', b'u', b'v', b'w', b'x', b'y', b'z',
  b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0',
  b'\n', 0x1B, 0x08, b'\t', b' ',
  b'-', b'=', b'[', b']', b'\\', 0, b';', b'\'', b'`', b',', b'.', b'/',
  0, /* CapsLock */
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* F1-F12 */
  0, 0, 0, 0, 0, 0, /* PrintScr..Home */
  0, 0, 0, 0, 0, /* PageUp..Delete */
  0, /* End */
  0, 0, 0, 0, 0, /* PageDown..arrow keys */
  0, 0, 0, 0, /* numpad */
  b'/', b'*', b'-', b'+', b'\n',
  b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'.', 0,
  0, 0, /* Application, Power */
  b'=', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, /* LCtrl */
  0, /* LShift */
  0, /* LAlt */
  0, /* LMeta */
  0, /* RCtrl */
  0, /* RShift */
  0, /* RAlt */
  0, /* RMeta */
];

// ---------------------------------------------------------------------------
// Modifier tracking
// ---------------------------------------------------------------------------

use spin::Mutex;

struct KbdState {
    extended:    bool,
    lshift:      bool,
    rshift:      bool,
    capslock:    bool,
}

static STATE: Mutex<KbdState> = Mutex::new(KbdState {
    extended: false, lshift: false, rshift: false, capslock: false,
});

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Process one raw PS/2 scancode byte.
/// Called from the keyboard IRQ handler (IRQ 1 on x86, PLIC source on RISC-V).
pub fn handle_scancode(sc: u8) {
    let mut st = STATE.lock();

    if sc == 0xE0 {
        st.extended = true;
        return;
    }

    let release = sc & 0x80 != 0;
    let code    = sc & 0x7F;
    let ext     = st.extended;
    st.extended = false;

    let hid: u16 = if ext {
        SC1_EXT_TO_HID[code as usize]
    } else {
        SC1_TO_HID[code as usize]
    };

    if hid == 0 { return; }

    // Track shift / capslock state.
    match hid {
        225 => { st.lshift = !release; }
        229 => { st.rshift = !release; }
        57  => { if !release { st.capslock = !st.capslock; } }
        _   => {}
    }

    let value = if release { 0i32 } else { 1 };
    drop(st); // release lock before evdev push

    evdev::push_key(hid, value);
    evdev::sync();
}

/// Translate a HID key code to its ASCII character (unshifted).
/// Returns 0 for non-printable keys.
pub fn hid_to_char(hid: u16, shifted: bool) -> u8 {
    let base = HID_TO_ASCII.get(hid as usize).copied().unwrap_or(0);
    if base == 0 { return 0; }
    if shifted && base.is_ascii_alphabetic() {
        base.to_ascii_uppercase()
    } else if shifted {
        shift_symbol(base)
    } else {
        base
    }
}

fn shift_symbol(c: u8) -> u8 {
    match c {
        b'1' => b'!', b'2' => b'@', b'3' => b'#', b'4' => b'$', b'5' => b'%',
        b'6' => b'^', b'7' => b'&', b'8' => b'*', b'9' => b'(', b'0' => b')',
        b'-' => b'_', b'=' => b'+', b'[' => b'{', b']' => b'}', b'\\' => b'|',
        b';' => b':', b'\'' => b'"', b'`' => b'~', b',' => b'<', b'.' => b'>',
        b'/' => b'?',
        _ => c,
    }
}

/// Read one keystroke as ASCII.  Returns 0 for non-printable / modifier keys.
/// Blocks until a key-press event is available.
pub fn read_char() -> u8 {
    use crate::drivers::input::evdev::{InputEvent, EV_KEY};
    let mut buf = [InputEvent::default(); 4];
    loop {
        let n = evdev::read(&mut buf);
        for i in 0..n {
            let ev = buf[i];
            if ev.r#type == EV_KEY && ev.value == 1 {
                let st = STATE.lock();
                let shifted = st.lshift || st.rshift || st.capslock;
                drop(st);
                let c = hid_to_char(ev.code, shifted);
                if c != 0 { return c; }
            }
        }
        core::hint::spin_loop();
    }
}

// ---------------------------------------------------------------------------
// Low-level PS/2 I/O
// ---------------------------------------------------------------------------

#[inline]
pub fn init() {
    // Flush any stale byte in the output buffer.
    unsafe {
        if inb(PS2_STATUS) & STATUS_OBF != 0 {
            let _ = inb(PS2_DATA);
        }
    }
}

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port);
    val
}
