//! Keyboard driver.
//!
//! ## Sources of key events
//!   1. PS/2 controller (i8042) — IRQ 1, x86 only.
//!      Decodes AT scancode set 2 → evdev KeyCode.
//!   2. virtio-input / HID — already normalised to evdev KeyCode before
//!      reaching this file.  `keyboard_push_keycode()` is the entry point.
//!
//! ## Public API
//!   keyboard_init()           — enable PS/2, register ISR
//!   keyboard_ps2_irq()        — call from IDT at IRQ 1 (vector 0x21)
//!   keyboard_push_keycode()   — called by virtio_input / hid decoders
//!   key_is_down(code: u16)    — returns true if the key is currently held
//!   read_char()               — pop one ASCII/Unicode char, or None
//!
//! ## State
//!   - 256-bit key-state bitmask (one bit per keycode, 0..255)
//!   - Modifier mask (shift / ctrl / alt / meta)
//!   - Character FIFO (32 slots)

use crate::drivers::evdev::{push_key, KeyCode};
use spin::Mutex;

// ── PS/2 ports ────────────────────────────────────────────────────────────────

const PS2_DATA: u16 = 0x60;
const PS2_STATUS: u16 = 0x64;

// ── Key state ─────────────────────────────────────────────────────────────────

/// 256-bit bitmask — bit N is set while key N is held down.
struct KeyState([u64; 4]);

impl KeyState {
    const fn new() -> Self {
        Self([0u64; 4])
    }
    fn set(&mut self, code: u16) {
        let c = code as usize & 0xFF;
        self.0[c >> 6] |= 1 << (c & 63);
    }
    fn clear(&mut self, code: u16) {
        let c = code as usize & 0xFF;
        self.0[c >> 6] &= !(1 << (c & 63));
    }
    fn is_set(&self, code: u16) -> bool {
        let c = code as usize & 0xFF;
        self.0[c >> 6] & (1 << (c & 63)) != 0
    }
}

// ── Modifier flags ────────────────────────────────────────────────────────────

/// Bit flags for modifier keys.
#[derive(Default, Clone, Copy)]
struct Mods {
    shift: bool,
    ctrl: bool,
    alt: bool,
    caps: bool, // capslock toggle
}

// ── Char FIFO ─────────────────────────────────────────────────────────────────

const CHAR_BUF: usize = 32;

struct CharFifo {
    buf: [char; CHAR_BUF],
    head: usize,
    tail: usize,
}

impl CharFifo {
    const fn new() -> Self {
        Self {
            buf: ['\0'; CHAR_BUF],
            head: 0,
            tail: 0,
        }
    }
    fn push(&mut self, c: char) {
        let next = (self.head + 1) % CHAR_BUF;
        if next != self.tail {
            self.buf[self.head] = c;
            self.head = next;
        }
    }
    fn pop(&mut self) -> Option<char> {
        if self.head == self.tail {
            return None;
        }
        let c = self.buf[self.tail];
        self.tail = (self.tail + 1) % CHAR_BUF;
        Some(c)
    }
}

// ── Global state ──────────────────────────────────────────────────────────────

struct KbdState {
    keys: KeyState,
    mods: Mods,
    chars: CharFifo,
    e0: bool, // E0-prefixed scancode in progress
}

unsafe impl Send for KbdState {}

static KBD: Mutex<KbdState> = Mutex::new(KbdState {
    keys: KeyState::new(),
    mods: Mods {
        shift: false,
        ctrl: false,
        alt: false,
        caps: false,
    },
    chars: CharFifo::new(),
    e0: false,
});

// ── Scancode set 2 → KeyCode table ────────────────────────────────────────────

/// Map scan set 2 byte (0x00..0x7F) → evdev key code.
/// 0 means "no mapping".
const SC2_NORMAL: [u16; 128] = {
    let mut t = [0u16; 128];
    // Row 0 — function keys & esc
    t[0x76] = KeyCode::KEY_ESC as u16;
    t[0x05] = KeyCode::KEY_F1 as u16;
    t[0x06] = KeyCode::KEY_F2 as u16;
    t[0x04] = KeyCode::KEY_F3 as u16;
    t[0x0C] = KeyCode::KEY_F4 as u16;
    t[0x03] = KeyCode::KEY_F5 as u16;
    t[0x0B] = KeyCode::KEY_F6 as u16;
    t[0x83] = 0; // F7 (> 0x7F, handled below)
    t[0x0A] = KeyCode::KEY_F8 as u16;
    t[0x01] = KeyCode::KEY_F9 as u16;
    t[0x09] = KeyCode::KEY_F10 as u16;
    t[0x78] = KeyCode::KEY_F11 as u16;
    t[0x07] = KeyCode::KEY_F12 as u16;
    // Number row
    t[0x0E] = KeyCode::KEY_GRAVE as u16;
    t[0x16] = KeyCode::KEY_1 as u16;
    t[0x1E] = KeyCode::KEY_2 as u16;
    t[0x26] = KeyCode::KEY_3 as u16;
    t[0x25] = KeyCode::KEY_4 as u16;
    t[0x2E] = KeyCode::KEY_5 as u16;
    t[0x36] = KeyCode::KEY_6 as u16;
    t[0x3D] = KeyCode::KEY_7 as u16;
    t[0x3E] = KeyCode::KEY_8 as u16;
    t[0x46] = KeyCode::KEY_9 as u16;
    t[0x45] = KeyCode::KEY_0 as u16;
    t[0x4E] = KeyCode::KEY_MINUS as u16;
    t[0x55] = KeyCode::KEY_EQUAL as u16;
    t[0x66] = KeyCode::KEY_BACKSPACE as u16;
    // QWERTY
    t[0x0D] = KeyCode::KEY_TAB as u16;
    t[0x15] = KeyCode::KEY_Q as u16;
    t[0x1D] = KeyCode::KEY_W as u16;
    t[0x24] = KeyCode::KEY_E as u16;
    t[0x2D] = KeyCode::KEY_R as u16;
    t[0x2C] = KeyCode::KEY_T as u16;
    t[0x35] = KeyCode::KEY_Y as u16;
    t[0x3C] = KeyCode::KEY_U as u16;
    t[0x43] = KeyCode::KEY_I as u16;
    t[0x44] = KeyCode::KEY_O as u16;
    t[0x4D] = KeyCode::KEY_P as u16;
    t[0x54] = KeyCode::KEY_LEFTBRACE as u16;
    t[0x5B] = KeyCode::KEY_RIGHTBRACE as u16;
    t[0x5A] = KeyCode::KEY_ENTER as u16;
    t[0x14] = KeyCode::KEY_LEFTCTRL as u16;
    t[0x1C] = KeyCode::KEY_A as u16;
    t[0x1B] = KeyCode::KEY_S as u16;
    t[0x23] = KeyCode::KEY_D as u16;
    t[0x2B] = KeyCode::KEY_F as u16;
    t[0x34] = KeyCode::KEY_G as u16;
    t[0x33] = KeyCode::KEY_H as u16;
    t[0x3B] = KeyCode::KEY_J as u16;
    t[0x42] = KeyCode::KEY_K as u16;
    t[0x4B] = KeyCode::KEY_L as u16;
    t[0x4C] = KeyCode::KEY_SEMICOLON as u16;
    t[0x52] = KeyCode::KEY_APOSTROPHE as u16;
    t[0x12] = KeyCode::KEY_LEFTSHIFT as u16;
    t[0x5D] = KeyCode::KEY_BACKSLASH as u16;
    t[0x1A] = KeyCode::KEY_Z as u16;
    t[0x22] = KeyCode::KEY_X as u16;
    t[0x21] = KeyCode::KEY_C as u16;
    t[0x2A] = KeyCode::KEY_V as u16;
    t[0x32] = KeyCode::KEY_B as u16;
    t[0x31] = KeyCode::KEY_N as u16;
    t[0x3A] = KeyCode::KEY_M as u16;
    t[0x41] = KeyCode::KEY_COMMA as u16;
    t[0x49] = KeyCode::KEY_DOT as u16;
    t[0x4A] = KeyCode::KEY_SLASH as u16;
    t[0x59] = KeyCode::KEY_RIGHTSHIFT as u16;
    t[0x11] = KeyCode::KEY_LEFTALT as u16;
    t[0x29] = KeyCode::KEY_SPACE as u16;
    t[0x58] = KeyCode::KEY_CAPSLOCK as u16;
    t[0x77] = KeyCode::KEY_NUMLOCK as u16;
    t[0x7E] = KeyCode::KEY_SCROLLLOCK as u16;
    t
};

/// E0-prefixed scancodes → evdev key code.
#[inline]
fn sc2_extended(sc: u8) -> u16 {
    match sc {
        0x14 => KeyCode::KEY_RIGHTCTRL as u16,
        0x11 => KeyCode::KEY_RIGHTALT as u16,
        0x75 => KeyCode::KEY_UP as u16,
        0x72 => KeyCode::KEY_DOWN as u16,
        0x6B => KeyCode::KEY_LEFT as u16,
        0x74 => KeyCode::KEY_RIGHT as u16,
        0x70 => KeyCode::KEY_INSERT as u16,
        0x71 => KeyCode::KEY_DELETE as u16,
        0x6C => KeyCode::KEY_HOME as u16,
        0x69 => KeyCode::KEY_END as u16,
        0x7D => KeyCode::KEY_PAGEUP as u16,
        0x7A => KeyCode::KEY_PAGEDOWN as u16,
        0x1F => KeyCode::KEY_LEFTMETA as u16,
        0x27 => KeyCode::KEY_RIGHTMETA as u16,
        _ => 0,
    }
}

// ── Keycode → ASCII ───────────────────────────────────────────────────────────

/// Map evdev KeyCode → ASCII (unshifted, shifted).  Returns (\0, \0) for
/// non-printable keys.
#[allow(non_upper_case_globals)]
fn keycode_to_char(code: u16, shift: bool, caps: bool) -> Option<char> {
    let effective_shift = shift ^ caps;
    let (lo, hi): (char, char) = match code {
        c if c == KeyCode::KEY_SPACE as u16 => (' ', ' '),
        c if c == KeyCode::KEY_ENTER as u16 => ('\n', '\n'),
        c if c == KeyCode::KEY_TAB as u16 => ('\t', '\t'),
        c if c == KeyCode::KEY_BACKSPACE as u16 => ('\x08', '\x08'),
        c if c == KeyCode::KEY_1 as u16 => ('1', '!'),
        c if c == KeyCode::KEY_2 as u16 => ('2', '@'),
        c if c == KeyCode::KEY_3 as u16 => ('3', '#'),
        c if c == KeyCode::KEY_4 as u16 => ('4', '$'),
        c if c == KeyCode::KEY_5 as u16 => ('5', '%'),
        c if c == KeyCode::KEY_6 as u16 => ('6', '^'),
        c if c == KeyCode::KEY_7 as u16 => ('7', '&'),
        c if c == KeyCode::KEY_8 as u16 => ('8', '*'),
        c if c == KeyCode::KEY_9 as u16 => ('9', '('),
        c if c == KeyCode::KEY_0 as u16 => ('0', ')'),
        c if c == KeyCode::KEY_MINUS as u16 => ('-', '_'),
        c if c == KeyCode::KEY_EQUAL as u16 => ('=', '+'),
        c if c == KeyCode::KEY_LEFTBRACE as u16 => ('[', '{'),
        c if c == KeyCode::KEY_RIGHTBRACE as u16 => (']', '}'),
        c if c == KeyCode::KEY_BACKSLASH as u16 => ('\\', '|'),
        c if c == KeyCode::KEY_SEMICOLON as u16 => (';', ':'),
        c if c == KeyCode::KEY_APOSTROPHE as u16 => ('\'', '"'),
        c if c == KeyCode::KEY_GRAVE as u16 => ('`', '~'),
        c if c == KeyCode::KEY_COMMA as u16 => (',', '<'),
        c if c == KeyCode::KEY_DOT as u16 => ('.', '>'),
        c if c == KeyCode::KEY_SLASH as u16 => ('/', '?'),
        // A-Z
        c @ 30..=55 => {
            // KEY_A(30)..KEY_Z: map sequentially
            // Careful: KeyCode::KEY_A == 30, ..KEY_Z == 44+... use offset
            let base = (c - KeyCode::KEY_A as u16) as u8;
            let ch = (b'a' + base) as char;
            let CH = (b'A' + base) as char;
            (ch, CH)
        }
        _ => return None,
    };
    Some(if effective_shift { hi } else { lo })
}

// ── PS/2 init ─────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn ps2_read() -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", out("al") v, in("dx") PS2_DATA, options(nomem, nostack));
    v
}

/// Enable PS/2 keyboard; switch to scancode set 2.
/// Call from kernel_main before enabling IRQ 1.
pub fn keyboard_init() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        // Flush OBF.
        let status: u8;
        core::arch::asm!("in al, dx", out("al") status, in("dx") PS2_STATUS, options(nomem, nostack));
        if status & 0x01 != 0 {
            let _: u8;
            core::arch::asm!("in al, dx", out("al") _,      in("dx") PS2_DATA,   options(nomem, nostack));
        }
        // Enable translation (scancode set 2 → set 1 by default on x86 BIOS).
        // QEMU already delivers set 1 bytes via IRQ1 without any setup,
        // but we request set 2 and handle it ourselves.
        // Send F0 02 to switch to set 2.
        let send = |byte: u8| {
            // Wait until IBF is clear.
            loop {
                let s: u8;
                core::arch::asm!("in al, dx", out("al") s, in("dx") PS2_STATUS, options(nomem, nostack));
                if s & 0x02 == 0 {
                    break;
                }
            }
            core::arch::asm!("out dx, al", in("dx") PS2_DATA, in("al") byte, options(nomem, nostack));
        };
        send(0xF0); // Set Scan Code Set
                    // Read ACK.
        let _ack = ps2_read();
        send(0x02); // Set 2
        let _ack2 = ps2_read();
    }
    crate::arch::x86_64::serial::serial_println!("keyboard: PS/2 init done");
}

// ── PS/2 IRQ handler ─────────────────────────────────────────────────────────

/// Call from IDT handler at vector 0x21 (IRQ 1).
pub fn keyboard_ps2_irq() {
    let sc: u8;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        sc = ps2_read();
    }
    #[cfg(not(target_arch = "x86_64"))]
    let sc = 0u8;

    let mut kbd = KBD.lock();

    // E0 prefix.
    if sc == 0xE0 {
        kbd.e0 = true;
        return;
    }

    let is_break = sc & 0x80 != 0;
    let make_sc = sc & 0x7F;

    let code: u16 = if kbd.e0 {
        kbd.e0 = false;
        sc2_extended(make_sc)
    } else if (make_sc as usize) < 128 {
        SC2_NORMAL[make_sc as usize]
    } else {
        0
    };

    if code == 0 {
        return;
    }
    process_key(&mut kbd, code, if is_break { 0 } else { 1 });
}

// ── virtio_input / HID entry point ────────────────────────────────────────────

/// Accept an already-decoded evdev key code + value from a non-PS/2 source.
/// value: 1 = key-down, 0 = key-up, 2 = auto-repeat.
pub fn keyboard_push_keycode(code: u16, value: i32) {
    let mut kbd = KBD.lock();
    process_key(&mut kbd, code, value);
}

// ── Core key processing ───────────────────────────────────────────────────────

fn process_key(kbd: &mut KbdState, code: u16, value: i32) {
    let down = value != 0;

    // Update bitmask.
    if down {
        kbd.keys.set(code);
    } else {
        kbd.keys.clear(code);
    }

    // Update modifier flags.
    update_mods(&mut kbd.mods, code, down);

    // Push to evdev bus.
    push_key(code, value);

    // Translate to char and push into char FIFO.
    if down {
        if let Some(ch) = keycode_to_char(code, kbd.mods.shift, kbd.mods.caps) {
            kbd.chars.push(ch);
        }
    }
}

fn update_mods(m: &mut Mods, code: u16, down: bool) {
    let ls = KeyCode::KEY_LEFTSHIFT as u16;
    let rs = KeyCode::KEY_RIGHTSHIFT as u16;
    let lc = KeyCode::KEY_LEFTCTRL as u16;
    let rc = KeyCode::KEY_RIGHTCTRL as u16;
    let la = KeyCode::KEY_LEFTALT as u16;
    let ra = KeyCode::KEY_RIGHTALT as u16;
    let cl = KeyCode::KEY_CAPSLOCK as u16;

    if code == ls || code == rs {
        m.shift = down;
    }
    if code == lc || code == rc {
        m.ctrl = down;
    }
    if code == la || code == ra {
        m.alt = down;
    }
    // Capslock toggles on key-down.
    if code == cl && down {
        m.caps = !m.caps;
    }
}

// ── Public query API ──────────────────────────────────────────────────────────

/// Returns true if the given evdev key code is currently held down.
pub fn key_is_down(code: u16) -> bool {
    KBD.lock().keys.is_set(code)
}

/// Returns true if any shift key is held.
pub fn shift_held() -> bool {
    KBD.lock().mods.shift
}
/// Returns true if any ctrl key is held.
pub fn ctrl_held() -> bool {
    KBD.lock().mods.ctrl
}
/// Returns true if any alt key is held.
pub fn alt_held() -> bool {
    KBD.lock().mods.alt
}

/// Pop one Unicode character from the char FIFO, or None if empty.
pub fn read_char() -> Option<char> {
    KBD.lock().chars.pop()
}
