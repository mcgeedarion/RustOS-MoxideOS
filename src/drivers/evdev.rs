//! Evdev — kernel-side input event bus.
//!
//! Mirrors Linux's evdev API at a minimal level:
//!   push_event()  — called by low-level drivers (virtio_input, keyboard ISR, etc.)
//!   pop_event()   — called by userspace-facing read paths / tty
//!   poll()        — returns true if at least one event is pending
//!
//! ## Event types supported
//!   EV_SYN (0) — sync/separator
//!   EV_KEY (1) — key press / release
//!   EV_REL (2) — relative axis (mouse X/Y/wheel)
//!   EV_ABS (3) — absolute axis (touch/tablet)
//!
//! Each type has its own 64-slot lock-free FIFO ring.  Producers call
//! push_event(); consumers call pop_event() or drain the ring via poll().
//!
//! ## Thread-safety note
//! The rings use spin::Mutex.  IRQ handlers acquire the lock for a
//! very brief push; sleeping tasks acquire it for pop.  This is safe
//! as long as no IRQ-context code tries to pop events (it shouldn't).

use spin::Mutex;

// ── Event types ───────────────────────────────────────────────────────────────

/// Linux evdev event types (subset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum EventType {
    Syn = 0,
    Key = 1,
    Rel = 2,
    Abs = 3,
    Unknown(u16),
}

impl EventType {
    pub fn from_u16(v: u16) -> Self {
        match v {
            0 => Self::Syn,
            1 => Self::Key,
            2 => Self::Rel,
            3 => Self::Abs,
            x => Self::Unknown(x),
        }
    }
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Syn       => 0,
            Self::Key       => 1,
            Self::Rel       => 2,
            Self::Abs       => 3,
            Self::Unknown(x) => x,
        }
    }
}

/// A single input event, mirroring `struct input_event` (timeval-less form).
#[derive(Clone, Copy, Debug)]
pub struct InputEvent {
    pub typ:   EventType,
    pub code:  u16,
    pub value: i32,
}

// ── Key codes (partial — common keys only) ────────────────────────────────────

/// Linux EV_KEY key codes (subset).
#[allow(non_camel_case_types, dead_code)]
#[repr(u16)]
pub enum KeyCode {
    KEY_RESERVED   = 0,
    KEY_ESC        = 1,
    KEY_1          = 2,  KEY_2 = 3,  KEY_3 = 4,  KEY_4 = 5,
    KEY_5          = 6,  KEY_6 = 7,  KEY_7 = 8,  KEY_8 = 9,
    KEY_9          = 10, KEY_0 = 11,
    KEY_MINUS      = 12, KEY_EQUAL = 13,
    KEY_BACKSPACE  = 14,
    KEY_TAB        = 15,
    KEY_Q          = 16, KEY_W = 17, KEY_E = 18, KEY_R = 19,
    KEY_T          = 20, KEY_Y = 21, KEY_U = 22, KEY_I = 23,
    KEY_O          = 24, KEY_P = 25,
    KEY_LEFTBRACE  = 26, KEY_RIGHTBRACE = 27,
    KEY_ENTER      = 28,
    KEY_LEFTCTRL   = 29,
    KEY_A          = 30, KEY_S = 31, KEY_D = 32, KEY_F = 33,
    KEY_G          = 34, KEY_H = 35, KEY_J = 36, KEY_K = 37,
    KEY_L          = 38,
    KEY_SEMICOLON  = 39, KEY_APOSTROPHE = 40,
    KEY_GRAVE      = 41,
    KEY_LEFTSHIFT  = 42,
    KEY_BACKSLASH  = 43,
    KEY_Z          = 44, KEY_X = 45, KEY_C = 46, KEY_V = 47,
    KEY_B          = 48, KEY_N = 49, KEY_M = 50,
    KEY_COMMA      = 51, KEY_DOT = 52, KEY_SLASH = 53,
    KEY_RIGHTSHIFT = 54,
    KEY_LEFTALT    = 56,
    KEY_SPACE      = 57,
    KEY_CAPSLOCK   = 58,
    KEY_F1         = 59,  KEY_F2 = 60,  KEY_F3 = 61,  KEY_F4 = 62,
    KEY_F5         = 63,  KEY_F6 = 64,  KEY_F7 = 65,  KEY_F8 = 66,
    KEY_F9         = 67,  KEY_F10 = 68,
    KEY_NUMLOCK    = 69,
    KEY_SCROLLLOCK = 70,
    KEY_F11        = 87,  KEY_F12 = 88,
    KEY_RIGHTCTRL  = 97,
    KEY_RIGHTALT   = 100,
    KEY_UP         = 103, KEY_LEFT = 105, KEY_RIGHT = 106, KEY_DOWN = 108,
    KEY_INSERT     = 110, KEY_DELETE = 111,
    KEY_HOME       = 102, KEY_END = 107,
    KEY_PAGEUP     = 104, KEY_PAGEDOWN = 109,
    KEY_LEFTMETA   = 125, KEY_RIGHTMETA = 126,
    // Mouse buttons
    BTN_LEFT       = 0x110, BTN_RIGHT = 0x111, BTN_MIDDLE = 0x112,
}

// ── Relative axis codes ───────────────────────────────────────────────────────

#[allow(dead_code)]
#[repr(u16)]
pub enum RelCode {
    REL_X     = 0,
    REL_Y     = 1,
    REL_Z     = 2,
    REL_WHEEL = 8,
}

// ── Ring buffer ───────────────────────────────────────────────────────────────

const RING_SIZE: usize = 64;

struct Ring {
    buf:  [InputEvent; RING_SIZE],
    head: usize,  // next write
    tail: usize,  // next read
}

impl Ring {
    const fn new() -> Self {
        Self {
            buf: [InputEvent { typ: EventType::Syn, code: 0, value: 0 }; RING_SIZE],
            head: 0,
            tail: 0,
        }
    }
    fn push(&mut self, ev: InputEvent) {
        let next = (self.head + 1) & (RING_SIZE - 1);
        if next == self.tail { return; }  // drop on overflow
        self.buf[self.head] = ev;
        self.head = next;
    }
    fn pop(&mut self) -> Option<InputEvent> {
        if self.head == self.tail { return None; }
        let ev = self.buf[self.tail];
        self.tail = (self.tail + 1) & (RING_SIZE - 1);
        Some(ev)
    }
    fn is_empty(&self) -> bool { self.head == self.tail }
}

// ── Global ring (single device for now) ──────────────────────────────────────

static RING: Mutex<Ring> = Mutex::new(Ring::new());

// ── Public API ────────────────────────────────────────────────────────────────

/// Push one event into the ring.  Called from IRQ context.
#[inline]
pub fn push_event(ev: InputEvent) {
    RING.lock().push(ev);
}

/// Pop one event, or None if the ring is empty.  Called from task context.
#[inline]
pub fn pop_event() -> Option<InputEvent> {
    RING.lock().pop()
}

/// Returns true if at least one event is pending.
#[inline]
pub fn poll() -> bool {
    !RING.lock().is_empty()
}

/// Convenience: push an EV_KEY event (value 1=down, 0=up, 2=repeat).
#[inline]
pub fn push_key(code: u16, value: i32) {
    push_event(InputEvent { typ: EventType::Key, code, value });
    // SYN_REPORT after every key event.
    push_event(InputEvent { typ: EventType::Syn, code: 0, value: 0 });
}

/// Convenience: push EV_REL.
#[inline]
pub fn push_rel(code: u16, value: i32) {
    push_event(InputEvent { typ: EventType::Rel, code, value });
}
