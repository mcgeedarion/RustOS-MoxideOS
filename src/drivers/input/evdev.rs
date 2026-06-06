//! evdev — generic input event interface.
//!
//! Kernel-side companion to Linux evdev: collects raw events from keyboard,
//! mouse and virtio-input drivers and exposes them through a single ring
//! buffer that userspace `read(2)` calls drain.
//!
//! ## Event format
//!
//!   Each `InputEvent` is 16 bytes:
//!     time_sec  u32   seconds since boot
//!     time_usec u32   microseconds fraction
//!     type      u16   EV_KEY, EV_REL, EV_ABS, EV_SYN, …
//!     code      u16   KEY_A, REL_X, …
//!     value     i32   1=press, 0=release, 2=repeat; delta for EV_REL

use spin::Mutex;

pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_MSC: u16 = 0x04;

pub const SYN_REPORT: u16 = 0;

pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_WHEEL: u16 = 0x08;

pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;

// KEY codes (subset)
pub const KEY_RESERVED: u16 = 0;
pub const KEY_ESC: u16 = 1;
pub const KEY_ENTER: u16 = 28;
pub const KEY_SPACE: u16 = 57;
pub const KEY_BACKSPACE: u16 = 14;
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;

#[derive(Clone, Copy, Debug, Default)]
pub struct InputEvent {
    pub time_sec: u32,
    pub time_usec: u32,
    pub r#type: u16,
    pub code: u16,
    pub value: i32,
}

const RING_CAP: usize = 512;

struct EventRing {
    buf: [InputEvent; RING_CAP],
    head: usize,
    tail: usize,
}

impl EventRing {
    const fn new() -> Self {
        Self {
            buf: [InputEvent {
                time_sec: 0,
                time_usec: 0,
                r#type: 0,
                code: 0,
                value: 0,
            }; RING_CAP],
            head: 0,
            tail: 0,
        }
    }
    fn push(&mut self, ev: InputEvent) {
        let next = (self.tail + 1) % RING_CAP;
        if next == self.head {
            return;
        } // drop on overflow
        self.buf[self.tail] = ev;
        self.tail = next;
    }
    fn pop(&mut self) -> Option<InputEvent> {
        if self.head == self.tail {
            return None;
        }
        let ev = self.buf[self.head];
        self.head = (self.head + 1) % RING_CAP;
        Some(ev)
    }
    fn len(&self) -> usize {
        (self.tail + RING_CAP - self.head) % RING_CAP
    }
}

static RING: Mutex<EventRing> = Mutex::new(EventRing::new());

/// Push one event into the evdev ring (called by driver ISRs / poll paths).
pub fn push(ev: InputEvent) {
    RING.lock().push(ev);
}

/// Push a synthetic EV_SYN/SYN_REPORT to terminate a logical event group.
pub fn sync() {
    push(InputEvent {
        r#type: EV_SYN,
        code: SYN_REPORT,
        value: 0,
        ..Default::default()
    });
}

/// Drain up to `buf.len()` events from the ring into `buf`.
/// Returns the number of events written.
pub fn read(buf: &mut [InputEvent]) -> usize {
    let mut ring = RING.lock();
    let mut n = 0;
    while n < buf.len() {
        match ring.pop() {
            Some(ev) => {
                buf[n] = ev;
                n += 1;
            },
            None => break,
        }
    }
    n
}

/// Returns how many events are queued.
pub fn pending() -> usize {
    RING.lock().len()
}

/// Timestamp helper: returns (sec, usec) since boot using the CLINT mtime.
fn timestamp() -> (u32, u32) {
    let ns = crate::drivers::platform::clint::monotonic_ns();
    (
        (ns / 1_000_000_000) as u32,
        ((ns % 1_000_000_000) / 1_000) as u32,
    )
}

/// Convenience: build and push a key event.
pub fn push_key(code: u16, value: i32) {
    let (s, us) = timestamp();
    push(InputEvent {
        time_sec: s,
        time_usec: us,
        r#type: EV_KEY,
        code,
        value,
    });
}

/// Convenience: build and push a relative motion event.
pub fn push_rel(code: u16, value: i32) {
    let (s, us) = timestamp();
    push(InputEvent {
        time_sec: s,
        time_usec: us,
        r#type: EV_REL,
        code,
        value,
    });
}
