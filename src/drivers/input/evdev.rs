//! evdev — kernel input event layer.
//!
//! Provides a generic `InputEvent` type and a global ring buffer that all
//! input drivers (keyboard, mouse, touch, gamepad …) push events into.
//! Userspace reads `/dev/input/event0` by draining this buffer via
//! the `read(2)` syscall.

extern crate alloc;
use alloc::collections::VecDeque;
use spin::Mutex;

// ---------------------------------------------------------------------------
// Event types  (subset of Linux evdev)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum EventType {
    Sync       = 0x00,
    Key        = 0x01,
    Relative   = 0x02,
    Absolute   = 0x03,
    Misc       = 0x04,
}

/// A single input event, layout-compatible with Linux `struct input_event`
/// (without the timestamp, which we omit to keep things simple).
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct InputEvent {
    pub ev_type: EventType,
    pub code:    u16,
    pub value:   i32,
}

// Well-known KEY codes (subset of Linux input-event-codes.h)
pub const KEY_ESC:       u16 = 1;
pub const KEY_BACKSPACE: u16 = 14;
pub const KEY_ENTER:     u16 = 28;
pub const KEY_SPACE:     u16 = 57;
pub const KEY_UP:        u16 = 103;
pub const KEY_DOWN:      u16 = 108;
pub const KEY_LEFT:      u16 = 105;
pub const KEY_RIGHT:     u16 = 106;

// REL codes
pub const REL_X:         u16 = 0x00;
pub const REL_Y:         u16 = 0x01;
pub const REL_WHEEL:     u16 = 0x08;

// BTN codes
pub const BTN_LEFT:      u16 = 0x110;
pub const BTN_RIGHT:     u16 = 0x111;
pub const BTN_MIDDLE:    u16 = 0x112;

// SYN codes
pub const SYN_REPORT:    u16 = 0;

// ---------------------------------------------------------------------------
// Global event queue
// ---------------------------------------------------------------------------

const MAX_EVENTS: usize = 512;

static QUEUE: Mutex<VecDeque<InputEvent>> = Mutex::new(VecDeque::new());

/// Push an event into the global queue (called from driver ISRs).
pub fn push(ev: InputEvent) {
    let mut q = QUEUE.lock();
    if q.len() < MAX_EVENTS {
        q.push_back(ev);
    }
    // Drop oldest if full to avoid blocking interrupt context.
}

/// Convenience: push a SYN_REPORT to signal end of an event batch.
pub fn sync() {
    push(InputEvent { ev_type: EventType::Sync, code: SYN_REPORT, value: 0 });
}

/// Pop one event.  Returns None if the queue is empty.
pub fn pop() -> Option<InputEvent> {
    QUEUE.lock().pop_front()
}

/// Read up to `buf.len() / size_of::<InputEvent>()` events into `buf`.
/// Returns number of events written.
pub fn read_events(buf: &mut [InputEvent]) -> usize {
    let mut q = QUEUE.lock();
    let n = buf.len().min(q.len());
    for i in 0..n {
        buf[i] = q.pop_front().unwrap();
    }
    n
}

/// Returns true if at least one event is pending.
pub fn pending() -> bool {
    !QUEUE.lock().is_empty()
}

/// Discard all pending events.
pub fn flush() {
    QUEUE.lock().clear();
}
