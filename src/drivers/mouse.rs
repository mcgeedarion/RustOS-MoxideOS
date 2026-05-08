//! Mouse driver — accumulates evdev EV_REL and EV_KEY events.
//!
//! ## Sources
//!   - virtio-input device posting EV_REL/EV_KEY events (via evdev::push_event)
//!   - PS/2 mouse (IRQ 12) — not yet implemented; stub left for future work.
//!
//! ## Public API
//!   mouse_update()            — drain evdev ring for mouse events; call from
//!                               main loop or timer tick.
//!   get_state() -> MouseState — snapshot of current pointer position + buttons.
//!   reset_delta()             — zero REL_X / REL_Y accumulators.

use crate::drivers::evdev::{pop_event, EventType, RelCode, KeyCode};
use spin::Mutex;

// ── State ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default, Debug)]
pub struct MouseState {
    /// Absolute cursor position (accumulated from REL events).
    pub x: i32,
    pub y: i32,
    /// Delta since last reset_delta().
    pub dx: i32,
    pub dy: i32,
    /// Button state bits: bit 0 = left, bit 1 = right, bit 2 = middle.
    pub buttons: u8,
    /// Mouse wheel accumulator.
    pub wheel: i32,
}

static STATE: Mutex<MouseState> = Mutex::new(MouseState {
    x: 0, y: 0, dx: 0, dy: 0, buttons: 0, wheel: 0,
});

// ── Evdev drain ───────────────────────────────────────────────────────────────

/// Process all pending evdev events that belong to the mouse.
/// Call from the main render loop or a periodic tick.
pub fn mouse_update() {
    let mut state = STATE.lock();
    while let Some(ev) = pop_event() {
        match ev.typ {
            EventType::Rel => {
                match ev.code {
                    c if c == RelCode::REL_X     as u16 => { state.dx += ev.value; state.x += ev.value; }
                    c if c == RelCode::REL_Y     as u16 => { state.dy += ev.value; state.y += ev.value; }
                    c if c == RelCode::REL_WHEEL as u16 => { state.wheel += ev.value; }
                    _ => {}
                }
            }
            EventType::Key => {
                let down = ev.value != 0;
                match ev.code {
                    c if c == KeyCode::BTN_LEFT   as u16 => set_btn(&mut state.buttons, 0, down),
                    c if c == KeyCode::BTN_RIGHT  as u16 => set_btn(&mut state.buttons, 1, down),
                    c if c == KeyCode::BTN_MIDDLE as u16 => set_btn(&mut state.buttons, 2, down),
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

#[inline]
fn set_btn(buttons: &mut u8, bit: u8, down: bool) {
    if down { *buttons |=  (1 << bit); }
    else    { *buttons &= !(1 << bit); }
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Snapshot of mouse state.
pub fn get_state() -> MouseState {
    *STATE.lock()
}

/// Zero the dx/dy delta accumulators (call once per frame).
pub fn reset_delta() {
    let mut s = STATE.lock();
    s.dx = 0;
    s.dy = 0;
}

/// Clamp cursor to a viewport [0, max_x] x [0, max_y].
pub fn clamp(max_x: i32, max_y: i32) {
    let mut s = STATE.lock();
    s.x = s.x.clamp(0, max_x);
    s.y = s.y.clamp(0, max_y);
}
