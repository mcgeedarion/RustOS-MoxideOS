//! USB HID boot-protocol driver.
//!
//! Handles the two standard HID boot descriptors:
//!   - Boot keyboard report (8 bytes)
//!   - Boot mouse report (3+ bytes)
//!
//! These are used by UEFI/legacy USB controllers before a full HID
//! class driver is available.  The decode path normalises reports
//! directly to evdev KeyCodes / REL events and pushes them via
//! evdev::push_key() / evdev::push_rel().
//!
//! ## Boot keyboard report (USB HID spec §B.1)
//!   byte 0: modifier byte
//!     bit 0: LEFT  CTRL   bit 1: LEFT  SHIFT  bit 2: LEFT  ALT
//!     bit 3: LEFT  META   bit 4: RIGHT CTRL   bit 5: RIGHT SHIFT
//!     bit 6: RIGHT ALT    bit 7: RIGHT META
//!   byte 1: reserved (0)
//!   bytes 2-7: up to 6 simultaneous key usage codes (HID usage page 0x07)
//!
//! ## Boot mouse report (USB HID spec §B.2)
//!   byte 0: button mask (bit 0=left, bit 1=right, bit 2=middle)
//!   byte 1: X delta (i8)
//!   byte 2: Y delta (i8)
//!   byte 3: wheel delta (i8, optional)
//!
//! ## Public API
//!   hid_kbd_report(report: &[u8])   — decode one keyboard boot report
//!   hid_mouse_report(report: &[u8]) — decode one mouse boot report

use crate::drivers::evdev::{push_key, push_rel, KeyCode, RelCode};

// ── HID Usage Page 0x07 (Keyboard) → evdev KeyCode ───────────────────────────

/// Map USB HID usage (0x00..0x7F) → evdev KeyCode.
/// Returns 0 for "no key".
const HID_TO_KEY: [u16; 128] = {
    let mut t = [0u16; 128];
    // a-z: HID 0x04..0x1D → KEY_A(30)..KEY_Z(44+)
    let mut i = 0u16;
    while i < 26 { t[(0x04 + i) as usize] = KeyCode::KEY_A as u16 + i; i += 1; }
    // 1-9, 0
    t[0x1E] = KeyCode::KEY_1 as u16;  t[0x1F] = KeyCode::KEY_2 as u16;
    t[0x20] = KeyCode::KEY_3 as u16;  t[0x21] = KeyCode::KEY_4 as u16;
    t[0x22] = KeyCode::KEY_5 as u16;  t[0x23] = KeyCode::KEY_6 as u16;
    t[0x24] = KeyCode::KEY_7 as u16;  t[0x25] = KeyCode::KEY_8 as u16;
    t[0x26] = KeyCode::KEY_9 as u16;  t[0x27] = KeyCode::KEY_0 as u16;
    // Misc
    t[0x28] = KeyCode::KEY_ENTER      as u16;
    t[0x29] = KeyCode::KEY_ESC        as u16;
    t[0x2A] = KeyCode::KEY_BACKSPACE  as u16;
    t[0x2B] = KeyCode::KEY_TAB        as u16;
    t[0x2C] = KeyCode::KEY_SPACE      as u16;
    t[0x2D] = KeyCode::KEY_MINUS      as u16;
    t[0x2E] = KeyCode::KEY_EQUAL      as u16;
    t[0x2F] = KeyCode::KEY_LEFTBRACE  as u16;
    t[0x30] = KeyCode::KEY_RIGHTBRACE as u16;
    t[0x31] = KeyCode::KEY_BACKSLASH  as u16;
    t[0x33] = KeyCode::KEY_SEMICOLON  as u16;
    t[0x34] = KeyCode::KEY_APOSTROPHE as u16;
    t[0x35] = KeyCode::KEY_GRAVE      as u16;
    t[0x36] = KeyCode::KEY_COMMA      as u16;
    t[0x37] = KeyCode::KEY_DOT        as u16;
    t[0x38] = KeyCode::KEY_SLASH      as u16;
    t[0x39] = KeyCode::KEY_CAPSLOCK   as u16;
    t[0x3A] = KeyCode::KEY_F1  as u16; t[0x3B] = KeyCode::KEY_F2  as u16;
    t[0x3C] = KeyCode::KEY_F3  as u16; t[0x3D] = KeyCode::KEY_F4  as u16;
    t[0x3E] = KeyCode::KEY_F5  as u16; t[0x3F] = KeyCode::KEY_F6  as u16;
    t[0x40] = KeyCode::KEY_F7  as u16; t[0x41] = KeyCode::KEY_F8  as u16;
    t[0x42] = KeyCode::KEY_F9  as u16; t[0x43] = KeyCode::KEY_F10 as u16;
    t[0x44] = KeyCode::KEY_F11 as u16; t[0x45] = KeyCode::KEY_F12 as u16;
    t[0x49] = KeyCode::KEY_INSERT   as u16;
    t[0x4A] = KeyCode::KEY_HOME     as u16;
    t[0x4B] = KeyCode::KEY_PAGEUP   as u16;
    t[0x4C] = KeyCode::KEY_DELETE   as u16;
    t[0x4D] = KeyCode::KEY_END      as u16;
    t[0x4E] = KeyCode::KEY_PAGEDOWN as u16;
    t[0x4F] = KeyCode::KEY_RIGHT    as u16;
    t[0x50] = KeyCode::KEY_LEFT     as u16;
    t[0x51] = KeyCode::KEY_DOWN     as u16;
    t[0x52] = KeyCode::KEY_UP       as u16;
    t[0xE0] = KeyCode::KEY_LEFTCTRL  as u16;
    t[0xE1] = KeyCode::KEY_LEFTSHIFT as u16;
    t[0xE2] = KeyCode::KEY_LEFTALT   as u16;
    t[0xE3] = KeyCode::KEY_LEFTMETA  as u16;
    t[0xE4] = KeyCode::KEY_RIGHTCTRL  as u16;
    t[0xE5] = KeyCode::KEY_RIGHTSHIFT as u16;
    t[0xE6] = KeyCode::KEY_RIGHTALT   as u16;
    t[0xE7] = KeyCode::KEY_RIGHTMETA  as u16;
    t
};

/// Previous report — used to detect key-down vs key-up transitions.
static mut PREV_KEYCODES: [u16; 6] = [0u16; 6];
static mut PREV_MODS:     u8       = 0;

// ── HID modifier byte → evdev KeyCode ────────────────────────────────────────

const MOD_KEYS: [u16; 8] = [
    KeyCode::KEY_LEFTCTRL   as u16,
    KeyCode::KEY_LEFTSHIFT  as u16,
    KeyCode::KEY_LEFTALT    as u16,
    KeyCode::KEY_LEFTMETA   as u16,
    KeyCode::KEY_RIGHTCTRL  as u16,
    KeyCode::KEY_RIGHTSHIFT as u16,
    KeyCode::KEY_RIGHTALT   as u16,
    KeyCode::KEY_RIGHTMETA  as u16,
];

// ── Keyboard boot report decoder ─────────────────────────────────────────────

/// Decode one USB HID boot keyboard report (8 bytes) and push key events.
/// # Safety
/// Caller must not invoke this concurrently from multiple interrupt contexts.
pub fn hid_kbd_report(report: &[u8]) {
    if report.len() < 8 { return; }

    let mods_now  = report[0];
    let keys_now  = &report[2..8];

    // SAFETY: single-threaded IRQ context; no re-entrant calls.
    let (prev_keys, prev_mods) = unsafe { (&mut PREV_KEYCODES, &mut PREV_MODS) };

    // Modifier transitions.
    let mod_changed = mods_now ^ *prev_mods;
    for bit in 0..8u8 {
        if mod_changed & (1 << bit) != 0 {
            let kc = MOD_KEYS[bit as usize];
            let down = (mods_now >> bit) & 1 != 0;
            push_key(kc, if down { 1 } else { 0 });
            crate::drivers::keyboard::keyboard_push_keycode(kc, if down { 1 } else { 0 });
        }
    }
    *prev_mods = mods_now;

    // Key-up: was in previous report, not in current.
    for &old_usage in prev_keys.iter() {
        if old_usage == 0 { continue; }
        if !keys_now.contains(&old_usage) {
            let kc = hid_usage_to_key(old_usage);
            if kc != 0 {
                push_key(kc, 0);
                crate::drivers::keyboard::keyboard_push_keycode(kc, 0);
            }
        }
    }
    // Key-down: in current report, not in previous.
    let mut new_prev = [0u16; 6];
    for (i, &usage) in keys_now.iter().enumerate() {
        let kc = hid_usage_to_key(usage);
        new_prev[i] = usage as u16;
        if kc != 0 && !prev_keys.iter().any(|&p| p == usage as u16) {
            push_key(kc, 1);
            crate::drivers::keyboard::keyboard_push_keycode(kc, 1);
        }
    }
    *prev_keys = new_prev;
}

#[inline]
fn hid_usage_to_key(usage: u8) -> u16 {
    if (usage as usize) < HID_TO_KEY.len() { HID_TO_KEY[usage as usize] } else { 0 }
}

// ── Mouse boot report decoder ─────────────────────────────────────────────────

/// Previous button state — for transition detection.
static mut PREV_MOUSE_BTNS: u8 = 0;

/// Decode one USB HID boot mouse report and push REL + button events.
/// # Safety
/// Single-threaded IRQ context.
pub fn hid_mouse_report(report: &[u8]) {
    if report.len() < 3 { return; }

    let btns = report[0];
    let dx   = report[1] as i8;
    let dy   = report[2] as i8;
    let dw   = if report.len() >= 4 { report[3] as i8 } else { 0 };

    if dx != 0 { push_rel(RelCode::REL_X as u16,     dx as i32); }
    if dy != 0 { push_rel(RelCode::REL_Y as u16,     dy as i32); }
    if dw != 0 { push_rel(RelCode::REL_WHEEL as u16, dw as i32); }

    let prev = unsafe { PREV_MOUSE_BTNS };
    let changed = btns ^ prev;
    for bit in 0..3u8 {
        if changed & (1 << bit) != 0 {
            let kc = match bit {
                0 => KeyCode::BTN_LEFT   as u16,
                1 => KeyCode::BTN_RIGHT  as u16,
                _ => KeyCode::BTN_MIDDLE as u16,
            };
            push_key(kc, if btns & (1 << bit) != 0 { 1 } else { 0 });
        }
    }
    unsafe { PREV_MOUSE_BTNS = btns; }
}
