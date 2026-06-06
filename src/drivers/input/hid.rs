//! USB HID report descriptor parser and report dispatcher.
//!
//! Parses HID report descriptors to extract Usage Page / Usage / Report Size /
//! Report Count / Logical Min-Max for each field, then decodes incoming
//! interrupt-transfer reports and forwards events to `evdev`.
//!
//! ## Supported HID usages
//!   - Generic Desktop / Keyboard  (Usage 0x06)
//!   - Generic Desktop / Mouse     (Usage 0x02)
//!   - Generic Desktop / Joystick  (Usage 0x04)  — axes only

extern crate alloc;
use alloc::vec::Vec;

use crate::drivers::input::evdev::{
    self, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, EV_KEY, EV_REL, REL_WHEEL, REL_X, REL_Y,
};

const UP_GENERIC_DESKTOP: u16 = 0x01;
const UP_KEYBOARD: u16 = 0x07;
const UP_BUTTON: u16 = 0x09;

// Generic Desktop usages
const USAGE_POINTER: u16 = 0x01;
const USAGE_MOUSE: u16 = 0x02;
const USAGE_JOYSTICK: u16 = 0x04;
const USAGE_KEYBOARD: u16 = 0x06;
const USAGE_X: u16 = 0x30;
const USAGE_Y: u16 = 0x31;
const USAGE_WHEEL: u16 = 0x38;

// Item tags
const TAG_USAGE_PAGE: u8 = 0x04;
const TAG_USAGE: u8 = 0x08;
const TAG_LOG_MIN: u8 = 0x14;
const TAG_LOG_MAX: u8 = 0x24;
const TAG_REPORT_SIZE: u8 = 0x74;
const TAG_REPORT_COUNT: u8 = 0x94;
const TAG_INPUT: u8 = 0x80;
const TAG_COLLECTION: u8 = 0xA0;
const TAG_END_COLLECTION: u8 = 0xC0;
const TAG_REPORT_ID: u8 = 0x84;

// Input item flags
const INP_CONST: u32 = 1 << 0;
const INP_VAR: u32 = 1 << 1;
const INP_REL: u32 = 1 << 2;

#[derive(Clone, Debug)]
struct Field {
    usage_page: u16,
    usages: Vec<u16>, // per-bit or per-count usage
    report_size: u32,
    report_count: u32,
    logical_min: i32,
    logical_max: i32,
    flags: u32,
}

#[derive(Clone, Debug)]
pub struct HidReport {
    fields: Vec<Field>,
    /// True if any field has a relative axis (pointer)
    pub is_mouse: bool,
    /// True if any field is a keyboard-style key array
    pub is_keyboard: bool,
}

pub fn parse_descriptor(desc: &[u8]) -> HidReport {
    let mut fields = Vec::new();
    let mut usage_page = 0u16;
    let mut usages: Vec<u16> = Vec::new();
    let mut report_size = 0u32;
    let mut report_count = 0u32;
    let mut log_min = 0i32;
    let mut log_max = 0i32;
    let mut is_mouse = false;
    let mut is_keyboard = false;

    let mut i = 0;
    while i < desc.len() {
        let b = desc[i];
        let tag = b & 0xFC;
        let size = match b & 0x03 {
            1 => 1,
            2 => 2,
            3 => 4,
            _ => 0,
        };
        i += 1;
        let val: u32 = match size {
            1 => {
                let v = desc.get(i).copied().unwrap_or(0) as u32;
                i += 1;
                v
            },
            2 => {
                let lo = desc.get(i).copied().unwrap_or(0) as u32;
                let hi = desc.get(i + 1).copied().unwrap_or(0) as u32;
                i += 2;
                lo | (hi << 8)
            },
            4 => {
                let v = desc
                    .get(i..i + 4)
                    .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
                    .unwrap_or(0);
                i += 4;
                v
            },
            _ => 0,
        };

        match tag {
            TAG_USAGE_PAGE => {
                usage_page = val as u16;
            },
            TAG_USAGE => {
                usages.push(val as u16);
            },
            TAG_LOG_MIN => {
                log_min = val as i32;
            },
            TAG_LOG_MAX => {
                log_max = val as i32;
            },
            TAG_REPORT_SIZE => {
                report_size = val;
            },
            TAG_REPORT_COUNT => {
                report_count = val;
            },
            TAG_COLLECTION | TAG_END_COLLECTION | TAG_REPORT_ID => {},
            TAG_INPUT => {
                let flags = val;
                if flags & INP_CONST == 0 {
                    let f = Field {
                        usage_page,
                        usages: usages.clone(),
                        report_size,
                        report_count,
                        logical_min: log_min,
                        logical_max: log_max,
                        flags,
                    };
                    if f.usage_page == UP_GENERIC_DESKTOP {
                        if f.usages.contains(&USAGE_X) || f.usages.contains(&USAGE_Y) {
                            is_mouse = true;
                        }
                    }
                    if f.usage_page == UP_KEYBOARD {
                        is_keyboard = true;
                    }
                    fields.push(f);
                }
                usages.clear();
            },
            _ => {},
        }
    }

    HidReport {
        fields,
        is_mouse,
        is_keyboard,
    }
}

/// Decode a raw HID report `data` according to `report` and push events.
pub fn dispatch(report: &HidReport, data: &[u8]) {
    let mut bit_off = 0usize;

    for field in &report.fields {
        for c in 0..field.report_count as usize {
            let raw = extract_bits(data, bit_off, field.report_size as usize);
            bit_off += field.report_size as usize;

            let usage = field
                .usages
                .get(c)
                .copied()
                .or_else(|| field.usages.last().copied())
                .unwrap_or(0);

            if field.flags & INP_CONST != 0 {
                continue;
            }

            if field.usage_page == UP_GENERIC_DESKTOP {
                if field.flags & INP_REL != 0 {
                    let signed = sign_extend(
                        raw,
                        field.report_size as usize,
                        field.logical_min,
                        field.logical_max,
                    );
                    match usage {
                        USAGE_X => evdev::push_rel(REL_X, signed),
                        USAGE_Y => evdev::push_rel(REL_Y, signed),
                        USAGE_WHEEL => evdev::push_rel(REL_WHEEL, signed),
                        _ => {},
                    }
                }
            } else if field.usage_page == UP_KEYBOARD {
                if raw != 0 {
                    evdev::push_key(raw as u16, 1);
                }
            } else if field.usage_page == UP_BUTTON {
                let code = match usage {
                    1 => BTN_LEFT,
                    2 => BTN_RIGHT,
                    3 => BTN_MIDDLE,
                    _ => continue,
                };
                evdev::push_key(code, raw as i32);
            }
        }
    }
    evdev::sync();
}

fn extract_bits(data: &[u8], bit_off: usize, bits: usize) -> u32 {
    if bits == 0 {
        return 0;
    }
    let mut val = 0u32;
    for b in 0..bits {
        let byte = (bit_off + b) / 8;
        let bit = (bit_off + b) % 8;
        if byte < data.len() {
            val |= (((data[byte] >> bit) & 1) as u32) << b;
        }
    }
    val
}

fn sign_extend(raw: u32, bits: usize, _lmin: i32, _lmax: i32) -> i32 {
    if bits == 0 {
        return 0;
    }
    let sign_bit = 1u32 << (bits - 1);
    if raw & sign_bit != 0 {
        (raw | (!0u32 << bits)) as i32
    } else {
        raw as i32
    }
}
