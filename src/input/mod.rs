//! Input event subsystem (keyboard/mouse routing to /dev/input).
//!
//! TODO: route events to /dev/input/eventN device nodes.
//! Both functions below are intentional no-op stubs until evdev routing
//! is wired. The unused-variable lint is suppressed because the parameter
//! names document the intended ABI even though the body is empty.
#[allow(dead_code, unused_variables)]
pub fn dispatch_key(_scancode: u8) {}
#[allow(dead_code, unused_variables)]
pub fn dispatch_mouse(_dx: i8, _dy: i8, _buttons: u8) {}
