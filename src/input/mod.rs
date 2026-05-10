//! Linux /dev/input evdev routing layer.
//!
//! Status: intentional no-op stubs.  The VFS device-node layer
//! (`/dev/input/eventN`) and the ringbuffer that backs each node are not
//! yet implemented.  Wire this up once devfs supports dynamic minor
//! allocation and per-fd read queues.
//!
//! Both functions form the stable ABI that driver code calls today;
//! the signatures must not change when the routing is implemented.

pub fn dispatch_key(_scancode: u8) {}
pub fn dispatch_mouse(_dx: i8, _dy: i8, _buttons: u8) {}
