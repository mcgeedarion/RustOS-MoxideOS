//! Input drivers.
//!
//! ## Modules
//!   evdev         — evdev input event layer
//!   hid           — USB HID
//!   keyboard      — PS/2 / USB keyboard
//!   mouse         — PS/2 / USB mouse
//!   usb           — USB xHCI host controller
//!   bluetooth     — Bluetooth HCI over USB transport
//!   virtio_input  — VirtIO input device

pub mod bluetooth;
pub mod evdev;
pub mod hid;
pub mod keyboard;
pub mod mouse;
pub mod usb;
pub mod virtio_input;
