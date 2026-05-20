//! NIC abstraction layer.
//!
//! Provides a unified `NetworkDevice` trait and a global registry so that
//! higher layers (TCP/IP stack, DHCP client) can send/receive frames without
//! knowing which physical driver is backing them.

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};
use spin::Mutex;

// ---------------------------------------------------------------------------
// NetworkDevice trait
// ---------------------------------------------------------------------------

/// Ethernet frame transmit/receive interface.
pub trait NetworkDevice: Send {
    /// Transmit a raw Ethernet frame.  `frame` includes the Ethernet header.
    /// Returns Ok(()) on success or Err on queue-full / hardware error.
    fn send(&mut self, frame: &[u8]) -> Result<(), &'static str>;

    /// Poll for a received frame.  Returns Some(Vec<u8>) if a frame is
    /// waiting, None if the receive queue is empty.
    fn recv(&mut self) -> Option<Vec<u8>>;

    /// 6-byte MAC address of this interface.
    fn mac(&self) -> [u8; 6];

    /// Link speed in Mbit/s, or 0 if unknown / link-down.
    fn link_speed(&self) -> u32 { 0 }

    /// True if the link is up.
    fn link_up(&self) -> bool { true }
}

// ---------------------------------------------------------------------------
// Global device registry
// ---------------------------------------------------------------------------

static DEVICES: Mutex<Vec<Box<dyn NetworkDevice>>> = Mutex::new(Vec::new());

/// Register a NIC.  Returns the assigned interface index.
pub fn register(dev: Box<dyn NetworkDevice>) -> usize {
    let mut devs = DEVICES.lock();
    let idx = devs.len();
    devs.push(dev);
    idx
}

/// Number of registered NICs.
pub fn count() -> usize {
    DEVICES.lock().len()
}

/// Transmit a frame on interface `idx`.
pub fn send(idx: usize, frame: &[u8]) -> Result<(), &'static str> {
    let mut devs = DEVICES.lock();
    devs.get_mut(idx).ok_or("no such nic")?.send(frame)
}

/// Poll interface `idx` for a received frame.
pub fn recv(idx: usize) -> Option<Vec<u8>> {
    let mut devs = DEVICES.lock();
    devs.get_mut(idx)?.recv()
}

/// MAC address of interface `idx`.
pub fn mac(idx: usize) -> Option<[u8; 6]> {
    DEVICES.lock().get(idx).map(|d| d.mac())
}

/// Poll all interfaces; returns the first frame found along with its
/// interface index, or None if all queues are empty.
pub fn recv_any() -> Option<(usize, Vec<u8>)> {
    let mut devs = DEVICES.lock();
    for (i, dev) in devs.iter_mut().enumerate() {
        if let Some(frame) = dev.recv() {
            return Some((i, frame));
        }
    }
    None
}
