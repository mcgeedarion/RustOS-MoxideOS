//! NIC abstraction layer.
//!
//! Provides a unified `NetworkDevice` trait and a global registry so the
//! network stack can send/receive frames without caring about the
//! underlying hardware driver (e1000e, virtio-net, etc.).

extern crate alloc;
use alloc::{boxed::Box, vec::Vec};
use spin::Mutex;

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Minimal NIC interface consumed by the kernel network stack.
pub trait NetworkDevice: Send {
    /// Transmit a raw Ethernet frame.  Returns Ok(()) on success.
    fn send(&mut self, frame: &[u8]) -> Result<(), &'static str>;

    /// Receive one pending Ethernet frame into `buf`.
    /// Returns Some(len) if a frame was available, None if the RX queue
    /// is empty.
    fn recv(&mut self, buf: &mut [u8]) -> Option<usize>;

    /// 6-byte MAC address of this NIC.
    fn mac(&self) -> [u8; 6];

    /// Human-readable driver name (e.g. "e1000e", "virtio-net").
    fn name(&self) -> &'static str;

    /// True if the link is up.
    fn link_up(&self) -> bool { true }
}

// ---------------------------------------------------------------------------
// Global registry
// ---------------------------------------------------------------------------

static NICS: Mutex<Vec<Box<dyn NetworkDevice>>> = Mutex::new(Vec::new());

/// Register a NIC with the global registry.  Returns the assigned index.
pub fn register(nic: Box<dyn NetworkDevice>) -> usize {
    let mut nics = NICS.lock();
    let idx = nics.len();
    nics.push(nic);
    idx
}

/// Number of registered NICs.
pub fn count() -> usize { NICS.lock().len() }

/// Send a frame via NIC `idx`.
pub fn send(idx: usize, frame: &[u8]) -> Result<(), &'static str> {
    NICS.lock().get_mut(idx).ok_or("no such nic")?.send(frame)
}

/// Receive a frame from NIC `idx` into `buf`.
pub fn recv(idx: usize, buf: &mut [u8]) -> Option<usize> {
    NICS.lock().get_mut(idx)?.recv(buf)
}

/// MAC address of NIC `idx`.
pub fn mac(idx: usize) -> Option<[u8; 6]> {
    NICS.lock().get(idx).map(|n| n.mac())
}

/// Poll all NICs and pass received frames to `handler`.
pub fn poll_all(handler: impl Fn(usize, &[u8])) {
    let mut buf = [0u8; 2048];
    let n = count();
    for i in 0..n {
        while let Some(len) = recv(i, &mut buf) {
            handler(i, &buf[..len]);
        }
    }
}
