//! NIC abstraction layer.
//!
//! Decouples the network stack (eth.rs / ip.rs / tcp.rs …) from any
//! specific hardware driver.  Each driver calls register_nic() during
//! its probe function; the stack calls send_frame() / rx_poll_all()
//! without knowing which hardware is underneath.
//!
//! ## Design
//!   - Up to MAX_NICS registered devices (static array, no heap).
//!   - send_frame() sends through the *first* registered NIC (primary uplink).
//!   - rx_poll_all() drains every registered NIC (called from timer tick
//!     or explicitly from IRQ handlers).
//!   - NicDevice is a plain struct (not a trait object) to avoid vtable
//!     overhead and dyn-incompatibility issues with no_std environments.
//!     Drivers fill in function pointers directly.
//!
//! ## Usage
//!   ```rust
//!   // In your driver probe function:
//!   nic::register_nic(NicDevice {
//!       send_frame: my_send_frame,
//!       rx_poll:    my_rx_poll,
//!       mac:        my_mac,
//!   });
//!
//!   // In eth.rs (or anywhere in the net stack):
//!   nic::send_frame(frame);
//!   nic::rx_poll_all();
//!   ```

use spin::Mutex;

pub const MAX_NICS: usize = 4;

/// Function-pointer based NIC descriptor.
/// Fill all fields before passing to register_nic().
#[derive(Clone, Copy)]
pub struct NicDevice {
    /// Transmit one raw Ethernet frame (caller includes Ethernet header,
    /// no FCS required).  Returns true on success.
    pub send_frame: fn(frame: &[u8]) -> bool,
    /// Drain any received frames and forward them into the network stack
    /// via crate::net::eth::receive_frame().  Called from IRQ or timer.
    pub rx_poll: fn(),
    /// The hardware MAC address of this interface.
    pub mac: [u8; 6],
}

struct NicTable {
    devs: [Option<NicDevice>; MAX_NICS],
    count: usize,
}

impl NicTable {
    const fn new() -> Self {
        Self {
            devs: [None; MAX_NICS],
            count: 0,
        }
    }
}

static TABLE: Mutex<NicTable> = Mutex::new(NicTable::new());

/// Register a NIC.  Called by each driver's probe function.
/// Silently drops registrations beyond MAX_NICS.
pub fn register_nic(dev: NicDevice) {
    let mut t = TABLE.lock();
    if t.count < MAX_NICS {
        t.devs[t.count] = Some(dev);
        t.count += 1;
        crate::arch::x86_64::serial::serial_println!(
            "nic: registered device {} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            t.count - 1,
            dev.mac[0],
            dev.mac[1],
            dev.mac[2],
            dev.mac[3],
            dev.mac[4],
            dev.mac[5],
        );
    }
}

/// Transmit a frame through the primary (first registered) NIC.
/// Returns false if no NIC is registered or the driver reports failure.
pub fn send_frame(frame: &[u8]) -> bool {
    let t = TABLE.lock();
    if let Some(Some(dev)) = t.devs.first() {
        (dev.send_frame)(frame)
    } else {
        false
    }
}

/// Drain received frames on every registered NIC.
/// Call from a periodic timer tick or from each NIC's IRQ handler.
pub fn rx_poll_all() {
    let t = TABLE.lock();
    for slot in t.devs.iter().take(t.count) {
        if let Some(dev) = slot {
            (dev.rx_poll)();
        }
    }
}

/// Return the MAC address of the primary NIC (first registered).
/// Returns all-zeros if no NIC has been registered yet.
pub fn primary_mac() -> [u8; 6] {
    let t = TABLE.lock();
    t.devs
        .first()
        .and_then(|s| s.as_ref())
        .map(|d| d.mac)
        .unwrap_or([0u8; 6])
}

/// Number of registered NICs.
pub fn nic_count() -> usize {
    TABLE.lock().count
}
