//! NIC abstraction layer.
//!
//! Decouples the network stack from any specific hardware driver.
//! Each driver calls register_nic() during probe; the stack calls
//! send_frame() / rx_poll_all() without knowing which hardware is underneath.
//!
//! - Up to MAX_NICS registered devices (static array, no heap).
//! - send_frame() sends through the *first* registered NIC (primary uplink).
//! - rx_poll_all() drains every registered NIC.

use spin::Mutex;

pub const MAX_NICS: usize = 4;

#[derive(Clone, Copy)]
pub struct NicDevice {
    pub send_frame: fn(frame: &[u8]) -> bool,
    pub rx_poll:    fn(),
    pub mac:        [u8; 6],
}

struct NicTable { devs: [Option<NicDevice>; MAX_NICS], count: usize }
impl NicTable { const fn new() -> Self { Self { devs: [None; MAX_NICS], count: 0 } } }
static TABLE: Mutex<NicTable> = Mutex::new(NicTable::new());

pub fn register_nic(dev: NicDevice) {
    let mut t = TABLE.lock();
    if t.count < MAX_NICS {
        t.devs[t.count] = Some(dev); t.count += 1;
        crate::println!("nic: registered device {} MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            t.count - 1, dev.mac[0], dev.mac[1], dev.mac[2], dev.mac[3], dev.mac[4], dev.mac[5]);
    }
}

pub fn send_frame(frame: &[u8]) -> bool {
    let t = TABLE.lock();
    if let Some(Some(dev)) = t.devs.first() { (dev.send_frame)(frame) } else { false }
}

pub fn rx_poll_all() {
    let t = TABLE.lock();
    for slot in t.devs.iter().take(t.count) {
        if let Some(dev) = slot { (dev.rx_poll)(); }
    }
}

pub fn primary_mac() -> [u8; 6] {
    let t = TABLE.lock();
    t.devs.first().and_then(|s| s.as_ref()).map(|d| d.mac).unwrap_or([0u8; 6])
}

pub fn nic_count() -> usize { TABLE.lock().count }
