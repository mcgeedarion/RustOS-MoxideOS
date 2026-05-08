//! Ethernet II framing and demultiplexing.

use crate::net::arp;
use crate::net::ip;
use spin::Mutex;

pub const ETH_HDR_LEN: usize = 14;
const ETHERTYPE_IP:  u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const BCAST_MAC: [u8; 6] = [0xFF; 6];

static OUR_MAC: Mutex<[u8; 6]> = Mutex::new([0u8; 6]);

/// Set our MAC address from the driver.
pub fn set_mac(mac: [u8; 6]) {
    *OUR_MAC.lock() = mac;
}

/// Return our MAC address.
pub fn our_mac() -> [u8; 6] {
    *OUR_MAC.lock()
}

/// Send an Ethernet frame to `dst_mac` with `ethertype` and `payload`.
pub fn send(dst_mac: [u8; 6], ethertype: u16, payload: &[u8]) {
    let mut frame = alloc::vec![0u8; ETH_HDR_LEN + payload.len()];
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&our_mac());
    frame[12] = (ethertype >> 8) as u8;
    frame[13] = ethertype as u8;
    frame[ETH_HDR_LEN..].copy_from_slice(payload);
    crate::drivers::nic::send_frame(&frame);
}

/// Called from any NIC driver on every received frame.
pub fn receive_frame(frame: &[u8]) {
    if frame.len() < ETH_HDR_LEN { return; }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let payload   = &frame[ETH_HDR_LEN..];
    let src_mac: [u8; 6] = frame[6..12].try_into().unwrap_or([0u8; 6]);
    match ethertype {
        ETHERTYPE_ARP => arp::receive(src_mac, payload),
        ETHERTYPE_IP  => ip::receive(payload),
        _             => {}
    }
}

/// Broadcast an Ethernet frame (ARP requests etc.).
pub fn send_broadcast(ethertype: u16, payload: &[u8]) {
    send(BCAST_MAC, ethertype, payload);
}
