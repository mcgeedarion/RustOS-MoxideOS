//! Ethernet II framing and demultiplexing.
//!
//! ## MAC address type
//!
//! `MacAddr` is defined here (absorbed from the old `ethernet.rs` stub) so
//! any module that needs a typed MAC can `use crate::net::eth::MacAddr` rather
//! than reaching into the now-deleted `ethernet` module.

extern crate alloc;

use crate::net::{arp, ip};
use spin::Mutex;

pub const ETH_HDR_LEN: usize = 14;
const ETHERTYPE_IP:  u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const BCAST_MAC: [u8; 6] = [0xFF; 6];

/// A 6-byte IEEE 802.3 MAC address.
///
/// The raw `[u8; 6]` form is used throughout the network stack for zero-copy
/// efficiency; `MacAddr` is provided for cases where a typed wrapper improves
/// readability (e.g. driver initialisation, ARP table display).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const ZERO:      Self = MacAddr([0x00; 6]);
    pub const BROADCAST: Self = MacAddr([0xFF; 6]);

    /// Construct from a raw byte array.
    #[inline]
    pub const fn from_bytes(b: [u8; 6]) -> Self { MacAddr(b) }

    /// Return the inner byte array.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 6] { &self.0 }

    /// True for the all-ones broadcast address.
    #[inline]
    pub fn is_broadcast(&self) -> bool { self.0 == [0xFF; 6] }

    /// True for addresses with the multicast bit set (bit 0 of first octet).
    #[inline]
    pub fn is_multicast(&self) -> bool { self.0[0] & 0x01 != 0 }
}

impl From<[u8; 6]> for MacAddr {
    fn from(b: [u8; 6]) -> Self { MacAddr(b) }
}

impl From<MacAddr> for [u8; 6] {
    fn from(m: MacAddr) -> Self { m.0 }
}

impl core::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = &self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

static OUR_MAC: Mutex<[u8; 6]> = Mutex::new([0u8; 6]);

/// Set our MAC address (called once by the NIC driver at init time).
pub fn set_mac(mac: [u8; 6]) {
    *OUR_MAC.lock() = mac;
}

/// Return our MAC address as a raw byte array.
pub fn our_mac() -> [u8; 6] {
    *OUR_MAC.lock()
}

/// Return our MAC address as a `MacAddr`.
pub fn our_mac_addr() -> MacAddr {
    MacAddr(*OUR_MAC.lock())
}

/// Send an Ethernet II frame to `dst_mac` carrying `payload` with `ethertype`.
pub fn send(dst_mac: [u8; 6], ethertype: u16, payload: &[u8]) {
    let mut frame = alloc::vec![0u8; ETH_HDR_LEN + payload.len()];
    frame[0..6].copy_from_slice(&dst_mac);
    frame[6..12].copy_from_slice(&our_mac());
    frame[12] = (ethertype >> 8) as u8;
    frame[13] =  ethertype       as u8;
    frame[ETH_HDR_LEN..].copy_from_slice(payload);
    crate::drivers::nic::send_frame(&frame);
}

/// Broadcast an Ethernet frame (used for ARP requests, DHCP discovers, etc.).
pub fn send_broadcast(ethertype: u16, payload: &[u8]) {
    send(BCAST_MAC, ethertype, payload);
}

/// Entry point called by every NIC driver on each received frame.
///
/// Frames not addressed to us and not broadcast/multicast are silently dropped
/// (promiscuous filtering is the driver's responsibility if needed).
pub fn receive_frame(frame: &[u8]) {
    if frame.len() < ETH_HDR_LEN { return; }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let src_mac: [u8; 6] = frame[6..12].try_into().unwrap_or([0u8; 6]);
    let payload   = &frame[ETH_HDR_LEN..];
    match ethertype {
        ETHERTYPE_ARP => arp::receive(src_mac, payload),
        ETHERTYPE_IP  => ip::receive(payload),
        _             => {}
    }
}
