//! ARP — IPv4 over Ethernet (RFC 826).
//!
//! Maintains a static ARP cache and sends/replies to ARP requests.

use crate::net::eth;
use spin::Mutex;

const ETHERTYPE_ARP: u16 = 0x0806;
const HW_ETHER:      u16 = 0x0001;
const PROTO_IP:      u16 = 0x0800;
const OP_REQUEST:    u16 = 0x0001;
const OP_REPLY:      u16 = 0x0002;

/// ARP cache entry.
#[derive(Clone, Copy, Default)]
pub struct ArpEntry {
    pub ip:  u32,
    pub mac: [u8; 6],
    pub valid: bool,
}

const CACHE_SIZE: usize = 64;
static CACHE: Mutex<[ArpEntry; CACHE_SIZE]> = Mutex::new([ArpEntry { ip: 0, mac: [0; 6], valid: false }; CACHE_SIZE]);

/// Look up IP → MAC in the ARP cache.
pub fn lookup(ip: u32) -> Option<[u8; 6]> {
    CACHE.lock().iter()
        .find(|e| e.valid && e.ip == ip)
        .map(|e| e.mac)
}

/// Insert or update an ARP cache entry.
pub fn insert(ip: u32, mac: [u8; 6]) {
    let mut cache = CACHE.lock();
    // Update existing
    if let Some(e) = cache.iter_mut().find(|e| e.valid && e.ip == ip) {
        e.mac = mac;
        return;
    }
    // Find empty slot
    if let Some(e) = cache.iter_mut().find(|e| !e.valid) {
        *e = ArpEntry { ip, mac, valid: true };
    }
    // TODO: evict LRU when full
}

/// Build and send an ARP request for `target_ip`.
pub fn send_request(target_ip: u32) {
    let our_mac = eth::our_mac();
    let our_ip  = crate::net::ip::our_ip();
    let mut pkt = [0u8; 28];
    pkt[0..2].copy_from_slice(&HW_ETHER.to_be_bytes());
    pkt[2..4].copy_from_slice(&PROTO_IP.to_be_bytes());
    pkt[4] = 6; // hw addr len
    pkt[5] = 4; // proto addr len
    pkt[6..8].copy_from_slice(&OP_REQUEST.to_be_bytes());
    pkt[8..14].copy_from_slice(&our_mac);
    pkt[14..18].copy_from_slice(&our_ip.to_be_bytes());
    // target hw = 00:00:…
    pkt[24..28].copy_from_slice(&target_ip.to_be_bytes());
    eth::send_broadcast(ETHERTYPE_ARP, &pkt);
}

/// Handle an incoming ARP packet.
pub fn receive(src_mac: [u8; 6], pkt: &[u8]) {
    if pkt.len() < 28 { return; }
    let op       = u16::from_be_bytes([pkt[6], pkt[7]]);
    let sender_mac: [u8; 6] = pkt[8..14].try_into().unwrap();
    let sender_ip = u32::from_be_bytes([pkt[14], pkt[15], pkt[16], pkt[17]]);
    let target_ip = u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]);

    // Always cache the sender.
    insert(sender_ip, sender_mac);

    if op == OP_REQUEST && target_ip == crate::net::ip::our_ip() {
        // Send ARP reply.
        let our_mac = eth::our_mac();
        let our_ip  = crate::net::ip::our_ip();
        let mut reply = [0u8; 28];
        reply[0..2].copy_from_slice(&HW_ETHER.to_be_bytes());
        reply[2..4].copy_from_slice(&PROTO_IP.to_be_bytes());
        reply[4] = 6;
        reply[5] = 4;
        reply[6..8].copy_from_slice(&OP_REPLY.to_be_bytes());
        reply[8..14].copy_from_slice(&our_mac);
        reply[14..18].copy_from_slice(&our_ip.to_be_bytes());
        reply[18..24].copy_from_slice(&sender_mac);
        reply[24..28].copy_from_slice(&sender_ip.to_be_bytes());
        eth::send(sender_mac, ETHERTYPE_ARP, &reply);
    }
}

/// Resolve an IP address to MAC, potentially sending an ARP request.
/// Returns None if not yet in cache (caller should retry later).
pub fn resolve(ip: u32) -> Option<[u8; 6]> {
    // Directed broadcast / subnet broadcast → Ethernet broadcast
    if ip == 0xFFFFFFFF { return Some([0xFF; 6]); }
    match lookup(ip) {
        Some(mac) => Some(mac),
        None => {
            send_request(ip);
            None
        }
    }
}
