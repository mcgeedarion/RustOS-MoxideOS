//! IPv4 — send, receive, fragment reassembly (RFC 791).

use crate::net::{arp, eth, icmp, tcp, udp};
use spin::Mutex;

extern crate alloc;

const ETHERTYPE_IP: u16 = 0x0800;
pub const IP_HDR_MIN: usize = 20;

// Protocol numbers
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

/// Our IPv4 address (host u32, network byte order semantics).
static OUR_IP: Mutex<u32> = Mutex::new(0x0A00_0202); // 10.0.2.2 (qemu user-mode default)
static GATEWAY_IP: Mutex<u32> = Mutex::new(0x0A00_0202);
static SUBNET_MASK: Mutex<u32> = Mutex::new(0xFFFF_FF00);

static ID_COUNTER: Mutex<u16> = Mutex::new(1);

pub fn our_ip() -> u32 {
    *OUR_IP.lock()
}
pub fn set_ip(ip: u32) {
    *OUR_IP.lock() = ip;
}
pub fn set_gw(gw: u32) {
    *GATEWAY_IP.lock() = gw;
}
pub fn set_mask(m: u32) {
    *SUBNET_MASK.lock() = m;
}

/// Alias for `our_ip()` — exposed under the name used by `fs/ioctl/net.rs`.
pub fn get_ip() -> u32 {
    our_ip()
}

/// Returns the MAC address of the first initialised NIC, or zeros if none.
pub fn get_mac() -> [u8; 6] {
    crate::drivers::net::nic::mac()
        .map(|m| m.0)
        .unwrap_or([0; 6])
}

fn next_id() -> u16 {
    let mut c = ID_COUNTER.lock();
    let id = *c;
    *c = c.wrapping_add(1);
    id
}

/// RFC 1071 Internet checksum.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build and send an IPv4 packet.
///
/// Routing:
///   - Same subnet → direct ARP to `dst_ip`
///   - Different subnet → ARP to the gateway
///
/// If the next-hop MAC is not yet in the ARP cache the packet is handed to
/// `arp::resolve_or_queue`, which buffers it and fires an ARP request.
/// The packet will be delivered automatically when the ARP reply arrives.
pub fn send(dst_ip: u32, proto: u8, payload: &[u8]) {
    let total_len = (IP_HDR_MIN + payload.len()) as u16;
    let id = next_id();

    let mut hdr = [0u8; IP_HDR_MIN];
    hdr[0] = 0x45; // version=4, IHL=5
    hdr[1] = 0; // DSCP/ECN
    hdr[2] = (total_len >> 8) as u8;
    hdr[3] = total_len as u8;
    hdr[4] = (id >> 8) as u8;
    hdr[5] = id as u8;
    hdr[6] = 0x40; // DF bit set, no fragmentation
    hdr[7] = 0;
    hdr[8] = 64; // TTL
    hdr[9] = proto;
    hdr[12..16].copy_from_slice(&our_ip().to_be_bytes());
    hdr[16..20].copy_from_slice(&dst_ip.to_be_bytes());

    let csum = checksum(&hdr);
    hdr[10] = (csum >> 8) as u8;
    hdr[11] = csum as u8;

    let mut pkt = alloc::vec![0u8; IP_HDR_MIN + payload.len()];
    pkt[..IP_HDR_MIN].copy_from_slice(&hdr);
    pkt[IP_HDR_MIN..].copy_from_slice(payload);

    // Route: same subnet → direct; otherwise → gateway.
    let mask = *SUBNET_MASK.lock();
    let next_hop = if dst_ip & mask == our_ip() & mask {
        dst_ip
    } else {
        *GATEWAY_IP.lock()
    };

    // Directed broadcast always goes straight out.
    if next_hop == 0xFFFF_FFFF {
        eth::send([0xFF; 6], ETHERTYPE_IP, &pkt);
        return;
    }

    // resolve_or_queue either sends immediately or buffers for ARP reply.
    arp::resolve_or_queue(next_hop, pkt);
}

/// Receive an IPv4 packet from the Ethernet layer.
pub fn receive(pkt: &[u8]) {
    if pkt.len() < IP_HDR_MIN {
        return;
    }
    let ihl = ((pkt[0] & 0x0F) * 4) as usize;
    if pkt.len() < ihl {
        return;
    }
    let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if pkt.len() < total {
        return;
    }

    if checksum(&pkt[..ihl]) != 0 {
        return;
    }

    let proto = pkt[9];
    let src_ip = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    let dst_ip = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
    let payload = &pkt[ihl..total];

    let our = our_ip();
    if dst_ip != our && dst_ip != 0xFFFF_FFFF && dst_ip != (our | !*SUBNET_MASK.lock()) {
        return;
    }

    match proto {
        PROTO_ICMP => icmp::receive(src_ip, dst_ip, payload),
        PROTO_TCP => tcp::receive(src_ip, payload),
        PROTO_UDP => udp::receive(src_ip, payload),
        _ => {},
    }
}
