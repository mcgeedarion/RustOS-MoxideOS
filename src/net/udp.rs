//! UDP — User Datagram Protocol (RFC 768).

use crate::net::ip;
use crate::net::socket::{UDP_SOCKETS, SocketState, demux_udp};

pub const UDP_HDR_LEN: usize = 8;

/// Compute UDP pseudo-header checksum.
fn udp_checksum(src_ip: u32, dst_ip: u32, payload_and_hdr: &[u8]) -> u16 {
    let len = payload_and_hdr.len() as u32;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip.to_be_bytes());
    pseudo[4..8].copy_from_slice(&dst_ip.to_be_bytes());
    pseudo[8]  = 0;
    pseudo[9]  = ip::PROTO_UDP;
    pseudo[10] = ((len) >> 8) as u8;
    pseudo[11] = len as u8;

    let mut sum: u32 = 0;
    for chunk in pseudo.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for i in (0..payload_and_hdr.len()).step_by(2) {
        let a = payload_and_hdr[i];
        let b = if i + 1 < payload_and_hdr.len() { payload_and_hdr[i+1] } else { 0 };
        sum += u16::from_be_bytes([a, b]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Send a UDP datagram.
pub fn send(src_port: u16, dst_ip: u32, dst_port: u16, data: &[u8]) {
    let len = (UDP_HDR_LEN + data.len()) as u16;
    let mut hdr = [0u8; UDP_HDR_LEN];
    hdr[0] = (src_port >> 8) as u8;
    hdr[1] = src_port as u8;
    hdr[2] = (dst_port >> 8) as u8;
    hdr[3] = dst_port as u8;
    hdr[4] = (len >> 8) as u8;
    hdr[5] = len as u8;
    // checksum = 0 means "not computed" for IPv4 UDP
    hdr[6] = 0;
    hdr[7] = 0;

    let mut pkt = alloc::vec![0u8; UDP_HDR_LEN + data.len()];
    pkt[..UDP_HDR_LEN].copy_from_slice(&hdr);
    pkt[UDP_HDR_LEN..].copy_from_slice(data);

    // Compute checksum (optional but good practice)
    let csum = udp_checksum(ip::our_ip(), dst_ip, &pkt);
    if csum != 0 {
        pkt[6] = (csum >> 8) as u8;
        pkt[7] = csum as u8;
    }

    ip::send(dst_ip, ip::PROTO_UDP, &pkt);
}

/// Receive a UDP datagram from the IP layer.
pub fn receive(src_ip: u32, pkt: &[u8]) {
    if pkt.len() < UDP_HDR_LEN { return; }
    let src_port = u16::from_be_bytes([pkt[0], pkt[1]]);
    let dst_port = u16::from_be_bytes([pkt[2], pkt[3]]);
    let _len     = u16::from_be_bytes([pkt[4], pkt[5]]);
    let data     = &pkt[UDP_HDR_LEN..];

    demux_udp(src_ip, src_port, dst_port, data);
}
