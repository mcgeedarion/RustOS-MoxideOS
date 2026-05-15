//! ICMP — echo request/reply + destination unreachable (RFC 792).

use crate::net::ip;

const TYPE_ECHO_REPLY: u8 = 0;
const TYPE_UNREACHABLE: u8 = 3;
const TYPE_ECHO_REQUEST: u8 = 8;

/// Handle an incoming ICMP packet.
pub fn receive(src_ip: u32, _dst_ip: u32, pkt: &[u8]) {
    if pkt.len() < 8 {
        return;
    }
    if ip::checksum(pkt) != 0 {
        return;
    } // bad checksum
    let typ = pkt[0];
    match typ {
        TYPE_ECHO_REQUEST => echo_reply(src_ip, pkt),
        _ => {}
    }
}

/// Send an ICMP echo reply in response to an echo request.
fn echo_reply(dst: u32, req: &[u8]) {
    let mut reply = alloc::vec![0u8; req.len()];
    reply.copy_from_slice(req);
    reply[0] = TYPE_ECHO_REPLY;
    reply[1] = 0; // code
    reply[2] = 0; // checksum (recompute)
    reply[3] = 0;
    let csum = ip::checksum(&reply);
    reply[2] = (csum >> 8) as u8;
    reply[3] = csum as u8;
    ip::send(dst, ip::PROTO_ICMP, &reply);
}

/// Send ICMP Port Unreachable for a UDP datagram.
pub fn port_unreachable(dst_ip: u32, original_ip_hdr: &[u8], original_udp: &[u8]) {
    // type=3, code=3, unused 4 bytes, then original IP header + first 8 bytes UDP
    let body_len = original_ip_hdr.len().min(28) + 8;
    let mut pkt = alloc::vec![0u8; 8 + body_len];
    pkt[0] = TYPE_UNREACHABLE;
    pkt[1] = 3; // port unreachable code
    let copy_len = (original_ip_hdr.len() + original_udp.len().min(8)).min(body_len);
    pkt[8..8 + copy_len].copy_from_slice(&original_ip_hdr[..original_ip_hdr.len().min(copy_len)]);
    let csum = ip::checksum(&pkt);
    pkt[2] = (csum >> 8) as u8;
    pkt[3] = csum as u8;
    ip::send(dst_ip, ip::PROTO_ICMP, &pkt);
}
