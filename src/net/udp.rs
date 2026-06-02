//! UDP — User Datagram Protocol (RFC 768).
//!
//! ## Port registry
//!
//! Two kinds of port registrations are supported:
//!
//!   - `register_port(port, sock_idx)` — binds a user-space socket slot to a
//!     well-known or explicitly bound port.  Used by `sys_bind`.
//!
//!   - `register_ephemeral(port)` / `unregister_ephemeral(port)` — temporary
//!     registrations for kernel-internal UDP clients (DHCP on port 68, DNS
//!     query source ports).  Packets arriving on these ports are routed to the
//!     appropriate kernel module by `demux_udp`.
//!
//! The registry is a flat array of 64 entries.  Both kinds share the same
//! table; ephemeral entries store `sock_idx = EPHEMERAL_MARKER` so `demux_udp`
//! knows not to enqueue them in a user socket.

extern crate alloc;
use alloc::vec;

use crate::net::ip;
use crate::net::socket::{demux_udp};
use spin::Mutex;

pub const UDP_HDR_LEN: usize = 8;

/// Sentinel value stored in `sock_idx` for ephemeral (kernel-internal) ports.
const EPHEMERAL_MARKER: usize = usize::MAX;

#[derive(Clone, Copy, Default)]
struct PortEntry {
    port:     u16,
    sock_idx: usize,
    valid:    bool,
    ephemeral: bool,
}

const REGISTRY_SIZE: usize = 64;
static PORT_REGISTRY: Mutex<[PortEntry; REGISTRY_SIZE]> =
    Mutex::new([PortEntry { port: 0, sock_idx: 0, valid: false, ephemeral: false }; REGISTRY_SIZE]);

/// Register a user-space socket slot against a UDP port.
/// Called from `sys_bind` for `SOCK_DGRAM` sockets.
pub fn register_port(port: u16, sock_idx: usize) {
    let mut reg = PORT_REGISTRY.lock();
    // Update existing.
    for e in reg.iter_mut() {
        if e.valid && e.port == port {
            e.sock_idx  = sock_idx;
            e.ephemeral = false;
            return;
        }
    }
    // Find empty slot.
    if let Some(e) = reg.iter_mut().find(|e| !e.valid) {
        *e = PortEntry { port, sock_idx, valid: true, ephemeral: false };
    }
    // If the table is full, silently drop (64 concurrent UDP binds is
    // generous for an embedded kernel; add eviction later if needed).
}

/// Register an ephemeral (kernel-internal) source port.
/// Packets arriving on this port are handed to the appropriate kernel module
/// by `demux_udp`; they are never enqueued in a user socket.
pub fn register_ephemeral(port: u16) {
    let mut reg = PORT_REGISTRY.lock();
    for e in reg.iter_mut() {
        if e.valid && e.port == port { return; } // already registered
    }
    if let Some(e) = reg.iter_mut().find(|e| !e.valid) {
        *e = PortEntry {
            port,
            sock_idx:  EPHEMERAL_MARKER,
            valid:     true,
            ephemeral: true,
        };
    }
}

/// Unregister a previously registered ephemeral port.
pub fn unregister_ephemeral(port: u16) {
    let mut reg = PORT_REGISTRY.lock();
    for e in reg.iter_mut() {
        if e.valid && e.ephemeral && e.port == port {
            *e = PortEntry::default();
            return;
        }
    }
}

/// Look up the socket index bound to `port`, or `None` if unregistered.
/// Ephemeral ports return `None` (they are not user sockets).
pub fn lookup_port(port: u16) -> Option<usize> {
    let reg = PORT_REGISTRY.lock();
    reg.iter()
        .find(|e| e.valid && !e.ephemeral && e.port == port)
        .map(|e| e.sock_idx)
}

/// Returns `true` if `port` is registered as an ephemeral kernel port.
pub fn is_ephemeral(port: u16) -> bool {
    let reg = PORT_REGISTRY.lock();
    reg.iter().any(|e| e.valid && e.ephemeral && e.port == port)
}

fn udp_checksum(src_ip: u32, dst_ip: u32, payload_and_hdr: &[u8]) -> u16 {
    let len = payload_and_hdr.len() as u32;
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip.to_be_bytes());
    pseudo[4..8].copy_from_slice(&dst_ip.to_be_bytes());
    pseudo[8]  = 0;
    pseudo[9]  = ip::PROTO_UDP;
    pseudo[10] = (len >> 8) as u8;
    pseudo[11] = len as u8;

    let mut sum: u32 = 0;
    for chunk in pseudo.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for i in (0..payload_and_hdr.len()).step_by(2) {
        let a = payload_and_hdr[i];
        let b = if i + 1 < payload_and_hdr.len() { payload_and_hdr[i + 1] } else { 0 };
        sum += u16::from_be_bytes([a, b]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Send a UDP datagram.
/// `src_port` is the local source port (bound or ephemeral).
pub fn send(src_port: u16, dst_ip: u32, dst_port: u16, data: &[u8]) {
    let total_len = (UDP_HDR_LEN + data.len()) as u16;
    let mut pkt = vec![0u8; UDP_HDR_LEN + data.len()];
    pkt[0] = (src_port  >> 8) as u8;
    pkt[1] =  src_port        as u8;
    pkt[2] = (dst_port  >> 8) as u8;
    pkt[3] =  dst_port        as u8;
    pkt[4] = (total_len >> 8) as u8;
    pkt[5] =  total_len       as u8;
    pkt[6] = 0; // checksum placeholder
    pkt[7] = 0;
    pkt[UDP_HDR_LEN..].copy_from_slice(data);

    let csum = udp_checksum(ip::our_ip(), dst_ip, &pkt);
    if csum != 0 {
        pkt[6] = (csum >> 8) as u8;
        pkt[7] =  csum       as u8;
    }

    ip::send(dst_ip, ip::PROTO_UDP, &pkt);
}

/// Receive a UDP datagram from the IP layer and route it via `demux_udp`.
pub fn receive(src_ip: u32, pkt: &[u8]) {
    if pkt.len() < UDP_HDR_LEN { return; }
    let src_port = u16::from_be_bytes([pkt[0], pkt[1]]);
    let dst_port = u16::from_be_bytes([pkt[2], pkt[3]]);
    let data     = &pkt[UDP_HDR_LEN..];
    demux_udp(src_ip, src_port, dst_port, data);
}
