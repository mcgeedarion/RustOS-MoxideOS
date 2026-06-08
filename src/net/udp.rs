//! UDP — User Datagram Protocol (RFC 768).
//!
//! ## Port registry
//!
//! Two kinds of port registrations are supported:
//!
//!   - `register_port(port, sock_idx)` — binds a user-space socket slot to a
//!     well-known or explicitly bound port. Used by `sys_bind` and `UdpScheme`.
//!
//!   - `register_ephemeral(port)` / `unregister_ephemeral(port)` — temporary
//!     registrations for kernel-internal UDP clients (DHCP on port 68, DNS
//!     query source ports). Packets arriving on these ports are routed to the
//!     appropriate kernel module by `demux_udp`.

extern crate alloc;
use alloc::vec;

use crate::net::ip;
use crate::net::socket::demux_udp;
use spin::Mutex;

pub const UDP_HDR_LEN: usize = 8;

/// Sentinel value stored in `sock_idx` for ephemeral (kernel-internal) ports.
const EPHEMERAL_MARKER: usize = usize::MAX;

#[derive(Clone, Copy, Default)]
struct PortEntry {
    port: u16,
    sock_idx: usize,
    valid: bool,
    ephemeral: bool,
}

const REGISTRY_SIZE: usize = 64;
static PORT_REGISTRY: Mutex<[PortEntry; REGISTRY_SIZE]> = Mutex::new(
    [PortEntry {
        port: 0,
        sock_idx: 0,
        valid: false,
        ephemeral: false,
    }; REGISTRY_SIZE],
);

/// Register a user-space socket slot against a UDP port.
pub fn register_port(port: u16, sock_idx: usize) {
    let mut reg = PORT_REGISTRY.lock();

    for e in reg.iter_mut() {
        if e.valid && e.port == port {
            e.sock_idx = sock_idx;
            e.ephemeral = false;
            return;
        }
    }

    if let Some(e) = reg.iter_mut().find(|e| !e.valid) {
        *e = PortEntry {
            port,
            sock_idx,
            valid: true,
            ephemeral: false,
        };
    }
}

/// Unregister a user-space socket port.
pub fn unregister_port(port: u16) {
    let mut reg = PORT_REGISTRY.lock();

    for e in reg.iter_mut() {
        if e.valid && !e.ephemeral && e.port == port {
            *e = PortEntry::default();
            return;
        }
    }
}

/// Register an ephemeral kernel-internal source port.
pub fn register_ephemeral(port: u16) {
    let mut reg = PORT_REGISTRY.lock();

    for e in reg.iter_mut() {
        if e.valid && e.port == port {
            return;
        }
    }

    if let Some(e) = reg.iter_mut().find(|e| !e.valid) {
        *e = PortEntry {
            port,
            sock_idx: EPHEMERAL_MARKER,
            valid: true,
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
/// Ephemeral ports return `None` because they are not user sockets.
pub fn lookup_port(port: u16) -> Option<usize> {
    let reg = PORT_REGISTRY.lock();

    reg.iter()
        .find(|e| e.valid && !e.ephemeral && e.port == port)
        .map(|e| e.sock_idx)
}

/// Returns `true` if `port` is registered as an ephemeral kernel port.
pub fn is_ephemeral(port: u16) -> bool {
    let reg = PORT_REGISTRY.lock();

    reg.iter()
        .any(|e| e.valid && e.ephemeral && e.port == port)
}

fn udp_checksum(src_ip: u32, dst_ip: u32, payload_and_hdr: &[u8]) -> u16 {
    let len = payload_and_hdr.len() as u32;

    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src_ip.to_be_bytes());
    pseudo[4..8].copy_from_slice(&dst_ip.to_be_bytes());
    pseudo[8] = 0;
    pseudo[9] = ip::PROTO_UDP;
    pseudo[10] = (len >> 8) as u8;
    pseudo[11] = len as u8;

    let mut sum: u32 = 0;

    for chunk in pseudo.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }

    for i in (0..payload_and_hdr.len()).step_by(2) {
        let a = payload_and_hdr[i];
        let b = if i + 1 < payload_and_hdr.len() {
            payload_and_hdr[i + 1]
        } else {
            0
        };

        sum += u16::from_be_bytes([a, b]) as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Send a UDP datagram.
/// `src_port` is the local source port.
pub fn send(src_port: u16, dst_ip: u32, dst_port: u16, data: &[u8]) {
    let total_len = (UDP_HDR_LEN + data.len()) as u16;
    let mut pkt = vec![0u8; UDP_HDR_LEN + data.len()];

    pkt[0] = (src_port >> 8) as u8;
    pkt[1] = src_port as u8;
    pkt[2] = (dst_port >> 8) as u8;
    pkt[3] = dst_port as u8;
    pkt[4] = (total_len >> 8) as u8;
    pkt[5] = total_len as u8;
    pkt[6] = 0;
    pkt[7] = 0;
    pkt[UDP_HDR_LEN..].copy_from_slice(data);

    // RFC 768: a computed checksum of zero is transmitted as all ones.
    // A transmitted zero means "checksum disabled".
    let mut csum = udp_checksum(ip::our_ip(), dst_ip, &pkt);
    if csum == 0 {
        csum = 0xFFFF;
    }

    pkt[6] = (csum >> 8) as u8;
    pkt[7] = csum as u8;

    ip::send(dst_ip, ip::PROTO_UDP, &pkt);
}

/// Receive a UDP datagram from the IP layer and route it via `demux_udp`.
pub fn receive(src_ip: u32, pkt: &[u8]) {
    if pkt.len() < UDP_HDR_LEN {
        return;
    }

    let src_port = u16::from_be_bytes([pkt[0], pkt[1]]);
    let dst_port = u16::from_be_bytes([pkt[2], pkt[3]]);
    let data = &pkt[UDP_HDR_LEN..];

    demux_udp(src_ip, src_port, dst_port, data);
}

fn parse_ipv4(s: &str) -> Result<u32, scheme_api::SchemeError> {
    let mut out = 0u32;
    let mut count = 0usize;

    for part in s.split('.') {
        if count >= 4 || part.is_empty() {
            return Err(scheme_api::SchemeError::InvalidArg);
        }

        let octet: u8 = part
            .parse()
            .map_err(|_| scheme_api::SchemeError::InvalidArg)?;
        out = (out << 8) | octet as u32;
        count += 1;
    }

    if count != 4 {
        return Err(scheme_api::SchemeError::InvalidArg);
    }

    Ok(out)
}

fn parse_port(s: &str) -> Result<u16, scheme_api::SchemeError> {
    let port: u16 = s.parse().map_err(|_| scheme_api::SchemeError::InvalidArg)?;

    if port == 0 {
        return Err(scheme_api::SchemeError::InvalidArg);
    }

    Ok(port)
}

fn errno_to_scheme_error(errno: isize) -> scheme_api::SchemeError {
    match errno {
        -11 => scheme_api::SchemeError::WouldBlock,
        -22 => scheme_api::SchemeError::InvalidArg,
        -9 => scheme_api::SchemeError::InvalidArg,
        _ => scheme_api::SchemeError::Io,
    }
}

fn alloc_udp_socket(
    local_port: Option<u16>,
    peer: Option<(u32, u16)>,
) -> Result<usize, scheme_api::SchemeError> {
    use crate::net::socket::{
        SockAddr, SocketState, AF_INET, IPPROTO_UDP, SOCKETS, SOCK_DGRAM,
    };

    let mut sockets = SOCKETS.lock();

    let Some(idx) = sockets.iter().position(|s| s.is_none()) else {
        return Err(scheme_api::SchemeError::Other);
    };

    let mut sock = crate::net::socket::core::new_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if let Some(port) = local_port {
        sock.local = Some(SockAddr::V4 {
            ip: crate::net::ip::our_ip(),
            port,
        });
        sock.state = SocketState::Bound;
        register_port(port, idx);
    }

    if let Some((ip, port)) = peer {
        sock.peer = Some(SockAddr::V4 { ip, port });

        if sock.local.is_none() {
            let local = crate::net::socket::next_ephemeral();

            sock.local = Some(SockAddr::V4 {
                ip: crate::net::ip::our_ip(),
                port: local,
            });

            register_port(local, idx);
        }

        sock.state = SocketState::Connected;
    }

    sockets[idx] = Some(sock);
    Ok(idx)
}

/// Scheme adapter for `udp:` URLs.
///
/// Supported paths:
/// - `bind/<local-port>`
/// - `connect/<dst-ip>/<dst-port>`
/// - `connect/<dst-ip>/<dst-port>/<src-port>`
/// - `<dst-ip>:<dst-port>`
/// - `<dst-ip>:<dst-port>:<src-port>`
pub struct UdpScheme;

impl UdpScheme {
    pub const fn new() -> Self {
        Self
    }
}

impl crate::fs::scheme_table::Scheme for UdpScheme {
    fn open(
        &self,
        path: &str,
        _flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        let path = path.trim_matches('/');

        if let Some(rest) = path.strip_prefix("bind/") {
            let local_port = parse_port(rest)?;
            let idx = alloc_udp_socket(Some(local_port), None)?;
            return Ok(scheme_api::SchemeFileId(idx as u64));
        }

        let target = path.strip_prefix("connect/").unwrap_or(path);

        let mut slash_parts = target.split('/');
        let first = slash_parts
            .next()
            .ok_or(scheme_api::SchemeError::InvalidArg)?;

        let (dst_ip, dst_port, src_port) = if let Some(second) = slash_parts.next() {
            let dst_ip = parse_ipv4(first)?;
            let dst_port = parse_port(second)?;
            let src_port = match slash_parts.next() {
                Some(src) => Some(parse_port(src)?),
                None => None,
            };

            if slash_parts.next().is_some() {
                return Err(scheme_api::SchemeError::InvalidArg);
            }

            (dst_ip, dst_port, src_port)
        } else {
            let mut parts = target.rsplitn(3, ':');

            let maybe_src_or_dst = parts
                .next()
                .ok_or(scheme_api::SchemeError::InvalidArg)?;
            let maybe_dst = parts
                .next()
                .ok_or(scheme_api::SchemeError::InvalidArg)?;
            let maybe_ip = parts.next();

            match maybe_ip {
                Some(ip) => (
                    parse_ipv4(ip)?,
                    parse_port(maybe_dst)?,
                    Some(parse_port(maybe_src_or_dst)?),
                ),
                None => (
                    parse_ipv4(maybe_dst)?,
                    parse_port(maybe_src_or_dst)?,
                    None,
                ),
            }
        };

        let idx = alloc_udp_socket(src_port, Some((dst_ip, dst_port)))?;
        Ok(scheme_api::SchemeFileId(idx as u64))
    }

    fn read(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &mut [u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let n = crate::net::socket::socket_read(fid.0 as usize, buf, 0);

        if n < 0 {
            return Err(errno_to_scheme_error(n));
        }

        Ok(n as usize)
    }

    fn write(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &[u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        use crate::net::socket::{SockAddr, SOCKETS};

        let (src_port, dst_ip, dst_port) = {
            let sockets = SOCKETS.lock();

            let Some(Some(sock)) = sockets.get(fid.0 as usize) else {
                return Err(scheme_api::SchemeError::InvalidArg);
            };

            let src_port = match sock.local {
                Some(SockAddr::V4 { port, .. }) => port,
                _ => return Err(scheme_api::SchemeError::InvalidArg),
            };

            let (dst_ip, dst_port) = match sock.peer {
                Some(SockAddr::V4 { ip, port }) => (ip, port),
                _ => return Err(scheme_api::SchemeError::InvalidArg),
            };

            (src_port, dst_ip, dst_port)
        };

        send(src_port, dst_ip, dst_port, buf);
        Ok(buf.len())
    }

    fn close(&self, fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        use crate::net::socket::{SockAddr, SOCKETS};

        let mut sockets = SOCKETS.lock();

        if let Some(slot) = sockets.get_mut(fid.0 as usize) {
            if let Some(sock) = slot.take() {
                if let Some(SockAddr::V4 { port, .. }) = sock.local {
                    unregister_port(port);
                }
            }

            return Ok(());
        }

        Err(scheme_api::SchemeError::InvalidArg)
    }
}