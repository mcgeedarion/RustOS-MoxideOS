//! DHCP client — RFC 2131 DISCOVER → OFFER → REQUEST → ACK.
//!
//! ## Design
//!
//! * Sends/receives raw UDP on ports 68 (client) / 67 (server) via the
//!   kernel UDP layer.  Before a lease is obtained `our_ip()` returns 0.0.0.0
//!   so we set the IP source to 0 and destination to the broadcast address
//!   (255.255.255.255), which is RFC-correct for the initial exchange.
//!
//! * A minimal fixed-format BOOTP/DHCP packet is used (no PRL, no hostname).
//!   The only options emitted are:
//!     - 53 (DHCP Message Type)
//!     - 54 (Server Identifier)  — only in REQUEST
//!     - 55 (Parameter Request List) — requests subnet mask, router, DNS
//!     - 255 (End)
//!
//! * After a successful ACK the leased addresses are pushed into `ip::set_ip`,
//!   `ip::set_gw`, `ip::set_mask`.  A background renewal task is not yet
//!   implemented; `init()` re-runs the full handshake if called again.
//!
//! * The receive path hooks into `net::socket::demux_udp`, which calls
//!   `dhcp::receive` when a packet arrives on port 68.
//!
//! ## Thread safety
//!
//! All mutable state is behind a `spin::Mutex`.  `init()` busy-waits (with
//! `scheduler::yield_now`) for the server reply; it must not be called from
//! interrupt context.

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::net::{ip, udp};

pub const DHCP_CLIENT_PORT: u16 = 68;
pub const DHCP_SERVER_PORT: u16 = 67;

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER:    u8 = 2;
const DHCP_REQUEST:  u8 = 3;
const DHCP_ACK:      u8 = 5;

const OPT_SUBNET:   u8 = 1;
const OPT_ROUTER:   u8 = 3;
const OPT_DNS:      u8 = 6;
const OPT_LEASE:    u8 = 51;
const OPT_MSGTYPE:  u8 = 53;
const OPT_SERVERID: u8 = 54;
const OPT_PRL:      u8 = 55;
const OPT_END:      u8 = 255;

const MAGIC: [u8; 4] = [99, 130, 83, 99];

//   op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
//   ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128)
//   magic(4)  → 240 bytes total

const BOOTP_HDR_LEN: usize = 240;

#[derive(Clone, Copy, Default)]
pub struct Lease {
    pub ip:      u32,
    pub gateway: u32,
    pub mask:    u32,
    pub dns:     u32,
    pub server:  u32,   // server identifier
    pub lease_s: u32,   // lease time in seconds
}

static LEASE: Mutex<Option<Lease>> = Mutex::new(None);

/// Inbound OFFER/ACK packet storage — set by `receive()`, read by `init()`.
static PENDING: Mutex<Option<InboundMsg>> = Mutex::new(None);

#[derive(Clone)]
struct InboundMsg {
    msg_type: u8,
    your_ip:  u32,
    server:   u32,
    mask:     u32,
    gateway:  u32,
    dns:      u32,
    lease_s:  u32,
    xid:      u32,
}

/// Returns the currently leased IP, or 0 if no lease is held.
pub fn leased_ip() -> u32 {
    LEASE.lock().map(|l| l.ip).unwrap_or(0)
}

/// Returns the gateway from the current lease, or 0.
pub fn leased_gateway() -> u32 {
    LEASE.lock().map(|l| l.gateway).unwrap_or(0)
}

/// Returns the subnet mask from the current lease, or 0xFFFFFF00.
pub fn leased_mask() -> u32 {
    LEASE.lock().map(|l| l.mask).unwrap_or(0xFFFF_FF00)
}

/// Build a DHCP packet.
///
/// `xid`       — transaction ID (random-ish, caller supplies)
/// `msg_type`  — DHCP_DISCOVER or DHCP_REQUEST
/// `server_id` — Some(ip) for REQUEST, None for DISCOVER
/// `requested` — Some(ip) for REQUEST, None for DISCOVER
fn build_packet(xid: u32, msg_type: u8,
                server_id: Option<u32>,
                requested: Option<u32>) -> Vec<u8> {
    let our_mac = crate::net::eth::our_mac();

    let mut pkt = alloc::vec![0u8; BOOTP_HDR_LEN];

    // op=1 (BOOTREQUEST), htype=1 (Ethernet), hlen=6, hops=0
    pkt[0] = 1; pkt[1] = 1; pkt[2] = 6; pkt[3] = 0;
    // xid
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());
    // secs=0, flags=0x8000 (broadcast bit)
    pkt[10] = 0x80; pkt[11] = 0x00;
    // ciaddr = 0 (we don't have one yet)
    // yiaddr, siaddr, giaddr = 0
    // chaddr — first 6 bytes = our MAC, rest = 0
    pkt[28..34].copy_from_slice(&our_mac);
    // magic cookie
    pkt[236..240].copy_from_slice(&MAGIC);

    // Options
    let mut opts: Vec<u8> = Vec::with_capacity(32);

    // Option 53: DHCP Message Type
    opts.extend_from_slice(&[OPT_MSGTYPE, 1, msg_type]);

    if let Some(sid) = server_id {
        // Option 54: Server Identifier
        opts.push(OPT_SERVERID); opts.push(4);
        opts.extend_from_slice(&sid.to_be_bytes());
    }

    if let Some(req) = requested {
        // Option 50: Requested IP Address
        opts.push(50); opts.push(4);
        opts.extend_from_slice(&req.to_be_bytes());
    }

    // Option 55: Parameter Request List (subnet, router, DNS)
    opts.extend_from_slice(&[OPT_PRL, 3, OPT_SUBNET, OPT_ROUTER, OPT_DNS]);

    // End
    opts.push(OPT_END);

    pkt.extend_from_slice(&opts);
    pkt
}

fn send_dhcp(pkt: &[u8]) {
    // Source IP 0.0.0.0, destination 255.255.255.255 (broadcast).
    // The IP layer normally routes via ARP; bypass that by temporarily
    // setting our IP to 0 and using the broadcast address.
    // `udp::send` calls `ip::send` which calls `arp::resolve`.  For the
    // broadcast address (0xFFFF_FFFF), eth::send should use FF:FF:FF:FF:FF:FF.
    // We force source to 0.0.0.0 via a temp override.
    let saved_ip = ip::our_ip();
    if saved_ip == 0 {
        ip::set_ip(0); // already 0 — fine
    }
    udp::send(DHCP_CLIENT_PORT, 0xFFFF_FFFF, DHCP_SERVER_PORT, pkt);
    // Restore in case we ran this after a partial lease.
    if saved_ip != 0 {
        ip::set_ip(saved_ip);
    }
}

/// Run the full DORA handshake.  Blocks until a lease is obtained or the
/// retry limit (8 attempts, ~4 s) is exhausted.  Updates the IP layer on
/// success.
pub fn init() {
    // Use a simple XID based on a counter + timer tick to avoid collisions
    // across reboots on the same network.
    let xid: u32 = 0xC0DE_0001u32.wrapping_add(
        crate::time::monotonic_ms() as u32
    );

    for attempt in 0..8u32 {
        *PENDING.lock() = None;
        let disc = build_packet(xid.wrapping_add(attempt), DHCP_DISCOVER,
                                None, None);
        send_dhcp(&disc);

        // Wait up to ~500 ms for an OFFER.
        let offer = wait_for(DHCP_OFFER, xid.wrapping_add(attempt), 500);
        let offer = match offer {
            Some(o) => o,
            None    => { continue; }
        };

        *PENDING.lock() = None;
        let req = build_packet(xid.wrapping_add(attempt), DHCP_REQUEST,
                               Some(offer.server),
                               Some(offer.your_ip));
        send_dhcp(&req);

        // Wait up to ~500 ms for an ACK.
        let ack = wait_for(DHCP_ACK, xid.wrapping_add(attempt), 500);
        if let Some(ack) = ack {
            // Commit the lease.
            let lease = Lease {
                ip:      ack.your_ip,
                gateway: ack.gateway,
                mask:    ack.mask,
                dns:     ack.dns,
                server:  ack.server,
                lease_s: ack.lease_s,
            };
            *LEASE.lock() = Some(lease);

            // Push into the IP layer.
            ip::set_ip(lease.ip);
            if lease.gateway != 0 { ip::set_gw(lease.gateway); }
            if lease.mask    != 0 { ip::set_mask(lease.mask);  }

            return;
        }
    }

    // All attempts exhausted — use a link-local fallback (RFC 3927).
    let fallback = 0xA9FE_0001u32; // 169.254.0.1
    ip::set_ip(fallback);
}

/// Busy-wait up to `timeout_ms` for a DHCP message of `expected_type` with
/// the given `xid`.  Returns the parsed message or None on timeout.
fn wait_for(expected_type: u8, xid: u32, timeout_ms: u64) -> Option<InboundMsg> {
    let deadline = crate::time::monotonic_ms() + timeout_ms;
    loop {
        {
            let pending = PENDING.lock();
            if let Some(ref msg) = *pending {
                if msg.msg_type == expected_type && msg.xid == xid {
                    return Some(msg.clone());
                }
            }
        }
        if crate::time::monotonic_ms() >= deadline {
            return None;
        }
        crate::proc::scheduler::yield_now();
    }
}

/// Called by the UDP demux when a packet arrives on port 68 (DHCP client).
pub fn receive(src_ip: u32, data: &[u8]) {
    let _ = src_ip; // we use siaddr / option 54 instead
    if data.len() < BOOTP_HDR_LEN { return; }

    // Verify magic cookie.
    if data[236..240] != MAGIC { return; }

    // op must be 2 (BOOTREPLY).
    if data[0] != 2 { return; }

    let xid     = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let your_ip = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

    // Parse options.
    let mut msg_type: u8 = 0;
    let mut server:   u32 = src_ip;
    let mut mask:     u32 = 0xFFFF_FF00;
    let mut gateway:  u32 = 0;
    let mut dns:      u32 = 0;
    let mut lease_s:  u32 = 86400; // default 24 h

    let opts = &data[BOOTP_HDR_LEN..];
    let mut i = 0;
    while i < opts.len() {
        let tag = opts[i]; i += 1;
        if tag == OPT_END { break; }
        if tag == 0 { continue; } // PAD
        if i >= opts.len() { break; }
        let len = opts[i] as usize; i += 1;
        if i + len > opts.len() { break; }
        let val = &opts[i..i + len];
        match tag {
            OPT_MSGTYPE  if len >= 1 => msg_type = val[0],
            OPT_SERVERID if len >= 4 => server   = u32::from_be_bytes([val[0],val[1],val[2],val[3]]),
            OPT_SUBNET   if len >= 4 => mask     = u32::from_be_bytes([val[0],val[1],val[2],val[3]]),
            OPT_ROUTER   if len >= 4 => gateway  = u32::from_be_bytes([val[0],val[1],val[2],val[3]]),
            OPT_DNS      if len >= 4 => dns      = u32::from_be_bytes([val[0],val[1],val[2],val[3]]),
            OPT_LEASE    if len >= 4 => lease_s  = u32::from_be_bytes([val[0],val[1],val[2],val[3]]),
            _ => {}
        }
        i += len;
    }

    if msg_type == 0 { return; }

    *PENDING.lock() = Some(InboundMsg {
        msg_type, your_ip, server, mask, gateway, dns, lease_s, xid,
    });
}
