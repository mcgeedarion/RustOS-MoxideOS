//! ICMPv6 (RFC 4443) + NDP (RFC 4861).
//!
//! ## Implemented message types
//!
//!   1   Destination Unreachable
//!   128 Echo Request  → send Echo Reply (129)
//!   129 Echo Reply    (received, no-op for now)
//!   133 Router Solicitation     (sent on link-up)
//!   134 Router Advertisement    (parsed: default GW + PIO)
//!   135 Neighbor Solicitation   (received → send NA; sent for NDP resolution)
//!   136 Neighbor Advertisement  (received → update NDP cache)
//!   137 Redirect                (received → update NDP next-hop)
//!
//! ## NDP neighbor cache
//!
//!   `ndp_resolve(addr)` — look up a link-layer address from the cache.
//!   `ndp_learn(addr, mac)` — insert / update a cache entry.
//!   `send_neighbor_solicitation(src, tgt)` — send NS triggering cache fill.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

use crate::net::eth;
use crate::net::ipv6::{self, Addr6, ALL_NODES_LL, ALL_ROUTERS_LL, NH_ICMPV6, UNSPECIFIED6};

// ─── ICMPv6 type codes ────────────────────────────────────────────────────────

const TYPE_DST_UNREACH: u8 = 1;
const TYPE_ECHO_REQ: u8 = 128;
const TYPE_ECHO_REPLY: u8 = 129;
const TYPE_RS: u8 = 133; // Router Solicitation
const TYPE_RA: u8 = 134; // Router Advertisement
const TYPE_NS: u8 = 135; // Neighbor Solicitation
const TYPE_NA: u8 = 136; // Neighbor Advertisement
const TYPE_REDIRECT: u8 = 137;

// NDP option types
const OPT_SLLA: u8 = 1; // Source Link-Layer Address
const OPT_TLLA: u8 = 2; // Target Link-Layer Address
const OPT_PIO: u8 = 3; // Prefix Information

// ─── NDP neighbor cache ───────────────────────────────────────────────────────

#[derive(Clone)]
struct NdpEntry {
    mac: [u8; 6],
    created: u64,
}

const NDP_CACHE_TTL: u64 = 30_000; // 30 seconds in millisecond ticks

static NDP_CACHE: Mutex<BTreeMap<Addr6, NdpEntry>> = Mutex::new(BTreeMap::new());

/// Look up a neighbor's MAC address.  Returns `None` if not cached.
pub fn ndp_resolve(addr: &Addr6) -> Option<[u8; 6]> {
    let cache = NDP_CACHE.lock();
    let now = crate::time::monotonic_ticks();
    cache.get(addr).and_then(|e| {
        if now.saturating_sub(e.created) < NDP_CACHE_TTL {
            Some(e.mac)
        } else {
            None
        }
    })
}

/// Insert or refresh a neighbor cache entry.
pub fn ndp_learn(addr: &Addr6, mac: [u8; 6]) {
    let mut cache = NDP_CACHE.lock();
    cache.insert(
        *addr,
        NdpEntry {
            mac,
            created: crate::time::monotonic_ticks(),
        },
    );
}

// ─── ICMPv6 checksum (RFC 4443 §2.3) ─────────────────────────────────────────

/// Compute the ICMPv6 checksum using an IPv6 pseudo-header.
/// `src` and `dst` are the packet's IPv6 src/dst addresses.
/// `payload` includes the ICMPv6 header + body (checksum field must be 0).
pub fn checksum(src: &Addr6, dst: &Addr6, payload: &[u8]) -> u16 {
    let upper_len = payload.len() as u32;
    let mut sum: u32 = 0;

    // Pseudo-header: src(16) + dst(16) + upper_len(4) + zeros(3) + NH_ICMPV6(1)
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
        sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
    }
    sum += (upper_len >> 16) as u32;
    sum += (upper_len & 0xFFFF) as u32;
    sum += NH_ICMPV6 as u32; // next header

    // ICMPv6 body
    let mut i = 0usize;
    while i + 1 < payload.len() {
        sum += u16::from_be_bytes([payload[i], payload[i + 1]]) as u32;
        i += 2;
    }
    if i < payload.len() {
        sum += (payload[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn make_icmpv6(src: &Addr6, dst: &Addr6, typ: u8, code: u8, body: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(4 + body.len());
    pkt.push(typ);
    pkt.push(code);
    pkt.push(0);
    pkt.push(0); // checksum placeholder
    pkt.extend_from_slice(body);
    let csum = checksum(src, dst, &pkt);
    pkt[2] = (csum >> 8) as u8;
    pkt[3] = csum as u8;
    pkt
}

// ─── Echo request / reply ─────────────────────────────────────────────────────

fn handle_echo_request(src: &Addr6, dst: &Addr6, payload: &[u8]) {
    if payload.len() < 4 {
        return;
    }
    // Reply: flip type to 129, copy identifier+sequence+data.
    let body = payload[4..].to_vec();
    let mut reply_body = Vec::with_capacity(4 + body.len());
    // identifier (bytes 4-5) and sequence (bytes 6-7) from request (bytes 0-3 of body after type/code/csum)
    reply_body.extend_from_slice(&payload[4..4.min(payload.len())]);
    // actually the full body after the 4-byte header:
    let reply_inner = &payload[4..];
    let mut reply_hdr = [0u8; 4];
    reply_hdr[0] = TYPE_ECHO_REPLY;
    reply_hdr[1] = 0;
    let mut full = Vec::with_capacity(4 + reply_inner.len());
    full.extend_from_slice(&reply_hdr);
    full.extend_from_slice(reply_inner);
    let csum = checksum(dst, src, &full); // src of reply = our dst
    full[2] = (csum >> 8) as u8;
    full[3] = csum as u8;
    ipv6::send6(src, NH_ICMPV6, &full);
}

// ─── Destination Unreachable ──────────────────────────────────────────────────

/// Send ICMPv6 Destination Unreachable, code 4 = Port Unreachable.
pub fn port_unreachable6(dst: &Addr6, original_hdr: &[u8], original_payload: &[u8]) {
    let src = ipv6::our_ip6();
    // body: 4 unused bytes + as much of the original packet as fits in 1280 bytes
    let copy_len = (original_hdr.len() + original_payload.len()).min(1232);
    let mut body = Vec::with_capacity(4 + copy_len);
    body.extend_from_slice(&[0u8; 4]); // unused
    body.extend_from_slice(&original_hdr[..original_hdr.len().min(copy_len)]);
    let pkt = make_icmpv6(&src, dst, TYPE_DST_UNREACH, 4, &body);
    ipv6::send6(dst, NH_ICMPV6, &pkt);
}

// ─── NDP: Neighbor Solicitation (outgoing) ────────────────────────────────────

/// Send a Neighbor Solicitation to resolve `target`.
/// `src` is our link-local or global address.
pub fn send_neighbor_solicitation(src: &Addr6, target: &Addr6) {
    let sol_node = ipv6::solicited_node(target);
    // Body: 4 reserved bytes + target address (16 bytes) + SLLA option
    let our_mac = eth::our_mac();
    let mut body = Vec::with_capacity(20 + 8);
    body.extend_from_slice(&[0u8; 4]); // reserved
    body.extend_from_slice(target);
    // Source Link-Layer Address option: type=1, len=1 (units of 8 bytes), MAC
    body.push(OPT_SLLA);
    body.push(1);
    body.extend_from_slice(&our_mac);
    let pkt = make_icmpv6(src, &sol_node, TYPE_NS, 0, &body);
    ipv6::send6(&sol_node, NH_ICMPV6, &pkt);
}

// ─── NDP: Neighbor Solicitation (incoming) ────────────────────────────────────

fn handle_ns(src: &Addr6, dst: &Addr6, payload: &[u8]) {
    if payload.len() < 24 {
        return;
    } // 4 reserved + 16 target
    let target: Addr6 = payload[4..20].try_into().unwrap();
    let our = ipv6::our_ip6();
    if target != our {
        return;
    } // not for us

    // Learn the sender's link-layer address from SLLA option if present.
    parse_lladdr_option(&payload[20..]).map(|mac| ndp_learn(src, mac));

    // Send Neighbor Advertisement.
    send_neighbor_advertisement(src, &target);
}

fn send_neighbor_advertisement(dst: &Addr6, target: &Addr6) {
    let src = ipv6::our_ip6();
    let our_mac = eth::our_mac();
    // Flags: S (solicited) | O (override) — bits 31 and 29 of the reserved field
    let flags: u32 = (1 << 31) | (1 << 30); // S=1, O=1
    let mut body = Vec::with_capacity(4 + 16 + 8);
    body.extend_from_slice(&flags.to_be_bytes());
    body.extend_from_slice(target);
    // Target Link-Layer Address option
    body.push(OPT_TLLA);
    body.push(1);
    body.extend_from_slice(&our_mac);
    let pkt = make_icmpv6(&src, dst, TYPE_NA, 0, &body);
    ipv6::send6(dst, NH_ICMPV6, &pkt);
}

// ─── NDP: Neighbor Advertisement (incoming) ───────────────────────────────────

fn handle_na(payload: &[u8]) {
    if payload.len() < 20 {
        return;
    }
    let target: Addr6 = payload[4..20].try_into().unwrap();
    // TLLA option starts at byte 20.
    if let Some(mac) = parse_lladdr_option(&payload[20..]) {
        ndp_learn(&target, mac);
    }
}

// ─── NDP: Router Solicitation (outgoing) ─────────────────────────────────────

/// Send a Router Solicitation.  Called when the interface comes up.
pub fn send_router_solicitation() {
    let src = ipv6::our_ip6();
    let our_mac = eth::our_mac();
    // Body: 4 reserved bytes + SLLA option (type=1, len=1, MAC)
    let mut body = Vec::with_capacity(12);
    body.extend_from_slice(&[0u8; 4]);
    body.push(OPT_SLLA);
    body.push(1);
    body.extend_from_slice(&our_mac);
    let pkt = make_icmpv6(&src, &ALL_ROUTERS_LL, TYPE_RS, 0, &body);
    ipv6::send6(&ALL_ROUTERS_LL, NH_ICMPV6, &pkt);
}

// ─── NDP: Router Advertisement (incoming) ────────────────────────────────────

fn handle_ra(payload: &[u8]) {
    // RA fixed body: cur_hop_limit(1) + flags(1) + router_lifetime(2) +
    //               reachable_time(4) + retrans_timer(4) = 12 bytes minimum (after type/code/csum)
    if payload.len() < 12 {
        return;
    }
    // payload[0..4] already consumed as type/code/checksum by the caller;
    // here `payload` is the RA body starting at byte 4 (after ICMPv6 hdr).
    // Walk options.
    let mut opt_off = 12;
    while opt_off + 2 <= payload.len() {
        let opt_type = payload[opt_off];
        let opt_len = payload[opt_off + 1] as usize * 8;
        if opt_len == 0 {
            break;
        }
        match opt_type {
            OPT_SLLA => {
                // Router's link-layer address; we don't know its IP6 here
                // so we skip updating the NDP cache for now.
            }
            OPT_PIO => {
                // Prefix Information Option (RFC 4861 §6.3.4)
                if opt_off + opt_len >= 32 {
                    let prefix_len = payload[opt_off + 2];
                    // L-bit (on-link) = bit 7 of payload[opt_off+3]
                    // A-bit (autonomous) = bit 6
                    let a_bit = (payload[opt_off + 3] & 0x40) != 0;
                    let prefix: Addr6 = payload[opt_off + 16..opt_off + 32]
                        .try_into()
                        .unwrap_or(UNSPECIFIED6);
                    if a_bit {
                        // SLAAC: form address = prefix + interface ID
                        let our_mac = eth::our_mac();
                        let mut addr = prefix;
                        // EUI-64 interface ID from MAC
                        addr[8] = our_mac[0] ^ 0x02;
                        addr[9] = our_mac[1];
                        addr[10] = our_mac[2];
                        addr[11] = 0xFF;
                        addr[12] = 0xFE;
                        addr[13] = our_mac[3];
                        addr[14] = our_mac[4];
                        addr[15] = our_mac[5];
                        ipv6::set_ip6(addr);
                        ipv6::set_prefix_len(prefix_len);
                    }
                }
            }
            _ => {}
        }
        opt_off += opt_len;
    }
    // The RA source is the default gateway.
    // We can't get src here directly; caller (receive) must pass it.
    // Gateway is set by the receive() function below.
}

// ─── Redirect (type 137) ─────────────────────────────────────────────────────

fn handle_redirect(payload: &[u8]) {
    // Redirect body: 4 reserved + target addr (16) + dest addr (16) + options
    if payload.len() < 36 {
        return;
    }
    let target: Addr6 = payload[4..20].try_into().unwrap();
    // Learn target MAC from TLLA option if present.
    if let Some(mac) = parse_lladdr_option(&payload[36..]) {
        ndp_learn(&target, mac);
    }
}

// ─── Option parser helper ─────────────────────────────────────────────────────

fn parse_lladdr_option(opts: &[u8]) -> Option<[u8; 6]> {
    let mut off = 0;
    while off + 2 <= opts.len() {
        let typ = opts[off];
        let len = opts[off + 1] as usize * 8;
        if len == 0 {
            break;
        }
        if (typ == OPT_SLLA || typ == OPT_TLLA) && off + 8 <= opts.len() {
            let mac: [u8; 6] = opts[off + 2..off + 8].try_into().ok()?;
            return Some(mac);
        }
        off += len;
    }
    None
}

// ─── Main receive dispatcher ──────────────────────────────────────────────────

/// Dispatch an incoming ICMPv6 message.
/// `payload` starts at the ICMPv6 type byte.
pub fn receive(src: &Addr6, dst: &Addr6, payload: &[u8]) {
    if payload.len() < 4 {
        return;
    }

    // Verify checksum.
    if checksum(src, dst, payload) != 0 {
        return;
    }

    let typ = payload[0];
    let body = &payload[4..]; // skip type(1)+code(1)+checksum(2)

    match typ {
        TYPE_ECHO_REQ => handle_echo_request(src, dst, payload),
        TYPE_ECHO_REPLY => {} // can wake waiting ping sockets in future
        TYPE_RA => {
            ipv6::set_gateway6(*src); // RA sender is default gateway
            handle_ra(body);
        }
        TYPE_NS => handle_ns(src, dst, body),
        TYPE_NA => handle_na(body),
        TYPE_REDIRECT => handle_redirect(body),
        TYPE_RS => {} // we're a host, ignore RS
        _ => {}
    }
}
