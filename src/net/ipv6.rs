//! IPv6 — send, receive, extension header walking, fragment reassembly.
//! RFC 8200 (IPv6), RFC 2460 (fragmentation).
//!
//! ## Key entry points
//!
//!   `receive6(frame)`       — called by `eth::receive` for EtherType 0x86DD
//!   `send6(dst, nh, data)`  — build IPv6 header and transmit
//!   `our_ip6()` / `set_ip6()` etc. — address configuration

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

use crate::net::{eth, icmpv6, tcp, udp};

pub const ETHERTYPE_IPV6: u16 = 0x86DD;

pub const NH_HOPOPT: u8 = 0; // Hop-by-Hop options
pub const NH_TCP: u8 = 6;
pub const NH_UDP: u8 = 17;
pub const NH_ROUTING: u8 = 43; // Routing header
pub const NH_FRAG: u8 = 44; // Fragment header
pub const NH_ICMPV6: u8 = 58;
pub const NH_NONE: u8 = 59; // No Next Header
pub const NH_DSTOPT: u8 = 60; // Destination options

pub const IPV6_HDR_LEN: usize = 40;

pub type Addr6 = [u8; 16];

pub const UNSPECIFIED6: Addr6 = [0u8; 16];
pub const LOOPBACK6: Addr6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// Solicited-node multicast address: ff02::1:ffXX:XXXX
pub fn solicited_node(addr: &Addr6) -> Addr6 {
    let mut m = [0u8; 16];
    m[0] = 0xFF;
    m[1] = 0x02;
    m[11] = 0x01;
    m[12] = 0xFF;
    m[13] = addr[13];
    m[14] = addr[14];
    m[15] = addr[15];
    m
}

/// ff02::1 — all-nodes link-local multicast
pub const ALL_NODES_LL: Addr6 = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
/// ff02::2 — all-routers link-local multicast
pub const ALL_ROUTERS_LL: Addr6 = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

pub fn is_multicast(a: &Addr6) -> bool {
    a[0] == 0xFF
}
pub fn is_link_local(a: &Addr6) -> bool {
    a[0] == 0xFE && (a[1] & 0xC0) == 0x80
}
pub fn is_loopback(a: &Addr6) -> bool {
    *a == LOOPBACK6
}

/// Multicast MAC for an IPv6 multicast address: 33:33:XX:XX:XX:XX
pub fn multicast_mac(addr: &Addr6) -> [u8; 6] {
    [0x33, 0x33, addr[12], addr[13], addr[14], addr[15]]
}

static OUR_IP6: Mutex<Addr6> = Mutex::new(UNSPECIFIED6);
static GATEWAY6: Mutex<Addr6> = Mutex::new(UNSPECIFIED6);
static PREFIX_LEN: Mutex<u8> = Mutex::new(64);
static FLOW_CTR: Mutex<u32> = Mutex::new(1);

pub fn our_ip6() -> Addr6 {
    *OUR_IP6.lock()
}
pub fn set_ip6(a: Addr6) {
    *OUR_IP6.lock() = a;
}
pub fn set_gateway6(a: Addr6) {
    *GATEWAY6.lock() = a;
}
pub fn set_prefix_len(p: u8) {
    *PREFIX_LEN.lock() = p;
}

fn next_flow() -> u32 {
    let mut c = FLOW_CTR.lock();
    let f = *c & 0x000F_FFFF; // 20-bit flow label
    *c = c.wrapping_add(1);
    f
}

#[derive(Clone)]
struct FragBuf {
    src: Addr6,
    dst: Addr6,
    id: u32,
    nh: u8,                           // next header of the fragmentable part
    frags: Vec<(u16, bool, Vec<u8>)>, // (offset_bytes, last, data)
    created: u64,                     // tick
}

const MAX_FRAG_BUFS: usize = 64;

static FRAG_TABLE: Mutex<Vec<FragBuf>> = Mutex::new(Vec::new());

fn frag_key_eq(b: &FragBuf, src: &Addr6, dst: &Addr6, id: u32) -> bool {
    b.id == id && b.src == *src && b.dst == *dst
}

/// Insert a fragment and attempt to reassemble.  Returns Some(data) when
/// complete.
fn frag_insert(
    src: Addr6,
    dst: Addr6,
    id: u32,
    nh: u8,
    offset: u16,
    last: bool,
    data: &[u8],
) -> Option<(u8, Vec<u8>)> {
    let mut table = FRAG_TABLE.lock();
    let now = crate::time::monotonic_ticks();

    // Expire old entries (>60 seconds).
    table.retain(|b| now.saturating_sub(b.created) < 60_000);

    let pos = table.iter().position(|b| frag_key_eq(b, &src, &dst, id));
    let idx = match pos {
        Some(i) => i,
        None => {
            if table.len() >= MAX_FRAG_BUFS {
                table.remove(0);
            }
            table.push(FragBuf {
                src,
                dst,
                id,
                nh,
                frags: Vec::new(),
                created: now,
            });
            table.len() - 1
        },
    };

    table[idx].frags.push((offset, last, data.to_vec()));

    // Sort by offset.
    table[idx].frags.sort_by_key(|(o, _, _)| *o);

    // Check if we have all fragments: offset 0 present, one fragment with
    // last=true, and no gaps.
    let has_last = table[idx].frags.iter().any(|(_, l, _)| *l);
    let has_first = table[idx]
        .frags
        .first()
        .map(|(o, _, _)| *o == 0)
        .unwrap_or(false);
    if !has_last || !has_first {
        return None;
    }

    let mut expected = 0u16;
    let mut ok = true;
    for (off, _, d) in &table[idx].frags {
        if *off != expected {
            ok = false;
            break;
        }
        expected += d.len() as u16;
    }
    if !ok {
        return None;
    }

    // Reassemble.
    let nh_out = table[idx].nh;
    let mut out = Vec::new();
    for (_, _, d) in &table[idx].frags {
        out.extend_from_slice(d);
    }
    table.remove(idx);
    Some((nh_out, out))
}

/// Walk IPv6 extension headers starting at `pkt[off]` with `nh`.
/// Returns `(final_nh, payload_start)` where `payload_start` is the index
/// of the first byte of the upper-layer payload, or `None` if the packet
/// should be consumed by fragment reassembly or is malformed.
fn walk_ext_headers(pkt: &[u8], mut off: usize, mut nh: u8) -> Option<(u8, usize)> {
    loop {
        match nh {
            NH_HOPOPT | NH_ROUTING | NH_DSTOPT => {
                if off + 2 > pkt.len() {
                    return None;
                }
                let next = pkt[off];
                let hlen = (pkt[off + 1] as usize + 1) * 8;
                if off + hlen > pkt.len() {
                    return None;
                }
                nh = next;
                off += hlen;
            },
            NH_FRAG => {
                // Fragment header is exactly 8 bytes.
                if off + 8 > pkt.len() {
                    return None;
                }
                let next_nh = pkt[off];
                let frag_off_raw = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
                let frag_off = frag_off_raw & 0xFFF8; // in bytes
                let more_frags = (frag_off_raw & 0x0001) != 0;
                let id =
                    u32::from_be_bytes([pkt[off + 4], pkt[off + 5], pkt[off + 6], pkt[off + 7]]);
                let payload = pkt[off + 8..].to_vec();
                // We need src/dst from the fixed header (bytes 8..24 and 24..40).
                if pkt.len() < IPV6_HDR_LEN {
                    return None;
                }
                let src: Addr6 = pkt[8..24].try_into().ok()?;
                let dst: Addr6 = pkt[24..40].try_into().ok()?;
                if let Some((rnh, data)) =
                    frag_insert(src, dst, id, next_nh, frag_off, !more_frags, &payload)
                {
                    // Reassembly complete — deliver the reconstructed payload.
                    // We return a special sentinel that the caller handles.
                    // Since we can't return a Vec here cleanly, we push to a
                    // thread-local reassembly output queue and return None to
                    // the current call; the caller will pick it up on the next
                    // eth::receive invocation.  For simplicity we dispatch inline.
                    drop(payload); // already moved
                                   // Re-enter receive6 with reassembled data.
                    receive6_upper(
                        rnh,
                        &pkt[8..24].try_into().ok()?,
                        &pkt[24..40].try_into().ok()?,
                        &data,
                    );
                }
                return None; // packet consumed by fragment reassembly
            },
            NH_NONE => return None,      // No next header
            _ => return Some((nh, off)), // upper-layer protocol
        }
    }
}

fn receive6_upper(nh: u8, src: &Addr6, dst: &Addr6, payload: &[u8]) {
    match nh {
        NH_ICMPV6 => icmpv6::receive(src, dst, payload),
        NH_UDP => udp::receive6(src, dst, payload),
        NH_TCP => tcp::receive6(src, dst, payload),
        _ => {},
    }
}

/// Called from `eth::receive` when EtherType == 0x86DD.
pub fn receive6(frame: &[u8]) {
    if frame.len() < IPV6_HDR_LEN {
        return;
    }

    let ver = (frame[0] >> 4) & 0xF;
    if ver != 6 {
        return;
    }

    let payload_len = u16::from_be_bytes([frame[4], frame[5]]) as usize;
    let first_nh = frame[6];
    // HopLimit = frame[7]; we could enforce > 0 here but for a host stack
    // we only receive, not forward, so we skip the decrement.

    if frame.len() < IPV6_HDR_LEN + payload_len {
        return;
    }

    let src: Addr6 = frame[8..24].try_into().unwrap();
    let dst: Addr6 = frame[24..40].try_into().unwrap();

    // Accept: our unicast, loopback, or any multicast addressed to us.
    let our = our_ip6();
    if dst != our && dst != LOOPBACK6 && !is_multicast(&dst) {
        return;
    }

    let ext_payload = &frame[IPV6_HDR_LEN..IPV6_HDR_LEN + payload_len];
    let Some((upper_nh, upper_off)) = walk_ext_headers(ext_payload, 0, first_nh) else {
        return; // consumed (fragment) or malformed
    };

    receive6_upper(upper_nh, &src, &dst, &ext_payload[upper_off..]);
}

/// Build an IPv6 packet and transmit it.
///
/// `next_header` is the upper-layer protocol number (NH_UDP, NH_TCP, NH_ICMPV6
/// …). Fragmentation of large payloads is not implemented here — the caller
/// must ensure `payload` fits within the path MTU (typically 1280 bytes for
/// link-local).
pub fn send6(dst: &Addr6, next_header: u8, payload: &[u8]) {
    let src = our_ip6();
    if src == UNSPECIFIED6 {
        // No IPv6 address configured — drop silently.
        return;
    }

    let payload_len = payload.len() as u16;
    let mut hdr = [0u8; IPV6_HDR_LEN];

    // Version=6, TC=0, Flow=next_flow()
    let flow = next_flow();
    hdr[0] = 0x60 | ((flow >> 16) as u8 & 0x0F);
    hdr[1] = (flow >> 8) as u8;
    hdr[2] = flow as u8;
    // Traffic class sits in bits [11:4] of the first 4 bytes — left as 0.
    hdr[3] = 0;
    // Payload length
    hdr[4] = (payload_len >> 8) as u8;
    hdr[5] = payload_len as u8;
    // Next header
    hdr[6] = next_header;
    // Hop limit
    hdr[7] = 64;
    // Source
    hdr[8..24].copy_from_slice(&src);
    // Destination
    hdr[24..40].copy_from_slice(dst);

    let mut pkt = Vec::with_capacity(IPV6_HDR_LEN + payload.len());
    pkt.extend_from_slice(&hdr);
    pkt.extend_from_slice(payload);

    // Determine next-hop MAC.
    let next_hop_mac = if is_multicast(dst) {
        Some(multicast_mac(dst))
    } else {
        // Try NDP cache; if not resolved, send NS and drop this packet.
        // The application will retransmit.
        let same_prefix = {
            let plen = *PREFIX_LEN.lock() as usize;
            let bytes = plen / 8;
            let bits = plen % 8;
            let mut eq = true;
            for i in 0..bytes {
                if src[i] != dst[i] {
                    eq = false;
                    break;
                }
            }
            if eq && bits > 0 {
                let mask = 0xFF_u8 << (8 - bits);
                eq = (src[bytes] & mask) == (dst[bytes] & mask);
            }
            eq
        };
        if same_prefix {
            match icmpv6::ndp_resolve(dst) {
                Some(mac) => Some(mac),
                None => {
                    // Trigger NDP Neighbor Solicitation and drop.
                    icmpv6::send_neighbor_solicitation(&src, dst);
                    None
                },
            }
        } else {
            let gw = *GATEWAY6.lock();
            if gw == UNSPECIFIED6 {
                return;
            } // no gateway
            icmpv6::ndp_resolve(&gw)
        }
    };

    if let Some(mac) = next_hop_mac {
        eth::send(mac, ETHERTYPE_IPV6, &pkt);
    }
}
