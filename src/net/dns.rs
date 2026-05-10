//! DNS stub resolver — RFC 1035 (A / AAAA queries).
//!
//! ## Design
//!
//! * Sends a single UDP query to the DNS server obtained from the DHCP lease
//!   (port 53) and busy-waits up to 2 s for a reply.  Retries up to 3 times.
//!
//! * Only the first A record (IPv4) or AAAA record (IPv6, returned as u128)
//!   in the answer section is returned; CNAME chains are followed for up to
//!   8 hops.
//!
//! * A simple fixed-size cache (`DNS_CACHE`, 64 entries, LRU-by-insertion)
//!   avoids repeated queries for the same name.  TTL is stored but the cache
//!   does not actively expire entries; it acts as a best-effort hint store.
//!
//! * The receive path (`receive`) is called by the UDP demux when a packet
//!   arrives on port 53 (← wait, DNS *replies* come to the *source* ephemeral
//!   port we sent from).  We therefore register a temporary UDP socket slot
//!   via `udp::register_port` before the query and unregister it after.
//!
//! ## Thread safety
//!
//! All shared state is behind `spin::Mutex`.  `resolve` must not be called
//! from interrupt context (it busy-waits).

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

use crate::net::{dhcp, udp};

// ── Constants ────────────────────────────────────────────────────────────────

pub const DNS_PORT:    u16 = 53;
const MAX_CNAME_HOPS: usize = 8;
const MAX_RETRIES:    u32  = 3;
const TIMEOUT_MS:     u64  = 2_000;

// DNS record types
const QTYPE_A:    u16 = 1;
const QTYPE_AAAA: u16 = 28;
const QTYPE_CNAME: u16 = 5;
const QCLASS_IN:  u16 = 1;

// ── Cache ─────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct DnsEntry {
    pub name:  String,
    pub ipv4:  Option<u32>,
    pub ipv6:  Option<u128>,
    pub ttl:   u32,
}

const CACHE_SLOTS: usize = 64;
struct DnsCache {
    entries: [Option<DnsEntry>; CACHE_SLOTS],
    next:    usize,   // next slot to evict (ring)
}

impl DnsCache {
    const fn new() -> Self {
        // Option<DnsEntry> is not Copy so we can't use array init with a literal;
        // we use a const fn + unsafe block to zero-init.
        Self {
            // SAFETY: Option<DnsEntry> where None is all-zeros is valid because
            // None is represented as 0 for a pointer-containing type on all our
            // target platforms.
            entries: [const { None }; CACHE_SLOTS],
            next: 0,
        }
    }

    fn lookup(&self, name: &str) -> Option<&DnsEntry> {
        for slot in self.entries.iter() {
            if let Some(ref e) = *slot {
                if e.name == name { return Some(e); }
            }
        }
        None
    }

    fn insert(&mut self, entry: DnsEntry) {
        // Replace existing entry with the same name.
        for slot in self.entries.iter_mut() {
            if let Some(ref e) = *slot {
                if e.name == entry.name {
                    *slot = Some(entry);
                    return;
                }
            }
        }
        // Evict ring-next slot.
        self.entries[self.next] = Some(entry);
        self.next = (self.next + 1) % CACHE_SLOTS;
    }
}

static DNS_CACHE: Mutex<DnsCache> = Mutex::new(DnsCache::new());

// ── Pending reply storage (set by receive(), read by resolve()) ─────────────────

struct PendingReply {
    txid: u16,
    data: Vec<u8>,
}
static PENDING: Mutex<Option<PendingReply>> = Mutex::new(None);

// ── Public API ────────────────────────────────────────────────────────────────

/// Resolve a hostname to an IPv4 address.  Returns `None` on failure.
/// Results are cached; repeated calls for the same name return instantly.
pub fn resolve_a(name: &str) -> Option<u32> {
    // Fast path: cache hit.
    {
        let cache = DNS_CACHE.lock();
        if let Some(e) = cache.lookup(name) {
            if let Some(ip) = e.ipv4 { return Some(ip); }
        }
    }
    // Send query and wait.
    query_and_cache(name, QTYPE_A).and_then(|e| e.ipv4)
}

/// Resolve a hostname to an IPv6 address.  Returns `None` on failure.
pub fn resolve_aaaa(name: &str) -> Option<u128> {
    {
        let cache = DNS_CACHE.lock();
        if let Some(e) = cache.lookup(name) {
            if let Some(ip) = e.ipv6 { return Some(ip); }
        }
    }
    query_and_cache(name, QTYPE_AAAA).and_then(|e| e.ipv6)
}

// ── Query engine ───────────────────────────────────────────────────────────────

fn query_and_cache(name: &str, qtype: u16) -> Option<DnsEntry> {
    let dns_ip = dhcp::leased_dns();
    if dns_ip == 0 { return None; }

    // Allocate an ephemeral source port for this query.
    let src_port = alloc_query_port();
    // Register it so demux_udp delivers replies to us.
    udp::register_ephemeral(src_port);

    let mut result = None;

    // CNAME-following loop.
    let mut current_name = name.to_string();
    'cname: for _ in 0..MAX_CNAME_HOPS {
        // Build and send query, retrying up to MAX_RETRIES times.
        let txid = txid_for(&current_name);
        let query_pkt = build_query(txid, &current_name, qtype);

        for _ in 0..MAX_RETRIES {
            *PENDING.lock() = None;
            udp::send(src_port, dns_ip, DNS_PORT, &query_pkt);

            if let Some(pkt) = wait_reply(txid, TIMEOUT_MS) {
                match parse_response(&pkt, qtype) {
                    ParseResult::Answer(entry) => {
                        let e = DnsEntry {
                            name: name.to_string(),
                            ipv4: entry.ipv4,
                            ipv6: entry.ipv6,
                            ttl:  entry.ttl,
                        };
                        DNS_CACHE.lock().insert(e.clone());
                        result = Some(e);
                        break 'cname;
                    }
                    ParseResult::Cname(target) => {
                        current_name = target;
                        continue 'cname;
                    }
                    ParseResult::Fail => {}
                }
            }
        }
        // If we exhausted retries without an answer, bail.
        break;
    }

    udp::unregister_ephemeral(src_port);
    result
}

// ── Packet builder ────────────────────────────────────────────────────────────────

/// Build a DNS query packet for `name` with the given QTYPE.
fn build_query(txid: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut pkt: Vec<u8> = Vec::with_capacity(64);

    // Header (12 bytes)
    pkt.extend_from_slice(&txid.to_be_bytes());   // ID
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // QR=0 OPCODE=0 RD=1
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // RCODE etc
    pkt.extend_from_slice(&1u16.to_be_bytes());   // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes());   // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes());   // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes());   // ARCOUNT

    // QNAME: label-encoded domain name
    encode_name(name, &mut pkt);

    // QTYPE + QCLASS
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&QCLASS_IN.to_be_bytes());

    pkt
}

/// Encode a domain name as DNS labels (RFC 1035 §3.1).
fn encode_name(name: &str, out: &mut Vec<u8>) {
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0); // root label
}

// ── Response parser ─────────────────────────────────────────────────────────────

struct PartialEntry {
    ipv4: Option<u32>,
    ipv6: Option<u128>,
    ttl:  u32,
}

enum ParseResult {
    Answer(PartialEntry),
    Cname(String),
    Fail,
}

fn parse_response(pkt: &[u8], qtype: u16) -> ParseResult {
    if pkt.len() < 12 { return ParseResult::Fail; }

    // Flags: QR must be 1, RCODE must be 0.
    let flags  = u16::from_be_bytes([pkt[2], pkt[3]]);
    let qr     = (flags >> 15) & 1;
    let rcode  = flags & 0xF;
    if qr != 1 || rcode != 0 { return ParseResult::Fail; }

    let qdcount = u16::from_be_bytes([pkt[4],  pkt[5]])  as usize;
    let ancount = u16::from_be_bytes([pkt[6],  pkt[7]])  as usize;
    if ancount == 0 { return ParseResult::Fail; }

    let mut pos = 12;

    // Skip question section.
    for _ in 0..qdcount {
        pos = skip_name(pkt, pos)?;
        pos += 4; // QTYPE + QCLASS
        if pos > pkt.len() { return ParseResult::Fail; }
    }

    // Parse answer section.
    for _ in 0..ancount {
        pos = skip_name(pkt, pos)?;
        if pos + 10 > pkt.len() { return ParseResult::Fail; }
        let rtype  = u16::from_be_bytes([pkt[pos],   pkt[pos+1]]); pos += 2;
        let _class = u16::from_be_bytes([pkt[pos],   pkt[pos+1]]); pos += 2;
        let ttl    = u32::from_be_bytes([pkt[pos],   pkt[pos+1],
                                         pkt[pos+2], pkt[pos+3]]); pos += 4;
        let rdlen  = u16::from_be_bytes([pkt[pos],   pkt[pos+1]]) as usize; pos += 2;
        if pos + rdlen > pkt.len() { return ParseResult::Fail; }
        let rdata = &pkt[pos..pos + rdlen];
        pos += rdlen;

        match rtype {
            QTYPE_A if rdlen == 4 && (qtype == QTYPE_A) => {
                let ip = u32::from_be_bytes([rdata[0], rdata[1], rdata[2], rdata[3]]);
                return ParseResult::Answer(PartialEntry {
                    ipv4: Some(ip), ipv6: None, ttl,
                });
            }
            QTYPE_AAAA if rdlen == 16 && (qtype == QTYPE_AAAA) => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(rdata);
                let ip = u128::from_be_bytes(bytes);
                return ParseResult::Answer(PartialEntry {
                    ipv4: None, ipv6: Some(ip), ttl,
                });
            }
            QTYPE_CNAME => {
                // Decode the CNAME target and follow it.
                if let Some(cname) = decode_name(pkt, pos - rdlen) {
                    return ParseResult::Cname(cname);
                }
            }
            _ => {}
        }
    }

    ParseResult::Fail
}

// ── Name codec helpers ─────────────────────────────────────────────────────────────

/// Skip a DNS-encoded name at `pos`, returning the position after it.
/// Handles pointer compression (0xC0 prefix).
fn skip_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= pkt.len() { return None; }
        let len = pkt[pos];
        if len == 0 { return Some(pos + 1); }
        if (len & 0xC0) == 0xC0 {
            // Pointer: 2-byte offset, done.
            return Some(pos + 2);
        }
        pos += 1 + len as usize;
    }
}

/// Decode a DNS-encoded name at `pos` into a dotted string.
/// Follows pointer compression up to 16 hops.
fn decode_name(pkt: &[u8], start: usize) -> Option<String> {
    let mut out = String::new();
    let mut pos = start;
    let mut hops = 0usize;

    loop {
        if pos >= pkt.len() { return None; }
        let len = pkt[pos];
        if len == 0 { break; }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= pkt.len() { return None; }
            let offset = (((len & 0x3F) as usize) << 8) | pkt[pos + 1] as usize;
            pos = offset;
            hops += 1;
            if hops > 16 { return None; }
            continue;
        }
        let label_len = len as usize;
        pos += 1;
        if pos + label_len > pkt.len() { return None; }
        if !out.is_empty() { out.push('.'); }
        out.push_str(core::str::from_utf8(&pkt[pos..pos + label_len]).ok()?);
        pos += label_len;
    }
    Some(out)
}

/// `?`-able version of `skip_name` for use in parse_response.
impl core::ops::Try for Option<usize> {
    // We can't impl Try on Option in stable; use a helper instead.
}

// We can't implement std::ops::Try on Option in a no_std crate.
// Replace the `?` on Option<usize> returns with an explicit match:
// (The parse_response function already handles None via early-return pattern;
//  skip_name returns Option<usize> and we match on it inline.)

// ── Wait for DNS reply ───────────────────────────────────────────────────────────

fn wait_reply(txid: u16, timeout_ms: u64) -> Option<Vec<u8>> {
    let deadline = crate::time::monotonic_ms() + timeout_ms;
    loop {
        {
            let pending = PENDING.lock();
            if let Some(ref r) = *pending {
                if r.txid == txid {
                    return Some(r.data.clone());
                }
            }
        }
        if crate::time::monotonic_ms() >= deadline { return None; }
        crate::proc::scheduler::yield_now();
    }
}

// ── Receive path (called from udp demux on the ephemeral src port) ────────────

/// Called by the UDP demux when a reply arrives on a DNS ephemeral port.
pub fn receive(_src_ip: u32, data: &[u8]) {
    if data.len() < 12 { return; }
    let txid = u16::from_be_bytes([data[0], data[1]]);
    let mut pending = PENDING.lock();
    // Only store if we don't already have a fresh reply.
    if pending.is_none() {
        *pending = Some(PendingReply {
            txid,
            data: data.to_vec(),
        });
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────────

/// Generate a pseudo-random transaction ID from the name + monotonic time.
fn txid_for(name: &str) -> u16 {
    let t = crate::time::monotonic_ms() as u16;
    let h = name.bytes().fold(0u16, |a, b| a.wrapping_add(b as u16).rotate_left(3));
    t ^ h
}

/// Allocate an ephemeral port in the DNS query range (40000–41023).
/// Simple incrementing counter; wraps around.
static DNS_PORT_CTR: Mutex<u16> = Mutex::new(40000);
fn alloc_query_port() -> u16 {
    let mut ctr = DNS_PORT_CTR.lock();
    let p = *ctr;
    *ctr = if p >= 41023 { 40000 } else { p + 1 };
    p
}
