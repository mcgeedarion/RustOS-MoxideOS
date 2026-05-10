//! ARP — IPv4 over Ethernet (RFC 826).
//!
//! ## Pending-packet queue
//!
//! When `resolve(ip)` is called and the MAC is not yet in the cache, it:
//!   1. Enqueues the fully-built IP packet in `PENDING_PKTS` (keyed by next-hop IP).
//!   2. Sends an ARP request.
//!   3. Returns `None` so the caller does *not* drop the packet.
//!
//! When an ARP reply arrives (via `receive`), the cache is updated and every
//! pending packet whose target matches the newly-learned MAC is immediately
//! flushed through `eth::send`.
//!
//! Queue limits:
//!   - At most `PENDING_PER_IP` (4) packets are held per destination IP.
//!   - At most `PENDING_TOTAL` (32) slots exist across all destinations.
//!   - If either limit is reached the oldest same-IP entry is evicted
//!     (tail-drop on the per-IP queue).
//!
//! ## Cache
//!
//! 64-entry static array, evicted round-robin when full.  TTL-based expiry
//! is not implemented (future work).

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::net::eth;

// ── Wire constants ────────────────────────────────────────────────────────────

const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IP:  u16 = 0x0800;
const HW_ETHER:      u16 = 0x0001;
const PROTO_IP:      u16 = 0x0800;
const OP_REQUEST:    u16 = 0x0001;
const OP_REPLY:      u16 = 0x0002;

// ── ARP cache ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
pub struct ArpEntry {
    pub ip:    u32,
    pub mac:   [u8; 6],
    pub valid: bool,
}

const CACHE_SIZE: usize = 64;
static CACHE: Mutex<[ArpEntry; CACHE_SIZE]> =
    Mutex::new([ArpEntry { ip: 0, mac: [0; 6], valid: false }; CACHE_SIZE]);

/// Eviction cursor for the cache (round-robin).
static CACHE_NEXT: Mutex<usize> = Mutex::new(0);

/// Look up IP → MAC in the ARP cache.
pub fn lookup(ip: u32) -> Option<[u8; 6]> {
    CACHE.lock().iter()
        .find(|e| e.valid && e.ip == ip)
        .map(|e| e.mac)
}

/// Insert or update an ARP cache entry.
pub fn insert(ip: u32, mac: [u8; 6]) {
    let mut cache = CACHE.lock();
    if let Some(e) = cache.iter_mut().find(|e| e.valid && e.ip == ip) {
        e.mac = mac;
        return;
    }
    // Find empty slot, else evict via round-robin cursor.
    let idx = if let Some(i) = cache.iter().position(|e| !e.valid) {
        i
    } else {
        let mut next = CACHE_NEXT.lock();
        let i = *next;
        *next = (i + 1) % CACHE_SIZE;
        i
    };
    cache[idx] = ArpEntry { ip, mac, valid: true };
}

// ── Pending-packet queue ──────────────────────────────────────────────────────────

const PENDING_TOTAL:  usize = 32;
const PENDING_PER_IP: usize = 4;

/// One buffered IP packet waiting for an ARP reply.
struct PendingPkt {
    dst_ip: u32,
    pkt:    Vec<u8>,  // fully-built Ethernet payload (IP packet)
}

struct PendingQueue {
    slots: [Option<PendingPkt>; PENDING_TOTAL],
    len:   usize,
}

impl PendingQueue {
    const fn new() -> Self {
        Self {
            slots: [const { None }; PENDING_TOTAL],
            len: 0,
        }
    }

    /// Count how many packets are queued for `ip`.
    fn count_for(&self, ip: u32) -> usize {
        self.slots.iter()
            .filter(|s| s.as_ref().map(|p| p.dst_ip == ip).unwrap_or(false))
            .count()
    }

    /// Enqueue a packet.  Drops the oldest same-IP entry if `PENDING_PER_IP`
    /// is exceeded, or the oldest overall entry if `PENDING_TOTAL` is full.
    fn enqueue(&mut self, dst_ip: u32, pkt: Vec<u8>) {
        // Evict oldest same-IP if at per-IP limit.
        if self.count_for(dst_ip) >= PENDING_PER_IP {
            if let Some(slot) = self.slots.iter_mut()
                .find(|s| s.as_ref().map(|p| p.dst_ip == dst_ip).unwrap_or(false))
            {
                *slot = None;
                self.len -= 1;
            }
        }
        // Evict oldest overall if total is full.
        if self.len >= PENDING_TOTAL {
            if let Some(slot) = self.slots.iter_mut().find(|s| s.is_some()) {
                *slot = None;
                self.len -= 1;
            }
        }
        // Store in first empty slot.
        if let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) {
            *slot = Some(PendingPkt { dst_ip, pkt });
            self.len += 1;
        }
    }

    /// Drain all packets destined for `dst_ip` and return them.
    fn drain_for(&mut self, dst_ip: u32) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for slot in self.slots.iter_mut() {
            if slot.as_ref().map(|p| p.dst_ip == dst_ip).unwrap_or(false) {
                if let Some(p) = slot.take() {
                    out.push(p.pkt);
                    self.len -= 1;
                }
            }
        }
        out
    }
}

static PENDING: Mutex<PendingQueue> = Mutex::new(PendingQueue::new());

// ── Public resolve API ────────────────────────────────────────────────────────────

/// Resolve `ip` to a MAC address.
///
/// * If the MAC is already cached, return it immediately.
/// * If `pkt` is provided (always the case from `ip::send`), enqueue it for
///   deferred delivery and send an ARP request.  Returns `None` so the caller
///   must NOT also transmit the packet — it will be sent when the reply
///   arrives.
/// * Directed / subnet broadcast always resolves to ff:ff:ff:ff:ff:ff.
pub fn resolve(ip: u32) -> Option<[u8; 6]> {
    if ip == 0xFFFF_FFFF { return Some([0xFF; 6]); }
    lookup(ip)
}

/// Like `resolve` but buffers `pkt` for deferred delivery if the MAC is
/// unknown.  Returns `true` if the packet was sent immediately, `false` if
/// it was queued (or dropped).
pub fn resolve_or_queue(ip: u32, pkt: Vec<u8>) -> bool {
    if ip == 0xFFFF_FFFF {
        eth::send([0xFF; 6], ETHERTYPE_IP, &pkt);
        return true;
    }
    if let Some(mac) = lookup(ip) {
        eth::send(mac, ETHERTYPE_IP, &pkt);
        return true;
    }
    // Not in cache: buffer the packet and send an ARP request.
    PENDING.lock().enqueue(ip, pkt);
    send_request(ip);
    false
}

// ── ARP send / receive ────────────────────────────────────────────────────────────

/// Build and send an ARP request for `target_ip`.
pub fn send_request(target_ip: u32) {
    let our_mac = eth::our_mac();
    let our_ip  = crate::net::ip::our_ip();
    let mut pkt = [0u8; 28];
    pkt[0..2].copy_from_slice(&HW_ETHER.to_be_bytes());
    pkt[2..4].copy_from_slice(&PROTO_IP.to_be_bytes());
    pkt[4] = 6;
    pkt[5] = 4;
    pkt[6..8].copy_from_slice(&OP_REQUEST.to_be_bytes());
    pkt[8..14].copy_from_slice(&our_mac);
    pkt[14..18].copy_from_slice(&our_ip.to_be_bytes());
    // target hardware = 00:00:00:00:00:00 (unknown)
    pkt[24..28].copy_from_slice(&target_ip.to_be_bytes());
    eth::send_broadcast(ETHERTYPE_ARP, &pkt);
}

/// Handle an incoming ARP packet.
///
/// Always updates the cache with the sender's address.  If this is a request
/// directed at us, send a reply.  If this is a reply, also flush any pending
/// packets queued for the sender's IP.
pub fn receive(_src_mac: [u8; 6], pkt: &[u8]) {
    if pkt.len() < 28 { return; }
    let op         = u16::from_be_bytes([pkt[6],  pkt[7]]);
    let sender_mac: [u8; 6] = pkt[8..14].try_into().unwrap();
    let sender_ip  = u32::from_be_bytes([pkt[14], pkt[15], pkt[16], pkt[17]]);
    let target_ip  = u32::from_be_bytes([pkt[24], pkt[25], pkt[26], pkt[27]]);

    // Always learn the sender.
    insert(sender_ip, sender_mac);

    // Reply to requests directed at us.
    if op == OP_REQUEST && target_ip == crate::net::ip::our_ip() {
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

    // Flush pending packets for this newly-learned IP.
    // We drain under the PENDING lock, then send outside it to avoid
    // re-entering the lock in eth::send.
    let to_flush = PENDING.lock().drain_for(sender_ip);
    for pkt in to_flush {
        eth::send(sender_mac, ETHERTYPE_IP, &pkt);
    }
}
