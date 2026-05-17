//! ACPI NUMA topology — SRAT + SLIT table parsers.
//!
//! ## Tables used
//!
//! - **SRAT** (System Resource Affinity Table, ACPI 6.5 §5.2.16)
//!   Maps CPUs (LAPIC / x2APIC) and memory ranges to proximity domains
//!   (NUMA nodes).
//! - **SLIT** (System Locality Information Table, ACPI 6.5 §5.2.17)
//!   Provides a symmetric distance matrix between all NUMA nodes.
//!
//! ## Topology model
//!
//! We expose:
//! - `MAX_NODES` proximity domains, each with a list of associated memory
//!   ranges and a bitmask of LAPIC IDs.
//! - A flat distance matrix indexed `[from][to]` where 10 = local access.

use crate::console::println;
use super::SdtHeader;

// ── Limits ────────────────────────────────────────────────────────────────

pub const MAX_NODES:        usize = 8;
const MAX_MEM_RANGES:       usize = 16;
const SRAT_DISTANCE_LOCAL:  u8    = 10;

// ── SRAT entry types ──────────────────────────────────────────────────────

const SRAT_TYPE_LAPIC:      u8 = 0;
const SRAT_TYPE_MEM:        u8 = 1;
const SRAT_TYPE_X2APIC:     u8 = 2;

// ── Memory range within a NUMA node ──────────────────────────────────────

#[derive(Copy, Clone, Default, Debug)]
pub struct MemRange {
    pub base: u64,
    pub len:  u64,
    /// Hot-pluggable memory range (SRAT flag bit 1).
    pub hotpluggable: bool,
    /// Non-volatile / persistent memory (SRAT flag bit 2).
    pub persistent: bool,
}

// ── NUMA node ─────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug)]
pub struct NumaNode {
    /// Proximity domain identifier.
    pub domain:        u32,
    pub mem_ranges:    [MemRange; MAX_MEM_RANGES],
    pub mem_range_cnt: usize,
    /// Bitmask of LAPIC IDs assigned to this node (up to 64 CPUs per node).
    pub lapic_mask:    u64,
    /// Set to true if at least one enabled LAPIC or memory range was found.
    pub present:       bool,
}

impl NumaNode {
    const fn empty() -> Self {
        Self {
            domain:        0,
            mem_ranges:    [MemRange { base: 0, len: 0, hotpluggable: false, persistent: false };
                            MAX_MEM_RANGES],
            mem_range_cnt: 0,
            lapic_mask:    0,
            present:       false,
        }
    }
}

// ── Global topology tables ────────────────────────────────────────────────

static mut NODES: [NumaNode; MAX_NODES] = [NumaNode::empty(); MAX_NODES];
static mut NODE_COUNT: usize = 0;

/// Distance matrix: `DISTANCES[i][j]` is the relative latency from node `i`
/// to node `j`.  Initialised to 10 (local) on the diagonal, 20 everywhere
/// else; overwritten by `parse_slit()` when the table is present.
static mut DISTANCES: [[u8; MAX_NODES]; MAX_NODES] = {
    let mut d = [[20u8; MAX_NODES]; MAX_NODES];
    let mut i = 0;
    while i < MAX_NODES {
        d[i][i] = SRAT_DISTANCE_LOCAL;
        i += 1;
    }
    d
};

// ── Helper: find or insert a proximity domain ─────────────────────────────

unsafe fn node_for_domain(domain: u32) -> Option<&'static mut NumaNode> {
    // Look for existing entry.
    for n in NODES[..NODE_COUNT].iter_mut() {
        if n.domain == domain {
            return Some(n);
        }
    }
    // Allocate a new slot.
    if NODE_COUNT >= MAX_NODES {
        return None;
    }
    let idx = NODE_COUNT;
    NODE_COUNT += 1;
    NODES[idx].domain  = domain;
    NODES[idx].present = true;
    Some(&mut NODES[idx])
}

// ── SRAT parser ───────────────────────────────────────────────────────────

#[repr(C, packed)]
struct SratLapic {
    kind:      u8,
    len:       u8,
    prox_lo:   u8,   // bits [7:0] of proximity domain
    lapic_id:  u8,
    flags:     u32,
    sapic_eid: u8,
    prox_hi:   [u8; 3], // bits [31:8] of proximity domain
    _clk:      u32,
}

#[repr(C, packed)]
struct SratMem {
    kind:      u8,
    len:       u8,
    prox_dom:  u32,
    _rsvd:     u16,
    base_lo:   u32,
    base_hi:   u32,
    len_lo:    u32,
    len_hi:    u32,
    _rsvd2:    u32,
    flags:     u32,
    _rsvd3:    u64,
}

#[repr(C, packed)]
struct SratX2Apic {
    kind:      u8,
    len:       u8,
    _rsvd:     u16,
    prox_dom:  u32,
    x2apic_id: u32,
    flags:     u32,
    _clk:      u32,
    _rsvd2:    u32,
}

pub unsafe fn parse_srat() {
    let hdr = match super::find_table(b"SRAT") {
        Some(p) => p,
        None => {
            println!("acpi/numa: no SRAT — assuming single node");
            // Populate a synthetic node 0 with no memory ranges.
            NODE_COUNT = 1;
            NODES[0].domain = 0;
            NODES[0].present = true;
            return;
        }
    };

    let total = (*hdr).len as usize;
    // SRAT header = SdtHeader (36) + 4 (reserved) + 8 (reserved2) = 48 bytes.
    let body_off = core::mem::size_of::<SdtHeader>() + 12;
    if total <= body_off {
        println!("acpi/numa: SRAT too small");
        return;
    }

    let base  = hdr as usize;
    let end   = base + total;
    let mut p = base + body_off;

    while p + 2 <= end {
        let kind = *(p as *const u8);
        let len  = *((p + 1) as *const u8) as usize;
        if len < 2 || p + len > end { break; }

        match kind {
            SRAT_TYPE_LAPIC => {
                if len < core::mem::size_of::<SratLapic>() { p += len; continue; }
                let e = &*(p as *const SratLapic);
                let flags = e.flags;
                if flags & 1 == 0 { p += len; continue; } // not enabled
                let domain = e.prox_lo as u32
                    | ((e.prox_hi[0] as u32) << 8)
                    | ((e.prox_hi[1] as u32) << 16)
                    | ((e.prox_hi[2] as u32) << 24);
                let lid = e.lapic_id;
                if let Some(node) = node_for_domain(domain) {
                    if lid < 64 { node.lapic_mask |= 1u64 << lid; }
                }
            }
            SRAT_TYPE_MEM => {
                if len < core::mem::size_of::<SratMem>() { p += len; continue; }
                let e = &*(p as *const SratMem);
                if e.flags & 1 == 0 { p += len; continue; } // not enabled
                let domain   = e.prox_dom;
                let base_pa  = (e.base_hi as u64) << 32 | e.base_lo as u64;
                let range_len = (e.len_hi  as u64) << 32 | e.len_lo  as u64;
                let hotplug  = e.flags & (1 << 1) != 0;
                let persist  = e.flags & (1 << 2) != 0;
                if let Some(node) = node_for_domain(domain) {
                    let idx = node.mem_range_cnt;
                    if idx < MAX_MEM_RANGES {
                        node.mem_ranges[idx] = MemRange {
                            base: base_pa,
                            len:  range_len,
                            hotpluggable: hotplug,
                            persistent:   persist,
                        };
                        node.mem_range_cnt += 1;
                    }
                }
            }
            SRAT_TYPE_X2APIC => {
                if len < core::mem::size_of::<SratX2Apic>() { p += len; continue; }
                let e = &*(p as *const SratX2Apic);
                if e.flags & 1 == 0 { p += len; continue; }
                let domain = e.prox_dom;
                let xid    = e.x2apic_id;
                if let Some(node) = node_for_domain(domain) {
                    if xid < 64 { node.lapic_mask |= 1u64 << xid; }
                }
            }
            _ => {}
        }
        p += len;
    }

    println!("acpi/numa: {} NUMA node(s) discovered from SRAT", NODE_COUNT);
    for i in 0..NODE_COUNT {
        let n = &NODES[i];
        println!("  Node {}  lapic_mask={:#018x}  {} mem range(s)",
            n.domain, n.lapic_mask, n.mem_range_cnt);
        for r in 0..n.mem_range_cnt {
            let mr = &n.mem_ranges[r];
            println!("    [{:#018x} + {:#010x})  hp={}  persist={}",
                mr.base, mr.len, mr.hotpluggable, mr.persistent);
        }
    }
}

// ── SLIT parser ───────────────────────────────────────────────────────────

pub unsafe fn parse_slit() {
    let hdr = match super::find_table(b"SLIT") {
        Some(p) => p,
        None => {
            println!("acpi/numa: no SLIT, using default distances");
            return;
        }
    };

    let total = (*hdr).len as usize;
    // SLIT header = SdtHeader (36) + 8 (locality_count: u64) = 44 bytes.
    let body_off = core::mem::size_of::<SdtHeader>();
    if total < body_off + 8 { return; }

    let count_ptr = (hdr as usize + body_off) as *const u64;
    let locality_count = count_ptr.read_unaligned() as usize;
    let matrix_off = body_off + 8;
    let matrix_bytes = total.saturating_sub(matrix_off);
    let expected = locality_count * locality_count;

    if matrix_bytes < expected {
        println!("acpi/numa: SLIT matrix too small ({} < {})", matrix_bytes, expected);
        return;
    }

    let matrix = (hdr as usize + matrix_off) as *const u8;
    let n = locality_count.min(MAX_NODES);
    for i in 0..n {
        for j in 0..n {
            DISTANCES[i][j] = *matrix.add(i * locality_count + j);
        }
    }
    println!("acpi/numa: SLIT {}×{} distance matrix loaded", n, n);
    // Print first row as a quick sanity check.
    let row: &[u8] = core::slice::from_raw_parts(matrix, n);
    print_distance_row(0, row);
}

fn print_distance_row(node: usize, row: &[u8]) {
    crate::console::print!("  node {} distances: ", node);
    for d in row {
        crate::console::print!("{:3} ", d);
    }
    println!();
}

// ── Public API ────────────────────────────────────────────────────────────

/// Initialise NUMA topology (must be called after `super::init()`).
pub unsafe fn init() {
    parse_srat();
    parse_slit();
}

/// Number of discovered NUMA nodes.
pub fn node_count() -> usize {
    unsafe { NODE_COUNT }
}

/// Immutable reference to all discovered nodes.
pub fn nodes() -> &'static [NumaNode] {
    unsafe { &NODES[..NODE_COUNT] }
}

/// Relative access distance from `from` to `to`.
/// Returns 10 for local, higher values for remote.
pub fn distance(from: usize, to: usize) -> u8 {
    if from >= MAX_NODES || to >= MAX_NODES {
        return u8::MAX;
    }
    unsafe { DISTANCES[from][to] }
}

/// Return the NUMA node that owns the physical address `pa`, if known.
pub fn node_for_phys(pa: u64) -> Option<usize> {
    let nodes = unsafe { &NODES[..NODE_COUNT] };
    for (idx, node) in nodes.iter().enumerate() {
        for r in 0..node.mem_range_cnt {
            let mr = &node.mem_ranges[r];
            if pa >= mr.base && pa < mr.base + mr.len {
                return Some(idx);
            }
        }
    }
    None
}

/// Return the NUMA node that owns the given LAPIC ID, if known.
pub fn node_for_lapic(lapic_id: u8) -> Option<usize> {
    if lapic_id >= 64 { return None; }
    let mask = 1u64 << lapic_id;
    let nodes = unsafe { &NODES[..NODE_COUNT] };
    for (idx, node) in nodes.iter().enumerate() {
        if node.lapic_mask & mask != 0 {
            return Some(idx);
        }
    }
    None
}
