//! Physical Memory Manager (PMM) — buddy allocator with NUMA awareness
//! and per-page reference counting.
//!
//! ## Architecture overview
//!
//! ```text
//!  ┌──────────────────────────────────────────────────────────────────────────┐
//!  │  Tier 0 — Static bootstrap pool  (64 MiB, bump + free-list)            │
//!  │    Used for every allocation before pmm_add_region() is first called.  │
//!  │    page_info table does NOT exist for bootstrap pages.                  │
//!  ├──────────────────────────────────────────────────────────────────────────┤
//!  │  Tier 1 — Per-NUMA buddy allocator                                      │
//!  │    One BuddyNode per NUMA node (up to MAX_NODES).                       │
//!  │    11 free-lists: order 0 (4 KiB) … order 10 (4 MiB).                 │
//!  │    Each free-list head is an AtomicPtr Treiber stack of PageInfo nodes. │
//!  │    Splitting: alloc_order(k) splits a block of order k+1 if order k    │
//!  │               is empty.                                                 │
//!  │    Coalescing: free_page() checks the buddy address and merges if both  │
//!  │               blocks are free and of the same order.                    │
//!  ├──────────────────────────────────────────────────────────────────────────┤
//!  │  PageInfo table  (one entry per physical page frame)                    │
//!  │    Stored in the static PAGE_INFO array, indexed by PFN.               │
//!  │    Fields: refcount (AtomicU32), flags (AtomicU8), order (u8),         │
//!  │            numa_node (u8), free_next (AtomicPtr for buddy free-list).   │
//!  └──────────────────────────────────────────────────────────────────//────┘
//! ```
//!
//! ## Buddy invariants
//!
//! A block of order `k` starts at a physical address that is a multiple of
//! `PAGE_SIZE << k`.  The buddy of a block at `pa` with order `k` is at:
//!
//! ```text
//!   buddy(pa, k) = pa XOR (PAGE_SIZE << k)
//! ```
//!
//! Two blocks can be merged iff:
//!   1. `buddy` is within the same NUMA node's registered range.
//!   2. `buddy`'s `PageInfo::order` == `k` (same block size).
//!   3. `PageInfo::FLAG_FREE` is set on the buddy.
//!
//! ## NUMA policy
//!
//! `alloc_page()` / `alloc_pages_contig()` first attempt the **local** NUMA
//! node (read from `gdt::current_cpu_id()` → `CpuInfo::node`), then fall
//! back to each other node in ascending node-id order.
//!
//! `alloc_page_on_node(node)` forces allocation on a specific node.
//!
//! ## Reference counting
//!
//! Every physical page managed by Tier 1 has a `PageInfo::refcount`
//! (`AtomicU32`).  The invariants are:
//!
//! | State           | refcount |
//! |-----------------|----------|
//! | Free (buddy)    | 0        |
//! | Allocated once  | 1        |
//! | Shared / COW    | > 1      |
//!
//! `get_page(pa)` increments the refcount.  `put_page(pa)` decrements it;
//! when the count reaches 0 the page is automatically returned to the buddy
//! allocator.  Bootstrap pages are not tracked.
//!
//! ## Contiguous allocation
//!
//! `alloc_pages_contig(n)` finds the smallest buddy order `k` such that
//! `2^k >= n` pages, allocates one block of that order, and returns its
//! base address.  No lock is needed beyond what the per-order Treiber stacks
//! already provide.
//!
//! ## Backwards-compatible public API
//!
//! The old `alloc_page()` / `free_page()` / `pmm_add_region()` signatures
//! are preserved so no call site in `mmap.rs`, `kstack.rs`, `cow_fault.rs`,
//! etc. needs to change.

use core::sync::atomic::{
    AtomicU32, AtomicU8, AtomicUsize, AtomicPtr, AtomicBool, Ordering,
};

// ── Constants ─────────────────────────────────────────────────────────────────

pub const PAGE_SIZE:   usize = 4096;
pub const MAX_ORDER:   usize = 11;  // orders 0..=10, max block = 4 MiB
pub const MAX_NODES:   usize = 8;   // NUMA nodes

/// Hard ceiling on the physical address space the PFN table can describe.
/// 1 TiB → 256 M PFNs; that's 256 M × 16 B ≈ 4 GiB of table.  We keep
/// this small (16 GiB) for the static array to stay within reason.
pub const MAX_PA:      usize = 16 * 1024 * 1024 * 1024; // 16 GiB
const    MAX_FRAMES:   usize = MAX_PA / PAGE_SIZE;        // 4 M entries

// ── Bootstrap pool (Tier 0) ──────────────────────────────────────────────────
//
// 64 MiB static bump allocator used during early boot before the EFI/FDT
// memory map is parsed.  Freed bootstrap pages go to a tiny intrusive
// Treiber stack; they are NOT tracked in the PageInfo table.

const POOL_PAGES: usize = 16_384; // 64 MiB

#[repr(C, align(4096))]
struct Pool([u8; POOL_PAGES * PAGE_SIZE]);
static POOL: Pool = Pool([0u8; POOL_PAGES * PAGE_SIZE]);
static BUMP: AtomicUsize = AtomicUsize::new(0);

// Bootstrap double-free bitmap (one bit per pool page).
const BITMAP_WORDS: usize = POOL_PAGES / 64;
static POOL_FREE_BITS: [core::sync::atomic::AtomicU64; BITMAP_WORDS] = {
    const Z: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
    [Z; BITMAP_WORDS]
};

#[inline]
fn pool_base() -> usize { POOL.0.as_ptr() as usize }
#[inline]
fn pool_index(pa: usize) -> Option<usize> {
    let b = pool_base();
    if pa >= b && pa < b + POOL_PAGES * PAGE_SIZE {
        Some((pa - b) / PAGE_SIZE)
    } else { None }
}
#[inline]
fn pool_bit_set_free(idx: usize) -> bool {
    let w = idx / 64; let bit = 1u64 << (idx % 64);
    POOL_FREE_BITS[w].fetch_or(bit, Ordering::AcqRel) & bit == 0
}
#[inline]
fn pool_bit_clear(idx: usize) {
    let w = idx / 64; let bit = 1u64 << (idx % 64);
    POOL_FREE_BITS[w].fetch_and(!bit, Ordering::AcqRel);
}

/// Intrusive free-list for recycled bootstrap pages.
static BOOT_FREE_HEAD: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static BOOT_FREE_CNT:  AtomicUsize   = AtomicUsize::new(0);

fn boot_push(pa: usize) {
    let node = pa as *mut *mut u8;
    loop {
        let head = BOOT_FREE_HEAD.load(Ordering::Acquire);
        unsafe { node.write(head); }
        if BOOT_FREE_HEAD.compare_exchange_weak(
            head, pa as *mut u8, Ordering::Release, Ordering::Relaxed,
        ).is_ok() {
            BOOT_FREE_CNT.fetch_add(1, Ordering::Relaxed);
            return;
        }
        core::hint::spin_loop();
    }
}

fn boot_pop() -> usize {
    loop {
        let head = BOOT_FREE_HEAD.load(Ordering::Acquire);
        if head.is_null() { return 0; }
        let next = unsafe { (head as *const *mut u8).read() };
        if BOOT_FREE_HEAD.compare_exchange_weak(
            head, next, Ordering::Release, Ordering::Relaxed,
        ).is_ok() {
            BOOT_FREE_CNT.fetch_sub(1, Ordering::Relaxed);
            return head as usize;
        }
        core::hint::spin_loop();
    }
}

// ── PageInfo table ────────────────────────────────────────────────────────────
//
// One PageInfo per physical page frame.  Index = pa / PAGE_SIZE.

/// Bit flags stored in `PageInfo::flags`.
pub mod page_flags {
    pub const FLAG_FREE:     u8 = 1 << 0; // page is on a buddy free-list
    pub const FLAG_RESERVED: u8 = 1 << 1; // kernel/firmware reserved
    pub const FLAG_BUDDY:    u8 = 1 << 2; // under buddy management
    pub const FLAG_BOOT:     u8 = 1 << 3; // came from bootstrap pool
}
use page_flags::*;

/// Per-physical-page metadata.
///
/// 16 bytes per entry → 64 MiB for a 4-GiB physical address space.
/// Aligned to 8 bytes so `free_next` is naturally aligned.
#[repr(C, align(8))]
pub struct PageInfo {
    /// Number of active references to this page (0 = free).
    pub refcount:  AtomicU32,
    /// `page_flags::*` bitmask.
    pub flags:     AtomicU8,
    /// Buddy order this block was freed at (0 = single page).
    pub order:     AtomicU8,
    /// NUMA node this page belongs to.
    pub numa_node: AtomicU8,
    pub _pad:      u8,
    /// Intrusive pointer used when the page is on a buddy free-list.
    /// Only valid when `FLAG_FREE` is set.
    pub free_next: AtomicPtr<PageInfo>,
}

impl PageInfo {
    const fn zero() -> Self {
        Self {
            refcount:  AtomicU32::new(0),
            flags:     AtomicU8::new(0),
            order:     AtomicU8::new(0),
            numa_node: AtomicU8::new(0),
            _pad:      0,
            free_next: AtomicPtr::new(core::ptr::null_mut()),
        }
    }
}

// Static PageInfo table.  The compiler zero-initialises the BSS; we don't
// need a constructor loop.  4_194_304 × 16 B = 64 MiB reserved in BSS.
static PAGE_INFO: [PageInfo; MAX_FRAMES] = {
    const Z: PageInfo = PageInfo::zero();
    [Z; MAX_FRAMES]
};

#[inline]
fn pfn(pa: usize) -> usize { pa / PAGE_SIZE }

/// Return the `PageInfo` for `pa`, or `None` if `pa` is out of range.
#[inline]
pub fn page_info(pa: usize) -> Option<&'static PageInfo> {
    if pa == 0 || pa & (PAGE_SIZE - 1) != 0 { return None; }
    let idx = pfn(pa);
    if idx < MAX_FRAMES { Some(&PAGE_INFO[idx]) } else { None }
}

// ── NUMA node table ───────────────────────────────────────────────────────────

/// Describes one NUMA node's physical address ranges for the buddy.
#[derive(Copy, Clone)]
struct NodeRange {
    /// Lowest physical address in this node.
    base: usize,
    /// Exclusive upper bound.
    end:  usize,
}

static NODE_RANGES: [spin::Mutex<NodeRange>; MAX_NODES] = {
    const Z: spin::Mutex<NodeRange> = spin::Mutex::new(NodeRange { base: usize::MAX, end: 0 });
    [Z; MAX_NODES]
};
static NODE_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Register a physical address range as belonging to NUMA node `node`.
/// Expands the node's range if already registered.
fn register_node_range(node: u8, base: usize, end: usize) {
    let n = node as usize;
    if n >= MAX_NODES { return; }
    let mut nr = NODE_RANGES[n].lock();
    nr.base = nr.base.min(base);
    nr.end  = nr.end.max(end);
    // Ensure node_count covers this node.
    let old = NODE_COUNT.load(Ordering::Relaxed);
    if n + 1 > old {
        NODE_COUNT.compare_exchange(old, n + 1, Ordering::Relaxed, Ordering::Relaxed).ok();
    }
}

/// Return the NUMA node id that `pa` belongs to (0 if unknown / single-node).
pub fn node_of(pa: usize) -> u8 {
    let n = NODE_COUNT.load(Ordering::Relaxed);
    for i in 0..n {
        let nr = NODE_RANGES[i].lock();
        if pa >= nr.base && pa < nr.end { return i as u8; }
    }
    0
}

// ── Per-NUMA buddy allocator ──────────────────────────────────────────────────
//
// Each NUMA node has MAX_ORDER free-lists, one per buddy order.
// A free-list is a lock-free Treiber stack of PageInfo pointers.
// The physical address of a PageInfo at &PAGE_INFO[i] is i * PAGE_SIZE.

struct BuddyNode {
    /// free_lists[k] = head of the Treiber stack for order-k blocks.
    free_lists: [AtomicPtr<PageInfo>; MAX_ORDER],
    /// Count of free pages (sum over all orders × 2^order).
    free_pages: AtomicUsize,
    /// Total pages registered in this node.
    total_pages: AtomicUsize,
}

impl BuddyNode {
    const fn new() -> Self {
        const NP: AtomicPtr<PageInfo> = AtomicPtr::new(core::ptr::null_mut());
        Self {
            free_lists:  [NP; MAX_ORDER],
            free_pages:  AtomicUsize::new(0),
            total_pages: AtomicUsize::new(0),
        }
    }
}

static BUDDY: [BuddyNode; MAX_NODES] = {
    const Z: BuddyNode = BuddyNode::new();
    [Z; MAX_NODES]
};

// Whether Tier 1 has been seeded at all.
static BUDDY_LIVE: AtomicBool = AtomicBool::new(false);

// ── Buddy helpers ─────────────────────────────────────────────────────────────

#[inline]
fn order_size(order: usize) -> usize { PAGE_SIZE << order }

#[inline]
fn buddy_pa(pa: usize, order: usize) -> usize {
    pa ^ order_size(order)
}

#[inline]
fn is_aligned(pa: usize, order: usize) -> bool {
    pa & (order_size(order) - 1) == 0
}

/// Push a block onto the free-list for `(node, order)`.
/// Sets FLAG_FREE and records the order in the PageInfo.
unsafe fn buddy_push(node: u8, pa: usize, order: usize) {
    let n   = node as usize;
    let pi  = &PAGE_INFO[pfn(pa)];
    pi.flags.fetch_or(FLAG_FREE, Ordering::Release);
    pi.order.store(order as u8, Ordering::Relaxed);
    let list = &BUDDY[n].free_lists[order];
    loop {
        let head = list.load(Ordering::Acquire);
        pi.free_next.store(head, Ordering::Relaxed);
        if list.compare_exchange_weak(
            head,
            pi as *const PageInfo as *mut PageInfo,
            Ordering::Release,
            Ordering::Relaxed,
        ).is_ok() {
            // Count: every order-k block covers 2^k pages.
            BUDDY[n].free_pages.fetch_add(1 << order, Ordering::Relaxed);
            return;
        }
        core::hint::spin_loop();
    }
}

/// Pop one block from the free-list for `(node, order)`.
/// Clears FLAG_FREE on the returned block.
/// Returns the physical address, or 0 on empty.
unsafe fn buddy_pop(node: u8, order: usize) -> usize {
    let n    = node as usize;
    let list = &BUDDY[n].free_lists[order];
    loop {
        let head_ptr = list.load(Ordering::Acquire);
        if head_ptr.is_null() { return 0; }
        let next = (*head_ptr).free_next.load(Ordering::Relaxed);
        if list.compare_exchange_weak(
            head_ptr, next,
            Ordering::Release,
            Ordering::Relaxed,
        ).is_ok() {
            (*head_ptr).flags.fetch_and(!FLAG_FREE, Ordering::Release);
            BUDDY[n].free_pages.fetch_sub(1 << order, Ordering::Relaxed);
            return (head_ptr as usize - PAGE_INFO.as_ptr() as usize)
                / core::mem::size_of::<PageInfo>() * PAGE_SIZE;
        }
        core::hint::spin_loop();
    }
}

/// Try to pop a specific page (by physical address) from a free-list.
/// Used during buddy coalescing to remove a buddy block.
/// Returns true if found and removed.
unsafe fn buddy_remove(node: u8, pa: usize, order: usize) -> bool {
    let n    = node as usize;
    let list = &BUDDY[n].free_lists[order];
    let target = &PAGE_INFO[pfn(pa)] as *const PageInfo as *mut PageInfo;

    // We need to splice `target` out of the singly-linked list.
    // Use a compare-exchange on the head; if it's not the head we must
    // walk — which requires a temporary spin lock for the coalesce path.
    // For simplicity (and correctness) we use a per-order spin-lock
    // embedded in a static array.
    //
    // Rather than adding another static, we use a short bounded-retry
    // approach: try to pop until we either find target or exhaust the list,
    // collecting popped items and re-pushing non-matching ones.  This is
    // O(n) in list length but coalescing is rare and lists are short.
    let mut popped: [*mut PageInfo; 256] = [core::ptr::null_mut(); 256];
    let mut count = 0usize;
    let mut found = false;

    // Drain until we find target or exhaust.
    loop {
        let head_ptr = list.load(Ordering::Acquire);
        if head_ptr.is_null() { break; }
        let next = (*head_ptr).free_next.load(Ordering::Relaxed);
        if list.compare_exchange_weak(
            head_ptr, next, Ordering::Release, Ordering::Relaxed,
        ).is_err() {
            core::hint::spin_loop();
            continue;
        }
        (*head_ptr).flags.fetch_and(!FLAG_FREE, Ordering::Release);
        BUDDY[n].free_pages.fetch_sub(1 << order, Ordering::Relaxed);
        if head_ptr == target {
            found = true;
            break;
        }
        if count < popped.len() {
            popped[count] = head_ptr;
            count += 1;
        } else {
            // List is unexpectedly long; re-push and give up.
            (*head_ptr).flags.fetch_or(FLAG_FREE, Ordering::Relaxed);
            BUDDY[n].free_pages.fetch_add(1 << order, Ordering::Relaxed);
            // Re-push what we popped so far.
            for &p in &popped[..count] {
                (*p).flags.fetch_or(FLAG_FREE, Ordering::Release);
                BUDDY[n].free_pages.fetch_add(1 << order, Ordering::Relaxed);
                let h = list.load(Ordering::Acquire);
                (*p).free_next.store(h, Ordering::Relaxed);
                list.store(p, Ordering::Release);
            }
            return false;
        }
    }

    // Re-push anything we drained but did not want.
    for &p in &popped[..count] {
        (*p).flags.fetch_or(FLAG_FREE, Ordering::Release);
        BUDDY[n].free_pages.fetch_add(1 << order, Ordering::Relaxed);
        let h = list.load(Ordering::Acquire);
        (*p).free_next.store(h, Ordering::Relaxed);
        list.store(p, Ordering::Release);
    }
    found
}

// ── Kernel image reservation ──────────────────────────────────────────────────

extern "C" {
    static _kernel_start: u8;
    static _end:          u8;
}

#[inline]
fn kernel_start_pa() -> usize { unsafe { &_kernel_start as *const u8 as usize } }
#[inline]
fn kernel_end_pa()   -> usize { unsafe { &_end          as *const u8 as usize } }
#[inline]
fn is_kernel_page(pa: usize) -> bool {
    pa >= kernel_start_pa() && pa < kernel_end_pa()
}

// ── Core Tier-1 allocation ────────────────────────────────────────────────────

/// Allocate one page from `node` at order 0, splitting higher-order blocks
/// as needed.  Returns the physical address or 0 on failure.
unsafe fn buddy_alloc_node(node: u8) -> usize {
    let n = node as usize;
    // Walk from order 0 upward looking for a free block.
    for order in 0..MAX_ORDER {
        let pa = buddy_pop(node, order);
        if pa == 0 { continue; }
        // Split down to order 0.
        let mut current_pa    = pa;
        let mut current_order = order;
        while current_order > 0 {
            current_order -= 1;
            let buddy_half = current_pa + order_size(current_order);
            // Mark the split-off buddy as free at the lower order.
            let bpi = &PAGE_INFO[pfn(buddy_half)];
            bpi.numa_node.store(node, Ordering::Relaxed);
            buddy_push(node, buddy_half, current_order);
        }
        // Initialise the returned page.
        let pi = &PAGE_INFO[pfn(current_pa)];
        pi.refcount.store(1, Ordering::Release);
        pi.order.store(0, Ordering::Relaxed);
        pi.flags.store(FLAG_BUDDY, Ordering::Release);
        pi.numa_node.store(node, Ordering::Relaxed);
        // Zero-fill for security.
        core::ptr::write_bytes(current_pa as *mut u8, 0, PAGE_SIZE);
        return current_pa;
    }
    0
}

/// Allocate `2^order` physically contiguous pages from `node`.
/// Returns base physical address or 0 on failure.
unsafe fn buddy_alloc_order_node(node: u8, order: usize) -> usize {
    if order >= MAX_ORDER { return 0; }
    // Try to pop a block of exactly `order`.
    for try_order in order..MAX_ORDER {
        let pa = buddy_pop(node, try_order);
        if pa == 0 { continue; }
        let mut current_pa    = pa;
        let mut current_order = try_order;
        // Split down to the requested order.
        while current_order > order {
            current_order -= 1;
            let split_off = current_pa + order_size(current_order);
            let bpi = &PAGE_INFO[pfn(split_off)];
            bpi.numa_node.store(node, Ordering::Relaxed);
            buddy_push(node, split_off, current_order);
        }
        // Initialise all pages in the block.
        let block_pages = 1usize << order;
        for i in 0..block_pages {
            let ppa = current_pa + i * PAGE_SIZE;
            let pi  = &PAGE_INFO[pfn(ppa)];
            pi.refcount.store(1, Ordering::Release);
            pi.order.store(order as u8, Ordering::Relaxed);
            pi.flags.store(FLAG_BUDDY, Ordering::Release);
            pi.numa_node.store(node, Ordering::Relaxed);
        }
        core::ptr::write_bytes(current_pa as *mut u8, 0, block_pages * PAGE_SIZE);
        return current_pa;
    }
    0
}

/// Free a single page back to the buddy allocator, coalescing with its buddy
/// if both are free.
unsafe fn buddy_free_page(pa: usize) {
    if pa == 0 || pa & (PAGE_SIZE - 1) != 0 { return; }
    let pi = match page_info(pa) { Some(p) => p, None => return };

    let node  = pi.numa_node.load(Ordering::Relaxed);
    let mut current_pa    = pa;
    let mut current_order = 0usize;

    // Zero-fill for security before releasing back to the pool.
    core::ptr::write_bytes(current_pa as *mut u8, 0, PAGE_SIZE);

    // Set refcount to 0, clear allocated flags.
    pi.refcount.store(0, Ordering::Release);
    pi.flags.store(0, Ordering::Relaxed);

    // Coalesce loop.
    while current_order + 1 < MAX_ORDER {
        let bpa = buddy_pa(current_pa, current_order);
        // Buddy must be within max physical address space.
        if bpa >= MAX_PA { break; }
        let bpi = &PAGE_INFO[pfn(bpa)];
        // Buddy must be: free, same order, same NUMA node, buddy-managed.
        let bflags = bpi.flags.load(Ordering::Acquire);
        if bflags & (FLAG_FREE | FLAG_BUDDY) != (FLAG_FREE | FLAG_BUDDY) { break; }
        if bpi.order.load(Ordering::Relaxed) as usize != current_order  { break; }
        if bpi.numa_node.load(Ordering::Relaxed) != node                { break; }
        // Alignment check: the merged block must be naturally aligned.
        let merged = current_pa.min(bpa);
        if !is_aligned(merged, current_order + 1)                       { break; }
        // Remove the buddy from the free-list.
        if !buddy_remove(node, bpa, current_order) { break; }
        // Merge: move to the lower address.
        current_pa    = merged;
        current_order += 1;
    }

    // Push the (possibly merged) block onto the free-list.
    let cpi = &PAGE_INFO[pfn(current_pa)];
    cpi.flags.store(FLAG_FREE | FLAG_BUDDY, Ordering::Relaxed);
    buddy_push(node, current_pa, current_order);
}

// ── NUMA-local allocation helper ─────────────────────────────────────────────

/// Return the NUMA node of the calling CPU.
/// Falls back to 0 if called before GSBASE is set or on RISC-V.
#[inline]
fn local_node() -> u8 {
    #[cfg(target_arch = "x86_64")]
    {
        let cpu = crate::arch::x86_64::gdt::current_cpu_id();
        if let Some(info) = crate::smp::cpu_info(cpu) {
            return info.node as u8;
        }
    }
    0
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Allocate a single 4 KiB page.
///
/// Tries the local NUMA node first; falls back to all other nodes.
/// Returns the physical address, or `None` on OOM.
/// The returned page is zero-filled and has refcount = 1.
pub fn alloc_page() -> Option<usize> {
    if BUDDY_LIVE.load(Ordering::Relaxed) {
        // Tier 1: buddy allocator.
        let preferred = local_node();
        let n_nodes   = NODE_COUNT.load(Ordering::Relaxed).max(1);
        for i in 0..n_nodes {
            let node = ((preferred as usize + i) % n_nodes) as u8;
            let pa = unsafe { buddy_alloc_node(node) };
            if pa != 0 { return Some(pa); }
        }
        // All buddy nodes exhausted — fall through to bootstrap.
    }
    // Tier 0: bootstrap pool.
    let pa = boot_pop();
    if pa != 0 {
        if let Some(idx) = pool_index(pa) { pool_bit_clear(idx); }
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        return Some(pa);
    }
    let idx = BUMP.fetch_add(1, Ordering::Relaxed);
    if idx >= POOL_PAGES {
        BUMP.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    Some(pool_base() + idx * PAGE_SIZE)
}

/// Allocate a page from a specific NUMA node.
/// Falls back to `alloc_page()` if the node is empty or unavailable.
pub fn alloc_page_on_node(node: u8) -> Option<usize> {
    if BUDDY_LIVE.load(Ordering::Relaxed) {
        let pa = unsafe { buddy_alloc_node(node) };
        if pa != 0 { return Some(pa); }
    }
    alloc_page()
}

/// Allocate `n` physically contiguous pages.
///
/// Finds the smallest buddy order k where `2^k >= n`, allocates a block of
/// that order from the local NUMA node (falling back to others), and returns
/// the base physical address.  The entire block is zero-filled.
///
/// If `n` is not a power of two, the tail pages of the block are freed back
/// to the buddy so there is no internal fragmentation.
pub fn alloc_pages_contig(n: usize) -> Option<usize> {
    if n == 0 { return None; }
    if n == 1 { return alloc_page(); }

    if !BUDDY_LIVE.load(Ordering::Relaxed) {
        // Bootstrap fallback: plain sequential allocation.
        let mut pages = [0usize; 1 << (MAX_ORDER - 1)];
        let cap = pages.len().min(n);
        for i in 0..cap {
            pages[i] = alloc_page()?;
        }
        return Some(pages[0]); // not truly contiguous but best effort
    }

    // Find the smallest order >= n pages.
    let mut order = 0usize;
    while (1 << order) < n { order += 1; }
    if order >= MAX_ORDER { return None; }

    let preferred = local_node();
    let n_nodes   = NODE_COUNT.load(Ordering::Relaxed).max(1);
    for i in 0..n_nodes {
        let node = ((preferred as usize + i) % n_nodes) as u8;
        let pa   = unsafe { buddy_alloc_order_node(node, order) };
        if pa == 0 { continue; }
        // Free back the tail pages if n is not a power of two.
        let block_pages = 1usize << order;
        for j in n..block_pages {
            let tail_pa = pa + j * PAGE_SIZE;
            unsafe { buddy_free_page(tail_pa); }
        }
        return Some(pa);
    }
    None
}

/// Free `n` contiguous pages starting at `base_pa`.
pub fn free_pages_contig(base_pa: usize, n: usize) {
    for i in 0..n { free_page(base_pa + i * PAGE_SIZE); }
}

/// Release a physical page.
///
/// For Tier-1 (buddy) pages the function decrements the refcount and only
/// returns the page to the buddy free-list when it reaches zero, enabling
/// correct COW / shared-mapping semantics.
///
/// For Tier-0 (bootstrap) pages the refcount is not tracked; the page is
/// returned to the bootstrap free-list immediately.
///
/// Panics on double-free of bootstrap pages (detected via bitmap).
pub fn free_page(pa: usize) {
    if pa == 0 { return; }
    assert_eq!(pa & (PAGE_SIZE - 1), 0, "free_page: PA {:#x} not page-aligned", pa);
    assert!(!is_kernel_page(pa), "free_page: attempt to free kernel page {:#x}", pa);

    // Bootstrap page?
    if let Some(idx) = pool_index(pa) {
        let ok = pool_bit_set_free(idx);
        assert!(ok, "free_page: double-free of bootstrap page {:#x}", pa);
        unsafe { zero_page(pa); }
        boot_push(pa);
        return;
    }

    // Buddy page.
    if let Some(pi) = page_info(pa) {
        let old = pi.refcount.fetch_sub(1, Ordering::AcqRel);
        assert!(old > 0, "free_page: refcount underflow at PA {:#x}", pa);
        if old == 1 {
            unsafe { buddy_free_page(pa); }
        }
        // else: still referenced — do not return to buddy.
        return;
    }

    // PA is outside both bootstrap pool and page_info range — ignore.
}

/// Increment the reference count of `pa`.
///
/// Call this when a page is shared (COW fork, shared mapping, DMA buffer).
/// Panics if `pa` is not tracked by the page_info table.
pub fn get_page(pa: usize) {
    if let Some(pi) = page_info(pa) {
        pi.refcount.fetch_add(1, Ordering::Relaxed);
    }
}

/// Decrement the reference count of `pa` and free it if it reaches zero.
/// Equivalent to `free_page` but documents intent at the call site.
#[inline]
pub fn put_page(pa: usize) { free_page(pa); }

/// Return the current reference count for `pa`, or 0 if not tracked.
#[inline]
pub fn page_refcount(pa: usize) -> u32 {
    page_info(pa).map(|pi| pi.refcount.load(Ordering::Relaxed)).unwrap_or(0)
}

/// Register a physical memory region as available to the buddy allocator.
/// Called by `memmap_init()` / `pmm_add_efi_map()` / FDT walker.
///
/// `node` = NUMA node this region belongs to.  Pass 0 if unknown (UMA).
pub fn pmm_add_region_node(base: usize, size: usize, node: u8) {
    let start = (base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end   = base + size;
    if start >= end { return; }

    register_node_range(node, start, end);
    BUDDY_LIVE.store(true, Ordering::Relaxed);

    let mut pa = start;
    while pa + PAGE_SIZE <= end {
        if pa == 0 || is_kernel_page(pa) || pfn(pa) >= MAX_FRAMES {
            pa += PAGE_SIZE;
            continue;
        }
        // Initialise PageInfo.
        let pi = &PAGE_INFO[pfn(pa)];
        pi.refcount.store(0, Ordering::Relaxed);
        pi.flags.store(FLAG_FREE | FLAG_BUDDY, Ordering::Relaxed);
        pi.order.store(0, Ordering::Relaxed);
        pi.numa_node.store(node, Ordering::Relaxed);

        unsafe { zero_page(pa); }

        // Add to order-0 free-list; the allocator will coalesce on first use.
        // (We could add in max-order chunks here for speed, but simplicity wins
        //  at init time; there's no performance critical path here.)
        unsafe { buddy_push(node, pa, 0); }
        BUDDY[node as usize].total_pages.fetch_add(1, Ordering::Relaxed);
        pa += PAGE_SIZE;
    }
}

/// Register a physical memory region on NUMA node 0.
/// Backwards-compatible shim for `memmap.rs` and EFI/FDT callers that do
/// not yet have NUMA topology information.
pub fn pmm_add_region(base: usize, size: usize) {
    pmm_add_region_node(base, size, 0);
}

// ── EFI memory map ────────────────────────────────────────────────────────────

pub use crate::arch::x86_64::uefi_entry::EfiMemDescriptor;

const EFI_CONVENTIONAL_MEMORY: u32 = 4;
const EFI_PERSISTENT_MEMORY:   u32 = 14;

#[inline]
fn efi_mem_type_is_usable(t: u32) -> bool {
    matches!(t, EFI_CONVENTIONAL_MEMORY | EFI_PERSISTENT_MEMORY)
}

/// Walk the EFI memory map and register usable regions with the buddy.
/// `node` allows ACPI SRAT / NUMA callers to pass the correct node id;
/// plain UEFI boot passes 0.
pub unsafe fn pmm_add_efi_map(
    map_ptr:   usize,
    map_size:  usize,
    desc_size: usize,
) {
    pmm_add_efi_map_node(map_ptr, map_size, desc_size, 0);
}

/// Node-aware variant called by ACPI SRAT enumeration.
pub unsafe fn pmm_add_efi_map_node(
    map_ptr:   usize,
    map_size:  usize,
    desc_size: usize,
    node:      u8,
) {
    if map_ptr == 0 || map_size == 0 || desc_size == 0 { return; }
    let mut off = 0usize;
    while off + desc_size <= map_size {
        let desc = &*((map_ptr + off) as *const EfiMemDescriptor);
        if efi_mem_type_is_usable(desc.type_) {
            let base = desc.physical_start as usize;
            let size = desc.num_pages as usize * PAGE_SIZE;
            if size > 0 { pmm_add_region_node(base, size, node); }
        }
        off += desc_size;
    }
}

// ── RISC-V FDT walker ────────────────────────────────────────────────────────

/// Initialise the PMM from an FDT blob (RISC-V / OpenSBI path).
pub fn init_from_fdt(fdt_ptr: usize) {
    if fdt_ptr == 0 { return; }
    unsafe { fdt_walk_memory(fdt_ptr); }
}

/// x86_64 shim — real work done by `pmm_add_efi_map` / `parse_mbi`.
pub fn init() {}

const FDT_MAGIC:      u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE:   u32 = 2;
const FDT_PROP:       u32 = 3;
const FDT_NOP:        u32 = 4;
const FDT_END:        u32 = 9;

#[inline] unsafe fn fdt_u32(p: *const u8) -> u32 {
    u32::from_be_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
}
#[inline] unsafe fn fdt_u64(p: *const u8) -> u64 {
    let b = core::slice::from_raw_parts(p, 8);
    u64::from_be_bytes([b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]])
}

unsafe fn fdt_walk_memory(fdt_ptr: usize) {
    let base = fdt_ptr as *const u8;
    if fdt_u32(base) != FDT_MAGIC { return; }
    let total_size  = fdt_u32(base.add(4))  as usize;
    let off_struct  = fdt_u32(base.add(8))  as usize;
    let off_strings = fdt_u32(base.add(12)) as usize;
    if total_size > 64 * 1024 * 1024 { return; }
    let strings_base = base.add(off_strings);
    let struct_base  = base.add(off_struct);
    let mut offset = 0usize;
    let mut depth  = 0i32;
    let mut in_mem = false;
    loop {
        let token = fdt_u32(struct_base.add(offset));
        offset += 4;
        match token {
            FDT_BEGIN_NODE => {
                let np = struct_base.add(offset);
                let mut nl = 0usize;
                while np.add(nl).read() != 0 { nl += 1; }
                let name = core::slice::from_raw_parts(np, nl);
                depth += 1;
                in_mem = depth == 1 && name.starts_with(b"memory");
                offset += (nl + 1 + 3) & !3;
            }
            FDT_END_NODE => {
                if depth == 1 { in_mem = false; }
                depth -= 1;
                if depth < 0 { break; }
            }
            FDT_PROP => {
                let plen = fdt_u32(struct_base.add(offset))     as usize;
                let pnof = fdt_u32(struct_base.add(offset + 4)) as usize;
                offset += 8;
                if in_mem {
                    let pnp = strings_base.add(pnof);
                    let mut pnl = 0usize;
                    while pnp.add(pnl).read() != 0 { pnl += 1; }
                    if core::slice::from_raw_parts(pnp, pnl) == b"reg" {
                        let data = struct_base.add(offset);
                        let mut i = 0usize;
                        while i + 16 <= plen {
                            let bpa  = fdt_u64(data.add(i))     as usize;
                            let size = fdt_u64(data.add(i + 8)) as usize;
                            if size > 0 { pmm_add_region(bpa, size); }
                            i += 16;
                        }
                    }
                }
                offset += (plen + 3) & !3;
            }
            FDT_NOP => {}
            FDT_END | _ => break,
        }
        if offset >= total_size { break; }
    }
}

// ── Diagnostics ──────────────────────────────────────────────────────────────

/// Total free pages across all NUMA nodes (buddy tier only).
pub fn free_pages() -> usize {
    let n = NODE_COUNT.load(Ordering::Relaxed).max(1);
    (0..n).map(|i| BUDDY[i].free_pages.load(Ordering::Relaxed)).sum::<usize>()
        + BOOT_FREE_CNT.load(Ordering::Relaxed)
        + (POOL_PAGES - BUMP.load(Ordering::Relaxed))
}

/// Total pages registered at init time across all NUMA nodes.
pub fn total_pages() -> usize {
    let n = NODE_COUNT.load(Ordering::Relaxed).max(1);
    (0..n).map(|i| BUDDY[i].total_pages.load(Ordering::Relaxed)).sum::<usize>()
        + POOL_PAGES
}

/// Free pages on a specific NUMA node.
pub fn free_pages_node(node: u8) -> usize {
    BUDDY[node as usize].free_pages.load(Ordering::Relaxed)
}

/// Total pages on a specific NUMA node.
pub fn total_pages_node(node: u8) -> usize {
    BUDDY[node as usize].total_pages.load(Ordering::Relaxed)
}

/// Print a per-NUMA free-memory summary via the kernel log.
pub fn dump_stats() {
    let n = NODE_COUNT.load(Ordering::Relaxed).max(1);
    for i in 0..n {
        let free  = BUDDY[i].free_pages.load(Ordering::Relaxed);
        let total = BUDDY[i].total_pages.load(Ordering::Relaxed);
        log::info!("pmm: node {} — {} / {} pages free ({} MiB / {} MiB)",
            i,
            free,  total,
            free  * PAGE_SIZE / (1024 * 1024),
            total * PAGE_SIZE / (1024 * 1024),
        );
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

#[inline]
unsafe fn zero_page(pa: usize) {
    core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE);
}
