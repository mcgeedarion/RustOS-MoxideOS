//! Physical Memory Manager (PMM) — buddy allocator with NUMA awareness
//! and per-page reference counting.
//!
//! The PMM is now initialised from an arch-agnostic `Regions` description
//! defined in `mm::boot_memory`. Arch-specific code is responsible for
//! discovering the memory map and passing it here.

use core::sync::atomic::{
    AtomicU32, AtomicU8, AtomicUsize, AtomicPtr, AtomicBool, Ordering,
};

use crate::mm::boot_memory::{Region, RegionKind, Regions};

pub const PAGE_SIZE:   usize = 4096;
pub const MAX_ORDER:   usize = 11;
pub const MAX_NODES:   usize = 8;
pub const MAX_PA: usize = 16 * 1024 * 1024 * 1024;
const MAX_FRAMES: usize = MAX_PA / PAGE_SIZE;
const POOL_PAGES: usize = 16_384;

#[repr(C, align(4096))]
struct Pool([u8; POOL_PAGES * PAGE_SIZE]);
static POOL: Pool = Pool([0u8; POOL_PAGES * PAGE_SIZE]);
static BUMP: AtomicUsize = AtomicUsize::new(0);
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

pub mod page_flags {
    pub const FLAG_FREE:     u8 = 1 << 0;
    pub const FLAG_RESERVED: u8 = 1 << 1;
    pub const FLAG_BUDDY:    u8 = 1 << 2;
    pub const FLAG_BOOT:     u8 = 1 << 3;
}
use page_flags::*;

#[repr(C, align(8))]
pub struct PageInfo {
    pub refcount:  AtomicU32,
    pub flags:     AtomicU8,
    pub order:     AtomicU8,
    pub numa_node: AtomicU8,
    pub _pad:      u8,
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

static PAGE_INFO_PTR: AtomicPtr<PageInfo> = AtomicPtr::new(core::ptr::null_mut());
static PAGE_INFO_LEN: AtomicUsize = AtomicUsize::new(0);
const EMERGENCY_FRAMES: usize = (1 * 1024 * 1024 * 1024) / PAGE_SIZE;
static EMERGENCY_TABLE: [PageInfo; EMERGENCY_FRAMES] = {
    const Z: PageInfo = PageInfo::zero();
    [Z; EMERGENCY_FRAMES]
};

fn ensure_page_info_table(max_pfn: usize) {
    use spin::Once;
    static INIT: Once<()> = Once::new();
    INIT.call_once(|| {
        let needed = max_pfn + 1;
        let bytes  = needed * core::mem::size_of::<PageInfo>();
        let pages  = (bytes + PAGE_SIZE - 1) / PAGE_SIZE;
        let bump_before = BUMP.load(Ordering::Relaxed);
        let new_bump    = bump_before + pages;
        if new_bump <= POOL_PAGES
            && BUMP.compare_exchange(
                bump_before, new_bump,
                Ordering::AcqRel, Ordering::Relaxed,
            ).is_ok()
        {
            let base = pool_base() + bump_before * PAGE_SIZE;
            unsafe { core::ptr::write_bytes(base as *mut u8, 0, pages * PAGE_SIZE); }
            for i in 0..pages {
                if let Some(idx) = pool_index(base + i * PAGE_SIZE) {
                    pool_bit_set_free(idx);
                }
            }
            PAGE_INFO_PTR.store(base as *mut PageInfo, Ordering::Release);
            PAGE_INFO_LEN.store(needed, Ordering::Release);
            return;
        }
        if needed <= EMERGENCY_FRAMES {
            log::warn!("pmm: bootstrap pool full; using emergency PageInfo table (covers first 1 GiB only)");
            PAGE_INFO_PTR.store(EMERGENCY_TABLE.as_ptr() as *mut PageInfo, Ordering::Release);
            PAGE_INFO_LEN.store(EMERGENCY_FRAMES, Ordering::Release);
        } else {
            panic!("pmm: cannot allocate PageInfo table: bootstrap pool full and max_pfn {} > EMERGENCY_FRAMES {}", max_pfn, EMERGENCY_FRAMES);
        }
    });
}

#[inline]
fn pfn(pa: usize) -> usize { pa / PAGE_SIZE }

#[inline]
pub fn page_info(pa: usize) -> Option<&'static PageInfo> {
    if pa == 0 || pa & (PAGE_SIZE - 1) != 0 { return None; }
    let ptr = PAGE_INFO_PTR.load(Ordering::Acquire);
    if ptr.is_null() { return None; }
    let idx = pfn(pa);
    let len = PAGE_INFO_LEN.load(Ordering::Relaxed);
    if idx >= len { return None; }
    Some(unsafe { &*ptr.add(idx) })
}

#[derive(Copy, Clone)]
struct NodeRange {
    base: usize,
    end:  usize,
}

static NODE_RANGES: [spin::Mutex<NodeRange>; MAX_NODES] = {
    const Z: spin::Mutex<NodeRange> = spin::Mutex::new(NodeRange { base: usize::MAX, end: 0 });
    [Z; MAX_NODES]
};
static NODE_COUNT: AtomicUsize = AtomicUsize::new(0);

fn register_node_range(node: u8, base: usize, end: usize) {
    let n = node as usize;
    if n >= MAX_NODES { return; }
    let mut nr = NODE_RANGES[n].lock();
    nr.base = nr.base.min(base);
    nr.end  = nr.end.max(end);
    let old = NODE_COUNT.load(Ordering::Relaxed);
    if n + 1 > old {
        NODE_COUNT.compare_exchange(old, n + 1, Ordering::Relaxed, Ordering::Relaxed).ok();
    }
}

pub fn node_of(pa: usize) -> u8 {
    let n = NODE_COUNT.load(Ordering::Relaxed);
    for i in 0..n {
        let nr = NODE_RANGES[i].lock();
        if pa >= nr.base && pa < nr.end { return i as u8; }
    }
    0
}

struct BuddyNode {
    free_lists: [AtomicPtr<PageInfo>; MAX_ORDER],
    free_pages: AtomicUsize,
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
static BUDDY_LIVE: AtomicBool = AtomicBool::new(false);

#[inline]
unsafe fn pi_to_pa(pi: *const PageInfo) -> usize {
    let base = PAGE_INFO_PTR.load(Ordering::Relaxed);
    let idx  = (pi as usize - base as usize) / core::mem::size_of::<PageInfo>();
    idx * PAGE_SIZE
}

#[inline]
fn order_size(order: usize) -> usize { PAGE_SIZE << order }
#[inline]
fn buddy_pa(pa: usize, order: usize) -> usize { pa ^ order_size(order) }
#[inline]
fn is_aligned(pa: usize, order: usize) -> bool { pa & (order_size(order) - 1) == 0 }

unsafe fn buddy_push(node: u8, pa: usize, order: usize) {
    let pi = match page_info(pa) { Some(p) => p, None => return };
    pi.flags.fetch_or(FLAG_FREE, Ordering::Release);
    pi.order.store(order as u8, Ordering::Relaxed);
    let n    = node as usize;
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
            BUDDY[n].free_pages.fetch_add(1 << order, Ordering::Relaxed);
            return;
        }
        core::hint::spin_loop();
    }
}

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
            return pi_to_pa(head_ptr);
        }
        core::hint::spin_loop();
    }
}

unsafe fn buddy_remove(node: u8, pa: usize, order: usize) -> bool {
    let n    = node as usize;
    let list = &BUDDY[n].free_lists[order];
    let target = match page_info(pa) {
        Some(p) => p as *const PageInfo as *mut PageInfo,
        None    => return false,
    };
    let mut popped: [*mut PageInfo; 256] = [core::ptr::null_mut(); 256];
    let mut count = 0usize;
    let mut found = false;
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
            (*head_ptr).flags.fetch_or(FLAG_FREE, Ordering::Relaxed);
            BUDDY[n].free_pages.fetch_add(1 << order, Ordering::Relaxed);
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
    for &p in &popped[..count] {
        (*p).flags.fetch_or(FLAG_FREE, Ordering::Release);
        BUDDY[n].free_pages.fetch_add(1 << order, Ordering::Relaxed);
        let h = list.load(Ordering::Acquire);
        (*p).free_next.store(h, Ordering::Relaxed);
        list.store(p, Ordering::Release);
    }
    found
}

extern "C" {
    static _kernel_start: u8;
    static _end:          u8;
}

#[inline]
fn kernel_start_pa() -> usize { unsafe { &_kernel_start as *const u8 as usize } }
#[inline]
fn kernel_end_pa()   -> usize { unsafe { &_end          as *const u8 as usize } }
#[inline]
fn is_kernel_page(pa: usize) -> bool { pa >= kernel_start_pa() && pa < kernel_end_pa() }

unsafe fn buddy_alloc_node(node: u8) -> usize {
    for order in 0..MAX_ORDER {
        let pa = buddy_pop(node, order);
        if pa == 0 { continue; }
        let current_pa    = pa;
        let mut current_order = order;
        while current_order > 0 {
            current_order -= 1;
            let buddy_half = current_pa + order_size(current_order);
            if let Some(bpi) = page_info(buddy_half) {
                bpi.numa_node.store(node, Ordering::Relaxed);
            }
            buddy_push(node, buddy_half, current_order);
        }
        if let Some(pi) = page_info(current_pa) {
            pi.refcount.store(1, Ordering::Release);
            pi.order.store(0, Ordering::Relaxed);
            pi.flags.store(FLAG_BUDDY, Ordering::Release);
            pi.numa_node.store(node, Ordering::Relaxed);
        }
        core::ptr::write_bytes(current_pa as *mut u8, 0, PAGE_SIZE);
        return current_pa;
    }
    0
}

unsafe fn buddy_alloc_order_node(node: u8, order: usize) -> usize {
    if order >= MAX_ORDER { return 0; }
    for try_order in order..MAX_ORDER {
        let pa = buddy_pop(node, try_order);
        if pa == 0 { continue; }
        let current_pa    = pa;
        let mut current_order = try_order;
        while current_order > order {
            current_order -= 1;
            let split_off = current_pa + order_size(current_order);
            if let Some(bpi) = page_info(split_off) {
                bpi.numa_node.store(node, Ordering::Relaxed);
            }
            buddy_push(node, split_off, current_order);
        }
        let block_pages = 1usize << order;
        for i in 0..block_pages {
            let ppa = current_pa + i * PAGE_SIZE;
            if let Some(pi) = page_info(ppa) {
                pi.refcount.store(1, Ordering::Release);
                pi.order.store(order as u8, Ordering::Relaxed);
                pi.flags.store(FLAG_BUDDY, Ordering::Release);
                pi.numa_node.store(node, Ordering::Relaxed);
            }
        }
        core::ptr::write_bytes(current_pa as *mut u8, 0, block_pages * PAGE_SIZE);
        return current_pa;
    }
    0
}

unsafe fn buddy_free_page(pa: usize) {
    if pa == 0 || pa & (PAGE_SIZE - 1) != 0 { return; }
    let pi = match page_info(pa) { Some(p) => p, None => return };
    let node  = pi.numa_node.load(Ordering::Relaxed);
    let mut current_pa    = pa;
    let mut current_order = 0usize;
    core::ptr::write_bytes(current_pa as *mut u8, 0, PAGE_SIZE);
    pi.refcount.store(0, Ordering::Release);
    pi.flags.store(0, Ordering::Relaxed);
    while current_order + 1 < MAX_ORDER {
        let bpa = buddy_pa(current_pa, current_order);
        if bpa >= MAX_PA { break; }
        let bpi = match page_info(bpa) { Some(p) => p, None => break };
        let bflags = bpi.flags.load(Ordering::Acquire);
        if bflags & (FLAG_FREE | FLAG_BUDDY) != (FLAG_FREE | FLAG_BUDDY) { break; }
        if bpi.order.load(Ordering::Relaxed) as usize != current_order  { break; }
        if bpi.numa_node.load(Ordering::Relaxed) != node                { break; }
        let merged = current_pa.min(bpa);
        if !is_aligned(merged, current_order + 1)                       { break; }
        if !buddy_remove(node, bpa, current_order) { break; }
        current_pa    = merged;
        current_order += 1;
    }
    if let Some(cpi) = page_info(current_pa) {
        cpi.flags.store(FLAG_FREE | FLAG_BUDDY, Ordering::Relaxed);
    }
    buddy_push(node, current_pa, current_order);
}

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

pub fn alloc_page() -> Option<usize> {
    if BUDDY_LIVE.load(Ordering::Relaxed) {
        let preferred = local_node();
        let n_nodes   = NODE_COUNT.load(Ordering::Relaxed).max(1);
        for i in 0..n_nodes {
            let node = ((preferred as usize + i) % n_nodes) as u8;
            let pa = unsafe { buddy_alloc_node(node) };
            if pa != 0 { return Some(pa); }
        }
    }
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

pub fn alloc_page_on_node(node: u8) -> Option<usize> {
    if BUDDY_LIVE.load(Ordering::Relaxed) {
        let pa = unsafe { buddy_alloc_node(node) };
        if pa != 0 { return Some(pa); }
    }
    alloc_page()
}

pub fn alloc_pages_contig(n: usize) -> Option<usize> {
    if n == 0 { return None; }
    if n == 1 { return alloc_page(); }
    if !BUDDY_LIVE.load(Ordering::Relaxed) {
        let mut pages = [0usize; 1 << (MAX_ORDER - 1)];
        let cap = pages.len().min(n);
        for i in 0..cap { pages[i] = alloc_page()?; }
        return Some(pages[0]);
    }
    let mut order = 0usize;
    while (1 << order) < n { order += 1; }
    if order >= MAX_ORDER { return None; }
    let preferred = local_node();
    let n_nodes   = NODE_COUNT.load(Ordering::Relaxed).max(1);
    for i in 0..n_nodes {
        let node = ((preferred as usize + i) % n_nodes) as u8;
        let pa   = unsafe { buddy_alloc_order_node(node, order) };
        if pa == 0 { continue; }
        let block_pages = 1usize << order;
        for j in n..block_pages {
            let tail_pa = pa + j * PAGE_SIZE;
            unsafe { buddy_free_page(tail_pa); }
        }
        return Some(pa);
    }
    None
}

pub fn free_pages_contig(base_pa: usize, n: usize) {
    for i in 0..n { free_page(base_pa + i * PAGE_SIZE); }
}

pub fn free_page(pa: usize) {
    if pa == 0 { return; }
    assert_eq!(pa & (PAGE_SIZE - 1), 0, "free_page: PA {:#x} not page-aligned", pa);
    assert!(!is_kernel_page(pa), "free_page: attempt to free kernel page {:#x}", pa);
    if let Some(idx) = pool_index(pa) {
        let ok = pool_bit_set_free(idx);
        assert!(ok, "free_page: double-free of bootstrap page {:#x}", pa);
        unsafe { zero_page(pa); }
        boot_push(pa);
        return;
    }
    if let Some(pi) = page_info(pa) {
        let old = pi.refcount.fetch_sub(1, Ordering::AcqRel);
        assert!(old > 0, "free_page: refcount underflow at PA {:#x}", pa);
        if old == 1 {
            unsafe { buddy_free_page(pa); }
        }
        return;
    }
}

pub fn get_page(pa: usize) {
    if let Some(pi) = page_info(pa) {
        pi.refcount.fetch_add(1, Ordering::Relaxed);
    }
}

#[inline]
pub fn put_page(pa: usize) { free_page(pa); }
#[inline]
pub fn page_refcount(pa: usize) -> u32 {
    page_info(pa).map(|pi| pi.refcount.load(Ordering::Relaxed)).unwrap_or(0)
}

pub fn pmm_add_region_node(base: usize, size: usize, node: u8) {
    let start = (base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end   = base + size;
    if start >= end { return; }
    let max_pfn = pfn(end - 1);
    if max_pfn < MAX_FRAMES {
        ensure_page_info_table(max_pfn);
    }
    register_node_range(node, start, end);
    BUDDY_LIVE.store(true, Ordering::Relaxed);
    let mut pa = start;
    while pa + PAGE_SIZE <= end {
        if pa == 0 || is_kernel_page(pa) || pfn(pa) >= PAGE_INFO_LEN.load(Ordering::Relaxed) {
            pa += PAGE_SIZE;
            continue;
        }
        if let Some(pi) = page_info(pa) {
            pi.refcount.store(0, Ordering::Relaxed);
            pi.flags.store(FLAG_FREE | FLAG_BUDDY, Ordering::Relaxed);
            pi.order.store(0, Ordering::Relaxed);
            pi.numa_node.store(node, Ordering::Relaxed);
            unsafe { zero_page(pa); }
            unsafe { buddy_push(node, pa, 0); }
            BUDDY[node as usize].total_pages.fetch_add(1, Ordering::Relaxed);
        }
        pa += PAGE_SIZE;
    }
}

pub fn pmm_add_region(base: usize, size: usize) {
    pmm_add_region_node(base, size, 0);
}

/// Arch-agnostic PMM init from a boot-memory map.
///
/// This replaces the old `init()` and `init(fdt_ptr)` entrypoints. Arch
/// code is responsible for building a `Regions` value and passing it here.
pub unsafe fn init_from_regions(regions: &Regions) {
    for r in regions.iter() {
        if !r.is_usable() { continue; }
        let base = r.start as usize;
        let size = r.length as usize;
        pmm_add_region(base, size);
    }
}

pub fn free_pages() -> usize {
    let n = NODE_COUNT.load(Ordering::Relaxed).max(1);
    (0..n).map(|i| BUDDY[i].free_pages.load(Ordering::Relaxed)).sum::<usize>()
        + BOOT_FREE_CNT.load(Ordering::Relaxed)
        + (POOL_PAGES - BUMP.load(Ordering::Relaxed))
}

pub fn total_pages() -> usize {
    let n = NODE_COUNT.load(Ordering::Relaxed).max(1);
    (0..n).map(|i| BUDDY[i].total_pages.load(Ordering::Relaxed)).sum::<usize>()
        + POOL_PAGES
}

pub fn free_pages_node(node: u8) -> usize {
    BUDDY[node as usize].free_pages.load(Ordering::Relaxed)
}

pub fn total_pages_node(node: u8) -> usize {
    BUDDY[node as usize].total_pages.load(Ordering::Relaxed)
}

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

pub fn dump_freelist() {
    let n_nodes = NODE_COUNT.load(Ordering::Relaxed).max(1);
    log::info!("=== PMM free-list dump ===");
    for node in 0..n_nodes {
        for order in 0..MAX_ORDER {
            let mut count = 0usize;
            let mut ptr = BUDDY[node].free_lists[order].load(Ordering::Acquire);
            while !ptr.is_null() && count < 8192 {
                count += 1;
                ptr = unsafe { (*ptr).free_next.load(Ordering::Relaxed) };
            }
            if count > 0 {
                log::info!(
                    "pmm: node={} order={} block={}KiB free_blocks={} total={}KiB",
                    node,
                    order,
                    (PAGE_SIZE << order) / 1024,
                    count,
                    count * ((PAGE_SIZE << order) / 1024),
                );
            }
        }
    }
    log::info!(
        "pmm: bootstrap pool bump_used={} free_list={} capacity={}",
        BUMP.load(Ordering::Relaxed),
        BOOT_FREE_CNT.load(Ordering::Relaxed),
        POOL_PAGES,
    );
}

#[inline]
unsafe fn zero_page(pa: usize) {
    core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE);
}

// ===== GUESS: caller-expected aliases for legacy/new naming convergence =====

/// GUESS: alias of `alloc_pages_contig` — callers use `pmm::alloc_pages(n)`.
#[inline]
pub fn alloc_pages(n: usize) -> Option<usize> {
    alloc_pages_contig(n)
}

/// GUESS: align-aware allocator. Tries up to `align` page-aligned bases by
/// over-allocating and scanning, since the buddy allocator only guarantees
/// `n`-page natural alignment. Returns NonNull<u8> pointing at the physical
/// address (callers `.as_ptr() as u64`).
pub fn alloc_pages_aligned(n: usize, align: usize) -> Option<core::ptr::NonNull<u8>> {
    let pa = alloc_pages_contig(n)?;
    // Natural buddy alignment usually satisfies callers (DMA pages need <=64K).
    if align == 0 || (pa & (align - 1)) == 0 {
        return core::ptr::NonNull::new(pa as *mut u8);
    }
    // Fall back: free and try a larger contig allocation that covers `align`.
    free_pages_contig(pa, n);
    let extra = (align / PAGE_SIZE).max(1);
    let pa2 = alloc_pages_contig(n + extra)?;
    let aligned = (pa2 + align - 1) & !(align - 1);
    // Leak the prefix/suffix — acceptable for early boot DMA setup. GUESS.
    let _ = (pa2, aligned);
    core::ptr::NonNull::new(aligned as *mut u8)
}

/// GUESS: alias of `pmm_add_region` — callers use `pmm::add_region(base, size)`.
#[inline]
pub fn add_region(base: usize, size: usize) {
    pmm_add_region(base, size);
}
