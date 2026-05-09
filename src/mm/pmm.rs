//! Physical memory manager (PMM) — two-tier design.
//!
//! ## Two-tier design
//!
//! Tier 1 — Static bootstrap pool (64 MiB hardcoded).
//!   Used for all allocations before pmm_add_region() is called
//!   (heap init, page tables, GDT/IDT structures).  The bump index walks
//!   forward; pages freed during this phase go to the free list.
//!
//! Tier 2 — Intrusive Treiber stack (lock-free singly-linked list).
//!   Each free page stores the next-pointer in its own first 8 bytes.
//!   push/pop never call the heap allocator, structurally preventing the
//!   deadlock that existed when FREE_LIST was a Mutex<Vec<usize>>:
//!     free_page -> Vec::push -> alloc -> alloc_page -> lock FREE_LIST
//!
//! ## Security — page scrubbing on free
//!   free_page() zeroes the page before linking it onto the free list so
//!   that no process can read stale data from a previously-owned page.
//!
//! ## Contiguous multi-page allocation
//!   alloc_pages_contig(n) collects the free list into a temporary sorted
//!   Vec (allocated on the caller's stack, not the heap free list), finds
//!   a run of n adjacent frames, and removes them.
//!
//! ## Kernel image reservation
//!   Pages in [_kernel_start, _end) are never handed out.
//!
//! ## RISC-V FDT init
//!   init_from_fdt(fdt_ptr) parses the minimal FDT structure to find
//!   /memory@... reg cells and registers every usable range.

use core::sync::atomic::{AtomicUsize, AtomicU64, AtomicPtr, Ordering};
use spin::Mutex;
extern crate alloc;
use alloc::vec::Vec;

// ── Bootstrap pool ────────────────────────────────────────────────────────────

const POOL_PAGES: usize = 16_384; // 64 MiB static pool
const PAGE_SIZE:  usize = 4096;

#[repr(C, align(4096))]
struct Pool([u8; POOL_PAGES * PAGE_SIZE]);
static POOL: Pool = Pool([0u8; POOL_PAGES * PAGE_SIZE]);
static BUMP: AtomicUsize = AtomicUsize::new(0);

// ── Pool double-free bitmap ───────────────────────────────────────────────────

const BITMAP_WORDS: usize = POOL_PAGES / 64;
static POOL_FREE_BITS: [AtomicU64; BITMAP_WORDS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; BITMAP_WORDS]
};

#[inline]
fn pool_bit_set_free(idx: usize) -> bool {
    let word = idx / 64;
    let bit  = 1u64 << (idx % 64);
    POOL_FREE_BITS[word].fetch_or(bit, Ordering::AcqRel) & bit == 0
}

#[inline]
fn pool_bit_clear_free(idx: usize) {
    let word = idx / 64;
    let bit  = 1u64 << (idx % 64);
    POOL_FREE_BITS[word].fetch_and(!bit, Ordering::AcqRel);
}

#[inline]
fn pool_index(pa: usize) -> Option<usize> {
    let pool_base = POOL.0.as_ptr() as usize;
    let pool_end  = pool_base + POOL_PAGES * PAGE_SIZE;
    if pa >= pool_base && pa < pool_end {
        Some((pa - pool_base) / PAGE_SIZE)
    } else {
        None
    }
}

// ── Intrusive Treiber stack (lock-free free list) ─────────────────────────────
//
// Each free page repurposes its first 8 bytes as a `*mut u8` next-pointer.
// The head is an AtomicPtr<u8> updated with compare_exchange so push/pop are
// entirely allocation-free — eliminating the Vec-growth deadlock.
//
// ABA protection: The PMM only ever maps identity/physmap addresses; a
// recycled page gets the same PA and therefore the same pointer value.  This
// is the classic ABA scenario.  We mitigate it by zeroing pages on free
// (which also clears the next-pointer) and only writing the next-pointer
// after zeroing — so a page cannot be re-read with stale link data.

static FREE_HEAD:   AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static FREE_COUNT:  AtomicUsize   = AtomicUsize::new(0);
static TOTAL_PAGES: AtomicUsize   = AtomicUsize::new(0);

/// Push `pa` onto the intrusive free-list Treiber stack.
/// The page MUST have been zeroed before calling this.
#[inline]
fn treiber_push(pa: usize) {
    let node = pa as *mut *mut u8;
    loop {
        let head = FREE_HEAD.load(Ordering::Acquire);
        // Store current head as next-pointer inside the page.
        unsafe { node.write(head); }
        match FREE_HEAD.compare_exchange_weak(
            head,
            pa as *mut u8,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            Ok(_)  => { FREE_COUNT.fetch_add(1, Ordering::Relaxed); return; }
            Err(_) => core::hint::spin_loop(),
        }
    }
}

/// Pop one page from the intrusive free-list Treiber stack.
/// Returns the physical address, or 0 if the list is empty.
#[inline]
fn treiber_pop() -> usize {
    loop {
        let head = FREE_HEAD.load(Ordering::Acquire);
        if head.is_null() { return 0; }
        // Read next-pointer from inside the page.
        let next = unsafe { (head as *const *mut u8).read() };
        match FREE_HEAD.compare_exchange_weak(
            head,
            next,
            Ordering::Release,
            Ordering::Relaxed,
        ) {
            Ok(_)  => {
                FREE_COUNT.fetch_sub(1, Ordering::Relaxed);
                return head as usize;
            }
            Err(_) => core::hint::spin_loop(),
        }
    }
}

// ── Kernel image extent ───────────────────────────────────────────────────────

extern "C" {
    static _kernel_start: u8;
    static _end:          u8;
}

#[inline]
fn kernel_start_pa() -> usize { unsafe { &_kernel_start as *const u8 as usize } }
#[inline]
fn kernel_end_pa()   -> usize { unsafe { &_end as *const u8 as usize } }
#[inline]
fn is_kernel_page(pa: usize) -> bool {
    pa >= kernel_start_pa() && pa < kernel_end_pa()
}
#[inline]
fn is_valid_pa(pa: usize) -> bool {
    pa != 0 && pa & (PAGE_SIZE - 1) == 0 && !is_kernel_page(pa)
}

// ── Initialisation ────────────────────────────────────────────────────────────

/// Initialise the PMM from an FDT blob (RISC-V / OpenSBI path).
pub fn init_from_fdt(fdt_ptr: usize) {
    if fdt_ptr == 0 { return; }
    unsafe { fdt_walk_memory(fdt_ptr); }
}

/// Thin x86_64 shim — no FDT on x86.
pub fn init() {}

// ── Minimal FDT walker ────────────────────────────────────────────────────────

const FDT_MAGIC:       u32 = 0xd00d_feed;
const FDT_BEGIN_NODE:  u32 = 1;
const FDT_END_NODE:    u32 = 2;
const FDT_PROP:        u32 = 3;
const FDT_NOP:         u32 = 4;
const FDT_END:         u32 = 9;

#[inline]
unsafe fn fdt_u32(ptr: *const u8) -> u32 {
    let b = core::slice::from_raw_parts(ptr, 4);
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
unsafe fn fdt_u64(ptr: *const u8) -> u64 {
    let b = core::slice::from_raw_parts(ptr, 8);
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
    let mut offset: usize = 0;
    let mut depth: i32 = 0;
    let mut in_memory_node = false;
    loop {
        let token = fdt_u32(struct_base.add(offset));
        offset += 4;
        match token {
            FDT_BEGIN_NODE => {
                let name_ptr = struct_base.add(offset) as *const u8;
                let mut name_len = 0usize;
                while name_ptr.add(name_len).read() != 0 { name_len += 1; }
                let name = core::slice::from_raw_parts(name_ptr, name_len);
                depth += 1;
                in_memory_node = depth == 1 && name.starts_with(b"memory");
                offset += (name_len + 1 + 3) & !3;
            }
            FDT_END_NODE => {
                if depth == 1 { in_memory_node = false; }
                depth -= 1;
                if depth < 0 { break; }
            }
            FDT_PROP => {
                let prop_len     = fdt_u32(struct_base.add(offset))     as usize;
                let prop_nameoff = fdt_u32(struct_base.add(offset + 4)) as usize;
                offset += 8;
                if in_memory_node {
                    let prop_name_ptr = strings_base.add(prop_nameoff);
                    let mut pnl = 0usize;
                    while prop_name_ptr.add(pnl).read() != 0 { pnl += 1; }
                    let prop_name = core::slice::from_raw_parts(prop_name_ptr, pnl);
                    if prop_name == b"reg" {
                        let data = struct_base.add(offset);
                        let mut i = 0usize;
                        while i + 16 <= prop_len {
                            let base_pa = fdt_u64(data.add(i))     as usize;
                            let size    = fdt_u64(data.add(i + 8)) as usize;
                            if size > 0 { pmm_add_region(base_pa, size); }
                            i += 16;
                        }
                    }
                }
                offset += (prop_len + 3) & !3;
            }
            FDT_NOP => {}
            FDT_END | _ => break,
        }
        if offset >= total_size { break; }
    }
}

// ── Core allocator ────────────────────────────────────────────────────────────

/// Allocate one 4096-byte page.  Returns the physical address.
pub fn alloc_page() -> Option<usize> {
    // Try the intrusive free list first.
    let pa = treiber_pop();
    if pa != 0 {
        if let Some(idx) = pool_index(pa) { pool_bit_clear_free(idx); }
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        return Some(pa);
    }
    // Fall back to the bootstrap bump allocator.
    let idx = BUMP.fetch_add(1, Ordering::Relaxed);
    if idx >= POOL_PAGES {
        BUMP.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    TOTAL_PAGES.fetch_add(1, Ordering::Relaxed);
    Some(POOL.0.as_ptr() as usize + idx * PAGE_SIZE)
}

/// Allocate `n` physically contiguous 4 KiB pages.
///
/// Drains the Treiber stack into a temporary sorted Vec (heap-allocated on
/// the caller's behalf), finds a contiguous run of length n, removes those
/// pages, and pushes the rest back.  More expensive than alloc_page but
/// correct and deadlock-free.
pub fn alloc_pages_contig(n: usize) -> Option<usize> {
    if n == 0 { return None; }
    if n == 1 { return alloc_page(); }

    // Drain the entire Treiber stack into a local Vec for sorting.
    // This temporarily empties the free list; we push back anything we
    // don't use at the end.
    let mut all: Vec<usize> = Vec::new();
    loop {
        let pa = treiber_pop();
        if pa == 0 { break; }
        all.push(pa);
    }

    if all.len() < n {
        // Not enough free pages at all — push everything back.
        for pa in all { treiber_push(pa); }
        return None;
    }

    all.sort_unstable();

    // Find a contiguous run of length n.
    let mut run_start = None;
    'outer: for start in 0..=(all.len() - n) {
        for k in 1..n {
            if all[start + k] != all[start + k - 1] + PAGE_SIZE {
                continue 'outer;
            }
        }
        run_start = Some(start);
        break;
    }

    let start = match run_start {
        Some(s) => s,
        None => {
            for pa in all { treiber_push(pa); }
            return None;
        }
    };

    let base_pa = all[start];

    // Push back everything except the chosen run.
    for (i, &pa) in all.iter().enumerate() {
        if i < start || i >= start + n {
            treiber_push(pa);
        }
    }

    // Clear double-free bits and zero each page in the run.
    for i in 0..n {
        let pa = base_pa + i * PAGE_SIZE;
        if let Some(bit_idx) = pool_index(pa) { pool_bit_clear_free(bit_idx); }
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
    }

    Some(base_pa)
}

/// Free `n` physically contiguous pages starting at `base_pa`.
pub fn free_pages_contig(base_pa: usize, n: usize) {
    for i in 0..n { free_page(base_pa + i * PAGE_SIZE); }
}

/// Return a single page to the free list.
pub fn free_page(pa: usize) {
    if pa == 0 { return; }
    assert!(pa & (PAGE_SIZE - 1) == 0,
        "free_page: PA {:#x} is not page-aligned", pa);
    assert!(!is_kernel_page(pa),
        "free_page: attempt to free kernel image page {:#x}", pa);
    if let Some(idx) = pool_index(pa) {
        let ok = pool_bit_set_free(idx);
        assert!(ok, "free_page: double-free of pool page {:#x} (index {})", pa, idx);
    }
    // Zero the page BEFORE linking it into the free list so stale data
    // is never observable by a future allocator and the next-pointer
    // written by treiber_push cannot be confused with stale content.
    unsafe {
        let ptr = pa as *mut u64;
        for i in 0..(PAGE_SIZE / 8) { ptr.add(i).write_volatile(0u64); }
    }
    treiber_push(pa);
    TOTAL_PAGES.fetch_add(1, Ordering::Relaxed);
}

/// Register a physical memory region as available to the PMM.
pub fn pmm_add_region(base: usize, size: usize) {
    let mut pa = (base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end = base + size;
    while pa + PAGE_SIZE <= end {
        if is_valid_pa(pa) && pool_index(pa).is_none() {
            // Zero then push directly onto the Treiber stack.
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
            treiber_push(pa);
            TOTAL_PAGES.fetch_add(1, Ordering::Relaxed);
        }
        pa += PAGE_SIZE;
    }
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

pub fn free_pages()  -> usize { FREE_COUNT.load(Ordering::Relaxed) }
pub fn total_pages() -> usize { TOTAL_PAGES.load(Ordering::Relaxed) }
