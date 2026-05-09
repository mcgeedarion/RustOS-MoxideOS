//! Physical memory manager (PMM) — two-tier design.
//!
//! ## Two-tier design
//!
//! Tier 1 — Static bootstrap pool (64 MiB hardcoded).
//!   Used for all allocations before pmm_add_region() is called
//!   (heap init, page tables, GDT/IDT structures).  The bump index walks
//!   forward; pages freed during this phase go to the free list.
//!
//! Tier 2 — Free list fed by the boot memory map.
//!   pmm_add_region(base, size) is called once per usable memory range
//!   from the UEFI memory map, Multiboot2 mmap tag, or FDT /memory node.
//!
//! ## Security — page scrubbing on free
//!   free_page() zeroes the page before pushing it onto the free list so
//!   that no process can read stale data from a previously-owned page.
//!
//! ## Kernel image reservation
//!   Pages in [_kernel_start, _end) are never handed out.
//!
//! ## RISC-V FDT init
//!   init_from_fdt(fdt_ptr) parses the minimal FDT structure to find
//!   /memory@... reg cells and registers every usable range.

use core::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use spin::Mutex;
extern crate alloc;
use alloc::vec::Vec;

// ── Bootstrap pool ────────────────────────────────────────────────────────

const POOL_PAGES: usize = 16_384; // 64 MiB static pool
const PAGE_SIZE:  usize = 4096;

#[repr(C, align(4096))]
struct Pool([u8; POOL_PAGES * PAGE_SIZE]);
static POOL: Pool = Pool([0u8; POOL_PAGES * PAGE_SIZE]);
static BUMP: AtomicUsize = AtomicUsize::new(0);

// ── Pool double-free bitmap ───────────────────────────────────────────────

const BITMAP_WORDS: usize = POOL_PAGES / 64;
static POOL_FREE_BITS: [AtomicU64; BITMAP_WORDS] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; BITMAP_WORDS]
};

#[inline]
fn pool_bit_set_free(idx: usize) -> bool {
    let word = idx / 64;
    let bit  = 1u64 << (idx % 64);
    POOL_FREE_BITS[word].fetch_or(bit, Ordering::Relaxed) & bit == 0
}

#[inline]
fn pool_bit_clear_free(idx: usize) {
    let word = idx / 64;
    let bit  = 1u64 << (idx % 64);
    POOL_FREE_BITS[word].fetch_and(!bit, Ordering::Relaxed);
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

// ── Free list ─────────────────────────────────────────────────────────────

static FREE_LIST:   Mutex<Vec<usize>> = Mutex::new(Vec::new());
static TOTAL_PAGES: AtomicUsize      = AtomicUsize::new(0);
static FREE_COUNT:  AtomicUsize      = AtomicUsize::new(0);

// ── Kernel image extent ───────────────────────────────────────────────────

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

// ── Initialisation ────────────────────────────────────────────────────────

/// Initialise the PMM from an FDT blob (RISC-V / OpenSBI path).
///
/// Walks every `/memory@*` node and registers its `reg` ranges.
/// If `fdt_ptr` is 0 or the blob is invalid, we silently fall back to the
/// 64 MiB bootstrap pool only.
pub fn init_from_fdt(fdt_ptr: usize) {
    if fdt_ptr == 0 { return; }
    // Safety: OpenSBI guarantees a valid FDT at this address in S-mode.
    unsafe { fdt_walk_memory(fdt_ptr); }
}

/// Thin x86_64 shim kept for compatibility — no FDT on x86.
pub fn init() {}

// ── Minimal FDT walker ────────────────────────────────────────────────────
//
// We only need to find /memory nodes and parse their `reg` property.
// A full DTB parser is overkill here; this handles the spec-compliant
// flat device tree structure produced by QEMU's OpenSBI.
//
// FDT blob layout (big-endian):
//   u32 magic (0xd00dfeed)
//   u32 totalsize
//   u32 off_dt_struct
//   u32 off_dt_strings
//   u32 off_mem_rsvmap
//   u32 version
//   u32 last_comp_version
//   u32 boot_cpuid_phys
//   u32 size_dt_strings
//   u32 size_dt_struct
//
// Structure tokens:
//   FDT_BEGIN_NODE = 1  — followed by NUL-terminated name
//   FDT_END_NODE   = 2
//   FDT_PROP       = 3  — followed by u32 len, u32 nameoff, then data
//   FDT_NOP        = 4
//   FDT_END        = 9

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

/// Walk the flat device tree and register all /memory nodes with the PMM.
unsafe fn fdt_walk_memory(fdt_ptr: usize) {
    let base = fdt_ptr as *const u8;

    // Validate magic.
    if fdt_u32(base) != FDT_MAGIC { return; }

    let total_size    = fdt_u32(base.add(4))  as usize;
    let off_struct    = fdt_u32(base.add(8))  as usize;
    let off_strings   = fdt_u32(base.add(12)) as usize;

    // Sanity caps to avoid runaway iteration on a corrupt blob.
    if total_size > 64 * 1024 * 1024 { return; }

    let strings_base = base.add(off_strings);
    let struct_base  = base.add(off_struct);

    let mut offset: usize = 0;
    // depth tracks nesting; we only look at depth-1 nodes (children of root).
    let mut depth: i32 = 0;
    let mut in_memory_node = false;

    loop {
        let token_ptr = struct_base.add(offset);
        let token = fdt_u32(token_ptr);
        offset += 4;

        match token {
            FDT_BEGIN_NODE => {
                // Read NUL-terminated node name.
                let name_ptr = struct_base.add(offset) as *const u8;
                let mut name_len = 0usize;
                while name_ptr.add(name_len).read() != 0 { name_len += 1; }
                let name = core::slice::from_raw_parts(name_ptr, name_len);

                depth += 1;
                // A memory node at depth 1 is a direct child of root.
                // Its name starts with "memory" (e.g. "memory@80000000").
                in_memory_node = depth == 1 && name.starts_with(b"memory");

                // Advance past name + NUL, aligned to 4 bytes.
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
                    // Check if property name is "reg".
                    let prop_name_ptr = strings_base.add(prop_nameoff);
                    let mut pnl = 0usize;
                    while prop_name_ptr.add(pnl).read() != 0 { pnl += 1; }
                    let prop_name = core::slice::from_raw_parts(prop_name_ptr, pnl);

                    if prop_name == b"reg" {
                        // QEMU virt machine uses #address-cells=2, #size-cells=2.
                        // Each reg entry is 2x u64 = 16 bytes: (base, size).
                        let data = struct_base.add(offset);
                        let mut i = 0usize;
                        while i + 16 <= prop_len {
                            let base_pa = fdt_u64(data.add(i))     as usize;
                            let size    = fdt_u64(data.add(i + 8)) as usize;
                            if size > 0 {
                                pmm_add_region(base_pa, size);
                            }
                            i += 16;
                        }
                    }
                }

                // Advance past property data, aligned to 4 bytes.
                offset += (prop_len + 3) & !3;
            }
            FDT_NOP => {}
            FDT_END | _ => break,
        }

        // Guard against running off the end of the struct block.
        if offset >= total_size { break; }
    }
}

// ── Core allocator ────────────────────────────────────────────────────────

/// Allocate one 4096-byte page.  Returns the physical (identity-mapped) address.
pub fn alloc_page() -> Option<usize> {
    let pa = if let Some(pa) = FREE_LIST.lock().pop() {
        FREE_COUNT.fetch_sub(1, Ordering::Relaxed);
        if let Some(idx) = pool_index(pa) { pool_bit_clear_free(idx); }
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        pa
    } else {
        let idx = BUMP.fetch_add(1, Ordering::Relaxed);
        if idx >= POOL_PAGES {
            BUMP.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        TOTAL_PAGES.fetch_add(1, Ordering::Relaxed);
        POOL.0.as_ptr() as usize + idx * PAGE_SIZE
    };
    Some(pa)
}

/// Return a page to the free list for reuse.
///
/// The page is zeroed before being pushed onto the free list to prevent
/// cross-process data leaks.
pub fn free_page(pa: usize) {
    if pa == 0 { return; }
    assert!(
        pa & (PAGE_SIZE - 1) == 0,
        "free_page: PA {:#x} is not page-aligned", pa
    );
    assert!(
        !is_kernel_page(pa),
        "free_page: attempt to free kernel image page {:#x}", pa
    );
    if let Some(idx) = pool_index(pa) {
        let ok = pool_bit_set_free(idx);
        assert!(ok, "free_page: double-free of pool page {:#x} (index {})", pa, idx);
    }
    unsafe {
        let ptr = pa as *mut u64;
        for i in 0..(PAGE_SIZE / 8) {
            ptr.add(i).write_volatile(0u64);
        }
    }
    let mut list = FREE_LIST.lock();
    list.push(pa);
    drop(list);
    FREE_COUNT.fetch_add(1, Ordering::Relaxed);
    TOTAL_PAGES.fetch_add(1, Ordering::Relaxed);
}

/// Register a physical memory region as available to the PMM.
///
/// Called once per usable entry in the UEFI / Multiboot2 / FDT memory map.
/// Pages overlapping the kernel image or the bootstrap pool are skipped.
pub fn pmm_add_region(base: usize, size: usize) {
    let mut pa = (base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end = base + size;
    while pa + PAGE_SIZE <= end {
        if is_valid_pa(pa) && pool_index(pa).is_none() {
            let mut list = FREE_LIST.lock();
            list.push(pa);
            drop(list);
            FREE_COUNT.fetch_add(1, Ordering::Relaxed);
            TOTAL_PAGES.fetch_add(1, Ordering::Relaxed);
        }
        pa += PAGE_SIZE;
    }
}

// ── Diagnostics ───────────────────────────────────────────────────────────

pub fn free_pages()  -> usize { FREE_COUNT.load(Ordering::Relaxed) }
pub fn total_pages() -> usize { TOTAL_PAGES.load(Ordering::Relaxed) }
