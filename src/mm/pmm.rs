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
//!   alloc_pages_contig(n) holds CONTIG_LOCK while it drains the Treiber
//!   stack into a temporary sorted Vec, finds a run of n adjacent frames,
//!   and removes them.  The lock prevents concurrent alloc_page() calls
//!   from racing with the drain/re-push sequence and producing duplicate
//!   page pointers.
//!
//! ## Kernel image reservation
//!   Pages in [_kernel_start, _end) are never handed out.
//!
//! ## EFI memory map filtering (x86_64 UEFI boot)
//!   pmm_add_efi_map() walks the EFI memory descriptor array saved by
//!   uefi_entry before ExitBootServices and only calls pmm_add_region()
//!   for EfiConventionalMemory (type 4) and EfiPersistentMemory (type 14)
//!   entries.  All firmware runtime regions, ACPI tables, MMIO ranges,
//!   and reserved pages are skipped, preventing NVRAM/runtime corruption.
//!
//! ## RISC-V FDT init
//!   init_from_fdt(fdt_ptr) parses the minimal FDT structure to find
//!   /memory@... reg cells and registers every usable range.
//!
//! ## TOTAL_PAGES semantics
//!   TOTAL_PAGES is a fixed watermark set at init time: every call to
//!   pmm_add_region() increments it by the number of pages registered.
//!   alloc_page() and free_page() do NOT touch TOTAL_PAGES — use
//!   free_pages() / total_pages() for current accounting.

use core::sync::atomic::{AtomicUsize, AtomicU64, AtomicPtr, AtomicBool, Ordering};
use spin::Mutex;
extern crate alloc;
use alloc::vec::Vec;

// ── Bootstrap pool ──────────────────────────────────────────────────────────────

const POOL_PAGES: usize = 16_384; // 64 MiB static pool
const PAGE_SIZE:  usize = 4096;

#[repr(C, align(4096))]
struct Pool([u8; POOL_PAGES * PAGE_SIZE]);
static POOL: Pool = Pool([0u8; POOL_PAGES * PAGE_SIZE]);
static BUMP: AtomicUsize = AtomicUsize::new(0);

// ── Pool double-free bitmap ──────────────────────────────────────────────────────

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

// ── Intrusive Treiber stack (lock-free free list) ─────────────────────────────────

static FREE_HEAD:   AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static FREE_COUNT:  AtomicUsize   = AtomicUsize::new(0);
/// Fixed watermark: total physical pages registered at init time.
/// Never modified by alloc_page() or free_page().
static TOTAL_PAGES: AtomicUsize   = AtomicUsize::new(0);

// ── Contiguous-allocation mutex ────────────────────────────────────────────────────
//
// alloc_pages_contig() drains the entire Treiber stack into a Vec, sorts it,
// finds a contiguous run, then re-pushes the remainder.  Without this lock a
// concurrent alloc_page() could pop a page between the drain and the re-push,
// see the stale next-pointer written during drain, and dereference garbage.
//
// We use a bare spin::Mutex<()> rather than a flag so that Rust's borrow
// checker enforces the critical section.
static CONTIG_LOCK: Mutex<()> = Mutex::new(());

#[inline]
fn treiber_push(pa: usize) {
    let node = pa as *mut *mut u8;
    loop {
        let head = FREE_HEAD.load(Ordering::Acquire);
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

#[inline]
fn treiber_pop() -> usize {
    loop {
        let head = FREE_HEAD.load(Ordering::Acquire);
        if head.is_null() { return 0; }
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

// ── Kernel image extent ────────────────────────────────────────────────────────────

extern "C" {
    static _kernel_start: u8;
    static _end:          u8;
}

#[inline]
fn kernel_start_pa() -> usize {
    unsafe { &_kernel_start as *const u8 as usize }
}
#[inline]
fn kernel_end_pa() -> usize {
    unsafe { &_end as *const u8 as usize }
}
#[inline]
fn is_kernel_page(pa: usize) -> bool {
    pa >= kernel_start_pa() && pa < kernel_end_pa()
}
#[inline]
fn is_valid_pa(pa: usize) -> bool {
    pa != 0 && pa & (PAGE_SIZE - 1) == 0 && !is_kernel_page(pa)
}

// ── EFI memory type constants (UEFI spec Table 7-6) ───────────────────────────────
//
// Only EfiConventionalMemory (4) and EfiPersistentMemory (14) are safe to
// hand to the PMM.  All other types are live firmware or hardware regions.
//
//   0  EfiReservedMemoryType
//   1  EfiLoaderCode           ← our own UEFI image; keep until we remap
//   2  EfiLoaderData           ← EFI pool allocs (map buffer, initrd buf)
//   3  EfiBootServicesCode     ← reclaimed *after* ExitBootServices
//   4  EfiConventionalMemory   ✔ free RAM
//   5  EfiUnusableMemory
//   6  EfiACPIReclaimMemory    ← ACPI tables; reclaim after parsing
//   7  EfiACPIMemoryNVS        ← firmware NVS; NEVER reclaim (NVRAM)
//   8  EfiMemoryMappedIO
//   9  EfiMemoryMappedIOPortSpace
//  10  EfiPalCode
//  11  EfiUnacceptedMemoryType (UEFI 2.9+; needs Accept call first)
//  12  EfiRuntimeServicesCode  ← live firmware; NEVER touch
//  13  EfiRuntimeServicesData  ← live firmware; NEVER touch (NVRAM corruption)
//  14  EfiPersistentMemory     ✔ NVDIMM / pmem (UEFI 2.6+)

const EFI_CONVENTIONAL_MEMORY: u32 = 4;
const EFI_PERSISTENT_MEMORY:   u32 = 14; // NVDIMM / pmem (UEFI 2.6+)

/// Returns true iff this EFI memory type is safe to give to the PMM.
#[inline]
fn efi_mem_type_is_usable(t: u32) -> bool {
    matches!(t, EFI_CONVENTIONAL_MEMORY | EFI_PERSISTENT_MEMORY)
}

// ── EFI memory map walk (x86_64 UEFI boot) ──────────────────────────────────────

/// Walk the EFI memory descriptor array saved before ExitBootServices
/// and register all usable (EfiConventionalMemory / EfiPersistentMemory)
/// physical ranges with the PMM.
///
/// `map_ptr`  — virtual address of the first EFI_MEMORY_DESCRIPTOR
/// `map_size` — total byte length of the descriptor array
/// `desc_size`— stride in bytes between descriptors (may be > sizeof the struct)
///
/// # Safety
/// Must be called after ExitBootServices.  `map_ptr` must point to valid
/// memory containing at least `map_size` bytes of EFI memory descriptors.
pub unsafe fn pmm_add_efi_map(
    map_ptr:   usize,
    map_size:  usize,
    desc_size: usize,
) {
    if map_ptr == 0 || map_size == 0 || desc_size == 0 { return; }

    // EfiMemDescriptor has a fixed layout but firmware may use a larger
    // stride (desc_size) for forward-compatibility padding.  Always advance
    // by desc_size, never sizeof(EfiMemDescriptor).
    let mut offset: usize = 0;
    while offset + desc_size <= map_size {
        let desc = &*((map_ptr + offset) as *const EfiMemDescriptor);
        if efi_mem_type_is_usable(desc.type_) {
            let base = desc.physical_start as usize;
            let size = desc.num_pages as usize * PAGE_SIZE;
            if size > 0 {
                pmm_add_region(base, size);
            }
        }
        offset += desc_size;
    }
}

// Re-export the descriptor type for uefi_entry.rs visibility.
#[doc(hidden)]
pub use crate::arch::x86_64::uefi_entry::EfiMemDescriptor;

// ── Initialisation ──────────────────────────────────────────────────────────────

/// Initialise the PMM from an FDT blob (RISC-V / OpenSBI path).
pub fn init_from_fdt(fdt_ptr: usize) {
    if fdt_ptr == 0 { return; }
    unsafe { fdt_walk_memory(fdt_ptr); }
}

/// x86_64 shim.  The real work is done by pmm_add_efi_map() called from
/// memmap_init() on the UEFI path, or by parse_mbi() on the multiboot2 path.
pub fn init() {}

// ── Minimal FDT walker ───────────────────────────────────────────────────────────

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

// ── Core allocator ──────────────────────────────────────────────────────────────

pub fn alloc_page() -> Option<usize> {
    // If a contiguous allocation is in progress, we must not pop from the
    // Treiber stack mid-drain.  Spin until CONTIG_LOCK is free.
    //
    // We use try_lock in a loop rather than lock() so that an interrupt
    // handler calling alloc_page() during a contig alloc doesn't deadlock
    // on the same CPU.  On a uni-processor kernel this is the only safe
    // approach; on SMP the contention window is very short.
    let _guard = loop {
        if let Some(g) = CONTIG_LOCK.try_lock() { break g; }
        core::hint::spin_loop();
    };

    let pa = treiber_pop();
    if pa != 0 {
        if let Some(idx) = pool_index(pa) { pool_bit_clear_free(idx); }
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        return Some(pa);
    }
    // _guard released here; bump path doesn't race with contig drain.
    drop(_guard);

    let idx = BUMP.fetch_add(1, Ordering::Relaxed);
    if idx >= POOL_PAGES {
        BUMP.fetch_sub(1, Ordering::Relaxed);
        return None;
    }
    // TOTAL_PAGES is NOT incremented here.  It is a fixed watermark set
    // entirely by pmm_add_region() at init time.
    Some(POOL.0.as_ptr() as usize + idx * PAGE_SIZE)
}

/// Allocate `n` physically contiguous pages.  Returns the base physical
/// address of the run, or `None` on failure.
///
/// # Locking
/// Holds `CONTIG_LOCK` for the entire drain → sort → find → re-push
/// sequence so that concurrent `alloc_page()` calls cannot pop pages
/// whose next-pointers were overwritten during the drain.
pub fn alloc_pages_contig(n: usize) -> Option<usize> {
    if n == 0 { return None; }
    if n == 1 { return alloc_page(); }

    // Hold the lock for the entire drain/re-push window.
    let _guard = CONTIG_LOCK.lock();

    let mut all: Vec<usize> = Vec::new();
    loop {
        let pa = treiber_pop();
        if pa == 0 { break; }
        all.push(pa);
    }

    if all.len() < n {
        for pa in all { treiber_push(pa); }
        return None;
    }

    all.sort_unstable();

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
    for (i, &pa) in all.iter().enumerate() {
        if i < start || i >= start + n {
            treiber_push(pa);
        }
    }
    for i in 0..n {
        let pa = base_pa + i * PAGE_SIZE;
        if let Some(bit_idx) = pool_index(pa) { pool_bit_clear_free(bit_idx); }
        unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
    }
    Some(base_pa)
    // _guard dropped here, unlocking CONTIG_LOCK.
}

pub fn free_pages_contig(base_pa: usize, n: usize) {
    for i in 0..n { free_page(base_pa + i * PAGE_SIZE); }
}

pub fn free_page(pa: usize) {
    if pa == 0 { return; }
    assert!(
        pa & (PAGE_SIZE - 1) == 0,
        "free_page: PA {:#x} is not page-aligned",
        pa,
    );
    assert!(
        !is_kernel_page(pa),
        "free_page: attempt to free kernel image page {:#x}",
        pa,
    );
    if let Some(idx) = pool_index(pa) {
        let ok = pool_bit_set_free(idx);
        assert!(
            ok,
            "free_page: double-free of pool page {:#x} (index {})",
            pa,
            idx,
        );
    }
    unsafe {
        let ptr = pa as *mut u64;
        for i in 0..(PAGE_SIZE / 8) {
            ptr.add(i).write_volatile(0u64);
        }
    }
    treiber_push(pa);
    // NOTE: TOTAL_PAGES is intentionally NOT incremented here.
    // It is a fixed watermark (set only by pmm_add_region at init time)
    // representing the total usable physical pages registered with the PMM.
    // Incrementing it on free would cause total_pages() to grow with every
    // free_page() call, making it useless for capacity reporting.
    // Use free_pages() for the current count of available pages.
}

/// Register a physical memory region as available to the PMM.
pub fn pmm_add_region(base: usize, size: usize) {
    let mut pa = (base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let end = base + size;
    while pa + PAGE_SIZE <= end {
        if is_valid_pa(pa) && pool_index(pa).is_none() {
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
            treiber_push(pa);
            TOTAL_PAGES.fetch_add(1, Ordering::Relaxed);
        }
        pa += PAGE_SIZE;
    }
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

/// Number of pages currently available for allocation.
pub fn free_pages()  -> usize { FREE_COUNT.load(Ordering::Relaxed) }
/// Total usable physical pages registered at init time (fixed watermark).
pub fn total_pages() -> usize { TOTAL_PAGES.load(Ordering::Relaxed) }
