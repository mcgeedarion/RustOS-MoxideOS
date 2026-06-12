//! Swap subsystem — swapout, swapin, slot management, and kswapd.
//!
//! ## Overview
//!
//! ```text
//!  ┌──────────────┐   evict   ┌──────────┐   write   ┌──────────────┐
//!  │  page_fault  │ ────────► │  swap.rs │ ────────► │  swap device │
//!  │  (OOM path)  │           │ (this)   │           │  (block dev) │
//!  └──────────────┘           └────┬─────┘           └──────────────┘
//!                                  │ swapin
//!                        ┌─────────▼──────────┐
//!                        │  demand_fault_swap  │
//!                        │  (PTE swap-special) │
//!                        └────────────────────┘
//! ```
//!
//! ## Swap slot layout
//!
//! The backing store is a single block device partition (or file) registered
//! via `add_swap_device`.  The partition is divided into 4 KiB slots:
//!
//! ```text
//!  slot 0 — reserved (swap header / signature)
//!  slot 1 … N-1 — data slots
//! ```
//!
//! Each slot is identified by a `SwapSlot(u32)`.  The maximum swap space is
//! `u32::MAX * PAGE_SIZE` ≈ 16 TiB.
//!
//! ## PTE encoding for swapped-out pages
//!
//! When a page is swapped out the PTE is overwritten with a **swap special**:
//!
//! ```text
//!  x86_64 (64-bit PTE):  [ slot:32 | dev_id:8 | type=SWAP:8 | P=0 ]
//!  RISC-V Sv39 (64-bit): [ slot:32 | dev_id:8 | type=SWAP:8 | V=0 ]
//!
//!  Bit layout (LSB = bit 0):
//!    bits  7:0  = 0xAB  (swap-type marker; bit 0 = P/V = 0)
//!    bits 23:16 = dev_id (0..MAX_SWAP_DEVS-1)
//!    bits 55:24 = slot index (1-based)
//! ```
//!
//! The P/V bit is **0** so the hardware treats it as not-present and traps;
//! the fault handler checks `is_swap_pte` and calls `swapin` instead of
//! allocating a fresh page.
//!
//! ## LRU clock eviction
//!
//! Physical pages eligible for eviction are tracked in `LRU_CLOCK`, a
//! circular buffer of `(pa, pid, va)` triples.  kswapd scans the clock hand
//! and evicts pages whose PTE accessed-bit (x86 bit 5 / RISC-V bit A) is
//! clear.  Pages with the accessed-bit set are given a second chance and the
//! bit is cleared.
//!
//! ## Interaction with page_fault.rs
//!
//! `page_fault::handle_demand_fault` calls `swap::try_free_page()` when
//! `pmm::alloc_page()` returns `None`.  If swap succeeds a fresh page is
//! re-attempted.  On swap fault (PTE present=0, swap-special=1) the fault
//! handler calls `swap::swapin(pid, va)` instead of allocating a fresh page.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, Once};

use crate::arch::{
    api::{PageFlags, Paging},
    Arch,
};
use crate::mm::pmm::{alloc_page, free_page};
use crate::proc::scheduler;

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = !(PAGE_SIZE - 1);
/// Maximum swap devices supported simultaneously.
pub const MAX_SWAP_DEVS: usize = 8;
/// Maximum swap slots per device (~16 GiB per device with 4 KiB pages).
pub const MAX_SLOTS: u32 = 4 * 1024 * 1024; // 4 M slots = 16 GiB
/// LRU clock ring capacity — limits the working set tracked for eviction.
const LRU_CAPACITY: usize = 65536;

/// Magic written at swap slot 0 (offset 0) as a sanity header.
const SWAP_MAGIC: u64 = 0x5257_4150_4D41_4743; // b"CGATPMAWS" reversed

/// An allocated slot on a specific swap device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SwapSlot {
    /// Device index (0 … MAX_SWAP_DEVS-1).
    pub dev: u8,
    /// Slot index within the device (1-based; 0 is reserved).
    pub slot: u32,
}

impl SwapSlot {
    /// Encode into the upper bits of a not-present PTE.
    ///
    /// Layout (LSB = bit 0):
    ///   bits  7:0  = 0xAB  (swap marker; bit 0 = P/V = 0)
    ///   bits 23:16 = dev   (8 bits, supports up to 256 devices)
    ///   bits 55:24 = slot  (32 bits; slot is u32 so this never overflows)
    ///
    /// Previously slot was at bit 16 and dev at bit 8, which caused slot
    /// values >= 256 to corrupt the dev field on decode.  The fields are
    /// now non-overlapping for the full u32 slot range.
    #[inline]
    pub fn encode_pte(self) -> usize {
        ((self.slot as usize) << 24) | ((self.dev as usize) << 16) | 0xAB // swap-type marker; bit 0
                                                                          // (PRESENT/VALID) = 0
    }

    /// Decode a not-present PTE back to a `SwapSlot`.
    /// Returns `None` if the PTE does not contain a valid swap entry.
    #[inline]
    pub fn decode_pte(pte: usize) -> Option<Self> {
        if pte & 1 != 0 {
            return None;
        } // present — not a swap PTE
        if (pte & 0xFF) != 0xAB {
            return None;
        } // wrong marker
        let dev = ((pte >> 16) & 0xFF) as u8;
        let slot = (pte >> 24) as u32;
        if dev as usize >= MAX_SWAP_DEVS || slot == 0 {
            return None;
        }
        Some(SwapSlot { dev, slot })
    }

    /// Byte offset in the device for this slot.
    #[inline]
    pub fn byte_offset(self) -> u64 {
        self.slot as u64 * PAGE_SIZE as u64
    }
}

/// I/O callbacks supplied by the block-device layer when a swap partition is
/// registered.  Both functions are synchronous from the caller's perspective;
/// the block driver may sleep-spin internally.
///
/// # Safety
/// `read_page` and `write_page` must copy exactly `PAGE_SIZE` bytes.
/// Both pointers are kernel-virtual (identity-mapped PMM pages).
pub struct SwapOps {
    /// Write one page from `buf` to `byte_offset` on this device.
    pub write_page: unsafe fn(dev_priv: u64, byte_offset: u64, buf: *const u8) -> isize,
    /// Read  one page into `buf` from `byte_offset` on this device.
    pub read_page: unsafe fn(dev_priv: u64, byte_offset: u64, buf: *mut u8) -> isize,
    /// Private data passed as the first argument to every I/O call.
    /// Typically a BAR base address or device index.
    pub dev_priv: u64,
}

struct SwapDevice {
    ops: SwapOps,
    /// Total number of slots on this device (including slot 0).
    num_slots: u32,
    /// Bitmap: bit N=1 → slot N is free.
    free_map: Vec<u64>,
    /// Number of free slots remaining.
    free_count: u32,
    /// Next slot to consider when scanning (clock-hand for allocation).
    alloc_hand: u32,
}

impl SwapDevice {
    fn new(ops: SwapOps, num_slots: u32) -> Self {
        let words = ((num_slots + 63) / 64) as usize;
        let mut free_map = alloc::vec![u64::MAX; words];
        // Slot 0 is reserved — mark as used.
        if !free_map.is_empty() {
            free_map[0] &= !1u64;
        }
        SwapDevice {
            ops,
            num_slots,
            free_map,
            free_count: num_slots.saturating_sub(1),
            alloc_hand: 1,
        }
    }

    fn alloc_slot(&mut self) -> Option<u32> {
        if self.free_count == 0 {
            return None;
        }
        let n = self.num_slots as usize;
        let start = self.alloc_hand as usize;
        for delta in 0..n {
            let idx = (start + delta) % n;
            if idx == 0 {
                continue;
            } // slot 0 reserved
            let word = idx / 64;
            let bit = idx % 64;
            if word >= self.free_map.len() {
                continue;
            }
            if self.free_map[word] & (1u64 << bit) != 0 {
                self.free_map[word] &= !(1u64 << bit); // mark used
                self.free_count -= 1;
                self.alloc_hand = ((idx + 1) % n).max(1) as u32;
                return Some(idx as u32);
            }
        }
        None
    }

    fn free_slot(&mut self, slot: u32) {
        let word = (slot / 64) as usize;
        let bit = (slot % 64) as usize;
        if word < self.free_map.len() {
            if self.free_map[word] & (1u64 << bit) == 0 {
                self.free_map[word] |= 1u64 << bit;
                self.free_count += 1;
            }
        }
    }

    fn free_slots(&self) -> u32 {
        self.free_count
    }
}

struct DevTable {
    devs: [Option<SwapDevice>; MAX_SWAP_DEVS],
    count: usize,
}

impl DevTable {
    const fn new() -> Self {
        DevTable {
            devs: [None, None, None, None, None, None, None, None],
            count: 0,
        }
    }
}

static DEV_TABLE: Mutex<DevTable> = Mutex::new(DevTable::new());

#[derive(Clone, Copy, Default)]
struct LruEntry {
    /// Physical address of the page frame.
    pa: usize,
    /// PID that owns the virtual mapping.
    pid: u32,
    /// Virtual address in that process's address space.
    va: usize,
}

struct LruClock {
    ring: Vec<LruEntry>,
    /// Index of the clock hand.
    hand: usize,
    /// Number of valid entries currently in the ring.
    count: usize,
}

impl LruClock {
    fn new() -> Self {
        LruClock {
            ring: alloc::vec![LruEntry::default(); LRU_CAPACITY],
            hand: 0,
            count: 0,
        }
    }

    /// Insert a newly-mapped page into the clock ring.
    fn insert(&mut self, pa: usize, pid: u32, va: usize) {
        // Find an empty slot or evict the oldest (just overwrite at hand).
        let slot = if self.count < LRU_CAPACITY {
            let s = self.count;
            self.count += 1;
            s
        } else {
            let s = self.hand;
            self.hand = (self.hand + 1) % LRU_CAPACITY;
            s
        };
        self.ring[slot] = LruEntry { pa, pid, va };
    }

    /// Remove an entry by physical address (called when page is freed).
    ///
    /// Uses swap-with-tail to keep the live region dense, so
    /// `next_candidate` never wastes iterations on tombstones.
    fn remove_pa(&mut self, pa: usize) {
        if let Some(pos) = self.ring[..self.count].iter().position(|e| e.pa == pa) {
            self.count -= 1;
            // Move the last live entry into the vacated slot.
            self.ring[pos] = self.ring[self.count];
            self.ring[self.count] = LruEntry::default();
            // Keep the clock hand in bounds after the shrink.
            if self.hand >= self.count && self.count > 0 {
                self.hand = self.hand % self.count;
            } else if self.count == 0 {
                self.hand = 0;
            }
        }
    }

    /// Advance the clock hand and return the next candidate for eviction.
    ///
    /// Returns `None` if the ring is empty.
    fn next_candidate(&mut self) -> Option<LruEntry> {
        if self.count == 0 {
            return None;
        }
        let e = self.ring[self.hand];
        self.hand = (self.hand + 1) % self.count;
        if e.pa != 0 {
            Some(e)
        } else {
            None
        }
    }
}

// Use spin::Once so LruClock::new() (which allocates a Vec) is called at
// runtime after the heap is ready, not at link time.  The previous approach
// of wrapping a mem::zeroed() LruClock in a Mutex was unsound because a
// zeroed Vec (null data pointer, zero len/cap) is not a valid Rust value.
static LRU: Once<Mutex<LruClock>> = Once::new();

static INITIALISED: AtomicBool = AtomicBool::new(false);

static STAT_SWAPOUT: AtomicU64 = AtomicU64::new(0);
static STAT_SWAPIN: AtomicU64 = AtomicU64::new(0);
static STAT_EVICT_FAIL: AtomicU64 = AtomicU64::new(0);
static STAT_FREE_SLOTS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy, Debug, Default)]
pub struct SwapStats {
    pub swapout_pages: u64,
    pub swapin_pages: u64,
    pub evict_failures: u64,
    pub free_slots: u32,
}

pub fn stats() -> SwapStats {
    SwapStats {
        swapout_pages: STAT_SWAPOUT.load(Ordering::Relaxed),
        swapin_pages: STAT_SWAPIN.load(Ordering::Relaxed),
        evict_failures: STAT_EVICT_FAIL.load(Ordering::Relaxed),
        free_slots: STAT_FREE_SLOTS.load(Ordering::Relaxed),
    }
}

/// Register a swap device.
///
/// `num_slots` should be the total number of 4 KiB slots on the partition
/// (including slot 0 which is reserved for the header).
///
/// Returns the device index (0 … MAX_SWAP_DEVS-1) on success.
/// Returns `Err(-28)` (ENOSPC) if all device slots are full.
/// Returns `Err(-22)` (EINVAL) if `num_slots < 2`.
pub fn add_swap_device(ops: SwapOps, num_slots: u32) -> Result<u8, isize> {
    if num_slots < 2 {
        return Err(-22);
    }
    let mut tbl = DEV_TABLE.lock();
    if tbl.count >= MAX_SWAP_DEVS {
        return Err(-28);
    } // ENOSPC
    let idx = (0..MAX_SWAP_DEVS)
        .find(|&i| tbl.devs[i].is_none())
        .ok_or(-28isize)?;
    // Write the magic header at slot 0.
    let hdr_magic = SWAP_MAGIC.to_le_bytes();
    unsafe {
        let _ = (ops.write_page)(ops.dev_priv, 0, hdr_magic.as_ptr());
    }
    let free = num_slots.saturating_sub(1);
    tbl.devs[idx] = Some(SwapDevice::new(ops, num_slots));
    tbl.count += 1;
    STAT_FREE_SLOTS.fetch_add(free, Ordering::Relaxed);
    Ok(idx as u8)
}

/// Remove a previously-registered swap device by index.
///
/// Callers must have already drained all pages off the device via
/// `drain_swap_device` before calling this (i.e. `sys_swapoff` does this).
/// In-use slots are silently abandoned only if the caller skips the drain.
pub fn remove_swap_device(dev_idx: u8) -> Result<(), isize> {
    let mut tbl = DEV_TABLE.lock();
    let idx = dev_idx as usize;
    if idx >= MAX_SWAP_DEVS || tbl.devs[idx].is_none() {
        return Err(-6);
    } // ENXIO
    let free = tbl.devs[idx].as_ref().map(|d| d.free_slots()).unwrap_or(0);
    tbl.devs[idx] = None;
    tbl.count -= 1;
    STAT_FREE_SLOTS.fetch_sub(free, Ordering::Relaxed);
    Ok(())
}

/// Return `true` if at least one swap device is registered and has free slots.
#[inline]
pub fn is_enabled() -> bool {
    STAT_FREE_SLOTS.load(Ordering::Relaxed) > 0
}

/// Call this every time a user page is mapped for the first time.
///
/// The page is registered in the LRU clock ring and becomes eligible for
/// future eviction by kswapd.
pub fn track_page(pa: usize, pid: u32, va: usize) {
    if let Some(lru) = LRU.get() {
        lru.lock().insert(pa, pid, va);
    }
}

/// Remove a page from the LRU ring (call when a page is freed by the process).
pub fn untrack_page(pa: usize) {
    if let Some(lru) = LRU.get() {
        lru.lock().remove_pa(pa);
    }
}

/// Attempt to evict one page from the LRU clock ring to the swap device.
///
/// On success the physical page is freed back to the PMM and its PTE in the
/// owning process is replaced with a swap-special entry.  Returns `true` if
/// a page was reclaimed.
///
/// This is called:
///   - from `try_free_page` when `alloc_page()` returns `None`
///   - from `kswapd_tick` on a schedule
pub fn swapout_one() -> bool {
    if !is_enabled() {
        return false;
    }
    let lru_mutex = match LRU.get() {
        Some(m) => m,
        None => return false,
    };

    let victim = {
        let mut lru = lru_mutex.lock();
        let mut candidate = None;
        let n = lru.count.min(LRU_CAPACITY);
        for _ in 0..n * 2 {
            let e = match lru.next_candidate() {
                Some(e) => e,
                None => break,
            };
            // Skip pages belonging to the kernel (pid 0).
            if e.pid == 0 {
                continue;
            }
            // Check the accessed bit in the PTE.
            let cr3 = scheduler::with_proc(e.pid, |p| p.user_satp).unwrap_or(0);
            if cr3 == 0 {
                continue;
            }
            if <Arch as Paging>::pte_accessed(cr3, e.va) {
                // Second-chance: clear the bit and skip this time.
                <Arch as Paging>::clear_accessed(cr3, e.va);
                continue;
            }
            candidate = Some(e);
            break;
        }
        candidate
    };

    let e = match victim {
        Some(e) => e,
        None => {
            STAT_EVICT_FAIL.fetch_add(1, Ordering::Relaxed);
            return false;
        },
    };

    let slot = {
        let mut tbl = DEV_TABLE.lock();
        let mut found = None;
        for i in 0..MAX_SWAP_DEVS {
            if let Some(ref mut dev) = tbl.devs[i] {
                if let Some(s) = dev.alloc_slot() {
                    found = Some(SwapSlot {
                        dev: i as u8,
                        slot: s,
                    });
                    break;
                }
            }
        }
        found
    };

    let slot = match slot {
        Some(s) => s,
        None => {
            STAT_EVICT_FAIL.fetch_add(1, Ordering::Relaxed);
            return false;
        },
    };
    STAT_FREE_SLOTS.fetch_sub(1, Ordering::Relaxed);

    // Extract the I/O function pointers and drop DEV_TABLE *before* calling
    // write_page.  Holding a spinlock across a synchronous block I/O write
    // would serialise all swap activity on all CPUs for the disk latency.
    let (write_fn, dev_priv, byte_offset) = {
        let tbl = DEV_TABLE.lock();
        match tbl.devs[slot.dev as usize].as_ref() {
            Some(dev) => (dev.ops.write_page, dev.ops.dev_priv, slot.byte_offset()),
            None => {
                // Device disappeared between slot allocation and write.
                STAT_EVICT_FAIL.fetch_add(1, Ordering::Relaxed);
                return false;
            },
        }
    }; // DEV_TABLE lock released here — before the I/O call

    let io_ok = unsafe { write_fn(dev_priv, byte_offset, e.pa as *const u8) } >= 0;

    if !io_ok {
        // I/O failed — free the slot and bail.
        let mut tbl = DEV_TABLE.lock();
        if let Some(ref mut dev) = tbl.devs[slot.dev as usize] {
            dev.free_slot(slot.slot);
        }
        STAT_FREE_SLOTS.fetch_add(1, Ordering::Relaxed);
        STAT_EVICT_FAIL.fetch_add(1, Ordering::Relaxed);
        return false;
    }

    let cr3 = scheduler::with_proc(e.pid, |p| p.user_satp).unwrap_or(0);
    if cr3 != 0 {
        let swap_pte = slot.encode_pte();
        <Arch as Paging>::set_pte(cr3, e.va, swap_pte);
        <Arch as Paging>::flush_va(e.va);
    }

    lru_mutex.lock().remove_pa(e.pa);
    free_page(e.pa);
    STAT_SWAPOUT.fetch_add(1, Ordering::Relaxed);
    true
}

/// Handle a swap fault: read the page back from the swap device into a fresh
/// physical page and update the PTE.
///
/// Returns `true` if the fault was resolved (instruction should be retried).
/// Returns `false` on I/O error or if `faulting_va` does not carry a valid
/// swap-special PTE.
///
/// Called from `page_fault::handle_demand_fault` after it detects that the
/// faulting PTE is a swap-special entry.
pub fn swapin(pid: u32, faulting_va: usize) -> bool {
    let page_va = faulting_va & PAGE_MASK;

    let cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if cr3 == 0 {
        return false;
    }

    let raw_pte = <Arch as Paging>::read_pte(cr3, page_va);
    let slot = match SwapSlot::decode_pte(raw_pte) {
        Some(s) => s,
        None => return false, // not a swap PTE after all
    };

    // If the PMM is empty, try to free a page via swapout before retrying.
    let pa_ptr = alloc_page().or_else(|| if swapout_one() { alloc_page() } else { None });
    let pa = match pa_ptr {
        Some(p) => p,
        None => {
            crate::proc::signal::send_signal(pid, 9 /* SIGKILL */);
            return false;
        },
    };

    // Same pattern as swapout_one: extract I/O pointers then drop the lock
    // before performing the I/O.
    let (read_fn, dev_priv, byte_offset) = {
        let tbl = DEV_TABLE.lock();
        match tbl.devs[slot.dev as usize].as_ref() {
            Some(dev) => (dev.ops.read_page, dev.ops.dev_priv, slot.byte_offset()),
            None => {
                free_page(pa);
                crate::proc::signal::send_signal(pid, 7 /* SIGBUS */);
                return false;
            },
        }
    }; // DEV_TABLE lock released here

    let io_ok = unsafe { read_fn(dev_priv, byte_offset, pa as *mut u8) } >= 0;

    if !io_ok {
        free_page(pa);
        crate::proc::signal::send_signal(pid, 7 /* SIGBUS */);
        return false;
    }

    {
        let mut tbl = DEV_TABLE.lock();
        if let Some(ref mut dev) = tbl.devs[slot.dev as usize] {
            dev.free_slot(slot.slot);
        }
    }
    STAT_FREE_SLOTS.fetch_add(1, Ordering::Relaxed);

    let prot = crate::mm::mmap::find_vma(pid, faulting_va)
        .map(|v| v.prot)
        .unwrap_or(crate::mm::mmap::PROT_READ);
    let flags = prot_to_flags(prot);
    <Arch as Paging>::map_page(cr3, page_va, pa as usize, flags);
    <Arch as Paging>::flush_va(page_va);

    track_page(pa as usize, pid, page_va);
    STAT_SWAPIN.fetch_add(1, Ordering::Relaxed);
    true
}

/// Called from `page_fault::handle_demand_fault` when `alloc_page()` returns
/// `None`.  Attempts up to `retries` swapout passes before giving up.
///
/// Returns `true` if at least one page was freed (caller should retry
/// `alloc_page()`).
pub fn try_free_page(retries: usize) -> bool {
    let mut freed = false;
    for _ in 0..retries {
        if swapout_one() {
            freed = true;
            break;
        }
    }
    freed
}

/// Watermarks: kswapd starts reclaiming below `LOW` and stops above `HIGH`.
/// Units: number of free PMM pages.
static WATERMARK_LOW: AtomicU64 = AtomicU64::new(256); // ~1 MiB
static WATERMARK_HIGH: AtomicU64 = AtomicU64::new(1024); // ~4 MiB

/// Set the low/high watermarks (in pages).  Must satisfy `low < high`.
pub fn set_watermarks(low: u64, high: u64) {
    if low < high {
        WATERMARK_LOW.store(low, Ordering::Relaxed);
        WATERMARK_HIGH.store(high, Ordering::Relaxed);
    }
}

/// One kswapd work tick.  Should be called periodically (e.g. every timer
/// interrupt or from the idle task).
///
/// Reclaims pages until the PMM free count is above the high watermark or
/// no more pages can be evicted.  Caps a single tick at `max_per_tick`
/// evictions to bound jitter.
pub fn kswapd_tick(max_per_tick: usize) {
    if !is_enabled() {
        return;
    }
    let low = WATERMARK_LOW.load(Ordering::Relaxed);
    let high = WATERMARK_HIGH.load(Ordering::Relaxed);
    let free = crate::mm::pmm::free_pages() as u64;
    if free >= low {
        return;
    } // above low watermark — nothing to do
    let mut reclaimed = 0;
    while reclaimed < max_per_tick {
        let now = crate::mm::pmm::free_pages() as u64;
        if now >= high {
            break;
        } // reached high watermark
        if !swapout_one() {
            break;
        } // no more candidates
        reclaimed += 1;
    }
}

/// `swapon(2)` — activate a swap partition identified by block device fd.
///
/// The kernel resolves `path` to a block device, queries its size in 4 KiB
/// sectors, constructs `SwapOps` from the device driver, and registers it.
///
/// Returns the new device index cast to `isize`, or a negative errno.
pub fn sys_swapon(path: *const u8, path_len: usize) -> isize {
    // Resolve path → block device.
    let name = unsafe { core::slice::from_raw_parts(path, path_len) };
    let (ops, num_slots) = match crate::fs::vfs::open_swap_device(name) {
        Ok(x) => x,
        Err(e) => return e,
    };
    match add_swap_device(ops, num_slots) {
        Ok(idx) => idx as isize,
        Err(e) => e,
    }
}

/// `swapoff(2)` — deactivate a swap device by the same path.
///
/// Drains all pages currently on this device back into RAM before
/// deregistering it, so no process is left with a live swap-special PTE
/// pointing at the removed device.  Returns `0` on success or a negative
/// errno.
pub fn sys_swapoff(path: *const u8, path_len: usize) -> isize {
    let name = unsafe { core::slice::from_raw_parts(path, path_len) };
    let dev_idx = match crate::fs::vfs::find_swap_device(name) {
        Ok(i) => i,
        Err(e) => return e,
    };
    // Drain all swapped-out pages back to RAM before removing the device.
    // This walks every live process's page tables and calls swapin for each
    // PTE whose SwapSlot::dev matches dev_idx.  Without this drain, any
    // subsequent fault on those addresses would find the device gone and
    // deliver SIGBUS with no recovery possible.
    drain_swap_device(dev_idx);
    match remove_swap_device(dev_idx) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Walk every live process's page tables and swapin any page whose backing
/// slot is on `dev_idx`.  Called by `sys_swapoff` before the device is
/// deregistered.
///
/// Requires `Paging::walk_swap_ptes` — a page-table walker that calls the
/// provided closure for every not-present PTE that decodes as a valid
/// `SwapSlot`.  The closure receives `(va, slot)` and should return `true`
/// to continue the walk.
fn drain_swap_device(dev_idx: u8) {
    // Collect (pid, cr3) pairs under a read lock so we don't hold the
    // scheduler lock across the (potentially slow) swapin I/O calls.
    let targets: alloc::vec::Vec<(u32, usize)> = scheduler::with_procs_ro(|procs| {
        procs
            .iter()
            .filter(|p| p.user_satp != 0)
            .map(|p| (p.pid as u32, p.user_satp))
            .collect()
    });

    for (pid, cr3) in targets {
        // Collect all VAs with swap PTEs on this device, then swapin each
        // one.  We collect first to avoid calling swapin while holding a
        // page-table lock inside walk_swap_ptes.
        let mut vas: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
        <Arch as Paging>::walk_swap_ptes(cr3, |va, slot| {
            if slot.dev == dev_idx {
                vas.push(va);
            }
            true // continue walk
        });
        for va in vas {
            swapin(pid, va);
        }
    }
}

/// One line of `/proc/swaps` output.
pub struct SwapEntry {
    pub dev_idx: usize,
    pub num_slots: u32,
    pub free_slots: u32,
}

/// Collect current swap device information for `/proc/swaps`.
pub fn proc_swaps() -> Vec<SwapEntry> {
    let tbl = DEV_TABLE.lock();
    let mut out = Vec::new();
    for i in 0..MAX_SWAP_DEVS {
        if let Some(ref d) = tbl.devs[i] {
            out.push(SwapEntry {
                dev_idx: i,
                num_slots: d.num_slots,
                free_slots: d.free_slots(),
            });
        }
    }
    out
}

/// Initialise the swap subsystem.  Call once from `mm::init()` after the PMM
/// and slab allocator are ready.
///
/// This call is idempotent — calling it a second time is a no-op.
pub fn init() {
    LRU.call_once(|| Mutex::new(LruClock::new()));
    INITIALISED.store(true, Ordering::Release);
}

use crate::mm::mmap::PROT_WRITE;
// PROT_EXEC re-exported from mmap so we don't duplicate the constant.
use crate::mm::mmap::PROT_EXEC;

#[inline]
fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 {
        f |= PageFlags::WRITE;
    }
    if prot & PROT_EXEC == 0 {
        f |= PageFlags::NX;
    }
    f
}
