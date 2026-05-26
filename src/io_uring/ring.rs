//! Shared ring buffer structures and per-process ring table.
//!
//! Each `io_uring_setup` call allocates two PMM pages:
//!   - one page for the SQ ring header + SQE array
//!   - one page for the CQ ring header + CQE array
//!
//! Both pages are mapped into the calling process's address space by `mmap`;
//! the user receives VAs via `sq_off`/`cq_off` in `IoUringParams`. The kernel
//! always accesses them through the kernel-virtual (identity-mapped) PA.
//!
//! ## Wakeup model
//!
//! Each ring owns a `cq_wq: WaitQueue`.  `post_cqe()` calls
//! `cq_wq.wake(POLLIN)` after successfully posting a CQE.  Tasks waiting
//! for completions in `sys_io_uring_enter` sleep on this queue instead of
//! busy-polling.  No `core::hint::spin_loop()` exists in this file.

extern crate alloc;
use alloc::vec::Vec;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

use crate::mm::pmm::{alloc_page, free_page};
use crate::sync::wait_queue::{WaitQueue, ReadyMask};
use crate::io_uring::sqe::Sqe;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum SQE/CQE depth for a single ring (must be a power of two).
pub const MAX_ENTRIES: u32   = 4096;
/// Maximum simultaneous rings across all processes.
pub const MAX_RINGS:   usize = 1024;

pub const SQE_SIZE: usize = 64; // struct io_uring_sqe
pub const CQE_SIZE: usize = 16; // struct io_uring_cqe

const PAGE_SIZE: usize = 4096;

// ── ReadyMask aliases ─────────────────────────────────────────────────────────────

/// Used by cq_wq to signal "at least one CQE is available".
const CQ_READY: ReadyMask = 0x0001; // POLLIN

// ── Wire structures (ABI-compatible with Linux) ────────────────────────────────

/// Submission Queue Entry — 64 bytes, matches Linux `struct io_uring_sqe`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoUringSqe {
    pub opcode:               u8,
    pub flags:                u8,
    pub ioprio:               u16,
    pub fd:                   i32,
    pub off_or_addr2:         u64,
    pub addr_or_splice_fd_in: u64,
    pub len:                  u32,
    pub op_flags:             u32,
    pub user_data:            u64,
    pub buf_index:            u16,
    pub personality:          u16,
    pub splice_fd_in:         i32,
    pub _pad:                 [u64; 2],
}

const _: () = assert!(core::mem::size_of::<IoUringSqe>() == SQE_SIZE);

/// Convert the internal `sqe::Sqe` type to the wire `IoUringSqe`.
impl From<Sqe> for IoUringSqe {
    fn from(s: Sqe) -> Self {
        IoUringSqe {
            opcode:               s.opcode,
            flags:                s.flags,
            ioprio:               s.ioprio,
            fd:                   s.fd,
            off_or_addr2:         s.off,
            addr_or_splice_fd_in: s.addr,
            len:                  s.len,
            op_flags:             s.op_flags,
            user_data:            s.user_data,
            buf_index:            s.buf_index,
            personality:          s.personality,
            splice_fd_in:         s.splice_fd_in,
            // addr3 and __pad2 go into the two-element _pad array.
            _pad:                 [s.addr3, s.__pad2],
        }
    }
}

/// Completion Queue Entry — 16 bytes, matches Linux `struct io_uring_cqe`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res:       i32,
    pub flags:     u32,
}

const _: () = assert!(core::mem::size_of::<IoUringCqe>() == CQE_SIZE);

/// `io_uring_params` — passed by the user to `io_uring_setup`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IoUringParams {
    pub sq_entries:     u32,
    pub cq_entries:     u32,
    pub flags:          u32,
    pub sq_thread_cpu:  u32,
    pub sq_thread_idle: u32,
    pub features:       u32,
    pub wq_fd:          u32,
    pub resv:           [u32; 3],
    pub sq_off:         SqRingOffsets,
    pub cq_off:         CqRingOffsets,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SqRingOffsets {
    pub head:         u32,
    pub tail:         u32,
    pub ring_mask:    u32,
    pub ring_entries: u32,
    pub flags:        u32,
    pub dropped:      u32,
    pub array:        u32,
    pub resv1:        u32,
    pub resv2:        u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct CqRingOffsets {
    pub head:         u32,
    pub tail:         u32,
    pub ring_mask:    u32,
    pub ring_entries: u32,
    pub overflow:     u32,
    pub cqes:         u32,
    pub flags:        u32,
    pub resv1:        u32,
    pub resv2:        u64,
}

// ── IORING_FEAT_* flags ────────────────────────────────────────────────────────────
pub const IORING_FEAT_SINGLE_MMAP:     u32 = 1 << 0;
pub const IORING_FEAT_NODROP:          u32 = 1 << 1;
pub const IORING_FEAT_SUBMIT_STABLE:   u32 = 1 << 2;
pub const IORING_FEAT_RW_CUR_POS:      u32 = 1 << 3;
pub const IORING_FEAT_CUR_PERSONALITY: u32 = 1 << 4;
pub const IORING_FEAT_FAST_POLL:       u32 = 1 << 5;
pub const IORING_FEAT_POLL_32BITS:     u32 = 1 << 6;

// ── SQ/CQ in-memory page layout ────────────────────────────────────────────────────
//
// SQ page (4 KiB):
//   offset  0 : SqRingHdr       (64 bytes)
//   offset 64 : u32 sq_array[entries]
//   offset 64 + entries*4 : IoUringSqe[entries]
//
// CQ page (4 KiB):
//   offset  0 : CqRingHdr       (64 bytes)
//   offset 64 : IoUringCqe[entries]

const RING_HDR_SIZE: usize = 64;

#[repr(C)]
struct SqRingHdr {
    head:         AtomicU32,
    tail:         AtomicU32,
    ring_mask:    u32,
    ring_entries: u32,
    flags:        AtomicU32,
    dropped:      AtomicU32,
    _pad:         [u32; 12],
}

#[repr(C)]
struct CqRingHdr {
    head:         AtomicU32,
    tail:         AtomicU32,
    ring_mask:    u32,
    ring_entries: u32,
    overflow:     AtomicU32,
    _pad:         [u32; 11],
}

const _: () = assert!(core::mem::size_of::<SqRingHdr>() <= RING_HDR_SIZE);
const _: () = assert!(core::mem::size_of::<CqRingHdr>() <= RING_HDR_SIZE);

// ── IoUringRing ────────────────────────────────────────────────────────────────

/// Kernel-side descriptor for one io_uring instance.
pub struct IoUringRing {
    /// Owner PID.
    pub pid:      u32,
    /// File descriptor in the owner's fd table.
    pub fd:       usize,
    /// Number of SQ/CQE entries (power of two).
    pub entries:  u32,
    /// Physical address of the SQ page.
    pub sq_pa:    usize,
    /// Physical address of the CQ page.
    pub cq_pa:    usize,
    /// Registered buffers: `(kernel_va, len)` pairs.
    pub reg_bufs: Vec<(usize, usize)>,
    /// Registered file descriptors.
    pub reg_fds:  Vec<i32>,
    /// Wait queue signalled by `post_cqe`. Tasks sleeping in
    /// `io_uring_enter` GETEVENTS wait here instead of spin-looping.
    pub cq_wq:    Arc<WaitQueue>,
}

impl IoUringRing {
    fn sq_hdr(&self) -> &SqRingHdr {
        unsafe { &*(self.sq_pa as *const SqRingHdr) }
    }

    fn cq_hdr(&self) -> &CqRingHdr {
        unsafe { &*(self.cq_pa as *const CqRingHdr) }
    }

    fn sq_array(&self) -> &[AtomicU32] {
        let base = self.sq_pa + RING_HDR_SIZE;
        unsafe { core::slice::from_raw_parts(base as *const AtomicU32, self.entries as usize) }
    }

    fn sqe_array_mut(&self) -> &mut [IoUringSqe] {
        let base = self.sq_pa + RING_HDR_SIZE + self.entries as usize * 4;
        let base = (base + SQE_SIZE - 1) & !(SQE_SIZE - 1);
        unsafe { core::slice::from_raw_parts_mut(base as *mut IoUringSqe, self.entries as usize) }
    }

    fn sqe_array(&self) -> &[IoUringSqe] {
        let base = self.sq_pa + RING_HDR_SIZE + self.entries as usize * 4;
        let base = (base + SQE_SIZE - 1) & !(SQE_SIZE - 1);
        unsafe { core::slice::from_raw_parts(base as *const IoUringSqe, self.entries as usize) }
    }

    fn cqe_array(&self) -> &mut [IoUringCqe] {
        let base = self.cq_pa + RING_HDR_SIZE;
        unsafe { core::slice::from_raw_parts_mut(base as *mut IoUringCqe, self.entries as usize) }
    }

    #[inline] pub fn mask(&self) -> u32 { self.entries - 1 }

    // ── CQ available count ────────────────────────────────────────────────────────────

    /// Number of CQEs available for the user to consume.
    #[inline]
    pub fn cq_available(&self) -> u32 {
        let hdr  = self.cq_hdr();
        hdr.tail.load(Ordering::Acquire)
            .wrapping_sub(hdr.head.load(Ordering::Acquire))
    }

    // ── SQ push ───────────────────────────────────────────────────────────────────

    /// Push one SQE into the submission queue.
    ///
    /// Uses an identity slot mapping: slot index = `tail & mask`, matching
    /// how `drain_sq` reads entries back out.  Returns `false` if the SQ is
    /// full (tail has lapped head).
    pub fn push_sqe(&self, sqe: IoUringSqe) -> bool {
        let hdr  = self.sq_hdr();
        let mask = self.mask();
        let tail = hdr.tail.load(Ordering::Relaxed);
        let head = hdr.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= self.entries {
            hdr.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let slot = (tail & mask) as usize;
        // Write the SQE into the SQE array.
        self.sqe_array_mut()[slot] = sqe;
        // Point sq_array[slot] at that same slot (identity mapping).
        self.sq_array()[slot].store(slot as u32, Ordering::Relaxed);
        // Publish the new tail so the consumer sees the entry.
        core::sync::atomic::fence(Ordering::Release);
        hdr.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    // ── SQ drain ──────────────────────────────────────────────────────────────────

    /// Drain all pending SQEs and return them. Advances `sq_head`.
    #[inline]
    pub fn drain_sq(&self) -> Vec<IoUringSqe> {
        let hdr   = self.sq_hdr();
        let mask  = self.mask();
        let head  = hdr.head.load(Ordering::Acquire);
        let tail  = hdr.tail.load(Ordering::Acquire);
        let count = tail.wrapping_sub(head) as usize;
        if count == 0 { return Vec::new(); }
        if count > self.entries as usize {
            hdr.dropped.fetch_add(1, Ordering::Relaxed);
            hdr.head.store(tail, Ordering::Release);
            return Vec::new();
        }

        let sq_arr = self.sq_array();
        let sqes   = self.sqe_array();
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let slot = sq_arr[(head.wrapping_add(i as u32) & mask) as usize]
                .load(Ordering::Acquire) as usize;
            if slot < self.entries as usize {
                out.push(sqes[slot]);
            } else {
                let mut nop = IoUringSqe::default();
                nop.opcode = 0;
                out.push(nop);
                hdr.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        hdr.head.store(tail, Ordering::Release);
        out
    }

    // ── CQ post ──────────────────────────────────────────────────────────────────

    /// Append a CQE and wake any task sleeping on `cq_wq`.
    ///
    /// Returns `false` if the CQ ring is full (overflow); no wakeup in that
    /// case since no new data was produced.
    pub fn post_cqe(&self, user_data: u64, res: i32, flags: u32) -> bool {
        let hdr  = self.cq_hdr();
        let mask = self.mask();
        let tail = hdr.tail.load(Ordering::Acquire);
        let head = hdr.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= self.entries {
            hdr.overflow.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let cqe = &mut self.cqe_array()[(tail & mask) as usize];
        cqe.user_data = user_data;
        cqe.res       = res;
        cqe.flags     = flags;
        hdr.tail.store(tail.wrapping_add(1), Ordering::Release);
        // Wake any task blocking in io_uring_enter GETEVENTS.
        self.cq_wq.wake(CQ_READY);
        true
    }

    // ── IoUringParams builder ───────────────────────────────────────────────────────

    pub fn build_params(&self) -> IoUringParams {
        let mut p = IoUringParams::default();
        p.sq_entries = self.entries;
        p.cq_entries = self.entries;
        p.features   = IORING_FEAT_NODROP
                     | IORING_FEAT_SUBMIT_STABLE
                     | IORING_FEAT_RW_CUR_POS
                     | IORING_FEAT_FAST_POLL;

        p.sq_off.head         = offset_of_sq_head();
        p.sq_off.tail         = offset_of_sq_tail();
        p.sq_off.ring_mask    = offset_of_sq_mask();
        p.sq_off.ring_entries = offset_of_sq_entries();
        p.sq_off.flags        = offset_of_sq_flags();
        p.sq_off.dropped      = offset_of_sq_dropped();
        p.sq_off.array        = RING_HDR_SIZE as u32;

        p.cq_off.head         = offset_of_cq_head();
        p.cq_off.tail         = offset_of_cq_tail();
        p.cq_off.ring_mask    = offset_of_cq_mask();
        p.cq_off.ring_entries = offset_of_cq_entries();
        p.cq_off.overflow     = offset_of_cq_overflow();
        p.cq_off.cqes         = RING_HDR_SIZE as u32;
        p
    }
}

impl Drop for IoUringRing {
    fn drop(&mut self) {
        if self.sq_pa != 0 { unsafe { free_page(self.sq_pa as *mut u8); } }
        if self.cq_pa != 0 { unsafe { free_page(self.cq_pa as *mut u8); } }
    }
}

// ── Field-offset helpers ─────────────────────────────────────────────────────────────

macro_rules! field_offset {
    ($T:ty, $field:ident) => {{
        let base = 0usize;
        let ptr  = unsafe { &(*(base as *const $T)).$field as *const _ as usize };
        ptr as u32
    }};
}

fn offset_of_sq_head()    -> u32 { field_offset!(SqRingHdr, head) }
fn offset_of_sq_tail()    -> u32 { field_offset!(SqRingHdr, tail) }
fn offset_of_sq_mask()    -> u32 { field_offset!(SqRingHdr, ring_mask) }
fn offset_of_sq_entries() -> u32 { field_offset!(SqRingHdr, ring_entries) }
fn offset_of_sq_flags()   -> u32 { field_offset!(SqRingHdr, flags) }
fn offset_of_sq_dropped() -> u32 { field_offset!(SqRingHdr, dropped) }

fn offset_of_cq_head()     -> u32 { field_offset!(CqRingHdr, head) }
fn offset_of_cq_tail()     -> u32 { field_offset!(CqRingHdr, tail) }
fn offset_of_cq_mask()     -> u32 { field_offset!(CqRingHdr, ring_mask) }
fn offset_of_cq_entries()  -> u32 { field_offset!(CqRingHdr, ring_entries) }
fn offset_of_cq_overflow() -> u32 { field_offset!(CqRingHdr, overflow) }

// ── Global ring table ───────────────────────────────────────────────────────────────

struct RingTable {
    rings: Vec<Option<IoUringRing>>,
}

impl RingTable {
    fn new() -> Self {
        let mut v = Vec::with_capacity(MAX_RINGS);
        for _ in 0..MAX_RINGS { v.push(None); }
        RingTable { rings: v }
    }

    pub(crate) fn insert(&mut self, ring: IoUringRing) -> Option<usize> {
        let slot = self.rings.iter().position(|r| r.is_none())?;
        self.rings[slot] = Some(ring);
        Some(slot)
    }

    pub(crate) fn remove(&mut self, idx: usize) -> Option<IoUringRing> {
        self.rings.get_mut(idx)?.take()
    }

    pub(crate) fn get(&self, idx: usize) -> Option<&IoUringRing> {
        self.rings.get(idx)?.as_ref()
    }

    pub(crate) fn get_mut(&mut self, idx: usize) -> Option<&mut IoUringRing> {
        self.rings.get_mut(idx)?.as_mut()
    }
}

static RING_TABLE: Mutex<Option<RingTable>> = Mutex::new(None);

pub fn init() {
    *RING_TABLE.lock() = Some(RingTable::new());
}

// ── Public ring-table API ────────────────────────────────────────────────────────────

pub fn alloc_ring(pid: u32, entries: u32) -> Result<usize, isize> {
    let entries = entries.next_power_of_two().clamp(1, MAX_ENTRIES);

    let sq_needed = RING_HDR_SIZE + entries as usize * 4 + entries as usize * SQE_SIZE;
    let cq_needed = RING_HDR_SIZE + entries as usize * CQE_SIZE;
    if sq_needed > PAGE_SIZE || cq_needed > PAGE_SIZE {
        return Err(-22);
    }

    let sq_pa = alloc_page().ok_or(-12isize)? as usize;
    let cq_pa = alloc_page().ok_or_else(|| {
        unsafe { free_page(sq_pa as *mut u8); }
        -12isize
    })? as usize;

    unsafe {
        core::ptr::write_bytes(sq_pa as *mut u8, 0, PAGE_SIZE);
        core::ptr::write_bytes(cq_pa as *mut u8, 0, PAGE_SIZE);
    }

    let sq_hdr = unsafe { &mut *(sq_pa as *mut SqRingHdr) };
    sq_hdr.ring_mask    = entries - 1;
    sq_hdr.ring_entries = entries;

    let cq_hdr = unsafe { &mut *(cq_pa as *mut CqRingHdr) };
    cq_hdr.ring_mask    = entries - 1;
    cq_hdr.ring_entries = entries;

    let ring = IoUringRing {
        pid,
        fd:       0,
        entries,
        sq_pa,
        cq_pa,
        reg_bufs: Vec::new(),
        reg_fds:  Vec::new(),
        cq_wq:    Arc::new(WaitQueue::new()),
    };

    let mut tbl = RING_TABLE.lock();
    let tbl = tbl.as_mut().ok_or(-5isize)?;
    tbl.insert(ring).ok_or(-24isize)
}

pub fn free_ring(idx: usize) {
    if let Some(tbl) = RING_TABLE.lock().as_mut() {
        tbl.remove(idx);
    }
}

pub fn with_ring<F, R>(idx: usize, f: F) -> Option<R>
where F: FnOnce(&IoUringRing) -> R {
    RING_TABLE.lock().as_ref()?.get(idx).map(f)
}

pub fn with_ring_mut<F, R>(idx: usize, f: F) -> Option<R>
where F: FnOnce(&mut IoUringRing) -> R {
    RING_TABLE.lock().as_mut()?.get_mut(idx).map(f)
}

pub fn ring_idx_for_fd(pid: u32, fd: usize) -> Option<usize> {
    let tbl = RING_TABLE.lock();
    tbl.as_ref()?.rings.iter().position(|r| {
        r.as_ref().map(|r| r.pid == pid && r.fd == fd).unwrap_or(false)
    })
}

/// Clone the `cq_wq` Arc so a caller can sleep on it without holding
/// the RING_TABLE lock.
pub fn cq_wq_for(idx: usize) -> Option<Arc<WaitQueue>> {
    with_ring(idx, |r| r.cq_wq.clone())
}
