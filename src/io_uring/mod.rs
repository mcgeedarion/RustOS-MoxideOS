// src/io_uring/mod.rs
//
// io_uring subsystem for RustOS.
//
// Architecture:
//   - IoUring owns two memory-mapped rings (SQ, CQ) backed by a single
//     kernel-allocated region.  In a bare-metal OS we manage this ourselves
//     with a statically-allocated backing store so we never touch libc.
//   - Callers build an Sqe via ops::*, push it onto the SQ with `submit()`,
//     then call `poll_completions()` from the scheduler tick to drain the CQ
//     and wake any registered futures.
//   - Every in-flight operation is identified by a u64 `user_data` token.
//     The waker table maps that token → Waker so futures are woken exactly
//     once their CQE arrives.

pub mod cqe;
pub mod ops;
pub mod ring;
pub mod ring_pub;
pub mod ring_buf;
pub mod sqe;
pub mod waker;
pub mod syscall;

use core::sync::atomic::{fence, AtomicU32, Ordering};
use crate::io_uring::{
    cqe::Cqe,
    ring_buf::{RingBuffer, SQ_ENTRIES, CQ_ENTRIES},
    sqe::Sqe,
    waker::WakerTable,
};

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoUringError {
    /// The submission queue is full; caller should poll completions first.
    SqFull,
    /// The completion queue overflowed (entries were dropped).
    CqOverflow,
    /// An SQE contained an unsupported or unknown opcode.
    UnknownOpcode(u8),
    /// The operation resulted in an OS-level error (negated errno).
    OsError(i32),
    /// Ring not yet initialised (init() was never called).
    NotInitialised,
}

// ── Ring head/tail indices (stored in the shared memory region) ───────────────
//
// In a real kernel io_uring the kernel and user-space share a page and
// communicate via atomic loads/stores of head/tail indices.  We mirror that
// contract here with AtomicU32 fields embedded in static storage.

#[repr(C)]
pub struct SqRing {
    pub head: AtomicU32, // consumed by the "kernel" (our dispatch loop)
    pub tail: AtomicU32, // produced by callers pushing SQEs
    pub entries: [Sqe; SQ_ENTRIES],
}

#[repr(C)]
pub struct CqRing {
    pub head: AtomicU32, // consumed by callers draining completions
    pub tail: AtomicU32, // produced by the "kernel" dispatch loop
    pub entries: [Cqe; CQ_ENTRIES],
}

// ── Global ring state ─────────────────────────────────────────────────────────

static mut SQ_RING: SqRing = SqRing {
    head: AtomicU32::new(0),
    tail: AtomicU32::new(0),
    entries: [Sqe::zeroed(); SQ_ENTRIES],
};

static mut CQ_RING: CqRing = CqRing {
    head: AtomicU32::new(0),
    tail: AtomicU32::new(0),
    entries: [Cqe::zeroed(); CQ_ENTRIES],
};

static mut WAKER_TABLE: WakerTable = WakerTable::new();

static mut INITIALISED: bool = false;

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the io_uring subsystem.
///
/// Called once from the boot sequence after the memory allocator is up.
/// Safe to call multiple times — subsequent calls are no-ops.
pub fn init() {
    // SAFETY: single-core boot path; no concurrent access yet.
    unsafe {
        if INITIALISED {
            return;
        }
        // Zero out the rings (static initialisers cover most of this but be
        // explicit for documentation purposes).
        SQ_RING.head.store(0, Ordering::Relaxed);
        SQ_RING.tail.store(0, Ordering::Relaxed);
        CQ_RING.head.store(0, Ordering::Relaxed);
        CQ_RING.tail.store(0, Ordering::Relaxed);
        WAKER_TABLE.clear();
        INITIALISED = true;
        log::info!("[io_uring] initialised — SQ={} CQ={}", SQ_ENTRIES, CQ_ENTRIES);
    }
}

/// Push one Sqe onto the submission queue.
///
/// Returns `Err(SqFull)` if there is no room.  The caller should call
/// `poll_completions()` to drain completed entries and then retry.
pub fn submit(sqe: Sqe) -> Result<(), IoUringError> {
    ensure_init()?;
    // SAFETY: single-threaded kernel context after init.
    unsafe {
        let sq = &mut SQ_RING;
        let head = sq.head.load(Ordering::Acquire);
        let tail = sq.tail.load(Ordering::Relaxed);
        let next_tail = tail.wrapping_add(1);
        if next_tail.wrapping_sub(head) > SQ_ENTRIES as u32 {
            return Err(IoUringError::SqFull);
        }
        let slot = (tail as usize) & (SQ_ENTRIES - 1);
        sq.entries[slot] = sqe;
        // Publish to the dispatch loop.
        fence(Ordering::Release);
        sq.tail.store(next_tail, Ordering::Release);
    }
    Ok(())
}

/// Drive pending SQEs through opcode dispatch, then drain the CQ and wake
/// any futures waiting on completed operations.
///
/// Call this from the scheduler tick / interrupt handler.
pub fn poll_completions() -> Result<(), IoUringError> {
    ensure_init()?;
    process_sq()?;
    drain_cq();
    Ok(())
}

// ── Internal: SQ processing ───────────────────────────────────────────────────

fn process_sq() -> Result<(), IoUringError> {
    // SAFETY: single-threaded kernel context.
    unsafe {
        let sq = &mut SQ_RING;
        loop {
            let head = sq.head.load(Ordering::Relaxed);
            let tail = sq.tail.load(Ordering::Acquire);
            if head == tail {
                break; // nothing pending
            }
            let slot = (head as usize) & (SQ_ENTRIES - 1);
            let sqe = sq.entries[slot].clone();
            // Advance head before dispatch so a re-entrant submit during
            // dispatch doesn't see a spurious "full" ring.
            sq.head.store(head.wrapping_add(1), Ordering::Release);

            let result = ops::dispatch(&sqe);
            push_cqe(Cqe {
                user_data: sqe.user_data,
                res: result,
                flags: 0,
            });
        }
    }
    Ok(())
}

// ── Internal: CQ push/drain ───────────────────────────────────────────────────

/// Write one CQE into the completion ring.
///
/// In a real io_uring the kernel writes here; in our model the dispatch loop
/// above is the "kernel" and writes completions synchronously.  If the CQ is
/// full we drop the entry and set a sticky overflow flag (future work).
pub(crate) fn push_cqe(cqe: Cqe) {
    // SAFETY: single-threaded kernel context.
    unsafe {
        let cq = &mut CQ_RING;
        let head = cq.head.load(Ordering::Acquire);
        let tail = cq.tail.load(Ordering::Relaxed);
        let next_tail = tail.wrapping_add(1);
        if next_tail.wrapping_sub(head) > CQ_ENTRIES as u32 {
            log::error!("[io_uring] CQ overflow — dropping cqe user_data={:#x}", cqe.user_data);
            return;
        }
        let slot = (tail as usize) & (CQ_ENTRIES - 1);
        cq.entries[slot] = cqe;
        fence(Ordering::Release);
        cq.tail.store(next_tail, Ordering::Release);
    }
}

/// Drain all available CQEs, waking any registered futures.
fn drain_cq() {
    // SAFETY: single-threaded kernel context.
    unsafe {
        let cq = &mut CQ_RING;
        loop {
            let head = cq.head.load(Ordering::Relaxed);
            let tail = cq.tail.load(Ordering::Acquire);
            if head == tail {
                break;
            }
            let slot = (head as usize) & (CQ_ENTRIES - 1);
            let cqe = cq.entries[slot];
            cq.head.store(head.wrapping_add(1), Ordering::Release);

            // Wake the future waiting on this user_data token.
            WAKER_TABLE.wake(cqe.user_data);
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

#[inline]
fn ensure_init() -> Result<(), IoUringError> {
    // SAFETY: reading a bool written once at init time.
    if unsafe { !INITIALISED } {
        Err(IoUringError::NotInitialised)
    } else {
        Ok(())
    }
}

/// Register a waker to be called when the CQE for `token` arrives.
pub fn register_waker(token: u64, waker: core::task::Waker) {
    // SAFETY: single-threaded kernel context.
    unsafe { WAKER_TABLE.register(token, waker) };
}
