//! Lock-free kernel trace ring buffer.
//!
//! Records syscall entry/exit, IRQ dispatch, and scheduler context-switch
//! events into a fixed-size circular buffer using only atomic operations —
//! no spinlock, no heap allocation.
//!
//! # Usage
//!
//! ```rust
//! // In syscall dispatch:
//! trace::emit(TraceEvent { kind: TraceKind::SyscallEnter, id: nr as u32, arg: 0, ticks: arch_ticks() });
//!
//! // Drain from shell/procfs:
//! trace::drain(|ev| serial_println!("{:?}", ev));
//!
//! // Drain only the last N events without advancing HEAD (e.g. from oops):
//! trace::drain_last_n(32, |ev| serial_println!("{:?}", ev));
//! ```
//!
//! Enabled only under `--features debug`.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Categories of traceable kernel events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TraceKind {
    SyscallEnter = 0,
    SyscallExit = 1,
    IrqDispatch = 2,
    SchedSwitch = 3,
    FuncEnter = 4,
    FuncExit = 5,
}

/// A single trace record written into the ring buffer.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TraceEvent {
    /// Event category.
    pub kind: TraceKind,
    /// Context-dependent ID: syscall number, IRQ number, or PID.
    pub id: u32,
    /// Context-dependent payload: return value, target PID, or function
    /// address.
    pub arg: u64,
    /// Hardware timestamp (RISC-V `cycle` CSR or x86_64 `rdtsc`).
    pub ticks: u64,
}

/// Ring buffer capacity — **must** be a power of two.
const RING_SIZE: usize = 4096;

// Safety: each slot is written by exactly one producer (atomic fetch_add
// guarantees unique slot ownership) before being read by the single
// consumer (drain). UnsafeCell is required because we hold a shared static.
struct RingBuf([core::cell::UnsafeCell<TraceEvent>; RING_SIZE]);
unsafe impl Sync for RingBuf {}

static RING: RingBuf = RingBuf(
    [const {
        core::cell::UnsafeCell::new(TraceEvent {
            kind: TraceKind::SyscallEnter,
            id: 0,
            arg: 0,
            ticks: 0,
        })
    }; RING_SIZE],
);

/// Monotonically-increasing tail (producer cursor).
static TAIL: AtomicUsize = AtomicUsize::new(0);
/// Monotonically-increasing head (consumer cursor).
static HEAD: AtomicUsize = AtomicUsize::new(0);

/// Emit one event into the ring buffer.
///
/// Lock-free and interrupt-safe. If the buffer is full the oldest entry is
/// silently overwritten (oldest-first eviction).
#[inline]
pub fn emit(ev: TraceEvent) {
    let slot = TAIL.fetch_add(1, Ordering::SeqCst) & (RING_SIZE - 1);
    // SAFETY: atomic fetch_add gives this call exclusive ownership of `slot`
    // for the duration of this write.
    unsafe {
        *RING.0[slot].get() = ev;
    }
}

/// Drain all pending events, calling `f` for each in order.
///
/// Intended for the shell `trace` command or a procfs `/proc/trace` reader.
/// Not re-entrant; call only from a single consumer context.
pub fn drain(mut f: impl FnMut(&TraceEvent)) {
    let tail = TAIL.load(Ordering::SeqCst);
    let head = HEAD.load(Ordering::SeqCst);
    // Clamp to at most RING_SIZE unread events to handle wrap-around.
    let start = if tail.saturating_sub(head) > RING_SIZE {
        tail - RING_SIZE
    } else {
        head
    };
    for i in start..tail {
        // SAFETY: consumer has exclusive read access to slots [head..tail).
        unsafe {
            f(&*RING.0[i & (RING_SIZE - 1)].get());
        }
    }
    HEAD.store(tail, Ordering::SeqCst);
}

/// Drain only the **last `n`** events without advancing `HEAD`.
///
/// Unlike [`drain`], this does not consume the pending events — a subsequent
/// call to `drain` will still see the full unread window.  Intended for crash
/// and oops paths where we want a look-back window without disturbing the
/// normal consumer.
///
/// If fewer than `n` events are available, all available events are returned.
pub fn drain_last_n(n: usize, mut f: impl FnMut(&TraceEvent)) {
    let tail = TAIL.load(Ordering::SeqCst);
    let head = HEAD.load(Ordering::SeqCst);
    let available = tail.saturating_sub(head).min(RING_SIZE);
    let count = available.min(n);
    let start = tail.saturating_sub(count);
    for i in start..tail {
        // SAFETY: same invariant as drain() — we only read within [head..tail),
        // and we do not advance HEAD so the consumer cursor is unmodified.
        unsafe {
            f(&*RING.0[i & (RING_SIZE - 1)].get());
        }
    }
}

/// Returns the number of events currently pending in the buffer.
#[inline]
pub fn pending() -> usize {
    let tail = TAIL.load(Ordering::Relaxed);
    let head = HEAD.load(Ordering::Relaxed);
    tail.saturating_sub(head).min(RING_SIZE)
}
