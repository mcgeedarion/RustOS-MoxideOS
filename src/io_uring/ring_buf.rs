// src/io_uring/ring_buf.rs
//
// Ring buffer sizing constants and the shared memory layout helpers used by
// the SQ and CQ rings.
//
// Sizes must be powers of two so that masking (`index & (N - 1)`) works
// instead of modulo, matching the Linux io_uring convention.

/// Number of SQE slots.  Increase for higher submission throughput.
pub const SQ_ENTRIES: usize = 256;
/// Number of CQE slots.  Typically 2× SQ to absorb bursts.
pub const CQ_ENTRIES: usize = 512;

const _: () = assert!(SQ_ENTRIES.is_power_of_two(), "SQ_ENTRIES must be a power of two");
const _: () = assert!(CQ_ENTRIES.is_power_of_two(), "CQ_ENTRIES must be a power of two");
const _: () = assert!(CQ_ENTRIES >= SQ_ENTRIES, "CQ must be at least as large as SQ");

// ── RingBuffer helper ─────────────────────────────────────────────────────────

/// Lightweight wrapper that enforces the power-of-two masking contract and
/// tracks available/used capacity without touching the atomics directly.
///
/// Useful for driver code that wants to reason about ring space without
/// importing the full ring state.
pub struct RingBuffer {
    capacity: usize,
    mask: usize,
}

impl RingBuffer {
    pub const fn new(capacity: usize) -> Self {
        // capacity must be a power of two — enforced by const assertions above.
        RingBuffer { capacity, mask: capacity - 1 }
    }

    /// Map a raw index to a slot index (wraps around).
    #[inline]
    pub fn slot(&self, index: u32) -> usize {
        (index as usize) & self.mask
    }

    /// Number of entries between `head` and `tail` (i.e. entries available
    /// to a consumer).
    #[inline]
    pub fn available(&self, head: u32, tail: u32) -> u32 {
        tail.wrapping_sub(head)
    }

    /// Remaining free slots a producer can write before the ring is full.
    #[inline]
    pub fn free_slots(&self, head: u32, tail: u32) -> u32 {
        self.capacity as u32 - self.available(head, tail)
    }

    /// True when the ring is empty (consumer is caught up with producer).
    #[inline]
    pub fn is_empty(&self, head: u32, tail: u32) -> bool {
        head == tail
    }

    /// True when the ring is full.
    #[inline]
    pub fn is_full(&self, head: u32, tail: u32) -> bool {
        self.available(head, tail) == self.capacity as u32
    }
}

pub const SQ_RING_BUF: RingBuffer = RingBuffer::new(SQ_ENTRIES);
pub const CQ_RING_BUF: RingBuffer = RingBuffer::new(CQ_ENTRIES);
