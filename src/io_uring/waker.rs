// src/io_uring/waker.rs
//
// Waker registration table.
//
// Every submitted SQE carries a unique u64 `user_data` token.  Before
// returning Poll::Pending a future calls `io_uring::register_waker(token,
// cx.waker().clone())`.  When the matching CQE arrives, `WakerTable::wake`
// looks up and calls the waker, driving the future to completion.
//
// Implementation:
//   - Fixed-size array of Option<(u64, Waker)> so we never allocate.
//   - Linear scan is fine for the ring sizes we use (≤ 256 in-flight ops).
//   - Each slot is cleared after the waker is consumed (wake-once semantics).

use core::task::Waker;

use crate::io_uring::ring_buf::SQ_ENTRIES;

/// Maximum number of simultaneously tracked wakers.
/// Matches SQ_ENTRIES — every in-flight SQE can have one waker.
const WAKER_SLOTS: usize = SQ_ENTRIES;

pub struct WakerTable {
    slots: [Option<WakerSlot>; WAKER_SLOTS],
}

struct WakerSlot {
    token: u64,
    waker: Waker,
}

impl WakerTable {
    /// Construct an empty table (const for static initialisation).
    pub const fn new() -> Self {
        // Option<WakerSlot> is not Copy, so we cannot use array repeat syntax.
        // We use MaybeUninit transmutation instead — all bytes zero == None.
        // SAFETY: Option<WakerSlot> with all-zero bytes is the None variant on
        // every target we care about (Rust ABI guarantee for Option<T> where T
        // is a non-ZST non-zero type — confirmed by repr).
        unsafe {
            core::mem::transmute([0u8; core::mem::size_of::<[Option<WakerSlot>; WAKER_SLOTS]>()])
        }
    }

    /// Reset all slots (called from `init()`).
    pub fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
    }

    /// Register `waker` to be called when a CQE arrives with `token`.
    ///
    /// If a waker was already registered for this token it is replaced
    /// (idempotent per the `Future::poll` contract).
    pub fn register(&mut self, token: u64, waker: Waker) {
        // Try to update an existing slot first.
        for slot in self.slots.iter_mut() {
            if let Some(ref mut s) = slot {
                if s.token == token {
                    // Update in place — avoids an extra clone if it's the same waker.
                    if !s.waker.will_wake(&waker) {
                        s.waker = waker;
                    }
                    return;
                }
            }
        }
        // Find an empty slot.
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(WakerSlot { token, waker });
                return;
            }
        }
        // Table is full — this should never happen if the ring is correctly
        // sized (SQ_ENTRIES wakers for SQ_ENTRIES in-flight ops).
        log::error!(
            "[io_uring::waker] waker table full — token {:#x} dropped",
            token
        );
    }

    /// Find and call the waker registered for `token`, then free the slot.
    pub fn wake(&mut self, token: u64) {
        for slot in self.slots.iter_mut() {
            if let Some(ref s) = slot {
                if s.token == token {
                    let entry = slot.take().unwrap();
                    entry.waker.wake();
                    return;
                }
            }
        }
        // No registered waker — the operation was fire-and-forget.
    }

    /// Cancel a waker (e.g. future dropped before completion).
    ///
    /// Returns `true` if a slot was freed.
    pub fn cancel(&mut self, token: u64) -> bool {
        for slot in self.slots.iter_mut() {
            if let Some(ref s) = slot {
                if s.token == token {
                    *slot = None;
                    return true;
                }
            }
        }
        false
    }
}
