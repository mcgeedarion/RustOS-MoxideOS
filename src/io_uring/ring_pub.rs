//! Public CQ-ring head/tail prefix view.
//!
//! This is a minimal view of the first two fields of the private `CqRingHdr`.
//! Keep this layout synchronized with `CqRingHdr` in `ring.rs`.

use core::sync::atomic::{AtomicU32, Ordering};

/// Public head/tail prefix of the CQ ring header.
///
/// Layout contract:
/// - `head` must match `CqRingHdr::head` at offset 0.
/// - `tail` must match `CqRingHdr::tail` at offset 4.
///
/// Do not use this as an owned CQ header. It is only valid as a prefix view over
/// an existing CQ ring header allocation.
#[repr(C)]
pub(crate) struct CqRingHeadTail {
    /// Monotonically increasing consumer index.
    ///
    /// Readers should use `Ordering::Acquire` when checking completion
    /// availability.
    pub head: AtomicU32,

    /// Monotonically increasing producer index.
    ///
    /// The kernel publishes this with `Ordering::Release` after writing CQEs.
    /// Waiters should read it with `Ordering::Acquire`.
    pub tail: AtomicU32,
}

impl CqRingHeadTail {
    #[inline]
    pub fn available(&self) -> u32 {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }
}

const _: () = assert!(core::mem::size_of::<CqRingHeadTail>() == 8);
const _: () = assert!(core::mem::align_of::<CqRingHeadTail>() == core::mem::align_of::<AtomicU32>());
