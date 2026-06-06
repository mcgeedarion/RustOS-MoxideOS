//! VirtIO split virtqueue (§2.6).
//!
//! A single `Virtqueue<N>` is statically allocated.  The driver owns all N
//! descriptor slots; for simplicity we issue one chain at a time (synchronous
//! I/O) and never have more than one in-flight request.

use crate::mm::phys::virt_to_phys;
use core::sync::atomic::{AtomicU16, Ordering};

// Descriptor flags
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
pub const VIRTQ_DESC_F_WRITE: u16 = 2; // device-writable

// ---------------------------------------------------------------------------
// On-wire structures (§2.6.5 / §2.6.6 / §2.6.8)
// ---------------------------------------------------------------------------

/// A single virtqueue descriptor.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// Available ring (driver → device).
#[repr(C)]
struct VirtqAvail<const N: usize> {
    flags: u16,
    idx: u16,
    ring: [u16; N],
    used_event: u16,
}

/// One entry in the used ring.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

/// Used ring (device → driver).
#[repr(C)]
struct VirtqUsed<const N: usize> {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; N],
    avail_event: u16,
}

// ---------------------------------------------------------------------------
// Virtqueue
// ---------------------------------------------------------------------------

/// Split virtqueue with compile-time size `N` (must be a power of two ≤ 32768).
///
/// All three rings are stored inline (no heap allocation) so their physical
/// addresses are stable for the lifetime of the driver.
#[repr(C, align(4096))]
pub struct Virtqueue<const N: usize> {
    desc: [VirtqDesc; N],
    avail: VirtqAvail<N>,
    // 4 KiB alignment between avail and used rings (spec §2.6)
    _pad: [u8; 4096],
    used: VirtqUsed<N>,

    // Driver-side bookkeeping (not mapped to device)
    last_used_idx: u16,
    next_free: u16,
}

impl<const N: usize> Virtqueue<N> {
    pub const fn new() -> Self {
        Self {
            desc: [VirtqDesc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            }; N],
            avail: VirtqAvail {
                flags: 0,
                idx: 0,
                ring: [0u16; N],
                used_event: 0,
            },
            _pad: [0u8; 4096],
            used: VirtqUsed {
                flags: 0,
                idx: 0,
                ring: [VirtqUsedElem { id: 0, len: 0 }; N],
                avail_event: 0,
            },
            last_used_idx: 0,
            next_free: 0,
        }
    }

    // --- physical address accessors for VirtioMmio::init_queue ---

    pub fn desc_phys(&self) -> u64 {
        virt_to_phys(self.desc.as_ptr() as usize) as u64
    }
    pub fn avail_phys(&self) -> u64 {
        virt_to_phys(&self.avail as *const _ as usize) as u64
    }
    pub fn used_phys(&self) -> u64 {
        virt_to_phys(&self.used as *const _ as usize) as u64
    }

    // --- descriptor chain management ---

    /// Place `descs` into the descriptor table starting at `self.next_free`,
    /// add the head index to the available ring, and bump the avail idx.
    ///
    /// Returns the head descriptor index (used to identify this chain in
    /// `has_used`).
    pub fn push_chain(&mut self, descs: &[VirtqDesc]) -> u16 {
        assert!(!descs.is_empty());
        assert!(descs.len() <= N);

        let head = self.next_free;

        for (i, d) in descs.iter().enumerate() {
            let slot = (head as usize + i) % N;
            self.desc[slot] = *d;
            // Fix up the `next` pointer to use actual ring indices
            if i + 1 < descs.len() {
                self.desc[slot].next = ((head as usize + i + 1) % N) as u16;
            }
        }

        // Write head into available ring
        let avail_slot = self.avail.idx as usize % N;
        self.avail.ring[avail_slot] = head;

        // Ensure descriptor writes are visible before idx bump
        core::sync::atomic::fence(Ordering::Release);
        self.avail.idx = self.avail.idx.wrapping_add(1);

        self.next_free = ((head as usize + descs.len()) % N) as u16;
        head
    }

    /// Returns `true` once the device has posted a used-ring entry whose
    /// `id` matches `head`.
    pub fn has_used(&self, head: u16) -> bool {
        if self.used.idx == self.last_used_idx {
            return false;
        }
        let slot = self.last_used_idx as usize % N;
        self.used.ring[slot].id as u16 == head
    }

    /// Consume the oldest used-ring entry (call after `has_used` returns true).
    pub fn consume_used(&mut self) {
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
    }
}
