//! Kernel security / capability subsystem (stub).

use core::sync::atomic::{AtomicU64, Ordering};

/// Linux-compatible capability bitmask (two 32-bit halves → one u64).
///
/// All 64 capability bits can be individually set, cleared, or tested.
/// The kernel starts every process with a full set (trusted root environment);
/// real capability enforcement is a future work item.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CapSet(pub u64);

impl CapSet {
    /// Full capability set — every bit set.
    pub const fn full() -> Self { CapSet(!0u64) }
    /// Empty capability set — no capabilities.
    pub const fn empty() -> Self { CapSet(0) }

    pub fn has(&self, cap: u32) -> bool {
        if cap >= 64 { return false; }
        self.0 & (1 << cap) != 0
    }

    pub fn grant(&mut self, cap: u32) {
        if cap < 64 { self.0 |= 1 << cap; }
    }

    pub fn revoke(&mut self, cap: u32) {
        if cap < 64 { self.0 &= !(1 << cap); }
    }
}

/// Global "privileged" flag used by simple capability checks.
static PRIVILEGED: AtomicU64 = AtomicU64::new(!0u64);

/// Returns `true` if the current task holds the given Linux capability number.
pub fn check_capability(cap: u32) -> bool {
    if cap >= 64 { return false; }
    PRIVILEGED.load(Ordering::Relaxed) & (1 << cap) != 0
}
