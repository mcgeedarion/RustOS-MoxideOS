//! Kernel security / capability subsystem.

use core::sync::atomic::{AtomicU64, Ordering};

/// Linux-compatible capability bitmask (two 32-bit halves → one u64).
///
/// All 64 capability bits can be individually set, cleared, or tested.
/// New processes inherit a full set from their parent; capability enforcement
/// is applied per-process via `check_capability`.
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

/// Global fallback used only before the scheduler has a current process
/// (e.g. during early kernel init).  Never modified after boot.
static BOOT_CAPS: AtomicU64 = AtomicU64::new(!0u64);

/// Returns `true` if the **current process** holds Linux capability `cap`.
///
/// Consults the per-process `CapSet` stored in the PCB.  Falls back to the
/// global boot caps during early init (before the scheduler has a runnable
/// process).
pub fn check_capability(cap: u32) -> bool {
    if cap >= 64 { return false; }
    // Ask the scheduler for the current process's capability set.
    // `with_proc` returns None if the scheduler has no current process.
    let pid = crate::proc::scheduler::current_pid();
    if pid != 0 {
        if let Some(has) = crate::proc::scheduler::with_proc(pid, |p| p.caps.has(cap)) {
            return has;
        }
    }
    // Fall back to boot-time global caps (always full during kernel init).
    BOOT_CAPS.load(Ordering::Relaxed) & (1 << cap) != 0
}
