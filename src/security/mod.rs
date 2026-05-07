//! Kernel security subsystem.
//!
//! Modules:
//!   - `aslr`      — address space layout randomisation
//!   - `canary`    — stack canary (`__stack_chk_guard` / `__stack_chk_fail`)
//!   - `smep_smap` — SMEP/SMAP/UMIP enforcement + STAC/CLAC wrappers
//!   - `pti`       — Page Table Isolation (dual PML4, CR3 switching)
//!   - `seccomp`   — syscall filter (BPF)

pub mod aslr;
pub mod canary;
pub mod smep_smap;
pub mod pti;
pub mod seccomp;

use core::sync::atomic::{AtomicU64, Ordering};

/// Initialise all security subsystems.  Called once from `kernel_main`
/// after the physical memory manager and paging are up, but before any
/// user processes are created.
pub fn init() {
    canary::init_kernel_canary();
    unsafe {
        smep_smap::enforce();
        pti::init();
    }
    log::info!("security: ASLR={} canary=on SMEP={} SMAP={} PTI={}",
        true,
        smep_smap::SMEP_ENABLED.load(Ordering::Relaxed),
        smep_smap::SMAP_ENABLED.load(Ordering::Relaxed),
        pti::PTI_ENABLED.load(Ordering::Relaxed),
    );
}

// ───── Capability system (unchanged) ───────────────────────────────────────────────

/// Linux-compatible capability bitmask (two 32-bit halves → one u64).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CapSet(pub u64);

impl CapSet {
    pub const fn full()  -> Self { CapSet(!0u64) }
    pub const fn empty() -> Self { CapSet(0) }
    pub fn has(&self, cap: u32) -> bool {
        if cap >= 64 { return false; }
        self.0 & (1 << cap) != 0
    }
    pub fn grant(&mut self, cap: u32)  { if cap < 64 { self.0 |=  1 << cap; } }
    pub fn revoke(&mut self, cap: u32) { if cap < 64 { self.0 &= !(1 << cap); } }
}

static BOOT_CAPS: AtomicU64 = AtomicU64::new(!0u64);

pub fn check_capability(cap: u32) -> bool {
    if cap >= 64 { return false; }
    let pid = crate::proc::scheduler::current_pid();
    if pid != 0 {
        if let Some(has) = crate::proc::scheduler::with_proc(pid, |p| p.caps.has(cap)) {
            return has;
        }
    }
    BOOT_CAPS.load(Ordering::Relaxed) & (1 << cap) != 0
}
