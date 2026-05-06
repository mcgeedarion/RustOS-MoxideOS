//! Kernel stack allocator.
//!
//! Layout for each kernel stack (addresses grow downward):
//!
//!   [guard_pa]  4 KiB  mapped PROT_NONE (not present) — overflow sentinel
//!   [pa0]       4 KiB  supervisor R/W
//!   [pa1]       4 KiB  supervisor R/W   ← RSP starts here (kstack_top)
//!
//! `alloc_kstack()` returns a `KstackInfo` that explicitly records every
//! physical address used. `free_kstack()` uses that record — never pointer
//! arithmetic — so the allocator is safe even when VA != PA (KASLR, higher
//! half, etc.).
//!
//! # Fix #1 – identity-map assumption removed
//! The old code called `free_kstack(top)` and re-derived `pa0`/`pa_guard`
//! by subtracting PAGE from `top`. That silently assumed VA == PA (identity
//! mapping). Now `alloc_kstack` returns a `KstackInfo` struct that carries
//! every PA; `free_kstack` uses those PAs directly.
//!
//! # Fix #2 – double-zero eliminated
//! `pmm::alloc_page()` guarantees every returned page is zeroed. The old
//! code called `write_bytes(0)` on `pa0` and `pa1` again. Those redundant
//! zeroes are removed; the PMM's single authoritative zero is relied upon.

use crate::arch::{Arch, api::{Paging, PageFlags}};

const PAGE: usize = 4096;

/// Opaque handle returned by `alloc_kstack`.
/// Stores every physical address so `free_kstack` never needs to infer them.
pub struct KstackInfo {
    /// Top of the usable stack (= pa1 + PAGE). This is the initial RSP value.
    pub top:  usize,
    pa1:      usize,
    pa0:      usize,
    pa_guard: usize,
}

/// Allocate a new kernel stack with a guard page.
/// Returns `None` on OOM.
///
/// The three pages come out of the PMM already zeroed — no additional
/// `write_bytes` calls are needed (and must not be added; see module doc).
pub fn alloc_kstack() -> Option<KstackInfo> {
    let pa_guard = crate::mm::pmm::alloc_page()?;
    let pa0      = crate::mm::pmm::alloc_page()?;
    let pa1      = crate::mm::pmm::alloc_page()?;
    // PMM guarantees zero-fill; do NOT zero again (fix #2).

    let cr3 = <Arch as Paging>::kernel_cr3();
    let kstack_flags = PageFlags::PRESENT | PageFlags::WRITE; // supervisor R/W

    // Guard page: no flags → not-present → any overflow faults immediately.
    <Arch as Paging>::map_page(cr3, pa_guard, pa_guard, PageFlags::empty());
    <Arch as Paging>::map_page(cr3, pa0,      pa0,      kstack_flags);
    <Arch as Paging>::map_page(cr3, pa1,      pa1,      kstack_flags);

    Some(KstackInfo {
        top: pa1 + PAGE, // RSP starts one byte past the top of pa1
        pa1,
        pa0,
        pa_guard,
    })
}

/// Free a kernel stack previously returned by `alloc_kstack`.
/// Uses the recorded physical addresses — never pointer arithmetic.
pub fn free_kstack(info: KstackInfo) {
    let cr3 = <Arch as Paging>::kernel_cr3();
    <Arch as Paging>::unmap_page(info.pa_guard);
    <Arch as Paging>::unmap_page(info.pa0);
    <Arch as Paging>::unmap_page(info.pa1);

    crate::mm::pmm::free_page(info.pa_guard);
    crate::mm::pmm::free_page(info.pa0);
    crate::mm::pmm::free_page(info.pa1);
}
