//! Kernel stack allocator.
//!
//! Layout for each kernel stack (addresses grow downward):
//!
//!   [guard_pa]  4 KiB  mapped PROT_NONE (not present) — overflow sentinel
//!   [pa0]       4 KiB  supervisor R/W
//!   [pa1]       4 KiB  supervisor R/W   ← RSP starts here (kstack_top)
//!
//! alloc_kstack() returns the top VA (exclusive end of pa1).
//! free_kstack(top) unmaps and frees all three pages.

use crate::arch::{Arch, api::{Paging, PageFlags}};

const PAGE: usize = 4096;

/// Allocate a new kernel stack with a guard page. Returns the top VA or None on OOM.
pub fn alloc_kstack() -> Option<usize> {
    let pa_guard = crate::mm::pmm::alloc_page()?;
    let pa0      = crate::mm::pmm::alloc_page()?;
    let pa1      = crate::mm::pmm::alloc_page()?;

    unsafe {
        // Zero the usable stack pages; guard page contents are irrelevant.
        core::ptr::write_bytes(pa0 as *mut u8, 0, PAGE);
        core::ptr::write_bytes(pa1 as *mut u8, 0, PAGE);
    }

    let cr3 = <Arch as Paging>::kernel_cr3();
    let kstack_flags = PageFlags::PRESENT | PageFlags::WRITE; // supervisor R/W, no USER, no NX

    // Guard page: mapped with no flags (not present) — any access faults immediately.
    <Arch as Paging>::map_page(cr3, pa_guard, pa_guard, PageFlags::empty());
    // Usable stack pages.
    <Arch as Paging>::map_page(cr3, pa0, pa0, kstack_flags);
    <Arch as Paging>::map_page(cr3, pa1, pa1, kstack_flags);

    Some(pa1 + PAGE) // RSP points one byte past the top of pa1
}

/// Free a kernel stack previously returned by alloc_kstack.
/// `top` is the value returned by alloc_kstack (pa1 + PAGE).
pub fn free_kstack(top: usize) {
    if top == 0 { return; }
    let pa1      = top   - PAGE;
    let pa0      = pa1   - PAGE;
    let pa_guard = pa0   - PAGE;

    let cr3 = <Arch as Paging>::kernel_cr3();
    <Arch as Paging>::unmap_page(pa_guard);
    <Arch as Paging>::unmap_page(pa0);
    <Arch as Paging>::unmap_page(pa1);

    crate::mm::pmm::free_page(pa_guard);
    crate::mm::pmm::free_page(pa0);
    crate::mm::pmm::free_page(pa1);
}
