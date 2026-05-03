//! Kernel stack allocator.
//!
//! Each kernel stack is KSTACK_PAGES * 4096 bytes.  alloc_kstack() allocates
//! physical pages, identity-maps them into the kernel address space, and
//! returns the top VA (exclusive end — stacks grow downward).
//!
//! free_kstack(top) returns pages to the PMM on thread exit.

const KSTACK_PAGES: usize = 2;                  // 8 KiB per kernel stack

/// Allocate a new kernel stack.  Returns the top VA or None on OOM.
pub fn alloc_kstack() -> Option<usize> {
    let pa0 = crate::mm::pmm::alloc_page()?;
    let pa1 = crate::mm::pmm::alloc_page()?;
    unsafe {
        core::ptr::write_bytes(pa0 as *mut u8, 0, 4096);
        core::ptr::write_bytes(pa1 as *mut u8, 0, 4096);
    }
    // Supervisor R/W, no User bit, no NX (data)
    let pte: u64 = 0x3; // Present | Writable
    let cr3 = crate::arch::x86_64::paging::kernel_cr3();
    crate::arch::x86_64::paging::map_page(cr3, pa0, pa0, pte);
    crate::arch::x86_64::paging::map_page(cr3, pa1, pa1, pte);
    Some(pa1 + 4096) // return TOP of second page
}

/// Free a kernel stack previously returned by alloc_kstack.
pub fn free_kstack(top: usize) {
    if top == 0 { return; }
    let pa1 = top - 4096;
    let pa0 = pa1 - 4096;
    crate::arch::x86_64::paging::unmap_page(pa0);
    crate::arch::x86_64::paging::unmap_page(pa1);
    crate::mm::pmm::free_page(pa0);
    crate::mm::pmm::free_page(pa1);
}
