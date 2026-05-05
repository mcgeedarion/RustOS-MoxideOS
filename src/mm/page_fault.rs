//! Demand-paging fault handler.
//!
//! Called from the arch IDT/trap handler when:
//!   - error_code bit 0 (P) == 0  — page not present
//!   - error_code bit 2 (U) == 1  — fault in user mode
//!
//! Arch-neutral: uses arch::Arch (Paging trait) throughout.

use crate::arch::{Arch, api::{Paging, PageFlags}};
use crate::mm::mmap::{VmaKind, PROT_WRITE, PROT_EXEC, find_vma};
use crate::mm::pmm::alloc_page;
use crate::proc::scheduler;

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = !(PAGE_SIZE - 1);

/// Try to resolve a not-present user fault at `faulting_va`.
/// Returns `true` if the fault was handled; `false` if SIGSEGV should be sent.
pub fn handle_demand_fault(faulting_va: usize) -> bool {
    let page_va = faulting_va & PAGE_MASK;
    let pid     = scheduler::current_pid();

    // O(log n) VMA lookup via binary search (find_vma, mmap.rs).
    let vma = match find_vma(pid, faulting_va) {
        Some(v) => v,
        None    => return false,
    };

    // Separate lock acquisition for the CR3: with_proc is O(log n) via pid_idx.
    let user_cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if user_cr3 == 0 { return false; }

    let pa = match alloc_page() {
        Some(p) => p,
        None    => return false,
    };

    match &vma.kind {
        VmaKind::Anonymous => {
            // alloc_page() guarantees zero-filled pages; no explicit zeroing needed.
        }
        VmaKind::FileBacked(fd, base_offset) => {
            // Zero first so any short-read region is clean, then fill from file.
            // Unlike Anonymous, we cannot rely on alloc_page's zero here because
            // pread may partially fill the page.
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
            // TODO: on pread failure, free `pa` and return false so the arch
            // trap handler delivers SIGBUS (currently the process silently
            // receives a zero page instead of the expected SIGBUS).
            let _ = crate::fs::vfs::pread(*fd, pa as *mut u8, PAGE_SIZE,
                (*base_offset + (page_va - vma.start) as u64) as i64);
        }
        VmaKind::Fixed => {
            // MAP_FIXED over an already-unmapped region — access violation.
            crate::mm::pmm::free_page(pa);
            return false;
        }
    }

    let flags = prot_to_flags(vma.prot);
    <Arch as Paging>::map_page(user_cr3, page_va, pa, flags);
    <Arch as Paging>::flush_va(page_va);
    true
}

#[inline]
fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  == 0 { f |= PageFlags::NX; }
    f
}
