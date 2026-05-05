//! Demand-paging fault handler.
//!
//! Called from the arch IDT/trap handler when:
//!   - error_code bit 0 (P) == 0  — page not present
//!   - error_code bit 2 (U) == 1  — fault in user mode
//!
//! Arch-neutral: uses arch::Arch (Paging trait) throughout.

use crate::arch::{Arch, api::{Paging, PageFlags}};
use crate::mm::mmap::{VmaKind, PROT_WRITE, PROT_EXEC};
use crate::mm::pmm::alloc_page;
use crate::proc::scheduler;

const PAGE_SIZE: usize = 4096;
const PAGE_MASK: usize = !(PAGE_SIZE - 1);

/// Try to resolve a not-present user fault at `faulting_va`.
/// Returns `true` if the fault was handled; `false` if SIGSEGV should be sent.
pub fn handle_demand_fault(faulting_va: usize) -> bool {
    let page_va = faulting_va & PAGE_MASK;

    // Look up the faulting process's VMA list and CR3 in one lock window.
    let (vma, user_cr3) = {
        let pid = scheduler::current_pid();
        let result = scheduler::with_procs(|procs| {
            procs.iter().find(|p| p.pid == pid).and_then(|p| {
                let vma = p.vmas.iter()
                    .find(|v| v.start <= faulting_va && faulting_va < v.end)
                    .cloned();
                vma.map(|v| (v, p.user_satp))
            })
        });
        match result {
            Some(pair) => pair,
            None       => return false,
        }
    };

    // Only map into the process's own address space, never kernel_cr3.
    if user_cr3 == 0 { return false; }

    let pa = match alloc_page() {
        Some(p) => p,
        None    => return false,
    };

    match &vma.kind {
        VmaKind::Anonymous => {
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
        }
        VmaKind::FileBacked(fd, base_offset) => {
            let page_idx = (page_va - vma.start) / PAGE_SIZE;
            let file_pos = base_offset + page_idx as u64 * PAGE_SIZE as u64;
            unsafe { core::ptr::write_bytes(pa as *mut u8, 0, PAGE_SIZE); }
            // TODO: on pread failure, free `pa` and return false so the arch
            // trap handler delivers SIGBUS (currently the process silently
            // receives a zero page instead of the expected SIGBUS).
            let _ = crate::fs::vfs::pread(*fd, pa as *mut u8, PAGE_SIZE, file_pos as i64);
        }
        VmaKind::Fixed => {
            // VmaKind::Fixed indicates a MAP_FIXED mapping that was placed
            // over an already-mapped region. A not-present fault here means
            // the region was unmapped under the process — treat as access
            // violation. Free the freshly allocated page and signal SIGSEGV.
            crate::mm::pmm::free_page(pa);
            return false;
        }
    }

    let flags = prot_to_flags(vma.prot);
    <Arch as Paging>::map_page(user_cr3, page_va, pa, flags);
    <Arch as Paging>::flush_va(page_va);
    true
}

/// POSIX PROT_* → canonical HAL PageFlags.
#[inline]
fn prot_to_flags(prot: u32) -> PageFlags {
    let mut f = PageFlags::PRESENT | PageFlags::USER;
    if prot & PROT_WRITE != 0 { f |= PageFlags::WRITE; }
    if prot & PROT_EXEC  == 0 { f |= PageFlags::NX; }
    f
}
