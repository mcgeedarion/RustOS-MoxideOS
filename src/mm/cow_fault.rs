//! Copy-on-Write page fault handler and fork address-space clone.

use crate::arch::{Arch, api::{Paging, PageFlags}};
use crate::mm::pmm;
use crate::proc::scheduler;

const PAGE_SIZE: usize = 4096;

// ── clone_for_fork ─────────────────────────────────────────────────────────────────────

/// Create a CoW copy of the parent’s address space for a fork() child.
/// Returns the child’s CR3 physical address, or 0 on OOM.
pub fn clone_for_fork(parent_pid: usize, child_pid: usize, parent_cr3: usize) -> usize {
    let child_cr3 = match <Arch as Paging>::clone_address_space(parent_cr3) {
        Some(c) => c,
        None    => return 0,
    };
    let parent_key = crate::proc::thread::vma_pid(parent_pid);
    let child_key  = crate::proc::thread::vma_pid(child_pid);
    if parent_key != child_key {
        crate::mm::mmap::clone_vmas(parent_key as usize, child_key as usize);
    }
    child_cr3
}

// ── handle_cow_fault ───────────────────────────────────────────────────────────────

/// Handle a write fault that may be a CoW page.
/// Returns true if resolved; false if genuine access violation.
///
/// # Safety invariant on free_page(old_pa)
/// `free_page(old_pa)` is called after the new private copy has been mapped.
/// This is safe only because `clone_address_space` (arch layer) decrements a
/// per-page refcount and marks pages CoW precisely when the refcount drops to
/// 1 — meaning that by the time a process faults with COW_BIT set, the arch
/// layer guarantees `old_pa` is referenced by exactly this one PTE.
/// If the arch layer ever changes to shared-page semantics (refcount > 1 CoW),
/// this free_page call must be gated on refcount == 0.
pub fn handle_cow_fault(faulting_va: usize, error_code: u64) -> bool {
    // P=1, W=1, U=1  (x86-64 page-fault error code bits 0-2)
    if error_code & 0x7 != 0x7 { return false; }

    let pid = scheduler::current_pid();
    let cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if cr3 == 0 { return false; }

    let old_pa = match <Arch as Paging>::virt_to_phys(cr3, faulting_va) {
        Some(pa) => pa,
        None     => return false,
    };

    let pte_val = match unsafe { pte_read(cr3, faulting_va) } {
        Some(v) => v,
        None    => return false,
    };

    if pte_val & (1 << 9) == 0 { return false; } // COW_BIT not set

    let new_pa = match pmm::alloc_page() {
        Some(p) => p,
        None    => return false,
    };

    // alloc_page() returns a zero-filled page; copy only the live content.
    unsafe {
        core::ptr::copy_nonoverlapping(
            old_pa as *const u8,
            new_pa as *mut u8,
            PAGE_SIZE,
        );
    }

    let flags = PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER;
    <Arch as Paging>::map_page(cr3, faulting_va & !0xFFF, new_pa, flags);
    <Arch as Paging>::flush_va(faulting_va & !0xFFF);
    // See safety invariant in doc comment above.
    // Debug assertion: the VA should now be unreachable via the old PA
    // (the arch layer must have replaced the PTE before we arrive here).
    #[cfg(debug_assertions)]
    {
        let current_pa = unsafe { crate::mm::cow_fault::pte_read_pub(cr3, faulting_va & !0xFFF) };
        debug_assert!(
            current_pa.map_or(true, |pte| pte & 0x000F_FFFF_FFFF_F000 != old_pa as u64),
            "cow_fault: PTE still points to old_pa {:#x} after map_page — \
             arch layer did not replace it before free_page",
            old_pa
        );
    }
    pmm::free_page(old_pa);

    true
}

// ── low-level PTE read (x86-64 4-level paging) ───────────────────────────────────

const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PRESENT:   u64 = 1;
/// Bit 7 in a PDPTE or PDE: page size (1 GiB / 2 MiB large page).
const PAGE_SIZE_BIT: u64 = 1 << 7;

/// Public alias for the debug assertion in handle_cow_fault.
/// Only used in debug builds.
#[cfg(debug_assertions)]
pub unsafe fn pte_read_pub(cr3: usize, va: usize) -> Option<u64> {
    unsafe { pte_read(cr3, va) }
}

/// Walk the 4-level page table and return the leaf PTE value for `va`.
///
/// Returns `None` if any level is not present OR if a large page (1 GiB PDPTE
/// or 2 MiB PDE) is encountered — large pages are not CoW-eligible in the
/// current design and the caller will fall through to the false (SIGSEGV) path.
unsafe fn pte_read(cr3: usize, va: usize) -> Option<u64> {
    let pml4i = (va >> 39) & 0x1FF;
    let pdpti = (va >> 30) & 0x1FF;
    let pdi   = (va >> 21) & 0x1FF;
    let pti   = (va >> 12) & 0x1FF;

    let pml4e = *((cr3 + pml4i * 8) as *const u64);
    if pml4e & PRESENT == 0 { return None; }

    let pdpte = *(((pml4e & ADDR_MASK) as usize + pdpti * 8) as *const u64);
    if pdpte & PRESENT == 0 { return None; }
    // 1 GiB page: leaf at PDPT level — not CoW-eligible.
    if pdpte & PAGE_SIZE_BIT != 0 { return None; }

    let pde = *(((pdpte & ADDR_MASK) as usize + pdi * 8) as *const u64);
    if pde & PRESENT == 0 { return None; }
    // 2 MiB page: leaf at PD level — not CoW-eligible.
    if pde & PAGE_SIZE_BIT != 0 { return None; }

    Some(*((  (pde & ADDR_MASK) as usize + pti * 8) as *const u64))
}
