//! Copy-on-Write page fault handler and fork address-space clone.
//!
//! Arch-neutral: uses arch::Arch (Paging trait) throughout.
//!
//! ## CoW fault error code bits (x86-64 / RISC-V scause store-page-fault)
//!   bit 0  P  — present
//!   bit 1  W  — write
//!   bit 2  U  — user
//! A CoW fault has P=1, W=1, U=1 (error_code & 0x7 == 0x7).

use crate::arch::{Arch, api::{Paging, PageFlags}};
use crate::mm::pmm;

const PAGE_SIZE: usize = 4096;

// ── clone_for_fork ────────────────────────────────────────────────────────

/// Create a CoW copy of the parent's address space for a fork() child.
/// Returns the child's CR3 / SATP physical address, or 0 on OOM.
pub fn clone_for_fork(parent_pid: usize, child_pid: usize, parent_cr3: usize) -> usize {
    let child_cr3 = match <Arch as Paging>::clone_address_space(parent_cr3) {
        Some(c) => c,
        None    => return 0,
    };
    let parent_key = crate::proc::thread::vma_pid(parent_pid);
    let child_key  = crate::proc::thread::vma_pid(child_pid);
    if parent_key != child_key {
        crate::mm::mmap::clone_vmas(parent_key, child_key);
    }
    child_cr3
}

// ── handle_cow_fault ──────────────────────────────────────────────────────

/// Handle a write fault that may be a CoW page.
/// Returns true if resolved; false if genuine access violation.
pub fn handle_cow_fault(faulting_va: usize, error_code: u64) -> bool {
    // P=1, W=1, U=1
    if error_code & 0x7 != 0x7 { return false; }

    let cr3 = <Arch as Paging>::kernel_cr3();

    // Resolve VA → current PTE value via virt_to_phys.
    // We need the raw PTE flags, not just the PA, so fall back to
    // the arch-internal walk if Paging::virt_to_phys drops flags.
    // For now: check virt_to_phys succeeds (page is present), then
    // do the COW_BIT check through the arch helper.
    let old_pa = match <Arch as Paging>::virt_to_phys(cr3, faulting_va) {
        Some(pa) => pa,
        None     => return false,
    };

    // Arch-specific: read the raw PTE to check COW_BIT.
    // We keep the raw-walk helpers in cow_fault so the HAL doesn't
    // need a "get_pte" method (which would be too low-level).
    let pte_val = match unsafe { pte_read(cr3, faulting_va) } {
        Some(v) => v,
        None    => return false,
    };

    if pte_val & (1 << 9) == 0 { return false; } // COW_BIT not set

    let new_pa = match pmm::alloc_page() {
        Some(p) => p,
        None    => return false,
    };

    unsafe {
        core::ptr::copy_nonoverlapping(
            old_pa as *const u8,
            new_pa as *mut u8,
            PAGE_SIZE,
        );
    }

    // Rebuild flags: restore WRITE, clear COW_BIT, keep USER + PRESENT.
    let flags = PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER;
    <Arch as Paging>::map_page(cr3, faulting_va & !0xFFF, new_pa, flags);
    <Arch as Paging>::flush_va(faulting_va & !0xFFF);

    true
}

// ── low-level PTE read (x86-64 4-level / RISC-V Sv39 compatible) ─────────
// Used only to check COW_BIT; kept here so arch::api stays clean.

const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PRESENT:   u64 = 1;

unsafe fn pte_read(cr3: usize, va: usize) -> Option<u64> {
    let pml4i = (va >> 39) & 0x1FF;
    let pdpti = (va >> 30) & 0x1FF;
    let pdi   = (va >> 21) & 0x1FF;
    let pti   = (va >> 12) & 0x1FF;

    let pml4e = *((cr3 + pml4i * 8) as *const u64);
    if pml4e & PRESENT == 0 { return None; }
    let pdpte = *(((pml4e & ADDR_MASK) as usize + pdpti * 8) as *const u64);
    if pdpte & PRESENT == 0 { return None; }
    let pde   = *(((pdpte & ADDR_MASK) as usize + pdi * 8) as *const u64);
    if pde   & PRESENT == 0 { return None; }
    Some(*((  (pde & ADDR_MASK) as usize + pti * 8) as *const u64))
}
