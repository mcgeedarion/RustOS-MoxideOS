//! Copy-on-Write page fault handler and fork address-space clone.
//!
//! ## CoW fork flow
//!
//!   sys_fork() / clone3 without CLONE_VM:
//!     child_cr3 = clone_for_fork(parent_pid, child_pid, parent_cr3)
//!       → clone_pml4_cow: marks shared pages read-only + COW_BIT
//!       → clone_vmas: child gets copy of parent VMA list
//!
//!   On first write by either parent or child to a shared page:
//!     CPU raises #PF (error code: Present | Write | User → 0x7)
//!     → handle_cow_fault(faulting_va, error_code) is called
//!     → alloc new page, copy old content, make new PTE writable
//!
//! ## Page-fault error code bits (x86-64)
//!   bit 0  P  — 0 = not-present, 1 = protection violation
//!   bit 1  W  — 0 = read, 1 = write
//!   bit 2  U  — 0 = supervisor, 1 = user
//!
//! A CoW fault has P=1, W=1, U=1 (error_code & 0x7 == 0x7).

use crate::arch::x86_64::paging;
use crate::mm::pmm;

const PAGE_SIZE: usize = 4096;
const COW_BIT:   u64 = 1 << 9;
const PRESENT:   u64 = 1 << 0;
const WRITABLE:  u64 = 1 << 1;
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// ── clone_for_fork ────────────────────────────────────────────────────────

/// Create a CoW copy of the parent's address space for a fork() child.
///
/// Wraps paging::clone_pml4_cow and mirrors the parent's VMA list
/// under the child's pid so the page-fault handler can validate addresses.
///
/// Returns the child's CR3 physical address.
pub fn clone_for_fork(parent_pid: usize, child_pid: usize, parent_cr3: usize) -> usize {
    let child_cr3 = paging::clone_pml4_cow(parent_cr3);
    let parent_key = crate::proc::thread::vma_pid(parent_pid);
    let child_key  = crate::proc::thread::vma_pid(child_pid);
    if parent_key != child_key {
        crate::mm::mmap::clone_vmas(parent_key, child_key);
    }
    child_cr3
}

// ── handle_cow_fault ─────────────────────────────────────────────────────

/// Handle a #PF that may be a CoW write fault.
///
/// Returns true if the fault was CoW and is now resolved.
/// Returns false if it is a genuine access violation.
pub fn handle_cow_fault(faulting_va: usize, error_code: u64) -> bool {
    // Must be Present (P=1) + Write (W=1) + User (U=1)
    if error_code & 0x7 != 0x7 { return false; }

    let cr3 = paging::current_cr3();

    let pte_val = match unsafe { pte_read(cr3, faulting_va) } {
        Some(v) => v,
        None    => return false,
    };

    // Must have COW_BIT; otherwise genuine write-to-RO violation
    if pte_val & COW_BIT == 0 { return false; }

    let old_pa = (pte_val & ADDR_MASK) as usize;

    let new_pa = match pmm::alloc_page() {
        Some(p) => p,
        None    => return false, // OOM
    };

    unsafe {
        core::ptr::copy_nonoverlapping(
            old_pa as *const u8,
            new_pa as *mut u8,
            PAGE_SIZE,
        );
    }

    // New PTE: same flags, Writable restored, COW_BIT cleared
    let new_pte = (new_pa as u64 & ADDR_MASK)
                | (pte_val & 0xFFF & !COW_BIT)
                | PRESENT | WRITABLE;

    unsafe { pte_write(cr3, faulting_va, new_pte); }
    paging::invlpg(faulting_va & !0xFFF);

    true
}

// ── low-level PTE read/write ──────────────────────────────────────────────

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
    let pte_p = ((pde & ADDR_MASK) as usize + pti * 8) as *const u64;
    Some(*pte_p)
}

unsafe fn pte_write(cr3: usize, va: usize, new_val: u64) {
    let pml4i = (va >> 39) & 0x1FF;
    let pdpti = (va >> 30) & 0x1FF;
    let pdi   = (va >> 21) & 0x1FF;
    let pti   = (va >> 12) & 0x1FF;

    let pml4e = *((cr3 + pml4i * 8) as *const u64);
    let pdpte = *(((pml4e & ADDR_MASK) as usize + pdpti * 8) as *const u64);
    let pde   = *(((pdpte & ADDR_MASK) as usize + pdi * 8) as *const u64);
    let pte_p = ((pde & ADDR_MASK) as usize + pti * 8) as *mut u64;
    *pte_p = new_val;
}
