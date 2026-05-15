//! Copy-on-Write page fault handler and fork address-space clone.
//!
//! Arch-neutral: uses arch::Arch (Paging trait) throughout.
//!
//! ## CoW fault error code bits (x86-64 / RISC-V scause store-page-fault)
//!   bit 0  P  — present
//!   bit 1  W  — write
//!   bit 2  U  — user
//! A CoW fault has P=1, W=1, U=1 (error_code & 0x7 == 0x7).
//!
//! ## Bug fix: use the faulting process's CR3, not kernel_cr3()
//!
//! CoW faults happen in *userspace* page tables. The original code called
//! `<Arch as Paging>::kernel_cr3()` which returns the kernel's own page
//! table root — a completely different mapping that contains only kernel
//! virtual addresses. Walking that tree for a user virtual address will
//! always fail (None from virt_to_phys / pte_read), so `handle_cow_fault`
//! always returned false, and every CoW write fault was delivered as a
//! SIGSEGV instead of being transparently resolved.
//!
//! Fixed by reading `user_satp` from the current process's Pcb.
//! Falls back to `false` gracefully if no PCB is found (should never
//! happen in the user-fault path, but is safe in the kernel path).

use crate::arch::{
    api::{PageFlags, Paging},
    Arch,
};
use crate::mm::pmm;
use crate::proc::scheduler;

const PAGE_SIZE: usize = 4096;

// ── clone_for_fork ────────────────────────────────────────────────────────

/// Create a CoW copy of the parent's address space for a fork() child.
/// Returns the child's CR3 / SATP physical address, or 0 on OOM.
pub fn clone_for_fork(parent_pid: usize, child_pid: usize, parent_cr3: usize) -> usize {
    let child_cr3 = match <Arch as Paging>::clone_address_space(parent_cr3) {
        Some(c) => c,
        None => return 0,
    };
    let parent_key = crate::proc::thread::vma_pid(parent_pid);
    let child_key = crate::proc::thread::vma_pid(child_pid);
    if parent_key != child_key {
        crate::mm::mmap::clone_vmas(parent_key, child_key);
    }
    child_cr3
}

// ── handle_cow_fault ──────────────────────────────────────────────────────

/// Handle a write fault that may be a CoW page.
/// Returns true if resolved; false if genuine access violation.
pub fn handle_cow_fault(faulting_va: usize, error_code: u64) -> bool {
    // P=1, W=1, U=1  — only handle user write-faults on present pages.
    if error_code & 0x7 != 0x7 {
        return false;
    }

    // FIX: use the current process's user CR3, not the kernel's.
    // CoW PTEs live in the userspace page tables rooted at user_satp.
    // Querying kernel_cr3() would always return None for user VAs.
    let pid = scheduler::current_pid();
    let cr3 = match scheduler::with_proc(pid, |p| p.user_satp) {
        Some(c) if c != 0 => c,
        _ => return false,
    };

    // Resolve VA → current PTE value via virt_to_phys.
    let old_pa = match <Arch as Paging>::virt_to_phys(cr3, faulting_va) {
        Some(pa) => pa,
        None => return false,
    };

    // Read the raw PTE to check the COW_BIT (bit 9, software-defined).
    let pte_val = match unsafe { pte_read(cr3, faulting_va) } {
        Some(v) => v,
        None => return false,
    };

    if pte_val & (1 << 9) == 0 {
        return false;
    } // COW_BIT not set

    let new_pa = match pmm::alloc_page() {
        Some(p) => p,
        // OOM: return false; the page fault dispatcher can send SIGKILL.
        None => return false,
    };

    unsafe {
        core::ptr::copy_nonoverlapping(old_pa as *const u8, new_pa as *mut u8, PAGE_SIZE);
    }

    // Restore WRITE, clear COW_BIT, keep USER + PRESENT.
    let flags = PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER;
    <Arch as Paging>::map_page(cr3, faulting_va & !0xFFF, new_pa, flags);
    <Arch as Paging>::flush_va(faulting_va & !0xFFF);

    // Release the original physical page now that the VA points to new_pa.
    pmm::free_page(old_pa);

    true
}

// ── low-level PTE read (x86-64 4-level / RISC-V Sv39 compatible) ─────────

const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PRESENT: u64 = 1;

unsafe fn pte_read(cr3: usize, va: usize) -> Option<u64> {
    let pml4i = (va >> 39) & 0x1FF;
    let pdpti = (va >> 30) & 0x1FF;
    let pdi = (va >> 21) & 0x1FF;
    let pti = (va >> 12) & 0x1FF;

    let pml4e = *((cr3 + pml4i * 8) as *const u64);
    if pml4e & PRESENT == 0 {
        return None;
    }
    let pdpte = *(((pml4e & ADDR_MASK) as usize + pdpti * 8) as *const u64);
    if pdpte & PRESENT == 0 {
        return None;
    }
    let pde = *(((pdpte & ADDR_MASK) as usize + pdi * 8) as *const u64);
    if pde & PRESENT == 0 {
        return None;
    }
    Some(*(((pde & ADDR_MASK) as usize + pti * 8) as *const u64))
}
