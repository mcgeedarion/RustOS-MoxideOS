//! Copy-on-Write page fault handler and fork address-space clone.

use crate::arch::{
    api::{PageFlags, Paging},
    Arch,
};
use crate::mm::pmm;
use crate::proc::scheduler;

const PAGE_SIZE: usize = 4096;

// Physical frames must be accessed through the kernel's physmap window.
// Passing a raw physical address to copy_nonoverlapping() would fault or
// alias an unrelated mapping.

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn to_virt(pa: usize) -> usize {
    // x86_64: physical memory is identity-mapped with a fixed offset.
    extern "C" {
        static PHYS_OFFSET: usize;
    }
    unsafe { PHYS_OFFSET + pa }
}

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn to_virt(pa: usize) -> usize {
    extern "C" {
        static KERNEL_PHYS_BASE: usize;
    }
    unsafe { KERNEL_PHYS_BASE + pa }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn to_virt(pa: usize) -> usize {
    crate::arch::aarch64::mem_layout::va48::phys_to_virt(pa)
}

/// Create a CoW copy of the parent's address space for a fork() child.
/// Returns the child's CR3/SATP physical address, or 0 on OOM.
pub fn clone_for_fork(parent_pid: usize, child_pid: usize, parent_cr3: usize) -> usize {
    let child_cr3 = match <Arch as Paging>::clone_address_space(parent_cr3) {
        Some(c) => c,
        None => return 0,
    };
    let parent_key = crate::proc::thread::vma_pid(parent_pid);
    let child_key = crate::proc::thread::vma_pid(child_pid);
    if parent_key != child_key {
        crate::mm::mmap::clone_vmas(parent_key as usize, child_key as usize);
    }
    child_cr3
}

/// Handle a write fault that may be a CoW page.
/// Returns true if resolved; false if genuine access violation.
///
/// ## `error_code` encoding (arch-specific)
///
/// **x86-64** (hardware-defined, passed directly from the IDT stub):
///   bit 0 (P)   = 1  → page was Present
///   bit 1 (W)   = 1  → fault was caused by a Write
///   bit 2 (U)   = 1  → fault occurred in User mode
///   A CoW fault always has P|W|U = 0x7.
///
/// **RISC-V** (synthesised by our trap handler in src/arch/riscv64/trap.rs):
///   bit 0       = 0  (unused; store-vs-load encoded in bit 1)
///   bit 1 (W)   = 1  → Store/AMO page fault (mcause 15)
///   bit 3 (U)   = 1  → fault occurred in U-mode (sstatus.SPP == 0)
///   A CoW fault has W|U = 0b1010 = 0xA.
///   (We do not check bit 0 / Present on RISC-V because the hardware does
///   not expose that information in a single fault-error word the same way
///   x86 does; the PTE walk below confirms the mapping exists.)
///
/// ## SMP TLB shootdown protocol
///
/// After mapping the new private copy and replacing the PTE, we must
/// invalidate the old mapping on ALL CPUs before releasing our reference
/// to `old_pa`.  The sequence is:
///
///   1. map_page()      — replace the PTE in this process's page tables
///   2. flush_va()      — invalidate local TLB entry
///   3. tlb_shootdown() — send TLB-shootdown IPIs to all other CPUs and
///                        WAIT for their acknowledgment (blocking)
///   4. put_page()      — decrement the refcount; buddy_free_page is called
///                        only when the count reaches zero, which is safe
///                        when multiple fork children share the same frame.
///
/// Skipping step 3 on a multi-processor system would allow another CPU
/// that held this process's address space loaded to dereference the freed
/// page via its stale TLB entry, causing a use-after-free.
pub fn handle_cow_fault(faulting_va: usize, error_code: u64) -> bool {
    // Reject faults that cannot possibly be CoW:
    //   x86_64 → P=1, W=1, U=1 (bits 0-2 all set → mask 0x7)
    //   riscv64 → W=1, U=1     (bits 1 and 3 set → mask 0xA)
    #[cfg(target_arch = "x86_64")]
    if error_code & 0x7 != 0x7 {
        return false;
    }

    #[cfg(target_arch = "riscv64")]
    if error_code & 0xA != 0xA {
        return false;
    }

    #[cfg(target_arch = "aarch64")]
    if error_code & 0x6 != 0x6 {
        return false;
    }

    let pid = scheduler::current_pid();
    let cr3 = scheduler::with_proc(pid, |p| p.user_satp).unwrap_or(0);
    if cr3 == 0 {
        return false;
    }

    let pte_val = match unsafe { pte_read(cr3, faulting_va) } {
        Some(v) => v,
        None => return false,
    };

    // COW_BIT = bit 9 (software-available bit on both x86-64 and RISC-V Sv39/48)
    if pte_val & (1 << 9) == 0 {
        return false;
    }

    let old_pa = match <Arch as Paging>::virt_to_phys(cr3, faulting_va) {
        Some(pa) => pa,
        None => return false,
    };

    let new_pa = match pmm::alloc_page() {
        Some(p) => p,
        None => return false,
    };

    // Copy through the physmap window — never dereference a raw PA directly.
    unsafe {
        core::ptr::copy_nonoverlapping(
            to_virt(old_pa) as *const u8,
            to_virt(new_pa) as *mut u8,
            PAGE_SIZE,
        );
    }

    let page_va = faulting_va & !0xFFF;
    let flags = PageFlags::PRESENT | PageFlags::WRITE | PageFlags::USER;

    // 5a. Replace the PTE with the new private copy (clears COW_BIT).
    <Arch as Paging>::map_page(cr3, page_va, new_pa, flags);

    // 5b. Flush the local TLB entry.
    <Arch as Paging>::flush_va(page_va);

    // 5c. TLB shootdown: wait for all other CPUs to drop the old mapping.
    //     This is a no-op when only one CPU is online.
    crate::smp::ipi::tlb_shootdown(
        page_va as u64,
        (page_va + PAGE_SIZE) as u64,
        0, // asid 0 = all address spaces (conservative)
    );

    // 5d. Release our reference to the old frame.
    // put_page() decrements the PMM refcount and only calls buddy_free_page
    // when it reaches zero.  This is correct when multiple fork() children
    // share the same CoW source frame — the last one to fault frees it.
    // Previously this was an unconditional free_page() which caused a
    // double-free when two children faulted the same frame concurrently.
    pmm::put_page(old_pa);

    true
}

// Each walker returns the *leaf* PTE value (4 KiB granule only).
// Large-page PTEs return None — they are not CoW-eligible.

// x86-64 PTE physical address mask
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PRESENT: u64 = 1;
/// Bit 7 in a PDPTE/PDE: page-size flag (1 GiB / 2 MiB large page).
const PAGE_SIZE_BIT: u64 = 1 << 7;

#[cfg(target_arch = "x86_64")]
unsafe fn pte_read(cr3: usize, va: usize) -> Option<u64> {
    let pml4i = (va >> 39) & 0x1FF;
    let pdpti = (va >> 30) & 0x1FF;
    let pdi = (va >> 21) & 0x1FF;
    let pti = (va >> 12) & 0x1FF;

    // All table base addresses are physical; translate through physmap.
    let pml4_base = to_virt(cr3);
    let pml4e = *((pml4_base + pml4i * 8) as *const u64);
    if pml4e & PRESENT == 0 {
        return None;
    }

    let pdpt_base = to_virt((pml4e & ADDR_MASK) as usize);
    let pdpte = *((pdpt_base + pdpti * 8) as *const u64);
    if pdpte & PRESENT == 0 {
        return None;
    }
    // 1 GiB large page — not CoW-eligible.
    if pdpte & PAGE_SIZE_BIT != 0 {
        return None;
    }

    let pd_base = to_virt((pdpte & ADDR_MASK) as usize);
    let pde = *((pd_base + pdi * 8) as *const u64);
    if pde & PRESENT == 0 {
        return None;
    }
    // 2 MiB large page — not CoW-eligible.
    if pde & PAGE_SIZE_BIT != 0 {
        return None;
    }

    let pt_base = to_virt((pde & ADDR_MASK) as usize);
    Some(*((pt_base + pti * 8) as *const u64))
}

// Sv39 PTE physical address: bits [53:10] × 4096.
// The page-size flag for large pages is V=1, R|W|X ≠ 0 at a non-leaf level.
// We detect non-leaf levels by checking that R, W, and X are all zero
// (a valid pointer entry has R=W=X=0).

#[cfg(target_arch = "riscv64")]
const RV_PTE_ADDR_MASK: u64 = 0x003F_FFFF_FFFF_FC00; // bits [53:10]
#[cfg(target_arch = "riscv64")]
const RV_PTE_VALID: u64 = 1; // bit 0
#[cfg(target_arch = "riscv64")]
const RV_PTE_RWX_MASK: u64 = 0b1110; // bits 3:1 (R|W|X)

#[cfg(target_arch = "riscv64")]
#[inline(always)]
fn rv_pte_to_pa(pte: u64) -> usize {
    // PPN = pte[53:10]; PA = PPN << 12
    ((pte & RV_PTE_ADDR_MASK) >> 10 << 12) as usize
}

#[cfg(target_arch = "riscv64")]
unsafe fn pte_read(satp_pa: usize, va: usize) -> Option<u64> {
    // Sv39: VPN[2] VPN[1] VPN[0] = va[38:30] va[29:21] va[20:12]
    let vpn2 = (va >> 30) & 0x1FF;
    let vpn1 = (va >> 21) & 0x1FF;
    let vpn0 = (va >> 12) & 0x1FF;

    // Level 2 (PGD)
    let pgd_base = to_virt(satp_pa);
    let pgde = *((pgd_base + vpn2 * 8) as *const u64);
    if pgde & RV_PTE_VALID == 0 {
        return None;
    }
    // 1 GiB leaf — large pages are not CoW-eligible.
    if pgde & RV_PTE_RWX_MASK != 0 {
        return None;
    }

    // Level 1 (PMD)
    let pmd_base = to_virt(rv_pte_to_pa(pgde));
    let pmde = *((pmd_base + vpn1 * 8) as *const u64);
    if pmde & RV_PTE_VALID == 0 {
        return None;
    }
    // 2 MiB leaf — large pages are not CoW-eligible.
    if pmde & RV_PTE_RWX_MASK != 0 {
        return None;
    }

    // Level 0 (PT)
    let pt_base = to_virt(rv_pte_to_pa(pmde));
    Some(*((pt_base + vpn0 * 8) as *const u64))
}

/// Public alias used in debug assertions / unit tests.
#[cfg(debug_assertions)]
pub unsafe fn pte_read_pub(cr3: usize, va: usize) -> Option<u64> {
    unsafe { pte_read(cr3, va) }
}

#[cfg(target_arch = "aarch64")]
unsafe fn pte_read(ttbr_pa: usize, va: usize) -> Option<u64> {
    let l0 = crate::arch::aarch64::mem_layout::va48::l0_index(va);
    let l1 = crate::arch::aarch64::mem_layout::va48::l1_index(va);
    let l2 = crate::arch::aarch64::mem_layout::va48::l2_index(va);
    let l3 = crate::arch::aarch64::mem_layout::va48::l3_index(va);
    const VALID: u64 = 1;
    const TABLE: u64 = 1 << 1;
    const ADDR: u64 = 0x0000_ffff_ffff_f000;

    let l0_base = to_virt(ttbr_pa);
    let l0e = *((l0_base + l0 * 8) as *const u64);
    if l0e & VALID == 0 {
        return None;
    }
    if l0e & TABLE == 0 {
        return None;
    }

    let l1_base = to_virt((l0e & ADDR) as usize);
    let l1e = *((l1_base + l1 * 8) as *const u64);
    if l1e & VALID == 0 {
        return None;
    }
    if l1e & TABLE == 0 {
        return None;
    }

    let l2_base = to_virt((l1e & ADDR) as usize);
    let l2e = *((l2_base + l2 * 8) as *const u64);
    if l2e & VALID == 0 {
        return None;
    }
    if l2e & TABLE == 0 {
        return None;
    }

    let l3_base = to_virt((l2e & ADDR) as usize);
    Some(*((l3_base + l3 * 8) as *const u64))
}
