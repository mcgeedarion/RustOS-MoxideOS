//! Copy-on-Write page fault handler and fork address-space clone.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::{
    api::{PageFlags, Paging},
    Arch,
};
use crate::mm::pmm;
use crate::proc::scheduler;

const PAGE_SIZE: usize = 4096;

// A completely-zeroed PTE is non-present on all three architectures and
// therefore acts as a safe sentinel value: any CPU that reads it while we
// are resolving the fault will re-fault immediately and find the finished
// RW mapping on the second attempt.
const SENTINEL_PTE: u64 = 0;

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
/// ## SMP race elimination (CAS sentinel)
///
/// Two threads (or two fork children) sharing a CoW frame can both take a
/// write fault before either has resolved it.  Without a lock, both would
/// pass the COW_BIT check, both allocate a new page, both copy old_pa,
/// and both call put_page(old_pa) — the second decrement reaches zero and
/// returns old_pa to the buddy while the first thread already holds the
/// new mapping.  That is a double-free of old_pa.
///
/// We close the race with a compare_exchange on the raw PTE slot:
///   1. Atomically swap the CoW PTE with SENTINEL_PTE (0 = non-present).
///   2. Only the winner proceeds to alloc/copy/map; the loser finds the
///      COW_BIT clear on its next read and returns Ok(()), then re-faults
///      into the winner's freshly written RW PTE.
///   3. put_page is called exactly once per CoW PTE.
///
/// ## SMP TLB shootdown protocol
///
/// After mapping the new private copy and replacing the PTE, we must
/// invalidate the old mapping on ALL CPUs before releasing our reference
/// to `old_pa`.  The sequence is:
///
///   1. map_page()      — replace the PTE in this process's page tables
///   2. flush_va()      — invalidate local TLB entry
///   3. tlb_shootdown() — send TLB-shootdown IPIs to all other CPUs and WAIT
///      for their acknowledgment (blocking)
///   4. put_page()      — decrement the refcount; buddy_free_page is called
///      only when the count reaches zero, which is safe when multiple fork
///      children share the same frame.
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

    // Locate the physical PTE slot so we can CAS it.
    let pte_pa = match unsafe { pte_addr(cr3, faulting_va) } {
        Some(pa) => pa,
        None => return false,
    };

    // SAFETY: pte_pa is a valid physical address inside the physmap window;
    // we cast it to AtomicU64 to perform a lock-free CAS.  Only one CPU will
    // win the exchange and proceed to allocate; losers see COW_BIT == 0 and
    // return immediately, re-faulting into the winner's RW PTE.
    let pte_virt = to_virt(pte_pa) as *const AtomicU64;
    let atomic_pte = unsafe { &*pte_virt };

    // Spin-read until we either see no COW_BIT (someone else resolved it)
    // or we successfully claim the slot with a sentinel.
    let old_pte_val = loop {
        let cur = atomic_pte.load(Ordering::Acquire);

        // COW_BIT = bit 9 (software-available on x86-64, RISC-V, and AArch64)
        if cur & (1 << 9) == 0 {
            // Another CPU already resolved this CoW fault — nothing to do.
            return true;
        }

        match atomic_pte.compare_exchange(cur, SENTINEL_PTE, Ordering::AcqRel, Ordering::Acquire) {
            Ok(prev) => break prev, // we won the race
            Err(_) => core::hint::spin_loop(), // lost; retry
        }
    };

    let old_pa = match <Arch as Paging>::virt_to_phys(cr3, faulting_va) {
        Some(pa) => pa,
        None => {
            // Restore the PTE so the page is not permanently unmapped.
            atomic_pte.store(old_pte_val, Ordering::Release);
            return false;
        }
    };

    let new_pa = match pmm::alloc_page() {
        Some(p) => p,
        None => {
            // OOM — restore the CoW PTE so a future fault can retry.
            atomic_pte.store(old_pte_val, Ordering::Release);
            return false;
        }
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

    // 5a. Replace the sentinel PTE with the new private RW mapping.
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
    // The CAS above guarantees put_page is called exactly once per CoW PTE.
    pmm::put_page(old_pa);

    true
}

// ---------------------------------------------------------------------------
// Architecture-specific page-table walkers
//
// Each walker returns the *physical address* of the leaf PTE slot (4 KiB
// granule only) so that handle_cow_fault can perform a CAS directly on it.
// Large-page PTEs return None — they are not CoW-eligible.
// ---------------------------------------------------------------------------

// x86-64 PTE physical address mask
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PRESENT: u64 = 1;
/// Bit 7 in a PDPTE/PDE: page-size flag (1 GiB / 2 MiB large page).
const PAGE_SIZE_BIT: u64 = 1 << 7;

/// Return the *physical address* of the leaf PTE slot for `va`, or None if
/// the walk terminates early (not mapped, large page, etc.).
///
/// The caller may then cast `to_virt(pte_pa)` to `*const AtomicU64` for
/// a lock-free CAS.
unsafe fn pte_addr(cr3: usize, va: usize) -> Option<usize> {
    pte_addr_impl(cr3, va)
}

#[cfg(target_arch = "x86_64")]
unsafe fn pte_addr_impl(cr3: usize, va: usize) -> Option<usize> {
    let pml4i = (va >> 39) & 0x1FF;
    let pdpti = (va >> 30) & 0x1FF;
    let pdi   = (va >> 21) & 0x1FF;
    let pti   = (va >> 12) & 0x1FF;

    let pml4_base = to_virt(cr3);
    let pml4e = *((pml4_base + pml4i * 8) as *const u64);
    if pml4e & PRESENT == 0 { return None; }

    let pdpt_base = to_virt((pml4e & ADDR_MASK) as usize);
    let pdpte = *((pdpt_base + pdpti * 8) as *const u64);
    if pdpte & PRESENT == 0 { return None; }
    if pdpte & PAGE_SIZE_BIT != 0 { return None; } // 1 GiB large page

    let pd_base = to_virt((pdpte & ADDR_MASK) as usize);
    let pde = *((pd_base + pdi * 8) as *const u64);
    if pde & PRESENT == 0 { return None; }
    if pde & PAGE_SIZE_BIT != 0 { return None; } // 2 MiB large page

    let pt_phys = (pde & ADDR_MASK) as usize;
    Some(pt_phys + pti * 8)
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
unsafe fn pte_addr_impl(satp_pa: usize, va: usize) -> Option<usize> {
    let vpn2 = (va >> 30) & 0x1FF;
    let vpn1 = (va >> 21) & 0x1FF;
    let vpn0 = (va >> 12) & 0x1FF;

    let pgd_base = to_virt(satp_pa);
    let pgde = *((pgd_base + vpn2 * 8) as *const u64);
    if pgde & RV_PTE_VALID == 0 { return None; }
    if pgde & RV_PTE_RWX_MASK != 0 { return None; } // 1 GiB leaf

    let pmd_base = to_virt(rv_pte_to_pa(pgde));
    let pmde = *((pmd_base + vpn1 * 8) as *const u64);
    if pmde & RV_PTE_VALID == 0 { return None; }
    if pmde & RV_PTE_RWX_MASK != 0 { return None; } // 2 MiB leaf

    let pt_phys = rv_pte_to_pa(pmde);
    Some(pt_phys + vpn0 * 8)
}

/// Public alias used in debug assertions / unit tests.
#[cfg(debug_assertions)]
pub unsafe fn pte_read_pub(cr3: usize, va: usize) -> Option<u64> {
    let pa = unsafe { pte_addr(cr3, va) }?;
    Some(unsafe { *(to_virt(pa) as *const u64) })
}

#[cfg(target_arch = "aarch64")]
unsafe fn pte_addr_impl(ttbr_pa: usize, va: usize) -> Option<usize> {
    let l0i = crate::arch::aarch64::mem_layout::va48::l0_index(va);
    let l1i = crate::arch::aarch64::mem_layout::va48::l1_index(va);
    let l2i = crate::arch::aarch64::mem_layout::va48::l2_index(va);
    let l3i = crate::arch::aarch64::mem_layout::va48::l3_index(va);

    // AArch64 descriptor type encoding (4 KiB granule, ARM DDI 0487):
    //   bits[1:0] == 0b00 or 0b10 → invalid
    //   bits[1:0] == 0b01         → block descriptor (large page) at L1/L2
    //   bits[1:0] == 0b11         → table descriptor at L0/L1/L2,
    //                               page descriptor at L3
    const VALID:  u64 = 1;       // bit 0
    const TABLE:  u64 = 1 << 1;  // bit 1: 1 = table/page, 0 = block/invalid
    const ADDR:   u64 = 0x0000_ffff_ffff_f000;

    // L0 — only table descriptors are valid here.
    let l0_base = to_virt(ttbr_pa);
    let l0e = *((l0_base + l0i * 8) as *const u64);
    if l0e & VALID == 0 { return None; }
    if l0e & TABLE == 0 { return None; } // block at L0 is architecturally reserved

    // L1 — table or 1 GiB block.
    let l1_base = to_virt((l0e & ADDR) as usize);
    let l1e = *((l1_base + l1i * 8) as *const u64);
    if l1e & VALID == 0 { return None; }
    if l1e & TABLE == 0 { return None; } // 1 GiB block — not CoW-eligible

    // L2 — table or 2 MiB block.
    // BUG FIX: the previous code only checked TABLE == 0 which is correct for
    // detecting a table descriptor, but a block descriptor at L2 also has
    // TABLE == 0 (bits[1:0] == 0b01).  We must explicitly reject it here;
    // otherwise we fall through and return the L2 block descriptor address
    // as if it were a valid L3 page-table base, which gives a garbage PA and
    // flags to the CoW handler.
    let l2_base = to_virt((l1e & ADDR) as usize);
    let l2e = *((l2_base + l2i * 8) as *const u64);
    if l2e & VALID == 0 { return None; }
    if l2e & TABLE == 0 { return None; } // 2 MiB block — not CoW-eligible

    // L3 — must be a page descriptor (bits[1:0] == 0b11).  A value of
    // 0b01 at L3 is architecturally UNPREDICTABLE; treat as not mapped.
    let l3_phys = (l2e & ADDR) as usize;
    let l3_slot_phys = l3_phys + l3i * 8;
    let l3e = *(to_virt(l3_slot_phys) as *const u64);
    if l3e & VALID == 0 { return None; }
    if l3e & TABLE == 0 { return None; } // not a page descriptor

    Some(l3_slot_phys)
}
