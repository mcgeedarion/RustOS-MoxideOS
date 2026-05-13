//! RISC-V Sv39 three-level page table management.
//!
//! ## Sv39 address layout
//!   Virtual address: [38:30] VPN[2] | [29:21] VPN[1] | [20:12] VPN[0] | [11:0] offset
//!   SATP: MODE(4 bits) | ASID(16 bits) | PPN(44 bits) — MODE 8 = Sv39
//!
//! ## PTE bits: V=0, R=1, W=2, X=3, U=4, G=5, A=6, D=7; [53:10] = PPN
//!
//! ## Identity map
//!   `paging_init()` identity-maps all physical RAM using 1 GiB superpages
//!   so the kernel can address page tables and MMIO by their physical address.
//!
//! All magic constants are imported from
//! [`crate::arch::riscv64::mem_layout`].

use crate::arch::riscv64::csr::{get_satp, set_satp};
use super::mem_layout::{page as P, sv39 as SV, satp as SATP_MODE};

// Re-export PTE flags so existing consumers (trap.rs etc.) keep working.
pub use SV::{PTE_V, PTE_R, PTE_W, PTE_X, PTE_U, PTE_G};

/// Build an identity-mapped Sv39 kernel page table, install it into SATP,
/// and return the root PPN.
pub fn paging_init(total_ram_bytes: usize) -> usize {
    let root_pa = crate::mm::pmm::alloc_page()
        .expect("OOM: no page for root PTE");
    unsafe { core::ptr::write_bytes(root_pa as *mut u8, 0, P::SIZE); }

    let mut pa = 0usize;
    while pa < total_ram_bytes {
        let vpn2 = SV::vpn2(pa);
        if vpn2 >= P::TABLE_ENTRIES { break; }
        unsafe {
            let pte = SV::pa_to_pte(pa, PTE_R | PTE_W | PTE_X | PTE_G);
            ((root_pa + vpn2 * 8) as *mut usize).write_volatile(pte);
        }
        pa += P::SUPERPAGE_1G;
    }

    let root_ppn = root_pa >> P::SHIFT;
    set_satp(SATP_MODE::MODE_SV39 | root_ppn);
    unsafe { core::arch::asm!("sfence.vma zero, zero"); }
    root_ppn
}

/// Allocate a fresh zeroed root page table.
/// Returns the PPN (physical page number) of the allocated page.
/// Does NOT install it into SATP — caller does that in jump_to_user.
pub fn alloc_root_page_table() -> usize {
    let pa = crate::mm::pmm::alloc_page()
        .expect("OOM: alloc_root_page_table");
    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, P::SIZE); }
    pa >> P::SHIFT
}

/// Map a 4 KiB page in the **current** SATP page table.
pub fn map_page(va: usize, pa: usize, flags: usize) {
    let satp    = get_satp();
    let root_pa = (satp & SV::SATP_PPN_MASK) << P::SHIFT;
    map_page_into(root_pa, va, pa, flags);
}

/// Map a 4 KiB page into the page table whose root physical address is `root_pa`.
/// `flags` should include desired PTE_R/W/X/U bits; PTE_V is always OR-ed in.
pub fn map_page_into(root_pa: usize, va: usize, pa: usize, flags: usize) {
    let vpn = [SV::vpn0(va), SV::vpn1(va), SV::vpn2(va)];
    let ppn = pa >> P::SHIFT;

    unsafe {
        let mut table = root_pa as *mut usize;
        for level in (1..=2).rev() {
            let slot = table.add(vpn[level]);
            let pte  = slot.read_volatile();
            if pte & PTE_V == 0 {
                let new_pa = crate::mm::pmm::alloc_page()
                    .expect("OOM in map_page_into");
                core::ptr::write_bytes(new_pa as *mut u8, 0, P::SIZE);
                slot.write_volatile(((new_pa >> P::SHIFT) << SV::PPN_SHIFT) | PTE_V);
                table = new_pa as *mut usize;
            } else {
                table = SV::pte_to_pa(pte) as *mut usize;
            }
        }
        let leaf = table.add(vpn[0]);
        leaf.write_volatile((ppn << SV::PPN_SHIFT) | flags | PTE_V);
        core::arch::asm!("sfence.vma {va}, zero", va = in(reg) va);
    }
}

/// Unmap a single page and return its physical page to the PMM.
pub fn unmap_page(va: usize) {
    let satp  = get_satp();
    let root  = (satp & SV::SATP_PPN_MASK) << P::SHIFT;
    let vpn   = [SV::vpn0(va), SV::vpn1(va), SV::vpn2(va)];
    unsafe {
        let mut table = root as *mut usize;
        for level in (1..=2).rev() {
            let pte = table.add(vpn[level]).read_volatile();
            if pte & PTE_V == 0 { return; }
            table = SV::pte_to_pa(pte) as *mut usize;
        }
        let leaf = table.add(vpn[0]);
        let pte  = leaf.read_volatile();
        if pte & PTE_V != 0 {
            let phys = SV::pte_to_pa(pte);
            leaf.write_volatile(0);
            core::arch::asm!("sfence.vma {va}, zero", va = in(reg) va);
            crate::mm::pmm::free_page(phys);
        }
    }
}

/// Walk the current page table to translate a VA to its PA.
/// Returns `None` if unmapped.
pub fn virt_to_phys(va: usize) -> Option<usize> {
    let satp = get_satp();
    if satp >> 60 == 0 { return Some(va); } // bare mode: identity
    let root = (satp & SV::SATP_PPN_MASK) << P::SHIFT;
    let vpn  = [SV::vpn0(va), SV::vpn1(va), SV::vpn2(va)];
    unsafe {
        let mut table = root as *mut usize;
        for level in (1..=2).rev() {
            let pte = table.add(vpn[level]).read_volatile();
            if pte & PTE_V == 0 { return None; }
            // Leaf at this level (superpage)?
            if pte & (PTE_R | PTE_W | PTE_X) != 0 {
                let ppn = SV::pte_to_pa(pte);
                return Some(ppn | (va & ((1 << (P::SHIFT + level * 9)) - 1)));
            }
            table = SV::pte_to_pa(pte) as *mut usize;
        }
        let pte = table.add(vpn[0]).read_volatile();
        if pte & PTE_V == 0 { return None; }
        Some(SV::pte_to_pa(pte) | (va & P::MASK))
    }
}
