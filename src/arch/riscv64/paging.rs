//! RISC-V Sv39 three-level page table management.
//!
//! ## Sv39 address layout
//!   Virtual address: [38:30] VPN[2] | [29:21] VPN[1] | [20:12] VPN[0] | [11:0] offset
//!   SATP: MODE(4 bits) | ASID(16 bits) | PPN(44 bits)
//!   Mode 8 = Sv39, mode 0 = bare (no translation)
//!
//! ## PTE bits
//!   V=0, R=1, W=2, X=3, U=4, G=5, A=6, D=7; [53:10] = PPN
//!
//! ## Identity map
//!   We identity-map all physical RAM so the kernel can access
//!   page tables and device MMIO using physical addresses directly.

use crate::arch::riscv64::csr::{get_satp, set_satp};

pub const PTE_V: usize = 1 << 0;
pub const PTE_R: usize = 1 << 1;
pub const PTE_W: usize = 1 << 2;
pub const PTE_X: usize = 1 << 3;
pub const PTE_U: usize = 1 << 4;
pub const PTE_G: usize = 1 << 5; // global
pub const SATP_SV39: usize = 8 << 60;

/// Allocate a root page table and install it into SATP.
/// Identity-maps [0, total_ram) with RWX permissions.
pub fn paging_init(total_ram_bytes: usize) {
    let root_pa = crate::mm::pmm::alloc_page()
        .expect("OOM: no page for root PTE");
    unsafe { core::ptr::write_bytes(root_pa as *mut u8, 0, 4096); }

    // Identity-map with 1 GiB superpages (Sv39 level-2 entries).
    // Each level-2 leaf PTE covers 1 GiB.
    let gib = 1usize << 30;
    let mut pa = 0usize;
    while pa < total_ram_bytes {
        let vpn2 = pa / gib;
        if vpn2 >= 512 { break; }
        let ppn = pa >> 12;
        let pte = (ppn << 10) | PTE_V | PTE_R | PTE_W | PTE_X | PTE_G;
        unsafe { ((root_pa + vpn2 * 8) as *mut usize).write_volatile(pte); }
        pa += gib;
    }

    let satp_val = SATP_SV39 | (root_pa >> 12);
    set_satp(satp_val);
    // Flush TLB.
    unsafe { core::arch::asm!("sfence.vma zero, zero"); }
}

/// Map a single 4 KiB page (va → pa) in the current page table.
pub fn map_page(va: usize, pa: usize, flags: usize) {
    let satp = get_satp();
    let root = (satp & 0x0FFF_FFFF_FFFF) << 12;
    let vpn  = [(va >> 12) & 0x1FF,
                (va >> 21) & 0x1FF,
                (va >> 30) & 0x1FF];
    let ppn  = pa >> 12;

    unsafe {
        let mut table = root as *mut usize;
        for level in (1..=2).rev() {
            let slot = table.add(vpn[level]);
            let pte  = slot.read_volatile();
            if pte & PTE_V == 0 {
                let new_pa = crate::mm::pmm::alloc_page()
                    .expect("OOM in map_page");
                core::ptr::write_bytes(new_pa as *mut u8, 0, 4096);
                slot.write_volatile(((new_pa >> 12) << 10) | PTE_V);
                table = new_pa as *mut usize;
            } else {
                table = ((pte >> 10) << 12) as *mut usize;
            }
        }
        let leaf = table.add(vpn[0]);
        leaf.write_volatile((ppn << 10) | flags | PTE_V);
        core::arch::asm!("sfence.vma {va}, zero", va = in(reg) va);
    }
}

/// Unmap a single page, returning the physical page to the PMM.
pub fn unmap_page(va: usize) {
    let satp = get_satp();
    let root = (satp & 0x0FFF_FFFF_FFFF) << 12;
    let vpn  = [(va >> 12) & 0x1FF,
                (va >> 21) & 0x1FF,
                (va >> 30) & 0x1FF];
    unsafe {
        let mut table = root as *mut usize;
        for level in (1..=2).rev() {
            let pte = table.add(vpn[level]).read_volatile();
            if pte & PTE_V == 0 { return; }
            table = ((pte >> 10) << 12) as *mut usize;
        }
        let leaf = table.add(vpn[0]);
        let pte  = leaf.read_volatile();
        if pte & PTE_V != 0 {
            let pa = ((pte >> 10) << 12) as usize;
            leaf.write_volatile(0);
            core::arch::asm!("sfence.vma {va}, zero", va = in(reg) va);
            crate::mm::pmm::free_page(pa);
        }
    }
}

/// Translate a virtual address to its physical address in the current
/// page table.  Returns None if not mapped.
pub fn virt_to_phys(va: usize) -> Option<usize> {
    let satp = get_satp();
    if satp >> 60 == 0 { return Some(va); } // bare mode = identity
    let root = (satp & 0x0FFF_FFFF_FFFF) << 12;
    let vpn  = [(va >> 12) & 0x1FF,
                (va >> 21) & 0x1FF,
                (va >> 30) & 0x1FF];
    unsafe {
        let mut table = root as *mut usize;
        for level in (1..=2).rev() {
            let pte = table.add(vpn[level]).read_volatile();
            if pte & PTE_V == 0 { return None; }
            // Check for superpage (leaf at this level).
            if pte & (PTE_R | PTE_W | PTE_X) != 0 {
                let ppn = (pte >> 10) << 12;
                return Some(ppn | (va & ((1 << (12 + level * 9)) - 1)));
            }
            table = ((pte >> 10) << 12) as *mut usize;
        }
        let pte = table.add(vpn[0]).read_volatile();
        if pte & PTE_V == 0 { return None; }
        Some(((pte >> 10) << 12) | (va & 0xFFF))
    }
}
