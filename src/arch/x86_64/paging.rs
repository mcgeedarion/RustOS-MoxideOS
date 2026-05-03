//! x86-64 4-level page table management.
//!
//! Layout: PML4 (L4) → PDPT (L3) → PD (L2) → PT (L1) → page frame.
//! All tables are 4096 bytes, containing 512 8-byte entries.
//!
//! VA bit decomposition (canonical 48-bit):
//!   [47:39] PML4 index   (9 bits)
//!   [38:30] PDPT index   (9 bits)
//!   [29:21] PD   index   (9 bits)
//!   [20:12] PT   index   (9 bits)
//!   [11:0]  page offset  (12 bits)
//!
//! PTE flag bits used here:
//!   bit  0  Present
//!   bit  1  Writable
//!   bit  2  User
//!   bit  9  SOFTWARE: Copy-on-Write marker (never set by hardware)
//!   bit 63  No-Execute
//!
//! All physical addresses are identity-mapped (PA == VA) in the kernel.
//! CR3 holds the PA of the current PML4.

const PRESENT:   u64 = 1 << 0;
const WRITABLE:  u64 = 1 << 1;
const USER:      u64 = 1 << 2;
const COW_BIT:   u64 = 1 << 9;   // software-defined CoW marker
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000; // bits [51:12]

// ── CR3 helpers ───────────────────────────────────────────────────────────

/// Read the current CR3 (physical address of the active PML4).
#[inline]
pub fn current_cr3() -> usize {
    let cr3: usize;
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem)); }
    cr3 & !0xFFF  // mask off PCID / flags in bits 11:0
}

/// Kernel CR3 — the one in use before any process is loaded.
/// We store it once at boot; here we lazily read CR3 and cache it.
pub fn kernel_cr3() -> usize {
    static KERNEL_CR3: core::sync::atomic::AtomicUsize =
        core::sync::atomic::AtomicUsize::new(0);
    let cached = KERNEL_CR3.load(core::sync::atomic::Ordering::Relaxed);
    if cached != 0 { return cached; }
    let cr3 = current_cr3();
    KERNEL_CR3.store(cr3, core::sync::atomic::Ordering::Relaxed);
    cr3
}

/// Load a new PML4 into CR3.
#[inline]
pub fn load_cr3(cr3: usize) {
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack)); }
}

/// Invalidate the TLB entry for one virtual address.
#[inline]
pub fn invlpg(va: usize) {
    unsafe { core::arch::asm!("invlpg [{v}]", v = in(reg) va, options(nostack)); }
}

// ── Page-table walk ───────────────────────────────────────────────────────

/// Allocate a zeroed 4096-byte table page. Returns PA.
fn alloc_table() -> usize {
    let pa = crate::mm::pmm::alloc_page().expect("pmm: out of pages for page table");
    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, 4096); }
    pa
}

/// Index a page-table level entry (PA of table + 9-bit index).
#[inline]
unsafe fn pte_ptr(table_pa: usize, idx: usize) -> *mut u64 {
    (table_pa + idx * 8) as *mut u64
}

/// Walk the 4-level page table for `va` under `cr3`.
/// Returns a mutable pointer to the leaf PT entry, creating
/// intermediate tables as needed.
unsafe fn walk_mut(cr3: usize, va: usize) -> *mut u64 {
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx   = (va >> 21) & 0x1FF;
    let pt_idx   = (va >> 12) & 0x1FF;

    let pml4e = pte_ptr(cr3, pml4_idx);
    if *pml4e & PRESENT == 0 {
        let t = alloc_table();
        *pml4e = t as u64 | PRESENT | WRITABLE | USER;
    }
    let pdpt = (*pml4e & ADDR_MASK) as usize;

    let pdpte = pte_ptr(pdpt, pdpt_idx);
    if *pdpte & PRESENT == 0 {
        let t = alloc_table();
        *pdpte = t as u64 | PRESENT | WRITABLE | USER;
    }
    let pd = (*pdpte & ADDR_MASK) as usize;

    let pde = pte_ptr(pd, pd_idx);
    if *pde & PRESENT == 0 {
        let t = alloc_table();
        *pde = t as u64 | PRESENT | WRITABLE | USER;
    }
    let pt = (*pde & ADDR_MASK) as usize;

    pte_ptr(pt, pt_idx)
}

/// Walk read-only; returns None if any level is not present.
unsafe fn walk_ro(cr3: usize, va: usize) -> Option<*mut u64> {
    let pml4_idx = (va >> 39) & 0x1FF;
    let pdpt_idx = (va >> 30) & 0x1FF;
    let pd_idx   = (va >> 21) & 0x1FF;
    let pt_idx   = (va >> 12) & 0x1FF;

    let pml4e = pte_ptr(cr3, pml4_idx);
    if *pml4e & PRESENT == 0 { return None; }
    let pdpt = (*pml4e & ADDR_MASK) as usize;

    let pdpte = pte_ptr(pdpt, pdpt_idx);
    if *pdpte & PRESENT == 0 { return None; }
    let pd = (*pdpte & ADDR_MASK) as usize;

    let pde = pte_ptr(pd, pd_idx);
    if *pde & PRESENT == 0 { return None; }
    let pt = (*pde & ADDR_MASK) as usize;

    Some(pte_ptr(pt, pt_idx))
}

// ── Public API ────────────────────────────────────────────────────────────

/// Map `va` → `pa` under `cr3` with the given PTE `flags`.
/// Creates any missing intermediate tables.
pub fn map_page(cr3: usize, va: usize, pa: usize, flags: u64) {
    unsafe {
        let pte = walk_mut(cr3, va);
        *pte = (pa as u64 & ADDR_MASK) | (flags & 0xFFF) | PRESENT;
    }
}

/// Remove the mapping for `va` in the CURRENT address space.
/// Returns the physical address that was mapped, or None.
pub fn unmap_page(va: usize) -> Option<usize> {
    let cr3 = current_cr3();
    unsafe {
        let pte = walk_ro(cr3, va)?;
        if *pte & PRESENT == 0 { return None; }
        let pa = (*pte & ADDR_MASK) as usize;
        *pte = 0;
        invlpg(va);
        Some(pa)
    }
}

/// Return the physical address mapped at `va` in `cr3`, or None.
pub fn virt_to_phys(cr3: usize, va: usize) -> Option<usize> {
    unsafe {
        let pte = walk_ro(cr3, va)?;
        if *pte & PRESENT == 0 { return None; }
        Some((*pte & ADDR_MASK) as usize)
    }
}

// ── Copy-on-Write PML4 clone ──────────────────────────────────────────────

/// Clone the parent's PML4 for a CoW fork.
///
/// For every leaf PTE in the parent that is Present:
///   - If Writable: clear Writable, set COW_BIT in both parent and child.
///   - Copy the (now read-only) PTE into the child's page tables.
///
/// The child gets its own PML4/PDPT/PD/PT tables (new pages for each level),
/// but the physical *leaf* pages are shared until a write fault occurs.
///
/// Returns the physical address of the new child PML4 (child CR3).
pub fn clone_pml4_cow(parent_cr3: usize) -> usize {
    let child_cr3 = alloc_table();

    unsafe {
        for pml4i in 0..512usize {
            let parent_pml4e = pte_ptr(parent_cr3, pml4i);
            if *parent_pml4e & PRESENT == 0 { continue; }

            let child_pdpt = alloc_table();
            let child_pml4e = pte_ptr(child_cr3, pml4i);
            *child_pml4e = child_pdpt as u64 | PRESENT | WRITABLE | USER;

            let parent_pdpt = (*parent_pml4e & ADDR_MASK) as usize;
            for pdpti in 0..512usize {
                let parent_pdpte = pte_ptr(parent_pdpt, pdpti);
                if *parent_pdpte & PRESENT == 0 { continue; }

                let child_pd = alloc_table();
                let child_pdpte = pte_ptr(child_pdpt, pdpti);
                *child_pdpte = child_pd as u64 | PRESENT | WRITABLE | USER;

                let parent_pd = (*parent_pdpte & ADDR_MASK) as usize;
                for pdi in 0..512usize {
                    let parent_pde = pte_ptr(parent_pd, pdi);
                    if *parent_pde & PRESENT == 0 { continue; }

                    let child_pt = alloc_table();
                    let child_pde = pte_ptr(child_pd, pdi);
                    *child_pde = child_pt as u64 | PRESENT | WRITABLE | USER;

                    let parent_pt = (*parent_pde & ADDR_MASK) as usize;
                    for pti in 0..512usize {
                        let parent_pte = pte_ptr(parent_pt, pti);
                        if *parent_pte & PRESENT == 0 { continue; }

                        let mut entry = *parent_pte;

                        if entry & WRITABLE != 0 {
                            entry = (entry & !WRITABLE) | COW_BIT;
                            *parent_pte = entry;
                            let va = (pml4i << 39) | (pdpti << 30)
                                   | (pdi << 21)   | (pti << 12);
                            invlpg(va);
                        }

                        let child_pte = pte_ptr(child_pt, pti);
                        *child_pte = entry;
                    }
                }
            }
        }
    }
    child_cr3
}
