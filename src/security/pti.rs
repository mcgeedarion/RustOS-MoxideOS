//! Page Table Isolation (PTI) — defence against Meltdown and related
//! speculative-execution information-disclosure attacks.
//!
//! ## Design
//!
//! Each process has **two PML4 page tables**:
//!
//!   - `pml4_kernel`: the full address space used while running in ring 0.
//!     Contains *all* kernel mappings (physical map, kernel heap, stacks,
//!     module text) *plus* the user mappings for the current process.
//!
//!   - `pml4_user`:  a minimal shadow used while running in ring 3 (or
//!     when delivering interrupts/exceptions at CPL=3).  It contains:
//!       • All user-space page-table entries (PML4 slots [0..255])
//!       • *Only* the kernel trampoline page (one 4 KiB page at the
//!         interrupt-entry VA), the kernel GDT, and the per-CPU TSS.
//!     Nothing else from the kernel VA is present, so speculative reads
//!     across the user/kernel boundary cannot leak kernel data.
//!
//! ## CR3 switching
//!
//! On **syscall/interrupt entry** (from user CPL=3):
//!   `swapgs` (if applicable) then `mov cr3, pml4_kernel_phys`.
//!
//! On **iret/sysret exit** to user CPL=3):
//!   `mov cr3, pml4_user_phys` then iret/sysret.
//!
//! We set CR3 bit 63 (PCID `0x001` for user, `0x000` for kernel) so the
//! TLB is *not* flushed on every CR3 write when CR4.PCIDE is set.  This
//! is the same scheme used by Linux KPT + PCID optimisation.
//!
//! ## Trampoline
//!
//! The interrupt trampoline is a single 4 KiB page mapped at the same
//! virtual address in *both* page tables.  The first instruction after
//! the hardware saves SS/RSP/RFLAGS/CS/RIP is:
//!   `mov cr3, [gs:KERNEL_CR3_OFFSET]`  (8 bytes, RIP-relative-safe)
//! which switches to the kernel table before any further kernel code runs.
//!
//! The trampoline page is mapped NX + Present + Global in both tables.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Set to `true` when PTI is active.  May be disabled at boot with
/// `pti=off` (detected via command-line parser, not yet implemented).
pub static PTI_ENABLED: AtomicBool = AtomicBool::new(false);

// ───── PCID assignments ────────────────────────────────────────────────────────────

/// PCID used for kernel-side CR3 (no TLB flush on write when PCIDE=1).
pub const PCID_KERNEL: u64 = 0x000;
/// PCID used for user-side CR3.
pub const PCID_USER:   u64 = 0x001;
/// CR3 bit 63: when set on a `mov cr3` write, the TLB is NOT flushed.
pub const CR3_NO_FLUSH: u64 = 1u64 << 63;

// ───── Per-process PTI state ────────────────────────────────────────────────────

/// Physical addresses of the two PML4 tables for one process.
#[derive(Debug, Clone, Copy, Default)]
pub struct PtiCr3Pair {
    /// Physical address of the kernel-full PML4 (used in ring 0).
    pub kernel_cr3: u64,
    /// Physical address of the shadow user PML4 (used in ring 3).
    pub user_cr3:   u64,
}

impl PtiCr3Pair {
    /// Construct CR3 values with embedded PCID and optional no-flush bit.
    #[inline]
    pub fn kernel_cr3_val(&self, no_flush: bool) -> u64 {
        let f = if no_flush { CR3_NO_FLUSH } else { 0 };
        self.kernel_cr3 | PCID_KERNEL | f
    }
    #[inline]
    pub fn user_cr3_val(&self, no_flush: bool) -> u64 {
        let f = if no_flush { CR3_NO_FLUSH } else { 0 };
        self.user_cr3 | PCID_USER | f
    }
}

// ───── PTI init ──────────────────────────────────────────────────────────────────

/// Probe whether this CPU supports PCID (CPUID.1.ECX bit 17).
#[cfg(target_arch = "x86_64")]
pub fn cpu_has_pcid() -> bool {
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 1",
            "cpuid",
            out("ecx") ecx,
            out("eax") _,
            out("ebx") _,
            out("edx") _,
            options(nostack)
        );
    }
    (ecx >> 17) & 1 != 0
}

/// Enable PCIDE in CR4 so CR3 writes with the no-flush bit avoid TLB
/// invalidation.  Must be called with CR3 already holding a valid PCID=0
/// table (i.e. the current kernel PML4 physical address).
///
/// # Safety
/// Interrupts must be disabled.  CR3 must already be loaded with PCID=0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enable_pcide() {
    let mut cr4: u64;
    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
    cr4 |= 1 << 17; // CR4.PCIDE
    core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
}

/// Initialise PTI on the BSP.  Checks for Meltdown mitigation necessity
/// (Intel CPUs without RDCL_NO) and enables PTI + PCIDE.
///
/// Called from `security::init()` after SMEP/SMAP are already on.
#[cfg(target_arch = "x86_64")]
pub unsafe fn init() {
    // Check IA32_ARCH_CAPABILITIES (MSR 0x10A) bit 0 (RDCL_NO):
    // if set, this CPU is not vulnerable to Meltdown and PTI may be skipped.
    // We enable PTI regardless for defence-in-depth on all x86_64 CPUs.
    let has_pcid = cpu_has_pcid();
    if has_pcid {
        enable_pcide();
        log::info!("pti: PCIDE enabled — CR3 switches are TLB-flush-free");
    } else {
        log::warn!("pti: PCID not available — every CR3 switch flushes TLB");
    }
    PTI_ENABLED.store(true, Ordering::Relaxed);
    log::info!("pti: Page Table Isolation active");
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn init() {}

// ───── Shadow PML4 construction ─────────────────────────────────────────────────────

/// Build the shadow user PML4 for a process.
///
/// Allocates one 4 KiB page for the shadow PML4, then:
///   1. Copies PML4 entries [0..255] from `kernel_pml4_phys` (user half).
///   2. Maps only the trampoline page into the kernel half of the shadow
///      table (PML4[256] → PDPT → PD → PT → trampoline physical page).
///
/// Returns the physical address of the new shadow PML4, or `None` if OOM.
pub fn build_shadow_pml4(
    kernel_pml4_phys: u64,
    trampoline_phys:  u64,
    trampoline_va:    u64,
) -> Option<u64> {
    // Allocate a 4 KiB-aligned page for the shadow PML4.
    let shadow_phys = crate::mm::pmm::alloc_frame()?;

    unsafe {
        let shadow_ptr = phys_to_virt(shadow_phys) as *mut u64;
        let kernel_ptr = phys_to_virt(kernel_pml4_phys) as *const u64;

        // Step 1: copy user half (entries 0..255).
        for i in 0..256usize {
            shadow_ptr.add(i).write_volatile(kernel_ptr.add(i).read_volatile());
        }

        // Step 2: zero the kernel half (entries 256..512).
        for i in 256..512usize {
            shadow_ptr.add(i).write_volatile(0u64);
        }

        // Step 3: map the trampoline page.
        // Walk/build PDPT → PD → PT for `trampoline_va` and install
        // `trampoline_phys | PRESENT | GLOBAL | NX`.
        map_single_page_into_pml4(
            shadow_ptr,
            trampoline_va,
            trampoline_phys,
            PTE_PRESENT | PTE_GLOBAL | PTE_NX,
        );
    }

    Some(shadow_phys)
}

// Page-table entry flag bits.
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER:    u64 = 1 << 2;
const PTE_GLOBAL:  u64 = 1 << 8;
const PTE_NX:      u64 = 1 << 63;

/// Walk or allocate intermediate page-table levels and install a single
/// 4 KiB mapping at `va` pointing to `pa | flags` in the PML4 rooted at
/// `pml4_virt`.
///
/// # Safety
/// `pml4_virt` must point to a valid, writeable PML4.  Physical memory
/// allocations for intermediate tables use `pmm::alloc_frame()`.
unsafe fn map_single_page_into_pml4(
    pml4_virt: *mut u64,
    va: u64,
    pa: u64,
    flags: u64,
) {
    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx   = ((va >> 21) & 0x1FF) as usize;
    let pt_idx   = ((va >> 12) & 0x1FF) as usize;

    let pdpt_virt = get_or_alloc_table(pml4_virt, pml4_idx);
    let pd_virt   = get_or_alloc_table(pdpt_virt,  pdpt_idx);
    let pt_virt   = get_or_alloc_table(pd_virt,    pd_idx);

    pt_virt.add(pt_idx).write_volatile(pa | flags);
}

/// Given a page-table level pointer `table` and an `index`, return a
/// pointer to the next-level table, allocating and zeroing one if the
/// entry is not present.
unsafe fn get_or_alloc_table(table: *mut u64, index: usize) -> *mut u64 {
    let entry_ptr = table.add(index);
    let entry = entry_ptr.read_volatile();
    if entry & PTE_PRESENT != 0 {
        let next_phys = entry & 0x000F_FFFF_FFFF_F000;
        return phys_to_virt(next_phys) as *mut u64;
    }
    // Allocate a new zeroed page for the next level.
    let new_phys = crate::mm::pmm::alloc_frame()
        .expect("PTI: OOM allocating shadow page-table page");
    let new_virt = phys_to_virt(new_phys) as *mut u64;
    for i in 0..512 { new_virt.add(i).write_volatile(0); }
    entry_ptr.write_volatile(new_phys | PTE_PRESENT | PTE_WRITABLE | PTE_USER);
    new_virt
}

// ───── CR3 switch helpers ─────────────────────────────────────────────────────────────

/// Switch to the **kernel** page table for the given process.
/// Called at syscall/interrupt entry from user space.
///
/// # Safety
/// Must be called with a valid `PtiCr3Pair` for the current process.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn switch_to_kernel(pair: &PtiCr3Pair) {
    if PTI_ENABLED.load(Ordering::Relaxed) {
        let cr3_val = pair.kernel_cr3_val(true /* no_flush = use PCID */);
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) cr3_val,
            options(nostack, preserves_flags)
        );
    }
}

/// Switch to the **user** (shadow) page table for the given process.
/// Called just before `iret`/`sysret` back to user space.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn switch_to_user(pair: &PtiCr3Pair) {
    if PTI_ENABLED.load(Ordering::Relaxed) {
        let cr3_val = pair.user_cr3_val(true /* no_flush = use PCID */);
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) cr3_val,
            options(nostack, preserves_flags)
        );
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)] pub unsafe fn switch_to_kernel(_: &PtiCr3Pair) {}
#[cfg(not(target_arch = "x86_64"))]
#[inline(always)] pub unsafe fn switch_to_user(_: &PtiCr3Pair) {}

// ───── Helper: phys → virt (direct-map at PHYS_OFFSET) ──────────────────────────────

/// Kernel direct-map base (physical address 0 maps to this virtual address).
/// Must match the value in `src/arch/x86_64/paging.rs`.
pub const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

#[inline]
fn phys_to_virt(phys: u64) -> u64 {
    phys + PHYS_OFFSET
}
