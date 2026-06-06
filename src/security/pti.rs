//! Page Table Isolation (PTI).
//!
//! ## C1 fix - shadow intermediate PTEs must NOT have PTE_USER
//! The original get_or_alloc_table set PTE_USER on intermediate entries,
//! letting userspace walk and corrupt the shadow tables. Fixed by using
//! get_or_alloc_kernel_table (no PTE_USER) for the kernel-only trampoline
//! mapping path.
//!
//! ## C2 fix - CR3 no-flush bit gated on PTI_PCID_ENABLED
//! CR3 bit 63 is reserved on CPUs without PCID. The old code set it
//! unconditionally, causing a #GP on every context switch on such CPUs.
//! PTI_PCID_ENABLED is now set only after enable_pcide() succeeds.

use core::sync::atomic::{AtomicBool, Ordering};

pub static PTI_ENABLED: AtomicBool = AtomicBool::new(false);

/// C2 fix: only set after enable_pcide() confirms PCID is working.
pub static PTI_PCID_ENABLED: AtomicBool = AtomicBool::new(false);

pub const PCID_KERNEL: u64 = 0x000;
pub const PCID_USER: u64 = 0x001;
pub const CR3_NO_FLUSH: u64 = 1u64 << 63;

#[derive(Debug, Clone, Copy, Default)]
pub struct PtiCr3Pair {
    pub kernel_cr3: u64,
    pub user_cr3: u64,
}

impl PtiCr3Pair {
    /// C2 fix: only set the no-flush bit when PCIDE is confirmed active.
    #[inline]
    pub fn kernel_cr3_val(&self, _hint: bool) -> u64 {
        let f = if PTI_PCID_ENABLED.load(Ordering::Relaxed) {
            CR3_NO_FLUSH
        } else {
            0
        };
        self.kernel_cr3 | PCID_KERNEL | f
    }
    #[inline]
    pub fn user_cr3_val(&self, _hint: bool) -> u64 {
        let f = if PTI_PCID_ENABLED.load(Ordering::Relaxed) {
            CR3_NO_FLUSH
        } else {
            0
        };
        self.user_cr3 | PCID_USER | f
    }
}

#[cfg(target_arch = "x86_64")]
pub fn cpu_has_pcid() -> bool {
    let ecx: u32;
    unsafe {
        core::arch::asm!(
            "mov eax, 1", "cpuid",
            out("ecx") ecx, out("eax") _, out("ebx") _, out("edx") _,
            options(nostack)
        );
    }
    (ecx >> 17) & 1 != 0
}

/// Enable PCIDE and set PTI_PCID_ENABLED.
///
/// # Safety
/// Interrupts must be disabled; CR3 must hold PCID=0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn enable_pcide() {
    let mut cr4: u64;
    core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nostack, preserves_flags));
    cr4 |= 1 << 17;
    core::arch::asm!("mov cr4, {}", in(reg) cr4, options(nostack, preserves_flags));
    PTI_PCID_ENABLED.store(true, Ordering::Relaxed); // C2 fix
}

#[cfg(target_arch = "x86_64")]
pub unsafe fn init() {
    if cpu_has_pcid() {
        enable_pcide();
        log::info!("pti: PCIDE enabled");
    } else {
        log::warn!("pti: PCID not available");
    }
    PTI_ENABLED.store(true, Ordering::Relaxed);
    log::info!("pti: Page Table Isolation active");
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn init() {}

/// Build the shadow user PML4.
/// Intermediate entries for the kernel-side trampoline mapping use
/// supervisor-only flags (C1 fix: no PTE_USER).
pub fn build_shadow_pml4(
    kernel_pml4_phys: u64,
    trampoline_phys: u64,
    trampoline_va: u64,
) -> Option<u64> {
    let shadow_phys = crate::mm::pmm::alloc_frame()?;
    unsafe {
        let shadow_ptr = phys_to_virt(shadow_phys) as *mut u64;
        let kernel_ptr = phys_to_virt(kernel_pml4_phys) as *const u64;
        for i in 0..256usize {
            shadow_ptr
                .add(i)
                .write_volatile(kernel_ptr.add(i).read_volatile());
        }
        for i in 256..512usize {
            shadow_ptr.add(i).write_volatile(0u64);
        }
        map_trampoline_into_shadow(
            shadow_ptr,
            trampoline_va,
            trampoline_phys,
            PTE_PRESENT | PTE_GLOBAL | PTE_NX,
        );
    }
    Some(shadow_phys)
}

const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
#[allow(dead_code)]
const PTE_USER: u64 = 1 << 2; // NOT used for kernel shadow intermediates
const PTE_GLOBAL: u64 = 1 << 8;
const PTE_NX: u64 = 1 << 63;

/// Walk/build PDPT->PD->PT for the trampoline VA using supervisor-only
/// intermediate entries. (C1 fix)
unsafe fn map_trampoline_into_shadow(pml4_virt: *mut u64, va: u64, pa: u64, leaf_flags: u64) {
    let pml4_idx = ((va >> 39) & 0x1FF) as usize;
    let pdpt_idx = ((va >> 30) & 0x1FF) as usize;
    let pd_idx = ((va >> 21) & 0x1FF) as usize;
    let pt_idx = ((va >> 12) & 0x1FF) as usize;
    let pdpt_virt = get_or_alloc_kernel_table(pml4_virt, pml4_idx);
    let pd_virt = get_or_alloc_kernel_table(pdpt_virt, pdpt_idx);
    let pt_virt = get_or_alloc_kernel_table(pd_virt, pd_idx);
    pt_virt.add(pt_idx).write_volatile(pa | leaf_flags);
}

/// Allocate or reuse an intermediate page-table page with supervisor-only
/// flags. PTE_USER is intentionally absent. (C1 fix)
unsafe fn get_or_alloc_kernel_table(table: *mut u64, index: usize) -> *mut u64 {
    let entry_ptr = table.add(index);
    let entry = entry_ptr.read_volatile();
    if entry & PTE_PRESENT != 0 {
        return phys_to_virt(entry & 0x000F_FFFF_FFFF_F000) as *mut u64;
    }
    let new_phys =
        crate::mm::pmm::alloc_frame().expect("PTI: OOM allocating shadow page-table page");
    let new_virt = phys_to_virt(new_phys) as *mut u64;
    for i in 0..512 {
        new_virt.add(i).write_volatile(0);
    }
    // C1 fix: no PTE_USER on kernel-only intermediate entries.
    entry_ptr.write_volatile(new_phys | PTE_PRESENT | PTE_WRITABLE);
    new_virt
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn switch_to_kernel(pair: &PtiCr3Pair) {
    if PTI_ENABLED.load(Ordering::Relaxed) {
        core::arch::asm!("mov cr3, {}", in(reg) pair.kernel_cr3_val(true),
                         options(nostack, preserves_flags));
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub unsafe fn switch_to_user(pair: &PtiCr3Pair) {
    if PTI_ENABLED.load(Ordering::Relaxed) {
        core::arch::asm!("mov cr3, {}", in(reg) pair.user_cr3_val(true),
                         options(nostack, preserves_flags));
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub unsafe fn switch_to_kernel(_: &PtiCr3Pair) {}
#[cfg(not(target_arch = "x86_64"))]
#[inline(always)]
pub unsafe fn switch_to_user(_: &PtiCr3Pair) {}

pub const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;
#[inline]
fn phys_to_virt(phys: u64) -> u64 {
    phys + PHYS_OFFSET
}
