//! RISC-V Platform-Level Interrupt Controller (PLIC) driver.
//!
//! Responsibilities at boot time:
//!   1. `set_base()`  — record the MMIO base discovered by the FDT walker.
//!   2. `init()`      — write threshold=0 for this hart's S-mode context so
//!                      all external interrupt priorities ≥1 are unmasked.
//!
//! PLIC memory map (SiFive / QEMU virt):
//!   0x000000 + src*4       — priority registers (1 per interrupt source)
//!   0x001000               — pending array
//!   0x002000 + ctx*0x80    — enable bits (1 bit per source, 32 sources/word)
//!   0x200000 + ctx*0x1000  — per-context threshold  (offset 0x000)
//!                          — claim/complete register (offset 0x004)
//!
//! S-mode context index for hart H = 2*H + 1.

use core::sync::atomic::{AtomicUsize, Ordering};

static PLIC_BASE: AtomicUsize = AtomicUsize::new(0);

/// Record the PLIC MMIO base address found in the FDT.
/// Must be called before `init()`.
pub fn set_base(base: usize) {
    PLIC_BASE.store(base, Ordering::Relaxed);
}

/// Return the stored PLIC base, or 0 if not yet set.
pub fn base() -> usize {
    PLIC_BASE.load(Ordering::Relaxed)
}

/// Initialise the PLIC for the boot hart's S-mode context.
///
/// Writes threshold = 0 so that all interrupt sources with priority ≥ 1
/// can fire.  Must be called:
///   - after  `set_base()` (i.e. after `fdt_phase1()`)
///   - after  `trap_init()` (stvec must be installed)
///   - before `fdt_phase2()` / any device probe that enables PLIC sources
///
/// # Panics
/// Panics if `set_base()` has not been called.
pub fn init() {
    let base = PLIC_BASE.load(Ordering::Relaxed);
    assert!(base != 0, "plic::init() called before plic::set_base()");

    let hart = crate::arch::riscv64::current_hart_id();
    // S-mode context = 2*hart + 1
    let ctx = 2 * hart + 1;
    // threshold register: PLIC_BASE + 0x0020_0000 + ctx * 0x1000
    let threshold_addr = base + 0x0020_0000 + ctx * 0x1000;

    // SAFETY: PLIC MMIO region; address is valid after set_base().
    unsafe {
        (threshold_addr as *mut u32).write_volatile(0);
    }

    crate::println!(
        "plic: hart {} S-mode context {} threshold set to 0",
        hart,
        ctx
    );
}

/// Enable a single interrupt source for this hart's S-mode context.
///
/// `irq` is the 1-based PLIC source number (as read from the FDT
/// `interrupts` property).
pub fn enable_irq(irq: u32) {
    let base = PLIC_BASE.load(Ordering::Relaxed);
    if base == 0 || irq == 0 {
        return;
    }

    let hart = crate::arch::riscv64::current_hart_id();
    let ctx = 2 * hart + 1;
    // enable array: PLIC_BASE + 0x0000_2000 + ctx * 0x80 + (irq / 32) * 4
    let word_addr = base + 0x0000_2000 + ctx * 0x80 + ((irq / 32) as usize) * 4;
    unsafe {
        let word = (word_addr as *mut u32).read_volatile();
        (word_addr as *mut u32).write_volatile(word | (1 << (irq % 32)));
    }
}

/// Set the priority of an interrupt source (1 = lowest, 7 = highest).
/// Priority 0 effectively disables the source.
pub fn set_priority(irq: u32, priority: u32) {
    let base = PLIC_BASE.load(Ordering::Relaxed);
    if base == 0 || irq == 0 {
        return;
    }
    // priority[irq] at PLIC_BASE + irq * 4
    let addr = base + (irq as usize) * 4;
    unsafe {
        (addr as *mut u32).write_volatile(priority & 0x7);
    }
}

/// Claim the highest-priority pending interrupt for this hart's S-mode context.
/// Returns the IRQ number, or 0 if none is pending.
pub fn claim() -> u32 {
    let base = PLIC_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return 0;
    }
    let hart = crate::arch::riscv64::current_hart_id();
    let ctx = 2 * hart + 1;
    let claim_addr = base + 0x0020_0000 + ctx * 0x1000 + 0x4;
    unsafe { (claim_addr as *const u32).read_volatile() }
}

/// Complete handling of `irq` for this hart's S-mode context.
pub fn complete(irq: u32) {
    let base = PLIC_BASE.load(Ordering::Relaxed);
    if base == 0 || irq == 0 {
        return;
    }
    let hart = crate::arch::riscv64::current_hart_id();
    let ctx = 2 * hart + 1;
    let complete_addr = base + 0x0020_0000 + ctx * 0x1000 + 0x4;
    unsafe {
        (complete_addr as *mut u32).write_volatile(irq);
    }
}
