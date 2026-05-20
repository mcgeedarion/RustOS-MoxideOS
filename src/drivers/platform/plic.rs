//! RISC-V PLIC (Platform-Level Interrupt Controller) driver.
//!
//! ## Spec reference
//!   RISC-V Platform-Level Interrupt Controller Specification v1.0.0
//!   https://github.com/riscv/riscv-plic-spec
//!
//! ## Memory map (base = PLIC_BASE, typically 0x0C00_0000 on QEMU virt)
//!
//!   +0x000000  priority[1..1023]   4 B each  (source priority, 0 = disabled)
//!   +0x001000  pending[0..31]       4 B each  (read-only bitfield)
//!   +0x002000  enable[ctx][0..31]   4 B each  (per-context enable bitfield)
//!   +0x200000  threshold[ctx]       4 B        (per-context priority threshold)
//!   +0x200004  claim/complete[ctx]  4 B        (R=claim, W=complete)
//!
//! ## Context layout on QEMU virt
//!   ctx 0 = hart 0 M-mode
//!   ctx 1 = hart 0 S-mode  ← kernel uses this
//!   ctx 2 = hart 1 M-mode
//!   ctx 3 = hart 1 S-mode
//!   …

use core::ptr::{read_volatile, write_volatile};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Physical base address of the PLIC on QEMU virt (matches device-tree).
pub const PLIC_BASE: usize = 0x0C00_0000;

/// Maximum number of interrupt sources the spec allows.
pub const MAX_SOURCES: usize = 1024;

/// Stride between per-context register banks.
const CTX_STRIDE: usize = 0x1000;

/// Offset of the enable array for context `ctx`.
#[inline]
const fn enable_base(ctx: usize) -> usize {
    PLIC_BASE + 0x002000 + ctx * CTX_STRIDE
}

/// Offset of the threshold register for context `ctx`.
#[inline]
const fn threshold_addr(ctx: usize) -> usize {
    PLIC_BASE + 0x200000 + ctx * 0x1000
}

/// Offset of the claim/complete register for context `ctx`.
#[inline]
const fn claim_addr(ctx: usize) -> usize {
    threshold_addr(ctx) + 4
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level register helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
unsafe fn plic_write(addr: usize, val: u32) {
    write_volatile(addr as *mut u32, val);
}

#[inline]
unsafe fn plic_read(addr: usize) -> u32 {
    read_volatile(addr as *const u32)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Set the priority of interrupt `source` (1–7; 0 disables the source).
pub fn set_priority(source: u32, priority: u32) {
    if source == 0 || source as usize >= MAX_SOURCES { return; }
    unsafe {
        plic_write(PLIC_BASE + source as usize * 4, priority & 0x7);
    }
}

/// Enable interrupt `source` for S-mode context of `hart`.
pub fn enable(hart: usize, source: u32) {
    let ctx = hart * 2 + 1; // S-mode context
    let base = enable_base(ctx);
    let word = (source / 32) as usize;
    let bit  = source % 32;
    unsafe {
        let cur = plic_read(base + word * 4);
        plic_write(base + word * 4, cur | (1 << bit));
    }
}

/// Disable interrupt `source` for S-mode context of `hart`.
pub fn disable(hart: usize, source: u32) {
    let ctx = hart * 2 + 1;
    let base = enable_base(ctx);
    let word = (source / 32) as usize;
    let bit  = source % 32;
    unsafe {
        let cur = plic_read(base + word * 4);
        plic_write(base + word * 4, cur & !(1 << bit));
    }
}

/// Set the minimum priority threshold for S-mode context of `hart`.
/// Interrupts with priority ≤ threshold are masked.
pub fn set_threshold(hart: usize, threshold: u32) {
    let ctx = hart * 2 + 1;
    unsafe { plic_write(threshold_addr(ctx), threshold & 0x7); }
}

/// Claim the highest-priority pending interrupt for S-mode on `hart`.
/// Returns the source ID, or 0 if none pending.
pub fn claim(hart: usize) -> u32 {
    let ctx = hart * 2 + 1;
    unsafe { plic_read(claim_addr(ctx)) }
}

/// Signal completion of interrupt `source` for S-mode on `hart`.
pub fn complete(hart: usize, source: u32) {
    let ctx = hart * 2 + 1;
    unsafe { plic_write(claim_addr(ctx), source); }
}

/// Initialise the PLIC for hart 0 S-mode:
/// - Zero all source priorities.
/// - Clear all enable bits.
/// - Set threshold to 0 (all priorities pass).
pub fn init() {
    // Zero out all source priorities.
    for src in 1..MAX_SOURCES {
        unsafe { plic_write(PLIC_BASE + src * 4, 0); }
    }
    // Disable all sources for S-mode hart 0 (context 1).
    let base = enable_base(1);
    for word in 0..32 {
        unsafe { plic_write(base + word * 4, 0); }
    }
    // Accept all priority levels.
    set_threshold(0, 0);
}
