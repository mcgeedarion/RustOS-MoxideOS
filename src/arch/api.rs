//! Architecture Abstraction Layer (HAL) — `arch::api`.
//!
//! Every piece of architecture-specific code that the generic kernel needs
//! should be surfaced through this small API.  That keeps `mm`, `proc`, `fs`,
//! and friends free of `cfg(target_arch = ...)` litter.

use core::ops::Range;

/// Human-readable architecture name (`"aarch64"`, `"riscv64"`, `"x86_64"`, ...).
pub fn name() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64"
    }
    #[cfg(target_arch = "riscv64")]
    {
        "riscv64"
    }
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64"
    }
}

/// Page size in bytes for the current MMU configuration.
pub const fn page_size() -> usize {
    4096
}

/// Returns the canonical kernel virtual address range.
///
/// On ARM64 and RV64 we identity-map a large chunk early, then move to the higher-half
/// if desired later.  On x86_64 this typically points at the higher-half.
pub fn kernel_va_range() -> Range<usize> {
    crate::arch::hal::kernel_va_range()
}

/// Returns `true` if a virtual address is in userspace.
#[inline]
pub fn is_user_addr(addr: usize) -> bool {
    crate::arch::hal::is_user_addr(addr)
}

/// Returns `true` if a virtual address is canonical / valid for the arch.
#[inline]
pub fn is_valid_addr(addr: usize) -> bool {
    crate::arch::hal::is_valid_addr(addr)
}

/// Flush the entire TLB on the local CPU.
#[inline]
pub unsafe fn tlb_flush_all() {
    crate::arch::hal::tlb_flush_all()
}

/// Flush a single virtual page from the local CPU's TLB.
#[inline]
pub unsafe fn tlb_flush_page(va: usize) {
    crate::arch::hal::tlb_flush_page(va)
}

/// Halt or idle the CPU until the next interrupt.
#[inline]
pub fn cpu_relax() {
    crate::arch::hal::cpu_relax()
}

/// Enter the architecture's low-power wait state.
#[inline]
pub fn wait_for_interrupt() {
    crate::arch::hal::wait_for_interrupt()
}

/// Read a monotonic timestamp counter, if available.
#[inline]
pub fn time_now_cycles() -> u64 {
    crate::arch::hal::time_now_cycles()
}

/// Trigger a breakpoint trap for the debugger.
#[inline]
pub fn debug_break() {
    crate::arch::hal::debug_break()
}

/// Returns the hardware thread / CPU id for the current core.
#[inline]
pub fn cpu_id() -> usize {
    crate::arch::hal::cpu_id()
}

/// Enables interrupts on the local CPU.
#[inline]
pub unsafe fn interrupts_enable() {
    crate::arch::hal::interrupts_enable()
}

/// Disables interrupts on the local CPU.
#[inline]
pub unsafe fn interrupts_disable() {
    crate::arch::hal::interrupts_disable()
}

/// Returns whether interrupts are currently enabled.
#[inline]
pub fn interrupts_enabled() -> bool {
    crate::arch::hal::interrupts_enabled()
}
