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

// ====================================================================
// HAL trait API
// --------------------------------------------------------------------
// Trait shape reverse-engineered from the canonical implementation in
// `src/arch/x86_64/hal.rs` (`impl <Trait> for ArchImpl`). Every method
// signature is taken verbatim from that file so the existing impls keep
// compiling unchanged. `TrapFrame` is HAL-neutral: a fixed-size struct
// with `pc`, `user_sp`, `flags`, and a general-purpose register array
// (per the field accesses in hal.rs::Syscall::syscall_return).
// ====================================================================

/// HAL-level trap/syscall frame. Layout chosen to match the offsets used
/// by `x86_64/hal.rs::ContextSwitch::switch_to` (callee-saved regs live
/// in `regs[6..12]`, hence at least 12 entries).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrapFrame {
    /// Return value register (rax on x86_64, a0 on riscv64).
    /// hal.rs reads `f.regs[0]` for the syscall return value.
    pub regs:    [u64; 16],
    pub pc:      u64,
    pub user_sp: u64,
    pub flags:   u64,
}

impl TrapFrame {
    #[inline]
    pub const fn zeroed() -> Self {
        Self { regs: [0; 16], pc: 0, user_sp: 0, flags: 0 }
    }
}

/// Page-table protection flags surfaced through the HAL.
/// Bit assignments are arbitrary at this layer; per-arch impls map them
/// to native PTE bits (see `x86_64/hal.rs::Paging::map_page`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PageFlags { bits: u32 }

impl PageFlags {
    pub const PRESENT: Self = Self { bits: 1 << 0 };
    pub const WRITE:   Self = Self { bits: 1 << 1 };
    pub const USER:    Self = Self { bits: 1 << 2 };
    pub const NX:      Self = Self { bits: 1 << 3 };
    pub const COW:     Self = Self { bits: 1 << 4 };
    pub const GLOBAL:  Self = Self { bits: 1 << 5 };

    #[inline] pub const fn empty() -> Self { Self { bits: 0 } }
    #[inline] pub const fn bits(self) -> u32 { self.bits }
    #[inline] pub const fn contains(self, other: Self) -> bool {
        (self.bits & other.bits) == other.bits
    }
}

impl core::ops::BitOr for PageFlags {
    type Output = Self;
    #[inline] fn bitor(self, rhs: Self) -> Self { Self { bits: self.bits | rhs.bits } }
}
impl core::ops::BitAnd for PageFlags {
    type Output = Self;
    #[inline] fn bitand(self, rhs: Self) -> Self { Self { bits: self.bits & rhs.bits } }
}
impl core::ops::BitOrAssign for PageFlags {
    #[inline] fn bitor_assign(&mut self, rhs: Self) { self.bits |= rhs.bits; }
}

/// Per-arch initialisation steps. Called once during boot.
pub trait ArchInit {
    fn early_init();
    fn late_init();
}

/// Local-CPU interrupt enable/disable.
pub trait Interrupts {
    fn enable();
    fn disable();
    fn are_enabled() -> bool;
}

/// CPU control & introspection.
pub trait Cpu {
    fn halt();
    fn spin_hint();
    fn id() -> u32;
    fn flags() -> usize;
}

/// Architectural timer (free-running counter).
pub trait Timer {
    fn init_timer();
    fn ticks_per_sec() -> u64;
    fn read_ticks() -> u64;
}

/// Page-table manipulation. `cr3` is the arch-neutral name for the
/// root page-table physical address (CR3 on x86, satp on RV, TTBR on ARM).
pub trait Paging {
    fn map_page(cr3: usize, va: usize, pa: usize, flags: PageFlags) -> bool;
    fn unmap_page(cr3: usize, va: usize) -> Option<usize>;
    fn virt_to_phys(cr3: usize, va: usize) -> Option<usize>;
    fn kernel_cr3() -> usize;
    fn load_cr3(cr3: usize);
    fn flush_va(va: usize);
    fn flush_all();
    fn clone_address_space(src_cr3: usize) -> Option<usize>;
    fn new_user_address_space() -> Option<usize>;
}

/// TLB invalidation. Separate from `Paging` because some operations
/// (e.g. ASID-tagged flushes) make sense only when paging is set up.
pub trait Tlb {
    fn flush_va(va: usize);
    fn flush_all();
    fn flush_asid(asid: u16);
}

/// Context switching between kernel-side task contexts.
pub trait ContextSwitch {
    /// # Safety
    ///
    /// Both pointers must reference valid, properly-aligned trap frames.
    /// The caller must guarantee the address space pointed at by
    /// `next_cr3` is live.
    unsafe fn switch_to(
        current_frame: *mut TrapFrame,
        next_frame:    *const TrapFrame,
        next_cr3:      usize,
    );

    /// Build an initial user-mode trap frame for a freshly exec'd process.
    fn make_user_frame(entry: u64, user_sp: u64) -> TrapFrame;

    /// Returns the current kernel stack pointer (used by the scheduler
    /// to find the per-task kernel stack region).
    fn current_sp() -> usize;
}

/// Syscall entry / exit.
pub trait Syscall {
    fn syscall_setup();
    /// # Safety
    ///
    /// `frame` must point at a valid, fully-populated `TrapFrame` that
    /// represents the user-mode register state to restore.
    unsafe fn syscall_return(frame: *const TrapFrame) -> !;
}

/// Polled serial console (boot logging fallback).
pub trait Serial {
    fn serial_init();
    fn serial_putc(byte: u8);
    fn serial_getc() -> Option<u8>;
}

/// Floating-point / SIMD state save & restore.
pub trait FpState {
    fn fp_init();
    /// # Safety
    ///
    /// `dst` must point to at least `fp_area_size()` writable bytes,
    /// aligned per the architecture's FP-save requirement (64 B on x86-64).
    unsafe fn fp_save(dst: *mut u8);
    /// # Safety
    ///
    /// `src` must point to a previously-saved FP area produced by `fp_save`.
    unsafe fn fp_restore(src: *const u8);
    fn fp_area_size() -> usize;
}


