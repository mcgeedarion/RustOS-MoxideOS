//! Architecture Abstraction Layer (HAL) — `arch::api`.
//!
//! Every piece of arch-generic kernel code (scheduler, syscall dispatch,
//! signal delivery, mm, drivers) imports from here. Nothing outside
//! `src/arch/` should ever import directly from `arch::x86_64` or
//! `arch::riscv64`.
//!
//! ## Design principles
//!
//! 1. **Traits, not functions.**  Each capability is a Rust trait.  The
//!    concrete impl lives in `arch::{x86_64,riscv64}::hal` and is
//!    re-exported as the `Arch` type alias at the bottom of this file.
//!    Generic code writes `Arch::halt()` or `<Arch as Interrupts>::enable()`.
//!
//! 2. **No heap in trait signatures.**  Every method takes/returns only
//!    primitive types, raw pointers, or small fixed-size structs so that
//!    the traits are usable before the heap is online.
//!
//! 3. **Fallible where appropriate.**  Methods that can silently fail
//!    (e.g. `map_page`) return `bool` or `Option` rather than panicking
//!    by default; callers decide how to handle failures.
//!
//! 4. **One impl type per arch.**  There are no vtables; all dispatch is
//!    monomorphised at compile time via the `Arch` type alias.
//!
//! ## Capability groups
//!
//!   | Trait              | Methods                                                  |
//!   |--------------------|----------------------------------------------------------|
//!   | `ArchInit`         | `early_init()`, `late_init()`                            |
//!   | `Interrupts`       | `enable()`, `disable()`, `are_enabled()`                 |
//!   | `Cpu`              | `halt()`, `spin_hint()`, `id()`, `flags()`               |
//!   | `Timer`            | `init_timer()`, `ticks_per_sec()`, `read_ticks()`        |
//!   | `Paging`           | `map_page()`, `unmap_page()`, `virt_to_phys()`,          |
//!   |                    | `kernel_cr3()`, `load_cr3()`, `invlpg()`,                |
//!   |                    | `clone_address_space()`, `new_user_address_space()`      |
//!   | `ContextSwitch`    | `switch_to()`, `make_user_frame()`, `current_sp()`       |
//!   | `Syscall`          | `syscall_setup()`, `syscall_return()`                    |
//!   | `Serial`           | `serial_init()`, `serial_putc()`, `serial_getc()`        |
//!   | `FpState`          | `fp_init()`, `fp_save()`, `fp_restore()`                 |
//!   | `Tlb`              | `flush_va()`, `flush_all()`, `flush_asid()`              |

// ─── ArchInit ────────────────────────────────────────────────────────────

/// CPU and hardware initialisation.
///
/// `early_init` runs **before** the heap and before interrupts.  It must
/// set up any state that other HAL methods depend on (GDT/TSS on x86-64,
/// medeleg on RISC-V).
///
/// `late_init` runs **after** heap, ACPI/DT, and the PMM memory map are
/// loaded.  It should start the periodic timer and enable interrupts.
pub trait ArchInit {
    /// Called from `kernel_main` as the very first thing, before heap.
    /// Must set up descriptor tables, trap vectors, and per-CPU state.
    fn early_init();

    /// Called after `heap_init()`, `memmap_init()`, and `acpi_init()`.
    /// Should start the hardware timer and issue `sti` / `sie` enable.
    fn late_init();
}

// ─── Interrupts ──────────────────────────────────────────────────────────

/// Masking and querying of hardware interrupts.
pub trait Interrupts {
    /// Enable hardware interrupts on this CPU.
    fn enable();

    /// Disable hardware interrupts on this CPU.
    fn disable();

    /// Returns `true` if hardware interrupts are currently enabled.
    fn are_enabled() -> bool;

    /// Disable interrupts, run `f`, then restore the previous state.
    /// This is the correct pattern for spinlock critical sections.
    #[inline]
    fn without<R, F: FnOnce() -> R>(f: F) -> R {
        let was = Self::are_enabled();
        if was { Self::disable(); }
        let r = f();
        if was { Self::enable(); }
        r
    }
}

// ─── Cpu ─────────────────────────────────────────────────────────────────

/// Basic CPU intrinsics.
pub trait Cpu {
    /// Halt the CPU until the next interrupt.  Must be called with
    /// interrupts enabled, otherwise the machine will freeze.
    fn halt();

    /// Emit a spin-wait hint (`pause` on x86, `nop` on RISC-V).
    fn spin_hint();

    /// Return a platform-unique CPU identifier (APIC ID / hart ID).
    fn id() -> u32;

    /// Read the CPU flags / status register (`rflags` on x86,
    /// `sstatus` on RISC-V).  Useful for saving/restoring interrupt state.
    fn flags() -> usize;
}

// ─── Timer ───────────────────────────────────────────────────────────────

/// Periodic preemption timer.
pub trait Timer {
    /// Initialise and start the timer.  After this call the timer fires
    /// at approximately `ticks_per_sec()` Hz.
    fn init_timer();

    /// Nominal ticks per second (may be an approximation at boot).
    fn ticks_per_sec() -> u64;

    /// Read a monotonically increasing tick counter.  Wraps on overflow.
    fn read_ticks() -> u64;
}

// ─── Paging ──────────────────────────────────────────────────────────────

/// PTE flag bits — same numerical values on both architectures.
/// The impl's `map_page` translates these to native PTE format.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageFlags(pub u64);

impl PageFlags {
    pub const PRESENT:  PageFlags = PageFlags(1 << 0);
    pub const WRITE:    PageFlags = PageFlags(1 << 1);
    pub const USER:     PageFlags = PageFlags(1 << 2);
    pub const EXEC:     PageFlags = PageFlags(1 << 3);
    pub const COW:      PageFlags = PageFlags(1 << 9);  // software bit
    pub const NX:       PageFlags = PageFlags(1 << 63);

    pub const fn bits(self) -> u64 { self.0 }
    pub const fn contains(self, other: PageFlags) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::ops::BitOr for PageFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { PageFlags(self.0 | rhs.0) }
}
impl core::ops::BitOrAssign for PageFlags {
    fn bitor_assign(&mut self, rhs: Self) { self.0 |= rhs.0; }
}
impl core::ops::BitAnd for PageFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self { PageFlags(self.0 & rhs.0) }
}
impl core::ops::Not for PageFlags {
    type Output = Self;
    fn not(self) -> Self { PageFlags(!self.0) }
}

/// Page table management.
pub trait Paging {
    /// Map `va` → `pa` in address space `cr3` with the given flags.
    /// Creates any missing intermediate page-table levels.
    /// Returns `false` if the PMM is out of pages.
    fn map_page(cr3: usize, va: usize, pa: usize, flags: PageFlags) -> bool;

    /// Remove the mapping for `va` from `cr3`.
    /// Returns the previously-mapped physical address, or `None`.
    fn unmap_page(cr3: usize, va: usize) -> Option<usize>;

    /// Walk `cr3` to resolve `va` → physical address.
    fn virt_to_phys(cr3: usize, va: usize) -> Option<usize>;

    /// Return the physical address of the kernel's root page table.
    fn kernel_cr3() -> usize;

    /// Load `cr3` into the page-table base register (CR3 / SATP).
    fn load_cr3(cr3: usize);

    /// Invalidate the TLB entry for a single virtual address.
    fn flush_va(va: usize);

    /// Flush the entire TLB.
    fn flush_all();

    /// Clone `src_cr3` into a new address space for CoW `fork()`.
    /// Returns the new root page table PA, or `None` on OOM.
    fn clone_address_space(src_cr3: usize) -> Option<usize>;

    /// Allocate a fresh (empty) root page table for a new process,
    /// with the kernel half already present.
    fn new_user_address_space() -> Option<usize>;
}

// ─── ContextSwitch ───────────────────────────────────────────────────────

/// Saved register state for one task, stored on its kernel stack.
/// The layout is architecture-defined; callers treat it as opaque.
#[repr(C)]
pub struct TrapFrame {
    /// 32 general-purpose register slots (x86: rax..r15 + padding;
    /// RISC-V: x0..x31).  Slot 0 is always the stack pointer.
    pub regs:    [u64; 32],
    /// Program counter (RIP / SEPC).
    pub pc:      u64,
    /// Flags / status register (RFLAGS / SSTATUS).
    pub flags:   u64,
    /// Saved user stack pointer.
    pub user_sp: u64,
}

impl TrapFrame {
    pub const fn zeroed() -> Self {
        Self { regs: [0u64; 32], pc: 0, flags: 0, user_sp: 0 }
    }

    /// Syscall return value slot (rax / a0).
    pub fn set_retval(&mut self, val: u64) {
        self.regs[0] = val;
    }
    pub fn retval(&self) -> u64 { self.regs[0] }
}

/// Task context switching.
pub trait ContextSwitch {
    /// Switch from the current task to `next`.
    ///
    /// Saves the full machine state into `*current_frame` and restores
    /// from `*next_frame`.  On x86-64 this also swaps CR3 if `next_cr3`
    /// differs from the current CR3.
    ///
    /// # Safety
    /// Both frame pointers must be valid, non-null, and point to
    /// kernel-stack-resident `TrapFrame` structs.
    unsafe fn switch_to(
        current_frame: *mut TrapFrame,
        next_frame:    *const TrapFrame,
        next_cr3:      usize,
    );

    /// Initialise a `TrapFrame` for a brand-new user process.
    ///
    /// Sets PC to `entry`, user SP to `user_sp`, and flags to the
    /// appropriate user-mode value (IF=1 on x86, SPP=0 on RISC-V).
    fn make_user_frame(entry: u64, user_sp: u64) -> TrapFrame;

    /// Return the kernel stack pointer for the currently running task.
    fn current_sp() -> usize;
}

// ─── Syscall ─────────────────────────────────────────────────────────────

/// Syscall entry/return machinery.
pub trait Syscall {
    /// Configure the CPU for fast system call entry:
    ///   - x86-64: program `LSTAR`, `STAR`, `FMASK` MSRs.
    ///   - RISC-V: set `stvec` to the ecall vector.
    fn syscall_setup();

    /// Return from a syscall to user space, placing `retval` in the
    /// appropriate register and restoring the saved user frame.
    ///
    /// # Safety
    /// `frame` must be a valid pointer to the task's kernel-stack frame.
    unsafe fn syscall_return(frame: *const TrapFrame) -> !;
}

// ─── Serial ──────────────────────────────────────────────────────────────

/// Early boot serial console.
pub trait Serial {
    /// Initialise the UART hardware.  Safe to call multiple times
    /// (subsequent calls are no-ops if already initialised).
    fn serial_init();

    /// Write one byte, blocking until the TX buffer has space.
    fn serial_putc(byte: u8);

    /// Read one byte if available.  Returns `None` if the RX FIFO is empty.
    fn serial_getc() -> Option<u8>;

    /// Write a full byte slice.
    fn serial_write(buf: &[u8]) {
        for &b in buf { Self::serial_putc(b); }
    }

    /// Write a string followed by `\r\n`.
    fn serial_println(s: &str) {
        Self::serial_write(s.as_bytes());
        Self::serial_write(b"\r\n");
    }
}

// ─── FpState ─────────────────────────────────────────────────────────────

/// Floating-point / SIMD state management for signal delivery.
pub trait FpState {
    /// Detect FP save capability and enable the FP unit in supervisor mode.
    fn fp_init();

    /// Save the current FP/SIMD state to `dst`.
    /// `dst` must be at least `fp_area_size()` bytes, aligned to 64.
    ///
    /// # Safety
    /// `dst` must be valid and properly aligned.
    unsafe fn fp_save(dst: *mut u8);

    /// Restore FP/SIMD state from `src`.
    ///
    /// # Safety
    /// `src` must contain a previously saved FP state.
    unsafe fn fp_restore(src: *const u8);

    /// Size in bytes of the FP save area (XSAVE area / F/D register file).
    fn fp_area_size() -> usize;
}

// ─── Tlb ─────────────────────────────────────────────────────────────────

/// TLB management.
pub trait Tlb {
    /// Invalidate the TLB entry for `va` in the current address space.
    fn flush_va(va: usize);

    /// Flush all TLB entries for the current address space.
    fn flush_all();

    /// Flush all TLB entries tagged with `asid`.
    /// On architectures without ASID support this is equivalent to `flush_all`.
    fn flush_asid(asid: u16);
}

// ─── Arch type alias ─────────────────────────────────────────────────────
//
// Generic kernel code uses `crate::arch::Arch` as the concrete type.
// Each impl file declares `pub struct ArchImpl;` and implements all the
// traits above, then `arch/mod.rs` re-exports it as `Arch`.
//
// Example:
//   use crate::arch::Arch;
//   use crate::arch::api::{Cpu, Interrupts};
//
//   Arch::halt();
//   Interrupts::without(|| { /* critical section */ });
