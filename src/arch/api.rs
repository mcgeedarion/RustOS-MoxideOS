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
//!   | `Syscall`          | `syscall_setup()`, `syscall_return()`,                   |
//!   |                    | `clear_child_tid()`                                      |
//!   | `Serial`           | `serial_init()`, `serial_putc()`, `serial_getc()`        |
//!   | `FpState`          | `fp_init()`, `fp_save()`, `fp_restore()`                 |
//!   | `Tlb`              | `flush_va()`, `flush_all()`, `flush_asid()`              |

// ─── ArchInit ────────────────────────────────────────────────────────────────────

/// CPU and hardware initialisation.
///
/// `early_init` runs **before** the heap and before interrupts.
/// `late_init` runs **after** heap, ACPI/DT, and PMM memory map are loaded.
pub trait ArchInit {
    fn early_init();
    fn late_init();
}

// ─── Interrupts ──────────────────────────────────────────────────────────────────

pub trait Interrupts {
    fn enable();
    fn disable();
    fn are_enabled() -> bool;

    #[inline]
    fn without<R, F: FnOnce() -> R>(f: F) -> R {
        let was = Self::are_enabled();
        if was { Self::disable(); }
        let r = f();
        if was { Self::enable(); }
        r
    }
}

// ─── Cpu ─────────────────────────────────────────────────────────────────────────

pub trait Cpu {
    /// Halt the CPU until the next interrupt.
    fn halt();
    /// Emit a spin-wait hint (`pause` on x86, `nop` on RISC-V).
    fn spin_hint();
    /// Return a platform-unique CPU identifier (APIC ID / hart ID).
    fn id() -> u32;
    /// Read the CPU flags / status register.
    fn flags() -> usize;
}

// ─── Timer ────────────────────────────────────────────────────────────────────

pub trait Timer {
    fn init_timer();
    fn ticks_per_sec() -> u64;
    fn read_ticks() -> u64;
}

// ─── Paging ───────────────────────────────────────────────────────────────────

/// PTE flag bits — same numerical values on both architectures.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PageFlags(pub u64);

impl PageFlags {
    pub const PRESENT: PageFlags = PageFlags(1 << 0);
    pub const WRITE:   PageFlags = PageFlags(1 << 1);
    pub const USER:    PageFlags = PageFlags(1 << 2);
    pub const EXEC:    PageFlags = PageFlags(1 << 3);
    pub const COW:     PageFlags = PageFlags(1 << 9);
    pub const NX:      PageFlags = PageFlags(1 << 63);

    pub const fn bits(self) -> u64 { self.0 }
    pub const fn contains(self, other: PageFlags) -> bool { self.0 & other.0 == other.0 }

    pub const fn empty() -> Self { PageFlags(0) }
}

impl core::ops::BitOr  for PageFlags { type Output = Self; fn bitor (self, r: Self) -> Self { PageFlags(self.0 | r.0) } }
impl core::ops::BitAnd for PageFlags { type Output = Self; fn bitand(self, r: Self) -> Self { PageFlags(self.0 & r.0) } }
impl core::ops::Not    for PageFlags { type Output = Self; fn not(self) -> Self { PageFlags(!self.0) } }
impl core::ops::BitOrAssign for PageFlags { fn bitor_assign(&mut self, r: Self) { self.0 |= r.0; } }

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

// ─── ContextSwitch ───────────────────────────────────────────────────────────────

#[repr(C)]
pub struct TrapFrame {
    pub regs:    [u64; 32],
    pub pc:      u64,
    pub flags:   u64,
    pub user_sp: u64,
}

impl TrapFrame {
    pub const fn zeroed() -> Self {
        Self { regs: [0u64; 32], pc: 0, flags: 0, user_sp: 0 }
    }
    pub fn set_retval(&mut self, val: u64) { self.regs[0] = val; }
    pub fn retval(&self) -> u64 { self.regs[0] }
}

pub trait ContextSwitch {
    unsafe fn switch_to(
        current_frame: *mut TrapFrame,
        next_frame:    *const TrapFrame,
        next_cr3:      usize,
    );
    fn make_user_frame(entry: u64, user_sp: u64) -> TrapFrame;
    fn current_sp() -> usize;
}

// ─── Syscall ───────────────────────────────────────────────────────────────────

pub trait Syscall {
    /// Configure the CPU for fast system call entry.
    fn syscall_setup();

    /// Return from a syscall to user space.
    ///
    /// # Safety
    /// `frame` must be a valid pointer to the task's kernel-stack frame.
    unsafe fn syscall_return(frame: *const TrapFrame) -> !;

    /// Implement the CLONE_CHILD_CLEARTID futex protocol for `pid`:
    /// zero the word at `clear_child_tid_va` in the process's user address
    /// space and issue a FUTEX_WAKE(1) on that address.  Called from
    /// do_exit / sys_exit_group immediately before the task is zombified.
    fn clear_child_tid(pid: usize);
}

// ─── Arch convenience re-export ───────────────────────────────────────────────
//
// Usage:
//   use crate::arch::Arch;
//   use crate::arch::api::{Cpu, Interrupts};
//   Arch::halt();

// ─── Serial ───────────────────────────────────────────────────────────────────

pub trait Serial {
    fn serial_init();
    fn serial_putc(byte: u8);
    fn serial_getc() -> Option<u8>;

    fn serial_write(buf: &[u8]) { for &b in buf { Self::serial_putc(b); } }
    fn serial_println(s: &str) {
        Self::serial_write(s.as_bytes());
        Self::serial_write(b"\r\n");
    }
}

// ─── FpState ───────────────────────────────────────────────────────────────────

pub trait FpState {
    fn fp_init();
    unsafe fn fp_save(dst: *mut u8);
    unsafe fn fp_restore(src: *const u8);
    fn fp_area_size() -> usize;
}

// ─── Tlb ─────────────────────────────────────────────────────────────────────────

pub trait Tlb {
    fn flush_va(va: usize);
    fn flush_all();
    fn flush_asid(asid: u16);
}
