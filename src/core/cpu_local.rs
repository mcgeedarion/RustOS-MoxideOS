//! Per-CPU variable accessor — `CpuLocal<T>`.
//!
//! # Approach
//!
//! Each logical CPU stores a pointer to its own `PerCpuBlock` in a
//! dedicated register:
//!
//! | Architecture | Register | Convention |
//! |---|---|---|
//! | x86_64  | `%gs`  | `SWAPGS` swaps to the kernel GS base on entry |
//! | riscv64 | `tp`   | Thread Pointer holds per-hart data |
//!
//! `CpuLocal<T>` is a zero-sized marker; the actual per-CPU memory is
//! allocated inside `PerCpuBlock` by the SMP bringup code
//! (`src/smp/percpu.rs`).  This module only provides the *accessor* API
//! so there are no circular dependencies.
//!
//! # Safety contract
//!
//! * `CpuLocal::get()` is `unsafe` — the caller must guarantee that preemption
//!   is disabled (interrupts off or a preemption guard held) for the duration
//!   of the access, or that `T` is `Sync + Copy`.
//! * The per-CPU pointer **must** be initialised by SMP code before any `get()`
//!   call.  Calling `get()` before init is undefined behaviour.

use core::cell::UnsafeCell;
use core::marker::PhantomData;

/// Maximum number of per-CPU slots.  Increase as subsystems register more.
pub const MAX_CPU_LOCAL_SLOTS: usize = 64;

/// The block of per-CPU data stored at the address held in `tp`/`%gs`.
#[repr(C)]
pub struct PerCpuBlock {

    pub self_ptr: *mut PerCpuBlock,
    pub cpu_id: u32,
    pub in_irq: u32,
    slots: [UnsafeCell<usize>; MAX_CPU_LOCAL_SLOTS],
}

// SAFETY: `PerCpuBlock` is exclusively owned by one CPU; sharing across
// CPUs would violate the ownership invariant anyway.
unsafe impl Sync for PerCpuBlock {}

impl PerCpuBlock {
    
    #[inline]
    pub unsafe fn read_slot(&self, index: usize) -> usize {
        debug_assert!(index < MAX_CPU_LOCAL_SLOTS);
        // SAFETY: caller guarantees preemption is disabled.
        unsafe { *self.slots[index].get() }
    }

    /// Write `value` into slot `index`.
    #[inline]
    pub unsafe fn write_slot(&self, index: usize, value: usize) {
        debug_assert!(index < MAX_CPU_LOCAL_SLOTS);
        // SAFETY: caller guarantees exclusive access.
        unsafe { *self.slots[index].get() = value };
    }
}

/// A compile-time-assigned index into the per-CPU slot array.
#[derive(Clone, Copy)]
pub struct CpuLocalKey {
    index: usize,
}

impl CpuLocalKey {
    /// Construct from a static slot index.  Only call from `cpu_local_key!`.
    #[doc(hidden)]
    pub const fn new(index: usize) -> Self {
        Self { index }
    }
}

/// Declare a per-CPU variable slot.
#[macro_export]
macro_rules! cpu_local_key {
    ($idx:expr) => {
        $crate::core::cpu_local::CpuLocalKey::new($idx)
    };
}

/// Zero-sized handle to a per-CPU value of type `T` stored in a slot.
pub struct CpuLocal<T: Copy + 'static> {
    key: CpuLocalKey,
    _marker: PhantomData<T>,
}

// SAFETY: the per-CPU discipline guarantees each CPU has exclusive access.
unsafe impl<T: Copy + 'static> Sync for CpuLocal<T> {}

impl<T: Copy + 'static> CpuLocal<T> {
    /// Create a new accessor for `key`.
    pub const fn new(key: CpuLocalKey) -> Self {
        Self {
            key,
            _marker: PhantomData,
        }
    }

    /// Return the per-CPU value for the **current** CPU.
    #[inline]
    pub unsafe fn get(&self) -> T {
        let block = unsafe { current_cpu_block() };
        let raw = unsafe { (*block).read_slot(self.key.index) };
        // SAFETY: caller guarantees T was stored as a usize-compatible repr.
        unsafe { core::mem::transmute_copy(&raw) }
    }

    /// Store `value` into the per-CPU slot for the **current** CPU.
    #[inline]
    pub unsafe fn set(&self, value: T) {
        let block = unsafe { current_cpu_block() };
        let raw: usize = unsafe { core::mem::transmute_copy(&value) };
        unsafe { (*block).write_slot(self.key.index, raw) };
    }
}

/// Retrieve the `PerCpuBlock` pointer for the executing CPU.
#[inline]
pub unsafe fn current_cpu_block() -> *mut PerCpuBlock {
    #[cfg(target_arch = "x86_64")]
    {
        let ptr: *mut PerCpuBlock;
        // Read self-pointer from GS base offset 0.
        unsafe {
            core::arch::asm!(
                "mov {ptr}, gs:[0]",
                ptr = out(reg) ptr,
                options(nostack, readonly, preserves_flags)
            );
        }
        ptr
    }

    #[cfg(target_arch = "riscv64")]
    {
        let ptr: *mut PerCpuBlock;
        // `tp` holds the PerCpuBlock pointer on riscv64.
        unsafe {
            core::arch::asm!(
                "mv {ptr}, tp",
                ptr = out(reg) ptr,
                options(nostack, readonly, nomem)
            );
        }
        ptr
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    compile_error!("cpu_local: unsupported architecture")
}
