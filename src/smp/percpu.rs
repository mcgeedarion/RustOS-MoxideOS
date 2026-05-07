//! Per-CPU storage.
//!
//! x86_64: `GSBASE` MSR points to a `PercpuBlock` in a dedicated per-CPU
//!         mapping.  The `gs:0` slot holds the self-pointer so that
//!         `current_cpu_id()` is a single `mov rax, gs:[0]` with no memory
//!         barrier.
//!
//! RISC-V: The `tp` (thread pointer) register holds the pointer to the block.

use core::sync::atomic::{AtomicU32, Ordering};
use core::cell::UnsafeCell;

/// Size of the interrupt stack allocated per CPU (16 KiB).
pub const IST_SIZE: usize = 16 * 1024;
/// Size of the syscall stack per CPU (16 KiB).
pub const SYSCALL_STACK_SIZE: usize = 16 * 1024;

/// The per-CPU block.  Must be `repr(C)` so the assembly trampoline can
/// access `self_ptr` at a fixed offset (offset 0).
#[repr(C, align(64))]
pub struct PercpuBlock {
    /// Pointer to self — must stay at offset 0.
    pub self_ptr: *mut PercpuBlock,
    /// Logical CPU id (0-based).
    pub cpu_id: u32,
    /// NUMA node.
    pub node: u32,
    /// Nesting depth of `push_off` / `pop_off` for disabling interrupts.
    pub intr_disable_depth: u32,
    /// Were interrupts enabled before the outermost `push_off`?
    pub intr_was_enabled: bool,
    /// Kernel interrupt stack (IST1 on x86_64).
    pub ist_stack: [u8; IST_SIZE],
    /// Syscall/SYSENTER stack.
    pub syscall_stack: [u8; SYSCALL_STACK_SIZE],
    /// Pointer to the currently running `Task` on this CPU.
    pub current_task: *mut crate::proc::task::Task,
    /// Runqueue for this CPU's CFS scheduler.
    pub runqueue: crate::proc::scheduler::RunQueue,
    /// Count of context switches on this CPU.
    pub ctx_switches: u64,
    /// IPI pending bitfield (one bit per `IpiKind`).
    pub ipi_pending: AtomicU32,
}

impl PercpuBlock {
    const fn zeroed() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Static storage for up to MAX_CPUS per-CPU blocks.
static mut PERCPU_BLOCKS: [PercpuBlock; crate::smp::MAX_CPUS] = {
    // const-init each element.
    let mut arr: [PercpuBlock; crate::smp::MAX_CPUS] =
        unsafe { core::mem::zeroed() };
    arr
};

/// Initialise per-CPU storage for `cpu_id` and install the block pointer
/// into the architecture-specific CPU register.
///
/// # Safety
/// Must be called exactly once per CPU before any other percpu access.
pub unsafe fn init(cpu_id: u32) {
    let blk = &mut PERCPU_BLOCKS[cpu_id as usize];
    blk.self_ptr = blk as *mut PercpuBlock;
    blk.cpu_id = cpu_id;
    if let Some(info) = crate::smp::cpu_info(cpu_id) {
        blk.node = info.node;
    }
    blk.intr_disable_depth = 0;
    blk.intr_was_enabled = false;
    blk.current_task = core::ptr::null_mut();
    blk.ctx_switches = 0;
    blk.ipi_pending = AtomicU32::new(0);
    blk.runqueue = crate::proc::scheduler::RunQueue::new();

    #[cfg(target_arch = "x86_64")]
    {
        // Write GSBASE MSR (0xC000_0101) with pointer to block.
        let addr = blk as *mut PercpuBlock as u64;
        let lo = addr as u32;
        let hi = (addr >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC000_0101u32,
            in("eax") lo,
            in("edx") hi,
            options(nostack, preserves_flags)
        );
    }
    #[cfg(target_arch = "riscv64")]
    {
        let addr = blk as *mut PercpuBlock as usize;
        core::arch::asm!("mv tp, {}", in(reg) addr, options(nostack));
    }
}

/// Returns the current CPU's logical id.
#[inline(always)]
pub fn current_cpu_id() -> u32 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let id: u32;
        core::arch::asm!(
            "mov {}, gs:[4]",  // offset 4 = cpu_id field
            out(reg) id,
            options(nostack, preserves_flags, readonly)
        );
        id
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let blk: *const PercpuBlock;
        core::arch::asm!("mv {}, tp", out(reg) blk, options(nostack, readonly));
        (*blk).cpu_id
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    0
}

/// Returns a raw pointer to the current CPU's PercpuBlock.
#[inline(always)]
pub fn current_block() -> *mut PercpuBlock {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let ptr: *mut PercpuBlock;
        core::arch::asm!(
            "mov {}, gs:[0]",
            out(reg) ptr,
            options(nostack, preserves_flags, readonly)
        );
        ptr
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let blk: *mut PercpuBlock;
        core::arch::asm!("mv {}, tp", out(reg) blk, options(nostack, readonly));
        blk
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    core::ptr::null_mut()
}

/// Disable interrupts and increment the nesting depth.  Returns `true` if
/// this is the outermost push (interrupts were enabled on entry).
#[inline]
pub fn push_off() -> bool {
    let blk = unsafe { &mut *current_block() };
    let was_on;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let flags: u64;
        core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nostack));
        was_on = (flags & (1 << 9)) != 0;
        core::arch::asm!("cli", options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let sstatus: usize;
        core::arch::asm!("csrrci {}, sstatus, 2", out(reg) sstatus, options(nostack));
        was_on = (sstatus & 2) != 0;
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "riscv64")))]
    { was_on = false; }
    if blk.intr_disable_depth == 0 {
        blk.intr_was_enabled = was_on;
    }
    blk.intr_disable_depth += 1;
    was_on
}

/// Decrement nesting depth; re-enable interrupts when depth reaches 0
/// if they were enabled before the outermost `push_off`.
#[inline]
pub fn pop_off() {
    let blk = unsafe { &mut *current_block() };
    assert!(blk.intr_disable_depth > 0, "pop_off underflow");
    blk.intr_disable_depth -= 1;
    if blk.intr_disable_depth == 0 && blk.intr_was_enabled {
        #[cfg(target_arch = "x86_64")]
        unsafe { core::arch::asm!("sti", options(nostack, preserves_flags)); }
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("csrsi sstatus, 2", options(nostack)); }
    }
}
