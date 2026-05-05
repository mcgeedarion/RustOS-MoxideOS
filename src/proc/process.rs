//! Process Control Block (PCB) — authoritative per-process kernel struct.

extern crate alloc;
use alloc::vec::Vec;
use crate::mm::mmap::Vma;
use crate::proc::context::Context;
use crate::proc::fork::SignalHandlers;
use crate::security::CapSet;

/// Process lifecycle state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State { Ready, Running, Blocked, Zombie }

/// Per-process kernel control block.
#[derive(Clone)]
pub struct Pcb {
    // Identity
    pub pid:       usize,
    pub ppid:      usize,
    pub state:     State,
    pub exit_code: i32,
    pub caps:      CapSet,

    // Saved user-mode PC / SP (mirrors SyscallFrame on kstack)
    pub pc: usize,
    pub sp: usize,

    // Address space (CR3 / SATP physical addresses)
    pub user_satp:    usize,
    pub kernel_satp:  usize,
    pub trapframe_pa: usize,

    // Virtual memory management (per-process — no global hash table needed)
    /// Virtual Memory Areas: sorted by start address.
    pub vmas:    Vec<Vma>,
    /// Next free virtual address for anonymous mmap allocations.
    pub next_va: usize,
    /// Current program break (top of heap).
    pub brk:     usize,

    // Kernel stack
    pub kstack_top:  usize,
    pub ctx:         Context,
    pub owned_pages: Vec<usize>,

    // clone3 / POSIX thread ABI fields
    /// CLONE_CHILD_SETTID: write pid here on first run. Zeroed after write.
    pub child_tid_va:  usize,
    pub child_tid_val: u32,
    /// CLONE_CHILD_CLEARTID / set_tid_address: zero + futex_wake on exit.
    pub clear_child_tid_va: usize,
    /// Signal to send parent on exit (default SIGCHLD = 17).
    pub exit_signal: u32,
    /// CLONE_VFORK: pid of parent to unsuspend on exec/exit. 0 = none.
    pub vfork_parent: usize,
    /// Per-process signal dispatch table.
    pub signal_handlers: SignalHandlers,
}

impl Pcb {
    /// Initial `next_va` for new processes: 128 MiB into user space.
    pub const INITIAL_NEXT_VA: usize = 0x0800_0000;
    /// Initial `brk` for new processes: 32 MiB into user space.
    pub const INITIAL_BRK:     usize = 0x0200_0000;
}
