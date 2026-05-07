//! Process Control Block (PCB) — authoritative per-process kernel struct.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use crate::mm::mmap::Vma;
use crate::proc::context::Context;
use crate::proc::fork::SignalHandlers;
use crate::proc::namespace::NsSet;
use crate::security::CapSet;
use crate::security::seccomp::FilterChain;

/// Process lifecycle state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State { Ready, Running, Blocked, Zombie }

/// Per-process kernel control block.
#[derive(Clone)]
pub struct Pcb {
    // Identity
    pub pid:       usize,
    pub ppid:      usize,
    /// Thread-group id. Equals `pid` for the main thread / fork child.
    /// Shared across all clone(CLONE_THREAD) threads in the same process.
    pub tgid:      usize,
    pub state:     State,
    pub exit_code: i32,
    pub caps:      CapSet,

    // Saved user-mode PC / SP (mirrors SyscallFrame on kstack)
    pub pc: usize,
    pub sp: usize,

    // Address space (CR3 physical address)
    pub user_satp: usize,

    // Virtual memory management
    /// Virtual Memory Areas: sorted by start address.
    pub vmas:    Vec<Vma>,
    /// Next free virtual address for anonymous mmap allocations.
    pub next_va: usize,
    /// Current program break (top of heap).
    pub brk:     usize,

    // Kernel stack
    pub kstack_top: usize,
    pub ctx:        Context,

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

    /// Path of the executable image currently running in this process.
    /// Set by exec, inherited across fork/clone, used by /proc/<pid>/exe.
    /// None for kernel threads or before the first successful execve.
    pub exe_path: Option<String>,

    // ── Namespace set ────────────────────────────────────────────────────────
    /// Linux namespace memberships (mount, pid, net, uts, ipc, user, time).
    /// Inherited from parent on fork; individual types may be unshared via
    /// unshare(2) / clone(CLONE_NEW*).
    pub ns: NsSet,

    // ── seccomp filter chain ─────────────────────────────────────────────────
    /// cBPF filter programs installed by seccomp(2).
    /// Empty chain = no filtering.  strict = SECCOMP_SET_MODE_STRICT.
    /// Inherited (copied) into fork/clone children.
    pub seccomp: FilterChain,

    // ── NPTL / robust futex ─────────────────────────────────────────────────
    /// User-VA of the robust_list_head registered by set_robust_list(2).
    /// 0 = not registered.
    pub robust_list_head: usize,
    /// Byte length of the robust list head struct (16 or 24).
    pub robust_list_len:  usize,
}

impl Pcb {
    /// Initial `next_va` for new processes: 128 MiB into user space.
    pub const INITIAL_NEXT_VA: usize = 0x0800_0000;
    /// Initial `brk` for new processes: 32 MiB into user space.
    pub const INITIAL_BRK:     usize = 0x0200_0000;
}
