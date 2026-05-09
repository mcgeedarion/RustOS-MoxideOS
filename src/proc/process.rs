//! Process Control Block (PCB) — authoritative per-process kernel struct.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use crate::mm::mmap::Vma;
use crate::proc::context::Context;
use crate::proc::fork::SignalHandlers;
use crate::proc::namespace::NsSet;
use crate::proc::ptrace::PtraceState;
use crate::proc::rlimit::RlimitSet;
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

    // Address space (CR3 / satp physical address)
    pub user_satp: usize,

    // Virtual memory management
    /// Virtual Memory Areas: sorted by start address.
    pub vmas:    Vec<Vma>,
    /// Next free virtual address for anonymous mmap allocations.
    pub next_va: usize,
    /// Base of the heap: first page-aligned address above the ELF image.
    pub brk_base: usize,
    /// Current program break (top of heap).  Always >= brk_base.
    pub brk:     usize,

    // Kernel stack
    pub kstack_top: usize,
    pub ctx:        Context,

    // ── TLS ───────────────────────────────────────────────────────────────────
    pub tls_base: usize,

    // clone3 / POSIX thread ABI fields
    pub child_tid_va:  usize,
    pub child_tid_val: u32,
    pub clear_child_tid_va: usize,
    pub exit_signal: u32,
    pub vfork_parent: usize,
    pub signal_handlers: SignalHandlers,
    pub exe_path: Option<String>,

    // ── Namespace set ────────────────────────────────────────────────────────────────
    pub ns: NsSet,

    // ── seccomp filter chain ─────────────────────────────────────────────────────
    pub seccomp: FilterChain,

    // ── NPTL / robust futex ──────────────────────────────────────────────────────
    pub robust_list_head: usize,
    pub robust_list_len:  usize,

    // ── ptrace ───────────────────────────────────────────────────────────────
    pub ptrace_state: PtraceState,
    pub ptrace_event: u64,

    // ── resource limits ───────────────────────────────────────────────────────
    /// Per-process resource limits.  Inherited on fork; shared across
    /// CLONE_THREAD threads (both get a clone, Linux semantics are identical).
    pub rlimits: RlimitSet,

    // ── CPU time accounting (for RLIMIT_CPU) ───────────────────────────────
    /// Accumulated CPU time in nanoseconds.  Incremented once per timer tick
    /// (TICK_NS = 1 ms) while this process is the running task.
    /// Compared in seconds against the RLIMIT_CPU soft/hard limits:
    ///   soft  → SIGXCPU delivered every second until the process exits or
    ///            raises its limit (POSIX allows an implementation-defined
    ///            grace period; we use 1-second intervals matching Linux).
    ///   hard  → SIGKILL sent immediately.
    pub cpu_time_ns: u64,
}

impl Pcb {
    pub const INITIAL_NEXT_VA: usize = 0x0800_0000;
    pub const INITIAL_BRK:     usize = 0x0200_0000;
}
