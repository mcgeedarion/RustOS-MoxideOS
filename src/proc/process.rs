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
///
/// Transitions:
///   Ready ↔ Running       — scheduler tick
///   Running → Blocked     — voluntary sleep / wait / pipe-block
///   Blocked → Ready       — wake_pid() / futex_wake / timer
///   Running → Zombie      — do_exit()
///   Running → Stopped     — SIGSTOP / ptrace-stop
///   Stopped → Ready       — SIGCONT delivered
///   Stopped → StopReported— waitpid(WUNTRACED) harvested the stop event
///   StopReported → Ready  — SIGCONT delivered after report was consumed
///   Ready   → Continued   — notify_continue() marks SIGCONT resume
///   Continued → Ready     — waitpid(WCONTINUED) consumed the event
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Ready,
    Running,
    Blocked,
    Zombie,
    /// Process stopped by SIGSTOP / SIGTSTP / ptrace; not yet reported to parent.
    Stopped,
    /// Stop was already reported via waitpid(WUNTRACED); waiting for SIGCONT.
    StopReported,
    /// Process was resumed by SIGCONT; not yet reported to parent via WCONTINUED.
    Continued,
}

/// Per-process kernel control block.
#[derive(Clone)]
pub struct Pcb {
    // Identity
    pub pid:       usize,
    pub ppid:      usize,
    /// Thread-group id. Equals `pid` for the main thread / fork child.
    /// Shared across all clone(CLONE_THREAD) threads in the same process.
    pub tgid:      usize,
    /// Process group id.  Set to pid on fork; changed by setpgrp/setpgid.
    /// Used by wait4(-pgid, …) to match children in the same process group.
    pub pgid:      usize,
    pub state:     State,
    /// Pre-encoded wait-status bits (see wait.rs for layout).
    /// Set by encode_exit() on normal exit, encode_signal() on kill,
    /// encode_stop() on stop, WSTATUS_CONTINUED on continue.
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

    // ── TLS ────────────────────────────────────────────────────────────────
    pub tls_base: usize,

    // clone3 / POSIX thread ABI fields
    pub child_tid_va:  usize,
    pub child_tid_val: u32,
    pub clear_child_tid_va: usize,
    pub exit_signal: u32,
    pub vfork_parent: usize,
    pub signal_handlers: SignalHandlers,
    pub pending_signals: alloc::collections::VecDeque<u32>,
    pub exe_path: Option<String>,

    // ── Namespace set ──────────────────────────────────────────────────────
    pub ns: NsSet,

    // ── seccomp filter chain ───────────────────────────────────────────────
    pub seccomp: FilterChain,

    // ── NPTL / robust futex ───────────────────────────────────────────────
    pub robust_list_head: usize,
    pub robust_list_len:  usize,

    // ── ptrace ────────────────────────────────────────────────────────────
    pub ptrace_state: PtraceState,
    pub ptrace_event: u64,

    // ── resource limits ───────────────────────────────────────────────────
    pub rlimits: RlimitSet,

    // ── CPU time accounting ───────────────────────────────────────────────
    /// Accumulated CPU time in nanoseconds.  Incremented once per timer tick
    /// while this process is Running.  Reported via getrusage / wait4 rusage.
    pub cpu_time_ns: u64,

    // ── RT CPU time accounting (RLIMIT_RTTIME) ────────────────────────────
    pub rt_cpu_time_us: u64,

    // ── nanosleep / timer blocking ────────────────────────────────────────
    pub sleep_deadline_ns: u64,
    pub sleep_timer_id: u64,
}

impl Pcb {
    pub const INITIAL_NEXT_VA: usize = 0x0800_0000;
    pub const INITIAL_BRK:     usize = 0x0200_0000;
}
