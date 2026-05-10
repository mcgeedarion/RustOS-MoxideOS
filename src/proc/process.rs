//! Process Control Block (PCB) — authoritative per-process kernel struct.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::sync::Arc;
use spin::Mutex;
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
pub enum State {
    Ready,
    Running,
    Blocked,
    Zombie,
    Stopped,
    StopReported,
    Continued,
}

/// Per-process kernel control block.
///
/// `signal_handlers` is wrapped in `Arc<Mutex<…>>` so that threads created
/// with `CLONE_SIGHAND` share a single handler table.  A plain `clone()` of
/// the Pcb (used for fork/vfork) clones the Arc — giving the child its own
/// independent copy of the table — because we immediately call
/// `Arc::new(Mutex::new((**p.signal_handlers.lock()).clone()))` in the fork
/// path.  For `CLONE_SIGHAND` clones we share the existing Arc.
#[derive(Clone)]
pub struct Pcb {
    // Identity
    pub pid:       usize,
    pub ppid:      usize,
    pub tgid:      usize,
    pub pgid:      usize,
    pub state:     State,
    pub exit_code: i32,
    pub caps:      CapSet,

    // Saved user-mode PC / SP
    pub pc: usize,
    pub sp: usize,

    // Address space
    pub user_satp: usize,

    // Virtual memory management
    pub vmas:     Vec<Vma>,
    pub next_va:  usize,
    pub brk_base: usize,
    pub brk:      usize,

    // Kernel stack
    pub kstack_top: usize,
    pub ctx:        Context,

    // TLS
    pub tls_base: usize,

    // clone3 / POSIX thread ABI
    pub child_tid_va:        usize,
    pub child_tid_val:       u32,
    pub clear_child_tid_va:  usize,
    pub exit_signal:         u32,
    pub vfork_parent:        usize,

    /// Shared signal handler table.
    /// - fork / vfork: child gets a *deep copy* (new Arc) — independent table.
    /// - CLONE_SIGHAND threads: share the *same* Arc — mutations visible to all.
    pub signal_handlers: Arc<Mutex<SignalHandlers>>,

    /// Per-thread pending signal queue (low-level, rarely used;
    /// process-wide queue lives in signal::PENDING).
    pub pending_signals: alloc::collections::VecDeque<u32>,

    pub exe_path: Option<String>,
    pub ns:       NsSet,
    pub seccomp:  FilterChain,

    pub robust_list_head: usize,
    pub robust_list_len:  usize,

    pub ptrace_state: PtraceState,
    pub ptrace_event: u64,

    pub rlimits: RlimitSet,

    pub cpu_time_ns:       u64,
    pub rt_cpu_time_us:    u64,
    pub sleep_deadline_ns: u64,
    pub sleep_timer_id:    u64,
}

impl Pcb {
    pub const INITIAL_NEXT_VA: usize = 0x0800_0000;
    pub const INITIAL_BRK:     usize = 0x0200_0000;

    /// Construct a Pcb with all zero/default fields.
    /// Callers must fill in at minimum: pid, ppid, tgid, pgid, user_satp,
    /// kstack_top, ctx, pc, sp.
    pub fn zeroed() -> Self {
        Self {
            pid:                 0,
            ppid:                0,
            tgid:                0,
            pgid:                0,
            state:               State::Ready,
            exit_code:           0,
            caps:                CapSet::empty(),
            pc:                  0,
            sp:                  0,
            user_satp:           0,
            vmas:                Vec::new(),
            next_va:             Self::INITIAL_NEXT_VA,
            brk_base:            0,
            brk:                 Self::INITIAL_BRK,
            kstack_top:          0,
            ctx:                 Context::zero(),
            tls_base:            0,
            child_tid_va:        0,
            child_tid_val:       0,
            clear_child_tid_va:  0,
            exit_signal:         17,
            vfork_parent:        0,
            signal_handlers:     Arc::new(Mutex::new(SignalHandlers::default())),
            pending_signals:     alloc::collections::VecDeque::new(),
            exe_path:            None,
            ns:                  NsSet::default(),
            seccomp:             FilterChain::default(),
            robust_list_head:    0,
            robust_list_len:     0,
            ptrace_state:        PtraceState::None,
            ptrace_event:        0,
            rlimits:             RlimitSet::default(),
            cpu_time_ns:         0,
            rt_cpu_time_us:      0,
            sleep_deadline_ns:   0,
            sleep_timer_id:      0,
        }
    }

    /// Fork semantics: give the child a deep copy of the signal handler table
    /// (independent from the parent's future sigaction calls).
    pub fn fork_signal_handlers(&self) -> Arc<Mutex<SignalHandlers>> {
        let copy = self.signal_handlers.lock().clone();
        Arc::new(Mutex::new(copy))
    }
}
