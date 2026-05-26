//! Process Control Block (PCB) — authoritative per-process kernel struct.
//!
//! ## Pcb / Task / ProcLock relationship
//!
//! ```text
//!   PROC_TABLE: SpinLock<Vec<Arc<ProcLock>>>
//!         │
//!         └── ProcLock { pid, tgid, state_atom, inner: Mutex<Pcb> }
//!                                                           │
//!                                                      Pcb { task: *mut Task, sched, mm_lock, … }
//!                                                           │
//!                                                      Task { pcb: *mut Pcb, pid, sched }
//! ```
//!
//! ## Locking protocol (S2 fix)
//!
//! The global `PROC_TABLE` SpinLock is held for the *shortest possible time*:
//! only to find the right `Arc<ProcLock>` and clone the Arc.  Once you hold
//! an Arc, release the table lock before touching `inner`.
//!
//! Per-process `ProcLock::inner` is a `spin::Mutex<Pcb>`.  Different PIDs
//! can be locked simultaneously without contention.
//!
//! `scheduler.rs` keeps its per-CPU `RunQueue` separately and never needs to
//! lock `PROC_TABLE` on the hot path; it accesses the task pointer directly.
//!
//! ## mm_lock (TOCTOU fix)
//!
//! `Pcb::mm_lock` is a `spin::RwLock<()>` that guards the virtual-memory
//! state of the process (`vmas`, `user_satp`, `brk`).  Two rules apply:
//!
//!   - **Writers** (`munmap`, `mmap`, `brk`, `exec`) take the write side
//!     before modifying `vmas` or remapping pages.
//!   - **Readers** (`uaccess::copy_from_user`, `copy_to_user`, `read_path`)
//!     take the read side across the entire validate+copy sequence.
//!
//! This closes the TOCTOU window where a concurrent `munmap` could unmap
//! pages between the `pages_mapped` and the actual memory copy.
//!
//! ### Deadlock-free ordering
//!
//!   1. Acquire `PROC_TABLE` lock (briefly, for lookup).
//!   2. Clone the `Arc<ProcLock>` for the target pid, then release table lock.
//!   3. Acquire `ProcLock::inner`.
//!   4. While holding `inner`, take `mm_lock` (read or write as needed).
//!   Never hold PROC_TABLE while holding any inner lock.

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
use crate::proc::scheduler::SchedEntity;
use crate::proc::task_types::Task;
use crate::security::CapSet;
use crate::security::seccomp::FilterChain;
use crate::proc::cgroup::CgroupId;
use crate::proc::cgroup::ROOT_CGROUP;

// ── State ──────────────────────────────────────────────────────────────────────────

/// Process lifecycle state.
///
/// Stored as a plain field inside `Pcb` (which is protected by `ProcLock`).
/// The `state_atom` in `ProcLock` is an `AtomicU8` copy used only by the
/// scheduler for lock-free ready checks on the hot wakeup path.
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

impl State {
    pub fn to_u8(self) -> u8 {
        match self {
            State::Ready        => 0,
            State::Running      => 1,
            State::Blocked      => 2,
            State::Zombie       => 3,
            State::Stopped      => 4,
            State::StopReported => 5,
            State::Continued    => 6,
        }
    }
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => State::Ready,
            1 => State::Running,
            2 => State::Blocked,
            3 => State::Zombie,
            4 => State::Stopped,
            5 => State::StopReported,
            6 => State::Continued,
            _ => State::Blocked,
        }
    }
}

// ── ProcLock — per-process locking unit ──────────────────────────────────────────

/// The entry stored in the global process table.
///
/// `state_atom` is a lock-free snapshot of the state for scheduler fast-paths
/// (e.g., `wake_pid` can check Blocked without taking `inner`).
/// `inner` holds the full Pcb and must be locked for any mutation.
pub struct ProcLock {
    pub pid:        u32,
    pub tgid:       u32,
    pub state_atom: core::sync::atomic::AtomicU8,
    pub inner:      Mutex<Pcb>,
}

impl ProcLock {
    pub fn new(pcb: Pcb) -> Arc<Self> {
        let state_byte = pcb.state.to_u8();
        Arc::new(ProcLock {
            pid:        pcb.pid as u32,
            tgid:       pcb.tgid as u32,
            state_atom: core::sync::atomic::AtomicU8::new(state_byte),
            inner:      Mutex::new(pcb),
        })
    }

    /// Update both the atomic snapshot and the inner state field atomically
    /// (caller must already hold `inner`).
    pub fn set_state(&self, pcb: &mut Pcb, s: State) {
        pcb.state = s;
        self.state_atom.store(
            s.to_u8(),
            core::sync::atomic::Ordering::Release,
        );
    }

    pub fn load_state(&self) -> State {
        State::from_u8(
            self.state_atom.load(core::sync::atomic::Ordering::Acquire)
        )
    }
}

// ── Pcb — per-process kernel control block ─────────────────────────────────────────

/// Full process kernel state.  Always accessed through `ProcLock::inner`.
#[derive(Clone)]
pub struct Pcb {
    // Identity
    pub pid:       usize,
    pub ppid:      usize,
    pub tgid:      usize,
    pub pgid:      usize,
    /// Session ID: pid of the session leader.  0 = not yet set (init).
    pub sid:       usize,
    pub state:     State,
    pub exit_code: i32,
    pub caps:      CapSet,

    // ── Credentials ─────────────────────────────────────────────────────────
    pub uid:  u32,
    pub gid:  u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,

    // Saved user-mode PC / SP
    pub pc: usize,
    pub sp: usize,

    // Address space
    pub user_satp: usize,

    // Virtual memory areas + mm_lock
    pub vmas:     Vec<Vma>,
    pub mm_lock:  Arc<spin::RwLock<()>>,
    pub next_va:  usize,
    pub brk_base: usize,
    pub brk:      usize,

    // Kernel stack
    pub kstack_top: usize,
    pub ctx:        Context,

    // TLS
    pub tls_base: usize,

    // ── Trampoline / trapframe (RISC-V) ──────────────────────────────────────
    /// Physical address of this process's trapframe page.
    /// Allocated by `map_trampoline_for_process` (or carved from the kstack
    /// for processes set up via `rebuild_trap_frame_riscv`).
    /// 0 on x86_64 (unused).
    pub trapframe_pa:   usize,
    /// User virtual address at which the trapframe page is mapped in this
    /// process's address space.  Equal to `TRAPFRAME_VADDR` on RISC-V.
    /// 0 on x86_64 (unused).
    pub trapframe_virt: usize,

    // clone3 / POSIX thread ABI
    pub child_tid_va:       usize,
    pub child_tid_val:      u32,
    pub clear_child_tid_va: usize,
    pub exit_signal:        u32,
    pub vfork_parent:       usize,

    // Signal handling
    pub signal_handlers: Arc<Mutex<SignalHandlers>>,
    pub pending_signals: alloc::collections::VecDeque<u32>,

    // Filesystem
    pub exe_path: Option<String>,
    /// Current working directory — absolute, canonical path.
    /// Inherited by fork/clone; updated by chdir/fchdir.
    /// Default: "/".
    pub cwd: String,

    // Namespaces / security
    pub ns:      NsSet,
    pub seccomp: FilterChain,

    // Futex / NPTL
    pub robust_list_head: usize,
    pub robust_list_len:  usize,

    // ptrace
    pub ptrace_state: PtraceState,
    pub ptrace_event: u64,

    // Resource limits
    pub rlimits: RlimitSet,

    // CPU time accounting
    /// Total CPU time = utime_ns + stime_ns (kept for legacy readers).
    pub cpu_time_ns:       u64,
    /// User-mode CPU time charged by scheduler tick().
    pub utime_ns:          u64,
    /// Kernel-mode CPU time (future CPL-aware accounting; currently 0).
    pub stime_ns:          u64,
    /// Execution-domain word — see personality(2).  0 = PER_LINUX.
    pub personality:       u32,
    pub rt_cpu_time_us:    u64,
    pub sleep_deadline_ns: u64,
    pub sleep_timer_id:    u64,

    // Scheduler fields
    pub task:  *mut Task,
    pub sched: SchedEntity,

    // ── cgroup membership ─────────────────────────────────────────────────
    pub cgroup_id: CgroupId,

    // ── Group scheduling ─────────────────────────────────────────────────
    pub tg_id: usize,

    // ── Priority inheritance ──────────────────────────────────────────────
    pub base_rt_priority: u8,

    // ── Supplemental groups ───────────────────────────────────────────────
    pub supp_groups: Vec<u32>,
}

// SAFETY: Pcb is accessed only under ProcLock::inner (spin::Mutex).
unsafe impl Send for Pcb {}
unsafe impl Sync for Pcb {}

impl Pcb {
    pub const INITIAL_NEXT_VA: usize = 0x0800_0000;
    pub const INITIAL_BRK:     usize = 0x0200_0000;

    /// Construct a zeroed Pcb.  Callers must fill in identity + arch fields.
    pub fn zeroed() -> Self {
        Self {
            pid:                 0,
            ppid:                0,
            tgid:                0,
            pgid:                0,
            sid:                 0,
            state:               State::Ready,
            exit_code:           0,
            caps:                CapSet::empty(),
            uid:                 0,
            gid:                 0,
            euid:                0,
            egid:                0,
            suid:                0,
            sgid:                0,
            pc:                  0,
            sp:                  0,
            user_satp:           0,
            vmas:                Vec::new(),
            mm_lock:             Arc::new(spin::RwLock::new(())),
            next_va:             Self::INITIAL_NEXT_VA,
            brk_base:            0,
            brk:                 Self::INITIAL_BRK,
            kstack_top:          0,
            ctx:                 Context::zero(),
            tls_base:            0,
            trapframe_pa:        0,
            trapframe_virt:      0,
            child_tid_va:        0,
            child_tid_val:       0,
            clear_child_tid_va:  0,
            exit_signal:         17,
            vfork_parent:        0,
            signal_handlers:     Arc::new(Mutex::new(SignalHandlers::default())),
            pending_signals:     alloc::collections::VecDeque::new(),
            exe_path:            None,
            cwd:                 String::from("/"),
            ns:                  NsSet::default(),
            seccomp:             FilterChain::default(),
            robust_list_head:    0,
            robust_list_len:     0,
            ptrace_state:        PtraceState::None,
            ptrace_event:        0,
            rlimits:             RlimitSet::default(),
            cpu_time_ns:         0,
            utime_ns:            0,
            stime_ns:            0,
            personality:         0,
            rt_cpu_time_us:      0,
            sleep_deadline_ns:   0,
            sleep_timer_id:      0,
            task:                core::ptr::null_mut(),
            sched:               SchedEntity::new(0),
            cgroup_id:           ROOT_CGROUP,
            tg_id:               0,
            base_rt_priority:    0,
            supp_groups:         Vec::new(),
        }
    }

    /// Fork semantics: give the child a deep copy of the signal handler table.
    pub fn fork_signal_handlers(&self) -> Arc<Mutex<SignalHandlers>> {
        let copy = self.signal_handlers.lock().clone();
        Arc::new(Mutex::new(copy))
    }

    /// Clone the mm_lock Arc so that threads in the same address space
    /// (clone(CLONE_VM)) share a single RwLock.
    #[inline]
    pub fn share_mm_lock(&self) -> Arc<spin::RwLock<()>> {
        Arc::clone(&self.mm_lock)
    }
}
