//! Minimal `Task` type used by the scheduler and context switcher.
//!
//! The scheduler (`scheduler.rs`) and context switcher (`context.rs`) operate
//! on `*mut Task` pointers.  This crate-internal struct is intentionally thin:
//! it holds only the fields those two modules need without pulling in all of
//! `Pcb`'s heavyweight dependencies.
//!
//! ## Layout
//!
//! ```text
//! Task  {                           // repr(C), 8-byte aligned
//!   pcb:       *mut Pcb,   // 0x00  — back-pointer to the owning PCB
//!   pid:       u32,        // 0x08  — cached copy of Pcb::pid (avoids deref)
//!   _pad:      u32,        // 0x0C  — alignment padding
//!   sched:     SchedEntity,// 0x10  — scheduling metadata (vruntime, cpumask …)
//!   run_state: TaskRunState// —     — cold-start vs. resume discriminant
//! }
//! ```
//!
//! `sched` is embedded directly (not behind a pointer) so the scheduler can
//! access `task.sched.cpumask` and `task.sched.on_rq` without an extra
//! indirection.
//!
//! ## TaskRunState
//!
//! Tracks whether this task has ever been scheduled before:
//!
//! - `Cold { pc, sp }` — task has never run.  `schedule()` must call
//!   `context::restore()` (or the arch first-time entry trampoline), not
//!   `context::switch()`.  The stored `pc`/`sp` are the initial user-mode
//!   instruction and stack pointers.
//!
//! - `Live` — task has been scheduled at least once.  Its `Pcb::ctx` holds a
//!   valid saved register file.  `schedule()` calls `context::switch()`.
//!
//! This replaces the previous implicit convention where a zeroed `ctx` meant
//! "never scheduled", which the switcher worked around by allocating a dummy
//! `Context` on the stack and immediately abandoning it.

use crate::proc::process::Pcb;
use crate::proc::scheduler::SchedEntity;

/// Lifecycle state of a task's CPU context.
///
/// The scheduler matches on this to decide whether to call
/// `context::switch` (resume a live task) or `context::restore`
/// (enter a brand-new task for the first time).
#[derive(Clone, Debug)]
pub enum TaskRunState {
    /// Task has never been scheduled.  Contains the initial user-mode
    /// program counter and stack pointer to use on first entry.
    Cold {
        /// Initial user-mode instruction pointer (entry point).
        pc: usize,
        /// Initial user-mode stack pointer (top of user stack).
        sp: usize,
    },
    /// Task has run at least once.  `Pcb::ctx` holds a valid saved context.
    Live,
}

impl Default for TaskRunState {
    fn default() -> Self {
        TaskRunState::Live
    }
}

#[repr(C)]
pub struct Task {
    /// Back-pointer to the owning `Pcb`.
    pub pcb: *mut Pcb,
    /// Cached pid — avoids an extra pointer deref in hot paths.
    pub pid: u32,
    pub _pad: u32,
    /// Scheduling metadata (vruntime, deadlines, cpumask, policy …).
    pub sched: SchedEntity,
    /// Whether this task needs first-time entry or a normal context switch.
    pub run_state: TaskRunState,
}

impl Task {
    /// Construct a new `Task` for an existing `Pcb`.
    ///
    /// Newly constructed tasks always start as `Cold` — they carry
    /// `pc`/`sp` from the `Pcb` and will transition to `Live` on
    /// their first context switch.
    pub fn new(pcb: *mut Pcb) -> Self {
        let (pid, pc, sp) = unsafe { ((*pcb).pid as u32, (*pcb).pc, (*pcb).sp) };
        Task {
            pcb,
            pid,
            _pad: 0,
            sched: SchedEntity::new(0),
            run_state: TaskRunState::Cold { pc, sp },
        }
    }

    /// Mark this task as live after its first context switch completes.
    ///
    /// Called by `context::restore()` just before jumping to user mode
    /// so that subsequent preemptions use `context::switch()`.
    #[inline]
    pub fn mark_live(&mut self) {
        self.run_state = TaskRunState::Live;
    }

    /// Returns `true` if this task has never been scheduled before.
    #[inline]
    pub fn is_cold(&self) -> bool {
        matches!(self.run_state, TaskRunState::Cold { .. })
    }
}

// SAFETY: Task is sent across CPU boundaries under the scheduler lock.
unsafe impl Send for Task {}
