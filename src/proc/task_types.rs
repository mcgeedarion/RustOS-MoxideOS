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
//!   pcb:         *mut Pcb,    // 0x00  — back-pointer to the owning PCB
//!   pid:         u32,         // 0x08  — cached copy of Pcb::pid
//!   _pad:        u32,         // 0x0C  — alignment padding
//!   sched:       SchedEntity, // 0x10  — scheduling metadata
//!   run_state:   TaskRunState // —     — cold-start vs. resume discriminant
//!   cpu_time_ns: u64          // —     — per-thread CPU time
//! }
//! ```
//!
//! `sched` is embedded directly so the scheduler can access
//! `task.sched.cpumask` and `task.sched.on_rq` without an extra indirection.

use crate::proc::process::Pcb;
use crate::proc::scheduler::SchedEntity;

/// Lifecycle state of a task's CPU context.
///
/// The scheduler matches on this to decide whether to call
/// `context::switch` or `context::restore`.
#[derive(Clone, Debug)]
pub enum TaskRunState {
    /// Task has never been scheduled. Contains the initial user-mode
    /// program counter and stack pointer to use on first entry.
    Cold {
        /// Initial user-mode instruction pointer.
        pc: usize,
        /// Initial user-mode stack pointer.
        sp: usize,
    },
    /// Task has run at least once.
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

    /// Scheduling metadata.
    pub sched: SchedEntity,

    /// Whether this task needs first-time entry or a normal context switch.
    pub run_state: TaskRunState,

    /// CPU time charged to this task/thread, in nanoseconds.
    pub cpu_time_ns: u64,
}

impl Task {
    /// Construct a new `Task` for an existing `Pcb`.
    pub fn new(pcb: *mut Pcb) -> Self {
        let (pid, pc, sp) = unsafe { ((*pcb).pid as u32, (*pcb).pc, (*pcb).sp) };

        Task {
            pcb,
            pid,
            _pad: 0,
            sched: SchedEntity::new(0),
            run_state: TaskRunState::Cold { pc, sp },
            cpu_time_ns: 0,
        }
    }

    /// Mark this task as live after its first context switch completes.
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
