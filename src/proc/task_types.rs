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
//!   pcb:   *mut Pcb,    // 0x00  — back-pointer to the owning PCB
//!   pid:   u32,         // 0x08  — cached copy of Pcb::pid (avoids deref)
//!   _pad:  u32,         // 0x0C  — alignment padding
//!   sched: SchedEntity, // 0x10  — scheduling metadata (vruntime, cpumask …)
//! }
//! ```
//!
//! `sched` is embedded directly (not behind a pointer) so the scheduler can
//! access `task.sched.cpumask` and `task.sched.on_rq` without an extra
//! indirection.

use crate::proc::process::Pcb;
use crate::proc::scheduler::SchedEntity;

#[repr(C)]
pub struct Task {
    /// Back-pointer to the owning `Pcb`.
    pub pcb:   *mut Pcb,
    /// Cached pid — avoids an extra pointer deref in hot paths.
    pub pid:   u32,
    pub _pad:  u32,
    /// Scheduling metadata (vruntime, deadlines, cpumask, policy …).
    pub sched: SchedEntity,
}

impl Task {
    /// Construct a new `Task` for an existing `Pcb`.
    pub fn new(pcb: *mut Pcb) -> Self {
        let pid = unsafe { (*pcb).pid as u32 };
        Task {
            pcb,
            pid,
            _pad: 0,
            sched: SchedEntity::new(0),
        }
    }
}

// SAFETY: Task is sent across CPU boundaries under the scheduler lock.
unsafe impl Send for Task {}
