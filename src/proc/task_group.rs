//! CFS Group Scheduling.
//!
//! ## Design
//!
//! Group scheduling adds a two-level CFS hierarchy:
//!
//! ```text
//!  Per-CPU RunQueue (level 0)
//!    ├─ dl_heap      — SCHED_DEADLINE tasks (unchanged)
//!    ├─ rt_queue     — SCHED_FIFO / SCHED_RR tasks (unchanged)
//!    ├─ cfs_heap     — SCHED_NORMAL tasks NOT in a group  (tg_id == 0)
//!    │                 AND group SchedEntities (one per active TaskGroup)
//!    ├─ batch_heap   — SCHED_BATCH tasks not in a group
//!    └─ idle_queue   — SCHED_IDLE tasks
//!
//!  TaskGroup (level 1)
//!    └─ per-cpu GroupRq
//!         └─ inner_heap  — CfsEntry for each task in this group on this CPU
//! ```
//!
//! When a task with `tg_id != 0` is enqueued:
//!   1. It is placed in its group's per-CPU `inner_heap`.
//!   2. If the group's `SchedEntity` is not already on the top-level
//!      `cfs_heap`, a `CfsEntry` for the group SE is inserted there.
//!
//! When the top-level `dequeue_cfs` picks a group SE:
//!   1. The group's `group_dequeue_next()` selects the lowest-vruntime
//!      task from the group's inner heap.
//!   2. The group SE's vruntime is advanced by
//!      `delta * NICE0_WEIGHT / group_weight`, giving weight-proportional
//!      share among groups.
//!   3. If the inner heap is still non-empty, the group SE is re-inserted
//!      into the top-level heap with its updated vruntime.
//!
//! ## Weight
//!
//! `TaskGroup::weight` is a u64 in the same scale as task weights
//! (NICE0_WEIGHT = 1024 = 100% share).  Setting a group's weight to 512
//! gives it half the CPU share of a weight-1024 group when both are
//! runnable.
//!
//! The default weight for a new group is `NICE0_WEIGHT` (equal share).
//!
//! ## Thread safety
//!
//! `TASK_GROUPS` is a `SpinLock<BTreeMap<...>>`.  The per-CPU `GroupRq`
//! fields are accessed only by the scheduler on the owning CPU (same
//! invariant as `RunQueue`), so they carry no additional lock.

extern crate alloc;
use alloc::collections::BinaryHeap;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use spin::Mutex;

use crate::proc::scheduler::{CfsEntry, NICE0_WEIGHT, BATCH_WEIGHT_CAP, SchedPolicy};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of CPUs a GroupRq array covers.
pub const MAX_GROUP_CPUS: usize = 64;

/// Group id 0 is reserved for "no group" / root cgroup.
pub const ROOT_TG_ID: usize = 0;

// ── GroupRq — per-CPU inner run queue for one TaskGroup ───────────────────────

/// Per-CPU inner CFS queue for tasks belonging to one `TaskGroup`.
///
/// Only accessed on the owning CPU (same guarantee as `RunQueue`), so no
/// extra lock is needed.
pub struct GroupRq {
    /// Min-heap of tasks in this group on this CPU, ordered by vruntime.
    pub inner_heap: BinaryHeap<CfsEntry>,
    /// Minimum vruntime seen among tasks that have been dequeued from this
    /// group on this CPU.  New tasks that re-enter the group are clamped to
    /// this value so they don't consume a burst of "catch-up" CPU time.
    pub min_vruntime: u64,
    /// True when the group's SchedEntity is currently on the top-level
    /// cfs_heap for this CPU.  Prevents double-insertion.
    pub on_top_rq: bool,
}

unsafe impl Send for GroupRq {}

impl GroupRq {
    pub const fn new() -> Self {
        GroupRq {
            inner_heap: BinaryHeap::new(),
            min_vruntime: 0,
            on_top_rq: false,
        }
    }

    /// Enqueue `task` into this group's inner heap.
    pub fn enqueue(&mut self, task: *mut crate::proc::task_types::Task) {
        let t = unsafe { &mut *task };
        if t.sched.vruntime < self.min_vruntime {
            t.sched.vruntime = self.min_vruntime;
        }
        self.inner_heap.push(CfsEntry {
            vruntime: t.sched.vruntime,
            pid:      t.pid,
            task_ptr: task,
        });
    }

    /// Dequeue the lowest-vruntime task from this group.
    /// Returns `None` if the inner heap is empty.
    pub fn dequeue_next(&mut self) -> Option<*mut crate::proc::task_types::Task> {
        self.inner_heap.pop().map(|e| {
            let t = unsafe { &mut *e.task_ptr };
            t.sched.on_rq = false;
            if t.sched.vruntime > self.min_vruntime {
                self.min_vruntime = t.sched.vruntime;
            }
            e.task_ptr
        })
    }

    /// Remove a specific pid from the inner heap.
    /// Returns true if the pid was found and removed.
    pub fn remove_pid(&mut self, pid: u32) -> bool {
        let old: alloc::vec::Vec<CfsEntry> =
            core::mem::take(&mut self.inner_heap).into_vec();
        let mut found = false;
        for e in old {
            if e.pid == pid {
                let t = unsafe { &mut *e.task_ptr };
                t.sched.on_rq = false;
                found = true;
            } else {
                self.inner_heap.push(e);
            }
        }
        found
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner_heap.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.inner_heap.len()
    }
}

// ── TaskGroup ─────────────────────────────────────────────────────────────────

/// A CFS scheduling group.  Corresponds to a cgroup `cpu` subsystem entry.
///
/// Each group has:
/// - a unique `id` (non-zero; 0 is reserved for the root/ungrouped class)
/// - a `weight` (same scale as task nice weights; default = NICE0_WEIGHT)
/// - a `vruntime` per-CPU group SchedEntity (stored in `grq[cpu].vruntime_se`)
/// - a per-CPU `GroupRq` holding the inner task heap
pub struct TaskGroup {
    pub id:     usize,
    /// Scheduling weight (NICE0_WEIGHT = 1024 = equal share).
    pub weight: u64,
    /// Group-level vruntime, one entry per CPU.  The scheduler advances
    /// this by `elapsed * NICE0_WEIGHT / weight` each time a task from this
    /// group runs, giving weight-proportional CPU allocation.
    pub vruntime: [u64; MAX_GROUP_CPUS],
    /// Per-CPU inner run queues.
    pub grq: [GroupRq; MAX_GROUP_CPUS],
}

// SAFETY: TaskGroup is stored behind Arc<Mutex<...>> and only accessed under
// that lock or on the owning CPU (grq fields).
unsafe impl Send for TaskGroup {}
unsafe impl Sync for TaskGroup {}

impl TaskGroup {
    /// Create a new group with the given id and default weight.
    pub fn new(id: usize) -> Self {
        // GroupRq and vruntime arrays must be initialised element-by-element
        // because GroupRq is not Copy.
        let grq = core::array::from_fn(|_| GroupRq::new());
        TaskGroup {
            id,
            weight: NICE0_WEIGHT,
            vruntime: [0u64; MAX_GROUP_CPUS],
            grq,
        }
    }

    /// Set this group's CPU weight.  Clamped to [1, CBS_SCALE].
    pub fn set_weight(&mut self, w: u64) {
        self.weight = w.clamp(1, 1u64 << 32);
    }
}

// ── Global task-group table ───────