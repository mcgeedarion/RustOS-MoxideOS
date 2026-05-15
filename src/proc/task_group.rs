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
//!    ├─ cfs_heap     — ungrouped SCHED_NORMAL tasks (tg_id == 0)
//!    │                 AND one GroupSe entry per active TaskGroup
//!    ├─ batch_heap   — SCHED_BATCH tasks not in a group
//!    └─ idle_queue   — SCHED_IDLE tasks
//!
//!  TaskGroup (level 1)
//!    └─ per-CPU GroupRq
//!         └─ inner_heap  — CfsEntry for each task in this group on this CPU
//! ```
//!
//! ### Enqueue
//! When a task with `tg_id != 0` is enqueued:
//!   1. The task is placed in `group.grq[cpu].inner_heap`.
//!   2. If `grq[cpu].on_top_rq == false`, a sentinel `CfsEntry` whose
//!      `task_ptr` is `null` and whose `vruntime` is the group's current
//!      `vruntime[cpu]` is pushed onto the top-level `cfs_heap`, and
//!      `on_top_rq` is set to true.
//!
//! ### Dequeue (top-level)
//! When `dequeue_cfs` pops a `CfsEntry` with `task_ptr == null`, it calls
//! `group_dequeue_next(tg_id, cpu)` which:
//!   1. Locks the group, pops the lowest-vruntime task from `grq[cpu]`.
//!   2. Advances `group.vruntime[cpu]` by `elapsed * NICE0_WEIGHT / weight`.
//!   3. If the inner heap is still non-empty, re-inserts the group sentinel
//!      with the updated vruntime so the group competes again next tick.
//!   4. Returns the concrete task pointer to the caller.
//!
//! ## Weight
//!
//! `TaskGroup::weight` uses the same scale as task nice weights
//! (NICE0_WEIGHT = 1024 ≡ 100% share).  A group with weight 512 receives
//! half the CPU time of a weight-1024 group when both are runnable.
//!
//! ## Thread safety
//!
//! `TASK_GROUPS` is a `Mutex<BTreeMap<usize, Arc<Mutex<TaskGroup>>>>`.
//! The inner `Mutex<TaskGroup>` is held only briefly for enqueue/dequeue;
//! `grq` fields are guarded by the per-CPU scheduler invariant (only the
//! owning CPU touches them while holding no cross-CPU lock).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::collections::BinaryHeap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

pub use crate::proc::scheduler::{CfsEntry, SchedPolicy, NICE0_WEIGHT};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of CPUs a GroupRq array covers.
pub const MAX_GROUP_CPUS: usize = 64;

/// Group id 0 is reserved for "no group" / root cgroup.
pub const ROOT_TG_ID: usize = 0;

/// Sentinel task_ptr value used in top-level cfs_heap entries that represent
/// a group (not a concrete task).  The scheduler detects this and calls
/// group_dequeue_next() instead of running the pointer directly.
pub const GROUP_SENTINEL: *mut crate::proc::task_types::Task = core::ptr::null_mut();

// ── GroupRq ─────────────────────────────────────────────────────────────────

/// Per-CPU inner CFS queue for tasks belonging to one `TaskGroup`.
pub struct GroupRq {
    /// Min-heap of tasks in this group on this CPU, keyed by vruntime.
    pub inner_heap: BinaryHeap<CfsEntry>,
    /// Minimum vruntime of tasks dequeued from this group on this CPU.
    /// Newly-woken tasks are clamped to this floor to prevent burst
    /// catch-up after sleeping.
    pub min_vruntime: u64,
    /// True while the group sentinel is in the top-level cfs_heap.
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

    /// Insert `task` into this group's inner heap.
    pub fn enqueue(&mut self, task: *mut crate::proc::task_types::Task) {
        let t = unsafe { &mut *task };
        if t.sched.vruntime < self.min_vruntime {
            t.sched.vruntime = self.min_vruntime;
        }
        self.inner_heap.push(CfsEntry {
            vruntime: t.sched.vruntime,
            pid: t.pid,
            task_ptr: task,
        });
    }

    /// Pop the lowest-vruntime task from this group.
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

    /// Remove a specific `pid`.  Returns true if found.
    pub fn remove_pid(&mut self, pid: u32) -> bool {
        let old: Vec<CfsEntry> = core::mem::take(&mut self.inner_heap).into_vec();
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

/// A CFS scheduling group.  Corresponds to a cpu-cgroup.
///
/// - `id`      : unique non-zero group identifier
/// - `weight`  : scheduling weight (NICE0_WEIGHT = 1024 = 100% share)
/// - `vruntime`: group-level virtual runtime, one slot per CPU
/// - `grq`     : per-CPU inner run queues
pub struct TaskGroup {
    pub id: usize,
    pub weight: u64,
    pub vruntime: [u64; MAX_GROUP_CPUS],
    pub grq: [GroupRq; MAX_GROUP_CPUS],
}

unsafe impl Send for TaskGroup {}
unsafe impl Sync for TaskGroup {}

impl TaskGroup {
    pub fn new(id: usize) -> Self {
        TaskGroup {
            id,
            weight: NICE0_WEIGHT,
            vruntime: [0u64; MAX_GROUP_CPUS],
            grq: core::array::from_fn(|_| GroupRq::new()),
        }
    }

    /// Set this group's CPU share weight.  Clamped to [1, 2^32].
    pub fn set_weight(&mut self, w: u64) {
        self.weight = w.clamp(1, 1u64 << 32);
    }
}

// ── Global task-group table ────────────────────────────────────────────────

/// Global registry of all TaskGroups.
/// Key = tg_id.  Value = Arc<Mutex<TaskGroup>>.
static TASK_GROUPS: Mutex<BTreeMap<usize, Arc<Mutex<TaskGroup>>>> = Mutex::new(BTreeMap::new());

/// Monotonically-increasing group id allocator.
static NEXT_TG_ID: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(1);

/// Allocate a fresh task group id.
pub fn alloc_tg_id() -> usize {
    NEXT_TG_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// Create a new task group and register it in TASK_GROUPS.
/// Returns the new `tg_id`.
pub fn create_task_group() -> usize {
    let id = alloc_tg_id();
    let tg = Arc::new(Mutex::new(TaskGroup::new(id)));
    TASK_GROUPS.lock().insert(id, tg);
    id
}

/// Look up a TaskGroup by id.
/// Returns None if the group does not exist.
pub fn find_task_group(tg_id: usize) -> Option<Arc<Mutex<TaskGroup>>> {
    TASK_GROUPS.lock().get(&tg_id).cloned()
}

/// Destroy a task group.  Safe to call even if tasks still reference the id;
/// they will fall back to ungrouped scheduling on next enqueue.
pub fn destroy_task_group(tg_id: usize) {
    TASK_GROUPS.lock().remove(&tg_id);
}

// ── Scheduler integration helpers ──────────────────────────────────────────────

/// Enqueue `task` (which has `tg_id != 0`) into its group's inner heap.
///
/// If the group's sentinel is not currently on the top-level `cfs_heap`,
/// returns `Some(CfsEntry)` — the caller must push that entry onto the
/// top-level heap.
///
/// Returns `None` if the sentinel is already on the top-level heap
/// (group is already represented there; nothing more to do).
pub fn group_enqueue(
    task: *mut crate::proc::task_types::Task,
    tg_id: usize,
    cpu: u32,
) -> Option<CfsEntry> {
    let tg_arc = find_task_group(tg_id)?;
    let mut tg = tg_arc.lock();
    let cpu = (cpu as usize).min(MAX_GROUP_CPUS - 1);
    tg.grq[cpu].enqueue(task);
    if tg.grq[cpu].on_top_rq {
        // Sentinel already present on top-level heap.
        return None;
    }
    // Build and return the sentinel entry for this group.
    tg.grq[cpu].on_top_rq = true;
    Some(CfsEntry {
        vruntime: tg.vruntime[cpu],
        // pid == 0 + task_ptr == null → group sentinel convention.
        pid: tg_id as u32,
        task_ptr: GROUP_SENTINEL,
    })
}

/// Called by the top-level `dequeue_cfs` when it pops a group sentinel entry.
///
/// 1. Pops the lowest-vruntime task from `grq[cpu].inner_heap`.
/// 2. Advances `group.vruntime[cpu]` proportionally to group weight so
///    heavier groups run more.
/// 3. If the inner heap is still non-empty, returns a new sentinel `CfsEntry`
///    with the updated vruntime so the group re-enters the top-level heap.
/// 4. Returns the concrete task pointer (or `null` if the inner heap was
///    already empty — caller should skip this slot).
pub struct GroupDequeueResult {
    /// The concrete task to run.  Null if the group inner heap was empty.
    pub task: *mut crate::proc::task_types::Task,
    /// If `Some`, caller must push this back onto the top-level cfs_heap.
    pub requeue_sentinel: Option<CfsEntry>,
}

pub fn group_dequeue_next(tg_id: usize, cpu: u32, elapsed: u64) -> GroupDequeueResult {
    let null_result = GroupDequeueResult {
        task: core::ptr::null_mut(),
        requeue_sentinel: None,
    };

    let tg_arc = match find_task_group(tg_id) {
        Some(a) => a,
        None => return null_result,
    };
    let mut tg = tg_arc.lock();
    let cpu = (cpu as usize).min(MAX_GROUP_CPUS - 1);

    // Mark sentinel gone from top-level heap.
    tg.grq[cpu].on_top_rq = false;

    let task = match tg.grq[cpu].dequeue_next() {
        Some(t) => t,
        None => return null_result,
    };

    // Advance group vruntime: delta = elapsed * NICE0_WEIGHT / group_weight.
    // A heavier group advances more slowly, giving it more wall-clock time
    // before the top-level CFS heap prefers another entity.
    if tg.weight > 0 && elapsed > 0 {
        let delta = elapsed.saturating_mul(NICE0_WEIGHT) / tg.weight;
        tg.vruntime[cpu] = tg.vruntime[cpu].saturating_add(delta);
    }

    // Re-insert sentinel if more tasks remain in this group on this CPU.
    let requeue = if !tg.grq[cpu].is_empty() {
        tg.grq[cpu].on_top_rq = true;
        Some(CfsEntry {
            vruntime: tg.vruntime[cpu],
            pid: tg_id as u32,
            task_ptr: GROUP_SENTINEL,
        })
    } else {
        None
    };

    GroupDequeueResult {
        task,
        requeue_sentinel: requeue,
    }
}

/// Remove `pid` from its group's inner heap on `cpu`.
/// Called by `RunQueue::remove_pid` when a task leaves the run queue.
/// Returns true if the pid was found.
pub fn group_remove_pid(tg_id: usize, pid: u32, cpu: u32) -> bool {
    let tg_arc = match find_task_group(tg_id) {
        Some(a) => a,
        None => return false,
    };
    let mut tg = tg_arc.lock();
    let cpu = (cpu as usize).min(MAX_GROUP_CPUS - 1);
    tg.grq[cpu].remove_pid(pid)
}

// ── Public syscall-level API ────────────────────────────────────────────────────

/// Create a new scheduling group and attach the calling process to it.
///
/// Returns the new tg_id (> 0) on success, or negative errno on error.
/// This is the backing implementation for a hypothetical
/// `sys_sched_create_group()` or cgroup cpu controller `tasks` write.
pub fn sys_create_task_group() -> isize {
    let tg_id = create_task_group();
    let pid = crate::proc::scheduler::current_pid() as usize;
    let ok = crate::proc::scheduler::with_proc_mut(pid, |pcb, _| {
        pcb.tg_id = tg_id;
    });
    if ok.is_none() {
        return -3;
    } // ESRCH
    tg_id as isize
}

/// Move process `pid` into task group `tg_id`.
///
/// Returns 0 on success, -ESRCH if the pid or group is not found.
pub fn sys_setgroup(pid: usize, tg_id: usize) -> isize {
    // Validate group exists (or is 0 = ungrouped).
    if tg_id != ROOT_TG_ID && find_task_group(tg_id).is_none() {
        return -3; // ESRCH
    }
    let ok = crate::proc::scheduler::with_proc_mut(pid, |pcb, _| {
        pcb.tg_id = tg_id;
    });
    if ok.is_none() {
        -3
    } else {
        0
    }
}

/// Set the CPU weight of a task group.
///
/// `weight` uses the same scale as task nice weights (1024 = equal share).
/// Returns 0 on success, -ESRCH if the group is not found.
pub fn sys_setweight(tg_id: usize, weight: u64) -> isize {
    let tg_arc = match find_task_group(tg_id) {
        Some(a) => a,
        None => return -3, // ESRCH
    };
    tg_arc.lock().set_weight(weight);
    0
}

/// Destroy a task group.  Any processes still referencing the group will be
/// implicitly moved to the root group (tg_id = 0) on their next enqueue
/// because find_task_group() will return None.
///
/// Returns 0 always (idempotent).
pub fn sys_destroy_task_group(tg_id: usize) -> isize {
    if tg_id == ROOT_TG_ID {
        return -22;
    } // EINVAL: cannot destroy root
    destroy_task_group(tg_id);
    0
}
