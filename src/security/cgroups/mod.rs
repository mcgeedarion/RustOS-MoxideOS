//! cgroups v1 resource controller.
//!
//! ## Controllers implemented
//!
//! | Subsystem | Knob file | Effect |
//! |-----------|-----------|--------|
//! | `cpu`     | `cpu.shares`, `cpu.cfs_period_us`, `cpu.cfs_quota_us` | Proportional share + CFS bandwidth |
//! | `memory`  | `memory.limit_in_bytes`, `memory.usage_in_bytes`, `memory.failcnt` | Hard memory cap; OOM on exceed |
//! | `pids`    | `pids.max`, `pids.current` | Maximum number of tasks in the cgroup |
//!
//! ## Hierarchy
//!
//! A single flat cgroup hierarchy is maintained: the root cgroup
//! `CgroupId(0)` is created at boot, all processes start there.  `create()`
//! allocates a child cgroup; `attach()` moves a task into it.
//!
//! ## Linux cgroupfs surface
//!
//!   /sys/fs/cgroup/cpu/<name>/          — cpu controller
//!   /sys/fs/cgroup/memory/<name>/       — memory controller
//!   /sys/fs/cgroup/pids/<name>/         — pids controller
//!   /sys/fs/cgroup/<name>/cgroup.procs  — list of task IDs

pub mod cpu;
pub mod memory;
pub mod pids;

extern crate alloc;
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

// ─────────────────────────────────────────────────────────────────────────────
// Cgroup identity
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct CgroupId(pub u64);

static NEXT_CG_ID: AtomicU64 = AtomicU64::new(1);
fn alloc_cg_id() -> CgroupId {
    CgroupId(NEXT_CG_ID.fetch_add(1, Ordering::SeqCst))
}

// ─────────────────────────────────────────────────────────────────────────────
// Cgroup node
// ─────────────────────────────────────────────────────────────────────────────

/// One cgroup node in the hierarchy.
pub struct Cgroup {
    pub id: CgroupId,
    pub name: String,
    pub parent: Option<CgroupId>,
    pub cpu: cpu::CpuCg,
    pub memory: memory::MemCg,
    pub pids: pids::PidsCg,
    /// Kernel task-IDs attached to this cgroup.
    tasks: Mutex<Vec<u64>>,
}

impl Cgroup {
    fn new_root() -> Self {
        Cgroup {
            id: CgroupId(0),
            name: String::from("/"),
            parent: None,
            cpu: cpu::CpuCg::default(),
            memory: memory::MemCg::default(),
            pids: pids::PidsCg::default(),
            tasks: Mutex::new(Vec::new()),
        }
    }

    fn new_child(name: String, parent: CgroupId) -> Self {
        Cgroup {
            id: alloc_cg_id(),
            name,
            parent: Some(parent),
            cpu: cpu::CpuCg::default(),
            memory: memory::MemCg::default(),
            pids: pids::PidsCg::default(),
            tasks: Mutex::new(Vec::new()),
        }
    }

    pub fn task_list(&self) -> Vec<u64> {
        self.tasks.lock().clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Global hierarchy
// ─────────────────────────────────────────────────────────────────────────────

struct CgroupTree {
    groups: BTreeMap<CgroupId, Cgroup>,
    /// Task-id → cgroup assignment.
    task_cg: BTreeMap<u64, CgroupId>,
}

impl CgroupTree {
    fn new() -> Self {
        let mut groups = BTreeMap::new();
        groups.insert(CgroupId(0), Cgroup::new_root());
        CgroupTree {
            groups,
            task_cg: BTreeMap::new(),
        }
    }
}

static CGTREE: Mutex<Option<CgroupTree>> = Mutex::new(None);

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

pub fn init() {
    *CGTREE.lock() = Some(CgroupTree::new());
}

/// Create a new child cgroup under `parent`.
/// Returns the new `CgroupId` or EEXIST if `name` is taken.
pub fn create(parent: CgroupId, name: String) -> Result<CgroupId, isize> {
    let mut tree = CGTREE.lock();
    let tree = tree.as_mut().ok_or(-1isize)?;
    if !tree.groups.contains_key(&parent) {
        return Err(-2);
    } // ENOENT
      // Check name uniqueness under parent.
    if tree
        .groups
        .values()
        .any(|g| g.parent == Some(parent) && g.name == name)
    {
        return Err(-17); // EEXIST
    }
    let cg = Cgroup::new_child(name, parent);
    let id = cg.id;
    tree.groups.insert(id, cg);
    Ok(id)
}

/// Remove a leaf cgroup.  Returns EBUSY if it has tasks or children.
pub fn remove(id: CgroupId) -> Result<(), isize> {
    if id == CgroupId(0) {
        return Err(-1);
    } // cannot remove root
    let mut tree = CGTREE.lock();
    let tree = tree.as_mut().ok_or(-1isize)?;
    let cg = tree.groups.get(&id).ok_or(-2isize)?;
    if !cg.tasks.lock().is_empty() {
        return Err(-16);
    } // EBUSY
    if tree.groups.values().any(|g| g.parent == Some(id)) {
        return Err(-16);
    }
    tree.groups.remove(&id);
    Ok(())
}

/// Attach `task_id` to `cgroup_id`, removing it from its current cgroup.
pub fn attach(task_id: u64, cgroup_id: CgroupId) -> Result<(), isize> {
    let mut tree = CGTREE.lock();
    let tree = tree.as_mut().ok_or(-1isize)?;
    // Remove from current cgroup.
    if let Some(&old_id) = tree.task_cg.get(&task_id) {
        if let Some(old_cg) = tree.groups.get(&old_id) {
            old_cg.tasks.lock().retain(|&t| t != task_id);
        }
    }
    let cg = tree.groups.get(&cgroup_id).ok_or(-2isize)?;
    // Check pids.max.
    if !cg.pids.can_fork() {
        return Err(-11);
    } // EAGAIN
    cg.tasks.lock().push(task_id);
    cg.pids.increment();
    tree.task_cg.insert(task_id, cgroup_id);
    Ok(())
}

/// Called on task exit to decrement pids counter and clean up.
pub fn task_exit(task_id: u64) {
    let mut tree = CGTREE.lock();
    let tree = match tree.as_mut() {
        Some(t) => t,
        None => return,
    };
    if let Some(&cg_id) = tree.task_cg.get(&task_id) {
        if let Some(cg) = tree.groups.get(&cg_id) {
            cg.tasks.lock().retain(|&t| t != task_id);
            cg.pids.decrement();
        }
        tree.task_cg.remove(&task_id);
    }
}

/// Look up which cgroup a task belongs to.
pub fn task_cgroup(task_id: u64) -> CgroupId {
    CGTREE
        .lock()
        .as_ref()
        .and_then(|t| t.task_cg.get(&task_id).copied())
        .unwrap_or(CgroupId(0))
}

/// Read a knob from the cpu controller by name.
/// Returns Err(ENOENT) for unknown knobs.
pub fn cpu_read(id: CgroupId, knob: &str) -> Result<i64, isize> {
    let tree = CGTREE.lock();
    let cg = tree
        .as_ref()
        .ok_or(-1isize)?
        .groups
        .get(&id)
        .ok_or(-2isize)?;
    cg.cpu.read(knob)
}

/// Write a knob to the cpu controller.
pub fn cpu_write(id: CgroupId, knob: &str, val: i64) -> Result<(), isize> {
    let tree = CGTREE.lock();
    let cg = tree
        .as_ref()
        .ok_or(-1isize)?
        .groups
        .get(&id)
        .ok_or(-2isize)?;
    cg.cpu.write(knob, val)
}

/// Read a memory controller knob.
pub fn mem_read(id: CgroupId, knob: &str) -> Result<i64, isize> {
    let tree = CGTREE.lock();
    let cg = tree
        .as_ref()
        .ok_or(-1isize)?
        .groups
        .get(&id)
        .ok_or(-2isize)?;
    cg.memory.read(knob)
}

/// Write a memory controller knob.
pub fn mem_write(id: CgroupId, knob: &str, val: i64) -> Result<(), isize> {
    let tree = CGTREE.lock();
    let cg = tree
        .as_ref()
        .ok_or(-1isize)?
        .groups
        .get(&id)
        .ok_or(-2isize)?;
    cg.memory.write(knob, val)
}

/// Check memory limit before a page fault / mmap.  Returns Err(-12) (ENOMEM)
/// if over the hard limit.  Adds `bytes` to usage on success.
pub fn mem_charge(task_id: u64, bytes: u64) -> Result<(), isize> {
    let tree = CGTREE.lock();
    let tree = match tree.as_ref() {
        Some(t) => t,
        None => return Ok(()),
    };
    let cg_id = tree.task_cg.get(&task_id).copied().unwrap_or(CgroupId(0));
    let cg = match tree.groups.get(&cg_id) {
        Some(c) => c,
        None => return Ok(()),
    };
    cg.memory.charge(bytes)
}

/// Release `bytes` from memory accounting.
pub fn mem_uncharge(task_id: u64, bytes: u64) {
    let tree = CGTREE.lock();
    let tree = match tree.as_ref() {
        Some(t) => t,
        None => return,
    };
    let cg_id = tree.task_cg.get(&task_id).copied().unwrap_or(CgroupId(0));
    if let Some(cg) = tree.groups.get(&cg_id) {
        cg.memory.uncharge(bytes);
    }
}

/// Read a pids controller knob.
pub fn pids_read(id: CgroupId, knob: &str) -> Result<i64, isize> {
    let tree = CGTREE.lock();
    let cg = tree
        .as_ref()
        .ok_or(-1isize)?
        .groups
        .get(&id)
        .ok_or(-2isize)?;
    cg.pids.read(knob)
}
pub fn pids_write(id: CgroupId, knob: &str, val: i64) -> Result<(), isize> {
    let tree = CGTREE.lock();
    let cg = tree
        .as_ref()
        .ok_or(-1isize)?
        .groups
        .get(&id)
        .ok_or(-2isize)?;
    cg.pids.write(knob, val)
}

/// Enumerate all cgroup IDs and names (for cgroupfs listing).
pub fn list_all() -> Vec<(CgroupId, String)> {
    let tree = CGTREE.lock();
    match tree.as_ref() {
        Some(t) => t.groups.values().map(|g| (g.id, g.name.clone())).collect(),
        None => Vec::new(),
    }
}
