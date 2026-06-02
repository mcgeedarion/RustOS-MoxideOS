//! cgroup v2 — unified hierarchy.
//!
//! ## Design summary
//!
//! Every process belongs to exactly one cgroup node, identified by a
//! `CgroupId` (u32).  The root cgroup (id = 1) is always present and has
//! no limits.  Child cgroups are created by writing to the cgroupfs virtual
//! filesystem (see `src/fs/cgroupfs.rs`).
//!
//! ## Resource controllers implemented
//!
//! | Controller    | Key knobs                                  |
//! |---------------|-------------------------------------------|
//! | **cpu**       | `cpu.weight` (nice-like 1..10000)          |
//! | **memory**    | `memory.max` (bytes, u64::MAX = unlimited) |
//! | **pids**      | `pids.max`   (count,  u64::MAX = unlimited)|
//! | **io**        | `io.weight`  (1..10000, advisory)          |
//!
//! ## Lifecycle hooks
//!
//! - `cgroup_fork(parent_pid, child_pid)` — child inherits parent's cgroup.
//! - `cgroup_exit(pid)`                  — remove PID from its cgroup;
//!   if the cgroup is empty and marked for removal, free it.
//!
//! ## cgroupfs integration
//!
//! The cgroup hierarchy is exposed under `/sys/fs/cgroup/`.  Reads and
//! writes are handled by `cgroupfs.rs`; this module provides the data layer.
//!
//! ## Locking
//!
//! A single global `CGROUPS` spinlock protects the `CgroupTable`.  Contention
//! is expected to be low (control-plane operations only; the hot scheduler
//! path reads `cgroup_id` from `Pcb` without any lock).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;
use core::sync::atomic::{AtomicU32, Ordering};

pub type CgroupId = u32;
pub const ROOT_CGROUP: CgroupId = 1;

static NEXT_CGID: AtomicU32 = AtomicU32::new(2);

fn alloc_cgid() -> CgroupId {
    NEXT_CGID.fetch_add(1, Ordering::Relaxed)
}

/// Per-cgroup resource configuration.
#[derive(Clone, Debug)]
pub struct CgroupLimits {
    /// cpu.weight — scheduler weight 1..10000 (default 100).
    pub cpu_weight: u32,
    /// memory.max — max RSS in bytes (u64::MAX = unlimited).
    pub memory_max: u64,
    /// pids.max   — max live PIDs in subtree (u64::MAX = unlimited).
    pub pids_max: u64,
    /// io.weight  — block-IO weight 1..10000 (default 100, advisory).
    pub io_weight: u32,
}

impl Default for CgroupLimits {
    fn default() -> Self {
        CgroupLimits {
            cpu_weight: 100,
            memory_max: u64::MAX,
            pids_max:   u64::MAX,
            io_weight:  100,
        }
    }
}

/// Live resource usage for a cgroup (sum over all member processes).
#[derive(Clone, Debug, Default)]
pub struct CgroupStat {
    /// Number of live PIDs directly and recursively in this cgroup.
    pub nr_pids: u32,
    /// Resident memory in bytes (approximate — updated on mmap/munmap).
    pub mem_bytes: u64,
    /// CPU usage in nanoseconds (updated on context switch).
    pub cpu_usage_ns: u64,
}

#[derive(Clone, Debug)]
pub struct CgroupNode {
    pub id:       CgroupId,
    pub parent:   CgroupId,   // 0 for root
    pub name:     String,     // path component, e.g. "containers"
    pub children: Vec<CgroupId>,
    pub pids:     Vec<usize>, // live PIDs directly in this cgroup
    pub limits:   CgroupLimits,
    pub stat:     CgroupStat,
    /// Set when `rmdir` has been called; cgroup is freed when pids empties.
    pub marked_for_removal: bool,
}

impl CgroupNode {
    fn new(id: CgroupId, parent: CgroupId, name: &str) -> Self {
        CgroupNode {
            id, parent,
            name: name.to_string(),
            children: Vec::new(),
            pids: Vec::new(),
            limits: CgroupLimits::default(),
            stat: CgroupStat::default(),
            marked_for_removal: false,
        }
    }
}

struct CgroupTable {
    nodes: BTreeMap<CgroupId, CgroupNode>,
}

impl CgroupTable {
    fn new() -> Self {
        let mut nodes = BTreeMap::new();
        nodes.insert(ROOT_CGROUP, CgroupNode::new(ROOT_CGROUP, 0, "/"));
        CgroupTable { nodes }
    }

    fn get(&self, id: CgroupId) -> Option<&CgroupNode> {
        self.nodes.get(&id)
    }

    fn get_mut(&mut self, id: CgroupId) -> Option<&mut CgroupNode> {
        self.nodes.get_mut(&id)
    }
}

static CGROUPS: Mutex<CgroupTable> = Mutex::new(CgroupTable::new());

/// Called once from `kernel_main` after `dhcp::init()` and before
/// `proc::spawn_init()`.
///
/// The `CGROUPS` static is already seeded with `ROOT_CGROUP` by
/// `CgroupTable::new()`, so this function's job is purely to:
///
/// 1. Assert the root node is healthy (debug sanity check).
/// 2. Register the cgroup v2 unified-hierarchy mount with the kernel
///    mount table (via `fs::mount::kernel_mount`) so that
///    `/sys/fs/cgroup` resolves to `FsType::Cgroupfs` before pid-1
///    runs.  The `init_mounts()` call in the initramfs path already does
///    this for the normal boot path; calling `kernel_mount` here is a
///    no-op (`-EBUSY`) if the entry already exists, which is safe to
///    ignore.
/// 3. Emit a boot log line so the init sequence is traceable.
pub fn init() {
    // Sanity: root node must exist.
    debug_assert!(
        CGROUPS.lock().nodes.contains_key(&ROOT_CGROUP),
        "cgroup: ROOT_CGROUP missing at init"
    );

    // Ensure /sys/fs/cgroup is registered in the mount table.  This is
    // normally done by fs::mount::init_mounts(); the call here is a
    // belt-and-suspenders guard for boot paths that skip init_mounts().
    let _ = crate::fs::mount::kernel_mount(
        "cgroup2",
        "/sys/fs/cgroup",
        crate::fs::mount::FsType::Cgroupfs,
        crate::fs::mount::MS_NOSUID
            | crate::fs::mount::MS_NODEV
            | crate::fs::mount::MS_NOEXEC,
        None,
    );
    // -EBUSY (-16) means it was already mounted — that's fine.

    log::info!("cgroup: v2 unified hierarchy ready (root cgid={})", ROOT_CGROUP);
}

/// Create a new child cgroup under `parent`.  Returns the new `CgroupId`,
/// or `-ENOENT` if `parent` does not exist, or `-EEXIST` if a child with
/// that name already exists.
pub fn create_cgroup(parent: CgroupId, name: &str) -> Result<CgroupId, isize> {
    let mut tbl = CGROUPS.lock();
    // Verify parent exists.
    if tbl.nodes.get(&parent).is_none() { return Err(-2); }
    // Check for duplicate name among siblings.
    let dup = tbl.nodes[&parent].children.iter()
        .any(|&cid| tbl.nodes.get(&cid)
            .map(|n| n.name == name)
            .unwrap_or(false));
    if dup { return Err(-17); }

    let id = alloc_cgid();
    let node = CgroupNode::new(id, parent, name);
    tbl.nodes.insert(id, node);
    tbl.nodes.get_mut(&parent).unwrap().children.push(id);
    Ok(id)
}

/// Mark a cgroup for removal.  Returns `-ENOTEMPTY` if it still has children.
/// If already empty of PIDs, frees immediately; otherwise deferred to the
/// last PID's exit.
pub fn remove_cgroup(id: CgroupId) -> isize {
    if id == ROOT_CGROUP { return -1; } // EPERM
    let mut tbl = CGROUPS.lock();
    let node = match tbl.nodes.get_mut(&id) { Some(n) => n, None => return -2 };
    if !node.children.is_empty() { return -39; } // ENOTEMPTY
    node.marked_for_removal = true;
    if node.pids.is_empty() {
        let parent = node.parent;
        tbl.nodes.remove(&id);
        if let Some(p) = tbl.nodes.get_mut(&parent) {
            p.children.retain(|&c| c != id);
        }
    }
    0
}

/// Move `pid` from its current cgroup into `target`.  Called via
/// `echo <pid> > /sys/fs/cgroup/<path>/cgroup.procs`.
pub fn move_pid(pid: usize, target: CgroupId) -> isize {
    let mut tbl = CGROUPS.lock();
    // Verify target exists.
    if tbl.nodes.get(&target).is_none() { return -2; }

    // Find and remove from current cgroup.
    let current = find_pid_cgroup_locked(&tbl, pid);
    if let Some(old_id) = current {
        if old_id == target { return 0; }
        if let Some(old) = tbl.nodes.get_mut(&old_id) {
            old.pids.retain(|&p| p != pid);
            old.stat.nr_pids = old.stat.nr_pids.saturating_sub(1);
        }
    }

    // Check pids.max before inserting.
    let pids_max = tbl.nodes[&target].limits.pids_max;
    if (tbl.nodes[&target].stat.nr_pids as u64) >= pids_max { return -11; } // EAGAIN (ESRCH)

    tbl.nodes.get_mut(&target).unwrap().pids.push(pid);
    tbl.nodes.get_mut(&target).unwrap().stat.nr_pids += 1;
    0
}

fn find_pid_cgroup_locked(tbl: &CgroupTable, pid: usize) -> Option<CgroupId> {
    for (id, node) in &tbl.nodes {
        if node.pids.contains(&pid) { return Some(*id); }
    }
    None
}

/// Return the `CgroupId` the given `pid` is currently a member of.
pub fn cgroup_of(pid: usize) -> CgroupId {
    // Fast path: read from Pcb.
    crate::proc::scheduler::with_proc(pid, |p| p.cgroup_id)
        .unwrap_or(ROOT_CGROUP)
}

/// Read a controller knob.  Returns a formatted string suitable for
/// `/sys/fs/cgroup/<path>/<file>` reads.
pub fn read_knob(id: CgroupId, file: &str) -> Option<String> {
    let tbl = CGROUPS.lock();
    let node = tbl.get(id)?;
    Some(match file {
        "cgroup.procs"    => node.pids.iter().map(|p| alloc::format!("{}", p)).collect::<Vec<_>>().join("\n") + "\n",
        "cgroup.children" => node.children.iter().map(|c| alloc::format!("{}", c)).collect::<Vec<_>>().join("\n") + "\n",
        "cpu.weight"      => alloc::format!("{}\n", node.limits.cpu_weight),
        "memory.max"      => if node.limits.memory_max == u64::MAX { "max\n".to_string() } else { alloc::format!("{}\n", node.limits.memory_max) },
        "memory.current"  => alloc::format!("{}\n", node.stat.mem_bytes),
        "pids.max"        => if node.limits.pids_max == u64::MAX { "max\n".to_string() } else { alloc::format!("{}\n", node.limits.pids_max) },
        "pids.current"    => alloc::format!("{}\n", node.stat.nr_pids),
        "io.weight"       => alloc::format!("{}\n", node.limits.io_weight),
        "cpu.stat"        => alloc::format!("usage_usec {}\n", node.stat.cpu_usage_ns / 1000),
        _                 => return None,
    })
}

/// Write a controller knob.  Returns 0 on success, negative errno on error.
pub fn write_knob(id: CgroupId, file: &str, value: &str) -> isize {
    let value = value.trim();
    let mut tbl = CGROUPS.lock();
    let node = match tbl.get_mut(id) { Some(n) => n, None => return -2 };
    match file {
        "cpu.weight" => {
            let v: u32 = match value.parse() { Ok(v) => v, Err(_) => return -22 };
            if v < 1 || v > 10000 { return -22; }
            node.limits.cpu_weight = v;
            0
        }
        "memory.max" => {
            node.limits.memory_max = if value == "max" {
                u64::MAX
            } else {
                match value.parse() { Ok(v) => v, Err(_) => return -22 }
            };
            0
        }
        "pids.max" => {
            node.limits.pids_max = if value == "max" {
                u64::MAX
            } else {
                match value.parse() { Ok(v) => v, Err(_) => return -22 }
            };
            0
        }
        "io.weight" => {
            let v: u32 = match value.parse() { Ok(v) => v, Err(_) => return -22 };
            if v < 1 || v > 10000 { return -22; }
            node.limits.io_weight = v;
            0
        }
        "cgroup.procs" => {
            // Write a PID to move it into this cgroup.
            drop(tbl); // release lock before calling move_pid which re-acquires
            let pid: usize = match value.parse() { Ok(v) => v, Err(_) => return -22 };
            move_pid(pid, id)
        }
        _ => -22,
    }
}

/// Called from `fork_syscall` / `clone` after the child `Pcb` is created.
/// Places the child in the same cgroup as the parent and increments counters.
pub fn cgroup_fork(parent_pid: usize, child_pid: usize) {
    let parent_cgid = crate::proc::scheduler::with_proc(parent_pid, |p| p.cgroup_id)
        .unwrap_or(ROOT_CGROUP);

    // Write child's cgroup_id into its Pcb.
    crate::proc::scheduler::with_proc_mut(child_pid, |p, _pl| {
        p.cgroup_id = parent_cgid;
    });

    let mut tbl = CGROUPS.lock();
    if let Some(node) = tbl.get_mut(parent_cgid) {
        // Enforce pids.max *before* adding.
        if (node.stat.nr_pids as u64) < node.limits.pids_max {
            node.pids.push(child_pid);
            node.stat.nr_pids += 1;
        }
        // pids.max exceeded: child still runs but is not tracked (soft limit).
        // A stricter implementation would SIGKILL the child here.
    }
}

/// Called from `do_exit` for every exiting process (all threads).
/// Removes the process from its cgroup and frees the cgroup if it was
/// marked for removal and is now empty.
pub fn cgroup_exit(pid: usize) {
    let cgid = crate::proc::scheduler::with_proc(pid, |p| p.cgroup_id)
        .unwrap_or(ROOT_CGROUP);
    if cgid == ROOT_CGROUP { return; }

    let mut tbl = CGROUPS.lock();
    let do_free = if let Some(node) = tbl.get_mut(cgid) {
        node.pids.retain(|&p| p != pid);
        node.stat.nr_pids = node.stat.nr_pids.saturating_sub(1);
        node.marked_for_removal && node.pids.is_empty() && node.children.is_empty()
    } else {
        false
    };
    if do_free {
        let parent = tbl.nodes[&cgid].parent;
        tbl.nodes.remove(&cgid);
        if let Some(p) = tbl.nodes.get_mut(&parent) {
            p.children.retain(|&c| c != cgid);
        }
    }
}

/// Add `delta_ns` CPU nanoseconds to pid's cgroup (and all ancestors).
pub fn charge_cpu_ns(pid: usize, delta_ns: u64) {
    let cgid = crate::proc::scheduler::with_proc(pid, |p| p.cgroup_id)
        .unwrap_or(ROOT_CGROUP);
    let mut tbl = CGROUPS.lock();
    let mut cur = cgid;
    loop {
        if let Some(node) = tbl.nodes.get_mut(&cur) {
            node.stat.cpu_usage_ns = node.stat.cpu_usage_ns.saturating_add(delta_ns);
            let parent = node.parent;
            if parent == 0 { break; }
            cur = parent;
        } else {
            break;
        }
    }
}

/// Update resident-memory bytes for pid's cgroup.  `delta` is signed
/// (positive on mmap, negative on munmap/free).
pub fn charge_mem(pid: usize, delta: i64) {
    let cgid = crate::proc::scheduler::with_proc(pid, |p| p.cgroup_id)
        .unwrap_or(ROOT_CGROUP);
    let mut tbl = CGROUPS.lock();
    let mut cur = cgid;
    loop {
        if let Some(node) = tbl.nodes.get_mut(&cur) {
            if delta >= 0 {
                node.stat.mem_bytes = node.stat.mem_bytes.saturating_add(delta as u64);
            } else {
                node.stat.mem_bytes = node.stat.mem_bytes.saturating_sub((-delta) as u64);
            }
            // Enforce memory.max: soft OOM — mark processes in cgroup for SIGKILL.
            if node.stat.mem_bytes > node.limits.memory_max {
                let pids_snap: Vec<usize> = node.pids.clone();
                drop(tbl);
                for p in pids_snap {
                    crate::proc::signal::send_signal_group(p, 9 /*SIGKILL*/);
                }
                return;
            }
            let parent = node.parent;
            if parent == 0 { break; }
            cur = parent;
        } else {
            break;
        }
    }
}

/// Check whether forking a new process into `pid`'s cgroup is allowed
/// (pids.max enforcement).  Returns true if allowed.
pub fn check_pids_max(pid: usize) -> bool {
    let cgid = crate::proc::scheduler::with_proc(pid, |p| p.cgroup_id)
        .unwrap_or(ROOT_CGROUP);
    let tbl = CGROUPS.lock();
    let mut cur = cgid;
    loop {
        if let Some(node) = tbl.nodes.get(&cur) {
            if (node.stat.nr_pids as u64) >= node.limits.pids_max { return false; }
            if node.parent == 0 { return true; }
            cur = node.parent;
        } else {
            return true;
        }
    }
}

/// Resolve a cgroupfs path like `/sys/fs/cgroup/foo/bar` to a `CgroupId`.
/// Returns `None` if the path does not exist.
pub fn path_to_cgid(path: &str) -> Option<CgroupId> {
    let stripped = path
        .strip_prefix("/sys/fs/cgroup")
        .unwrap_or(path)
        .trim_matches('/');
    if stripped.is_empty() { return Some(ROOT_CGROUP); }
    let tbl = CGROUPS.lock();
    let mut cur = ROOT_CGROUP;
    for component in stripped.split('/') {
        let next = tbl.nodes[&cur].children.iter()
            .find(|&&c| tbl.nodes.get(&c).map(|n| n.name == component).unwrap_or(false))
            .copied()?;
        cur = next;
    }
    Some(cur)
}

/// Build the full path string for a given `CgroupId`.
pub fn cgid_to_path(id: CgroupId) -> String {
    let tbl = CGROUPS.lock();
    let mut parts: Vec<String> = Vec::new();
    let mut cur = id;
    loop {
        match tbl.nodes.get(&cur) {
            None => break,
            Some(n) => {
                if cur == ROOT_CGROUP { break; }
                parts.push(n.name.clone());
                cur = n.parent;
            }
        }
    }
    parts.reverse();
    if parts.is_empty() {
        "/sys/fs/cgroup".to_string()
    } else {
        alloc::format!("/sys/fs/cgroup/{}", parts.join("/"))
    }
}
