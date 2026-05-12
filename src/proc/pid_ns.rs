//! PID namespace hierarchy.
//!
//! ## Linux semantics implemented here
//!
//! 1. **Multi-level PIDs** — a process in a child namespace has one local PID
//!    per ancestor namespace up to and including INIT_NS.  The kernel stores
//!    all of them so that a process in ns[2] is visible to ns[0] and ns[1]
//!    with its appropriate local PID at each level.
//!
//! 2. **Namespace init (PID 1)** — the first process registered in a new
//!    namespace automatically becomes its `init_pid`.  When init exits, every
//!    process still in that namespace receives SIGKILL.
//!
//! 3. **Ancestor visibility** — a process in ns[A] can send signals, waitpid,
//!    and ptrace a process in ns[B] only if ns[A] is an ancestor (or equal)
//!    of ns[B].  `ns_is_ancestor_or_equal` implements this check.
//!
//! 4. **getpid / getppid translation** — `current_visible_pid` and
//!    `current_visible_ppid` return the local PID as seen from the calling
//!    process's own namespace.  If the parent lives outside the namespace,
//!    PPID is 0.
//!
//! ## Data model
//!
//! ```text
//! PidNsEntry {
//!     parent:   NsId,                  // INIT_NS → no parent
//!     init_pid: Option<usize>,         // global PID of ns-init
//!     counter:  u32,                   // monotone local PID counter
//!     map:      BTreeMap<global, local>
//!     rmap:     BTreeMap<local, global>
//! }
//! ```
//!
//! `PID_NS_TABLE: Mutex<BTreeMap<NsId, PidNsEntry>>`

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;
use crate::proc::namespace::{NsId, INIT_NS, alloc_ns_id};

// ── Per-namespace entry ───────────────────────────────────────────────────────────

struct PidNsEntry {
    /// Parent namespace.  INIT_NS entries have parent == INIT_NS (sentinel).
    parent:   NsId,
    /// Global PID of the init process (PID 1 as seen inside this namespace).
    /// None until the first process is registered.
    init_pid: Option<usize>,
    /// Monotone local-PID counter; starts at 1.
    counter:  u32,
    /// global PID → local PID
    map:  BTreeMap<usize, u32>,
    /// local PID → global PID
    rmap: BTreeMap<u32, usize>,
}

impl PidNsEntry {
    fn new(parent: NsId) -> Self {
        PidNsEntry {
            parent,
            init_pid: None,
            counter: 1,
            map:  BTreeMap::new(),
            rmap: BTreeMap::new(),
        }
    }

    /// Allocate the next local PID for `global_pid`.
    fn alloc(&mut self, global_pid: usize) -> u32 {
        let local = self.counter;
        self.counter += 1;
        self.map.insert(global_pid, local);
        self.rmap.insert(local, global_pid);
        if self.init_pid.is_none() {
            self.init_pid = Some(global_pid); // first registrant is ns-init
        }
        local
    }

    fn local_of(&self, global: usize) -> Option<u32> {
        self.map.get(&global).copied()
    }

    fn global_of(&self, local: u32) -> Option<usize> {
        self.rmap.get(&local).copied()
    }

    fn remove(&mut self, global: usize) {
        if let Some(local) = self.map.remove(&global) {
            self.rmap.remove(&local);
        }
    }

    fn is_init(&self, global: usize) -> bool {
        self.init_pid == Some(global)
    }
}

// ── Global registry ──────────────────────────────────────────────────────────────

static PID_NS_TABLE: Mutex<BTreeMap<NsId, PidNsEntry>> =
    Mutex::new(BTreeMap::new());

/// Seed INIT_NS.  Called once from kernel init.
pub fn init_pid_ns() {
    let mut tbl = PID_NS_TABLE.lock();
    tbl.entry(INIT_NS).or_insert_with(|| PidNsEntry::new(INIT_NS));
}

/// Create a new child PID namespace under `parent_ns` and return its NsId.
/// Called by `unshare(CLONE_NEWPID)` / `clone(CLONE_NEWPID)`.
/// Note: CLONE_NEWPID takes effect for *children*, not the caller.
pub fn create_pid_ns(parent_ns: NsId) -> NsId {
    let new_id = alloc_ns_id();
    PID_NS_TABLE.lock().insert(new_id, PidNsEntry::new(parent_ns));
    new_id
}

/// Destroy a PID namespace when it is no longer referenced.
/// No-op for INIT_NS.
pub fn drop_pid_ns(ns: NsId) {
    if ns == INIT_NS { return; }
    PID_NS_TABLE.lock().remove(&ns);
}

// ── Ancestor chain helpers ───────────────────────────────────────────────────────

/// Return the full ancestor chain for `ns`, from `ns` up to (and including)
/// INIT_NS.  Maximum depth is capped at 32 to prevent infinite loops on
/// corrupt state.
fn ancestor_chain(ns: NsId) -> Vec<NsId> {
    let mut chain = Vec::new();
    let tbl = PID_NS_TABLE.lock();
    let mut cur = ns;
    for _ in 0..32 {
        chain.push(cur);
        if cur == INIT_NS { break; }
        match tbl.get(&cur) {
            Some(e) => cur = e.parent,
            None    => break,
        }
    }
    chain
}

/// True if `ancestor` is an ancestor of (or equal to) `descendant`.
///
/// Used by signal and ptrace permission checks: a process in `ancestor` can
/// target a process in `descendant`.
pub fn ns_is_ancestor_or_equal(ancestor: NsId, descendant: NsId) -> bool {
    if ancestor == descendant { return true; }
    // Walk descendant's parent chain looking for ancestor.
    let tbl = PID_NS_TABLE.lock();
    let mut cur = descendant;
    for _ in 0..32 {
        match tbl.get(&cur) {
            Some(e) if e.parent == ancestor => return true,
            Some(e) if e.parent == INIT_NS  => return ancestor == INIT_NS,
            Some(e) => cur = e.parent,
            None    => break,
        }
    }
    false
}

// ── Registration (fork / clone path) ───────────────────────────────────────

/// Register `global_pid` into `ns` **and every ancestor namespace** up to
/// INIT_NS.  Returns the local PID as seen from `ns` (the innermost ns).
///
/// This mirrors Linux's multi-level PID allocation: a process in a deeply
/// nested namespace has one local PID per level, all allocated atomically
/// here so that `local_pid(ancestor_ns, global)` always works.
pub fn register_pid(ns: NsId, global_pid: usize) -> u32 {
    if ns == INIT_NS {
        // INIT_NS: identity mapping, no entry needed.
        return global_pid as u32;
    }
    let chain = ancestor_chain(ns);
    let mut tbl = PID_NS_TABLE.lock();
    let mut innermost_local: u32 = global_pid as u32;
    // Allocate from innermost (index 0) to outermost (INIT_NS).
    for &level_ns in &chain {
        if level_ns == INIT_NS { break; } // identity — no allocation needed
        if let Some(entry) = tbl.get_mut(&level_ns) {
            let local = entry.alloc(global_pid);
            if level_ns == ns {
                innermost_local = local;
            }
        }
    }
    innermost_local
}

// ── Translation ─────────────────────────────────────────────────────────────────

/// Translate `global_pid` to its local PID as seen from namespace `ns`.
/// Returns the global PID unchanged for INIT_NS or unregistered processes.
pub fn local_pid(ns: NsId, global_pid: usize) -> usize {
    if ns == INIT_NS { return global_pid; }
    let tbl = PID_NS_TABLE.lock();
    tbl.get(&ns)
        .and_then(|e| e.local_of(global_pid))
        .map(|l| l as usize)
        .unwrap_or(global_pid)
}

/// Translate a local PID (as seen in `ns`) back to the global PID.
pub fn global_pid(ns: NsId, local: usize) -> usize {
    if ns == INIT_NS { return local; }
    let tbl = PID_NS_TABLE.lock();
    tbl.get(&ns)
        .and_then(|e| e.global_of(local as u32))
        .unwrap_or(local)
}

// ── Deregistration (exit path) ───────────────────────────────────────────────

/// Remove `global_pid` from `ns` and every ancestor namespace.
/// If the exiting process is the ns-init (local PID 1), all remaining
/// processes in that namespace are sent SIGKILL.
///
/// Called from `exit::do_exit`.
pub fn unregister_pid(ns: NsId, global_pid: usize) {
    if ns == INIT_NS { return; }

    // Check whether this is the namespace init *before* we remove the entry.
    let is_init = {
        let tbl = PID_NS_TABLE.lock();
        tbl.get(&ns).map(|e| e.is_init(global_pid)).unwrap_or(false)
    };

    // Remove from every ancestor level.
    let chain = ancestor_chain(ns);
    {
        let mut tbl = PID_NS_TABLE.lock();
        for &level_ns in &chain {
            if level_ns == INIT_NS { break; }
            if let Some(e) = tbl.get_mut(&level_ns) {
                e.remove(global_pid);
            }
        }
    }

    // If ns-init exited, SIGKILL every surviving process in this namespace.
    if is_init {
        kill_namespace(ns);
    }
}

/// Send SIGKILL to all processes currently registered in `ns`.
/// Called when namespace-init exits.
fn kill_namespace(ns: NsId) {
    // Snapshot the global PIDs currently in the namespace so we can
    // release the table lock before calling into the signal path.
    let victims: Vec<usize> = {
        let tbl = PID_NS_TABLE.lock();
        tbl.get(&ns)
            .map(|e| e.map.keys().copied().collect())
            .unwrap_or_default()
    };
    for pid in victims {
        crate::proc::signal::send_signal(pid, 9 /* SIGKILL */);
    }
}

// ── getpid / getppid helpers ────────────────────────────────────────────────────

/// Return the PID visible to the calling process in its own namespace.
/// Used by `getpid(2)` (NR 39) and `gettid(2)` (NR 186).
pub fn current_visible_pid() -> usize {
    let pid = crate::proc::scheduler::current_pid();
    let ns  = crate::proc::scheduler::with_proc(pid, |p| p.ns.pid)
        .unwrap_or(INIT_NS);
    local_pid(ns, pid)
}

/// Return the PPID visible to the calling process in its own namespace.
/// If the parent lives *outside* this namespace, returns 0 (Linux convention).
pub fn current_visible_ppid() -> usize {
    let pid = crate::proc::scheduler::current_pid();
    let (ppid, ns) = crate::proc::scheduler::with_proc(pid, |p| (p.ppid, p.ns.pid))
        .unwrap_or((0, INIT_NS));
    if ns == INIT_NS { return ppid; }
    let tbl = PID_NS_TABLE.lock();
    match tbl.get(&ns).and_then(|e| e.local_of(ppid)) {
        Some(local) => local as usize,
        None        => 0, // parent is outside (or above) this ns
    }
}

// ── Signal permission check ─────────────────────────────────────────────────────

/// True if a process in `sender_ns` is permitted to send signals to a process
/// in `target_ns` by namespace hierarchy rules alone.
///
/// The UID/GID check is a separate layer performed in `signal::may_send`.
/// Here we only check that sender_ns is an ancestor-or-equal of target_ns.
pub fn may_signal_across_ns(sender_ns: NsId, target_ns: NsId) -> bool {
    ns_is_ancestor_or_equal(sender_ns, target_ns)
}
