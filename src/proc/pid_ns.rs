//! PID namespace — per-NsId PID allocation and translation.
//!
//! ## Semantics
//! When a process calls `unshare(CLONE_NEWPID)` or `clone(CLONE_NEWPID)`,
//! the *first child* created in that namespace sees itself as PID 1.
//! The parent's PID does **not** change (Linux behaviour: CLONE_NEWPID
//! only affects children, not the calling process itself).
//!
//! ## Data model
//! `PID_NS_TABLE` maps `NsId → PidNs`.  Each `PidNs` has:
//!   - a local PID counter (starts at 1)
//!   - a `BTreeMap<global_pid, local_pid>` translation map
//!
//! `local_pid(ns_id, global_pid)` → visible PID inside the namespace.
//! If no mapping exists the raw global PID is returned (INIT_NS behaviour).

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::proc::namespace::{NsId, INIT_NS};

// ─── Per-namespace PID state ─────────────────────────────────────────────────

struct PidNs {
    /// Monotone counter for this ns; starts at 1.
    counter: u32,
    /// global_pid → local_pid
    map: BTreeMap<usize, u32>,
    /// local_pid → global_pid (for reverse lookup)
    rmap: BTreeMap<u32, usize>,
}

impl PidNs {
    fn new() -> Self {
        PidNs { counter: 1, map: BTreeMap::new(), rmap: BTreeMap::new() }
    }

    /// Allocate the next local PID for `global_pid` and record the mapping.
    fn alloc(&mut self, global_pid: usize) -> u32 {
        let local = self.counter;
        self.counter += 1;
        self.map.insert(global_pid, local);
        self.rmap.insert(local, global_pid);
        local
    }

    /// Translate global → local.  Returns `None` if not registered.
    fn local_of(&self, global_pid: usize) -> Option<u32> {
        self.map.get(&global_pid).copied()
    }

    /// Translate local → global.
    fn global_of(&self, local_pid: u32) -> Option<usize> {
        self.rmap.get(&local_pid).copied()
    }

    /// Remove all entries for a global PID (called on process exit).
    fn remove(&mut self, global_pid: usize) {
        if let Some(local) = self.map.remove(&global_pid) {
            self.rmap.remove(&local);
        }
    }
}

// ─── Global registry ────────────────────────────────────────────────────────

struct PidNsTable {
    entries: BTreeMap<NsId, PidNs>,
}

impl PidNsTable {
    const fn new() -> Self { PidNsTable { entries: BTreeMap::new() } }

    fn get_or_create(&mut self, ns: NsId) -> &mut PidNs {
        self.entries.entry(ns).or_insert_with(PidNs::new)
    }

    fn get(&self, ns: NsId) -> Option<&PidNs> {
        self.entries.get(&ns)
    }

    fn get_mut(&mut self, ns: NsId) -> Option<&mut PidNs> {
        self.entries.get_mut(&ns)
    }
}

static PID_NS_TABLE: Mutex<PidNsTable> = Mutex::new(PidNsTable::new());

// ─── Public API ──────────────────────────────────────────────────────────────

/// Register `global_pid` into namespace `ns` and return its local PID.
/// Call this from fork/clone when creating a process inside a non-INIT pid-ns.
/// The first process registered becomes local PID 1 (the ns-init).
pub fn register_pid(ns: NsId, global_pid: usize) -> u32 {
    if ns == INIT_NS {
        return global_pid as u32;
    }
    let mut tbl = PID_NS_TABLE.lock();
    tbl.get_or_create(ns).alloc(global_pid)
}

/// Translate `global_pid` to its local PID as seen from namespace `ns`.
/// Returns the global PID unchanged for INIT_NS or unregistered namespaces.
pub fn local_pid(ns: NsId, global_pid: usize) -> usize {
    if ns == INIT_NS { return global_pid; }
    let tbl = PID_NS_TABLE.lock();
    tbl.get(ns)
        .and_then(|n| n.local_of(global_pid))
        .map(|l| l as usize)
        .unwrap_or(global_pid)
}

/// Translate a local PID (as seen in namespace `ns`) back to the global PID.
/// Returns `local` unchanged for INIT_NS.
pub fn global_pid(ns: NsId, local: usize) -> usize {
    if ns == INIT_NS { return local; }
    let tbl = PID_NS_TABLE.lock();
    tbl.get(ns)
        .and_then(|n| n.global_of(local as u32))
        .unwrap_or(local)
}

/// Remove a process from its PID namespace on exit.
pub fn unregister_pid(ns: NsId, global_pid: usize) {
    if ns == INIT_NS { return; }
    let mut tbl = PID_NS_TABLE.lock();
    if let Some(ns_entry) = tbl.get_mut(ns) {
        ns_entry.remove(global_pid);
    }
}

/// Returns the visible PID of the *current* process according to its own
/// pid namespace.  Used by getpid(2).
///
/// Resolves: global → local in the process's own pid-ns.
pub fn current_visible_pid() -> usize {
    let pid = crate::proc::scheduler::current_pid();
    let ns  = crate::proc::scheduler::with_proc(pid, |p| p.ns.pid)
                  .unwrap_or(INIT_NS);
    local_pid(ns, pid)
}

/// Returns the visible PPID.  If the parent is outside this pid-ns, returns 0
/// (the "unknown parent" convention Linux uses for namespace boundaries).
pub fn current_visible_ppid() -> usize {
    let pid  = crate::proc::scheduler::current_pid();
    let (ppid, ns) = crate::proc::scheduler::with_proc(pid, |p| (p.ppid, p.ns.pid))
                          .unwrap_or((0, INIT_NS));
    if ns == INIT_NS { return ppid; }
    // Check whether ppid is visible in this ns.
    let tbl = PID_NS_TABLE.lock();
    match tbl.get(ns).and_then(|n| n.local_of(ppid)) {
        Some(local) => local as usize,
        None        => 0, // parent is outside this ns
    }
}
