//! Namespace tracking and `setns` / `unshare` support.
//!
//! ## NsId
//! A `NsId` is a `u64` inode-like identifier assigned when a namespace is
//! created.  INIT_NS (the boot-time namespace) uses a fixed value of
//! `0xF000_0000_0000_0000` so it sorts last in BTreeMaps and is easy to
//! recognise in debuggers.
//!
//! ## NsSet
//! Each process carries a `NsSet` struct (stored in `Process`) with one
//! `NsId` per namespace type.  Forking copies the NsSet; `unshare` or
//! `setns` replace one or more fields.
//!
//! ## Mount namespace
//! Mount namespaces hold a snapshot of the VFS mount table.  The global
//! `MOUNT_NS_TABLE` maps `NsId → Vec<MountEntry>`.  `unshare(CLONE_NEWNS)`
//! COW-copies the parent's mount list into a new entry; `sys_mount` and
//! `sys_umount` modify only the calling process's mount ns.
//!
//! ## ns_fd_open
//! Opening `/proc/<pid>/ns/<name>` calls `ns_fd_open(pid, name)` which
//! allocates a synthetic fd in the `NSFD_FD_BASE` range.  The fd carries
//! enough information that `setns(fd, nstype)` can resolve it back to a
//! concrete `NsId` via `nsfd_to_ns_id`.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

// ─── NsId ─────────────────────────────────────────────────────────────────────

/// Opaque namespace identifier (equivalent to Linux nsfs inode number).
pub type NsId = u64;

/// The boot-time namespace shared by all initial processes.
pub const INIT_NS: NsId = 0xF000_0000_0000_0000;

/// Monotonically-increasing counter for allocating fresh namespace IDs.
static NEXT_NS_ID: Mutex<NsId> = Mutex::new(1);

pub fn alloc_ns_id() -> NsId {
    let mut n = NEXT_NS_ID.lock();
    let id = *n;
    *n += 1;
    id
}

// ─── NsSet ───────────────────────────────────────────────────────────────────

/// The set of namespace IDs attached to one process.
#[derive(Clone, Debug)]
pub struct NsSet {
    pub mnt:  NsId,
    pub pid:  NsId,
    pub net:  NsId,
    pub uts:  NsId,
    pub ipc:  NsId,
    pub user: NsId,
    pub time: NsId,
}

impl NsSet {
    /// All fields point to INIT_NS (used for the first process and all
    /// processes that never call unshare/setns).
    pub const fn init() -> Self {
        NsSet {
            mnt:  INIT_NS,
            pid:  INIT_NS,
            net:  INIT_NS,
            uts:  INIT_NS,
            ipc:  INIT_NS,
            user: INIT_NS,
            time: INIT_NS,
        }
    }
}

// ─── Mount namespace table ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct MountEntry {
    pub source: String,
    pub target: String,
    pub fstype: String,
    pub flags:  u64,
}

struct MountNsTable {
    entries: BTreeMap<NsId, Vec<MountEntry>>,
}

impl MountNsTable {
    const fn new() -> Self { MountNsTable { entries: BTreeMap::new() } }
}

pub static MOUNT_NS_TABLE: Mutex<MountNsTable> = Mutex::new(MountNsTable::new());

/// Initialise the INIT_NS mount namespace with an empty mount list.
/// Called once from kernel init.
pub fn init_mount_ns() {
    MOUNT_NS_TABLE.lock().entries.entry(INIT_NS).or_insert_with(Vec::new);
}

/// Clone the parent's mount namespace into a new NsId.
/// Called by `unshare(CLONE_NEWNS)` and `clone(CLONE_NEWNS)`.
pub fn clone_mount_ns(parent_ns: NsId) -> NsId {
    let new_id = alloc_ns_id();
    let mounts: Vec<MountEntry> = {
        let tbl = MOUNT_NS_TABLE.lock();
        tbl.entries.get(&parent_ns).cloned().unwrap_or_default()
    };
    MOUNT_NS_TABLE.lock().entries.insert(new_id, mounts);
    new_id
}

/// Add a mount entry into the given mount namespace.
/// Called by `sys_mount`.
pub fn mount_ns_add(ns: NsId, entry: MountEntry) {
    MOUNT_NS_TABLE.lock()
        .entries
        .entry(ns)
        .or_insert_with(Vec::new)
        .push(entry);
}

/// Remove a mount entry (by target path) from the given mount namespace.
/// Called by `sys_umount2`.
pub fn mount_ns_remove(ns: NsId, target: &str) {
    if let Some(v) = MOUNT_NS_TABLE.lock().entries.get_mut(&ns) {
        v.retain(|e| e.target != target);
    }
}

/// List all mounts in a mount namespace.
pub fn mount_ns_list(ns: NsId) -> Vec<MountEntry> {
    MOUNT_NS_TABLE.lock()
        .entries
        .get(&ns)
        .cloned()
        .unwrap_or_default()
}

/// Destroy a private mount namespace when the last process holding it exits.
///
/// Removes the entry from `MOUNT_NS_TABLE`, freeing the mount list.
/// No-op for `INIT_NS` — the boot namespace is never freed.
/// Called from `exit::ns_exit` after confirming no other live process shares
/// the namespace.
pub fn drop_mount_ns(ns: NsId) {
    if ns == INIT_NS { return; }
    MOUNT_NS_TABLE.lock().entries.remove(&ns);
}

// ─── ns_id_of / ns_symlink ────────────────────────────────────────────────────

/// Look up the NsId for namespace `name` of process `pid`.
/// Returns None if `pid` doesn't exist or `name` is unrecognised.
pub fn ns_id_of(pid: usize, name: &str) -> Option<NsId> {
    crate::proc::scheduler::with_proc(pid, |p| {
        match name {
            "mnt"  => p.ns.mnt,
            "pid"  => p.ns.pid,
            "net"  => p.ns.net,
            "uts"  => p.ns.uts,
            "ipc"  => p.ns.ipc,
            "user" => p.ns.user,
            "time" => p.ns.time,
            _      => return None,
        }
        .into()
    })
    .flatten()
}

/// Format the symlink target string for a namespace pseudo-symlink,
/// e.g. `"mnt:[4026531840]"`.
pub fn ns_symlink(name: &str, ns_id: NsId) -> String {
    format!("{}:[{}]", name, ns_id)
}

// ─── Namespace fd (nsfd) table ────────────────────────────────────────────────

/// Synthetic fd numbers for namespace fds start here, well above the
/// procfs synthetic fd range (256–511).
pub const NSFD_FD_BASE: isize = 0x4000_0000;

struct NsFdEntry {
    ns_name: String,
    ns_id:   NsId,
}

struct NsFdTable {
    entries: BTreeMap<usize, NsFdEntry>,
    next:    usize,
}

impl NsFdTable {
    const fn new() -> Self {
        NsFdTable {
            entries: BTreeMap::new(),
            next:    NSFD_FD_BASE as usize,
        }
    }

    fn alloc(&mut self, ns_name: String, ns_id: NsId) -> usize {
        let fd = self.next;
        self.next += 1;
        self.entries.insert(fd, NsFdEntry { ns_name, ns_id });
        fd
    }
}

static NSFD_TABLE: Mutex<NsFdTable> = Mutex::new(NsFdTable::new());

/// Open a namespace fd for `/proc/<pid>/ns/<name>`.
///
/// Allocates a synthetic fd in the `NSFD_FD_BASE` range that records the
/// `NsId` so that `setns(2)` can resolve it without re-reading procfs.
/// Returns the fd number, or a negative errno on error.
pub fn ns_fd_open(pid: usize, name: &str) -> isize {
    let ns_id = match ns_id_of(pid, name) {
        Some(id) => id,
        None     => return -3, // ESRCH
    };
    let fd = NSFD_TABLE.lock().alloc(name.into(), ns_id);
    fd as isize
}

/// Close (free) a namespace fd.
pub fn ns_fd_close(fd: usize) {
    NSFD_TABLE.lock().entries.remove(&fd);
}

/// Resolve a namespace fd to its `(ns_name, NsId)` pair.
/// Used by `setns(2)` to identify which namespace to join.
pub fn nsfd_to_ns_id(fd: usize) -> Option<(String, NsId)> {
    let tbl = NSFD_TABLE.lock();
    tbl.entries.get(&fd).map(|e| (e.ns_name.clone(), e.ns_id))
}

// ─── setns / unshare helpers ──────────────────────────────────────────────────

/// Apply a new `NsId` for the named namespace slot on process `pid`.
///
/// Called by `sys_setns` after permission and compatibility checks pass.
pub fn setns_apply(pid: usize, name: &str, ns_id: NsId) -> isize {
    let ok = crate::proc::scheduler::with_proc_mut(pid, |p| {
        match name {
            "mnt"  => p.ns.mnt  = ns_id,
            "pid"  => p.ns.pid  = ns_id,
            "net"  => p.ns.net  = ns_id,
            "uts"  => p.ns.uts  = ns_id,
            "ipc"  => p.ns.ipc  = ns_id,
            "user" => p.ns.user = ns_id,
            "time" => p.ns.time = ns_id,
            _      => return,
        }
    });
    if ok.is_some() { 0 } else { -3 } // ESRCH
}

/// Allocate a fresh namespace of type `name` and attach it to process `pid`.
///
/// Called by `sys_unshare` for each flag bit it processes.
/// For mount namespaces, COW-copies the current mount table.
/// For net namespaces, seeds a new loopback-only interface table.
pub fn unshare_ns(pid: usize, name: &str) -> isize {
    let new_id = alloc_ns_id();
    // Type-specific initialisation
    match name {
        "mnt" => {
            let parent_ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.mnt)
                .unwrap_or(INIT_NS);
            let mounts: Vec<MountEntry> = {
                let tbl = MOUNT_NS_TABLE.lock();
                tbl.entries.get(&parent_ns).cloned().unwrap_or_default()
            };
            MOUNT_NS_TABLE.lock().entries.insert(new_id, mounts);
        }
        "net" => {
            crate::proc::net_ns::create_net_ns(new_id);
        }
        // UTS, IPC, user, pid, time: no extra global state needed yet.
        _ => {}
    }
    setns_apply(pid, name, new_id)
}
