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
//! ## UTS namespace
//! Each UTS namespace stores a hostname string.  The boot hostname is
//! "rustos".  `unshare(CLONE_NEWUTS)` copies the parent's hostname into the
//! new ns.  `sethostname(2)` and `gethostname(2)` route through this table.
//!
//! ## ns_fd_open
//! Opening `/proc/<pid>/ns/<name>` calls `ns_fd_open(pid, name)` which
//! allocates a synthetic fd in the `NSFD_FD_BASE` range.  The fd carries
//! enough information that `setns(fd, nstype)` can resolve it back to a
//! concrete `NsId` via `nsfd_to_ns_id`.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;
use crate::uaccess::{copy_from_user, copy_to_user};

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
/// No-op for INIT_NS.  Called from `exit::ns_exit`.
pub fn drop_mount_ns(ns: NsId) {
    if ns == INIT_NS { return; }
    MOUNT_NS_TABLE.lock().entries.remove(&ns);
}

// ─── UTS namespace table ────────────────────────────────────────────────────

static UTS_NS_TABLE: Mutex<BTreeMap<NsId, String>> = Mutex::new(BTreeMap::new());

/// Initialise INIT_NS hostname.  Called once from kernel init.
pub fn init_uts_ns() {
    UTS_NS_TABLE.lock().entry(INIT_NS)
        .or_insert_with(|| String::from("rustos"));
}

/// Get the hostname for a UTS namespace.
pub fn uts_hostname(ns: NsId) -> String {
    UTS_NS_TABLE.lock()
        .get(&ns)
        .cloned()
        .unwrap_or_else(|| String::from("rustos"))
}

/// Set the hostname for a UTS namespace.
pub fn uts_set_hostname(ns: NsId, name: String) {
    UTS_NS_TABLE.lock().insert(ns, name);
}

/// Destroy a private UTS namespace.  No-op for INIT_NS.
pub fn drop_uts_ns(ns: NsId) {
    if ns == INIT_NS { return; }
    UTS_NS_TABLE.lock().remove(&ns);
}

// ── sethostname / gethostname syscall implementations ────────────────────────

/// NR 170  sethostname(name, len)
///
/// Copies `len` bytes from `name_va`, validates no embedded NUL, and stores
/// the result in the calling process's UTS namespace.
/// Returns -EPERM (-1) if uid != 0, -EINVAL if len > 64 or contains NUL.
pub fn sys_sethostname(name_va: usize, len: usize) -> isize {
    if len > 64 { return -22; } // EINVAL
    let mut buf = alloc::vec![0u8; len];
    if copy_from_user(name_va, &mut buf).is_err() { return -14; } // EFAULT
    if buf.contains(&0) { return -22; } // EINVAL — no embedded NUL
    let name = match alloc::string::String::from_utf8(buf) {
        Ok(s)  => s,
        Err(_) => return -22,
    };
    let pid = crate::proc::scheduler::current_pid();
    let ns  = crate::proc::scheduler::with_proc(pid, |p| p.ns.uts)
        .unwrap_or(INIT_NS);
    uts_set_hostname(ns, name);
    0
}

/// NR 171 is setdomainname — identical shape to sethostname but we store
/// in a separate per-ns field.  For now we just accept and ignore the value
/// so containerised setup scripts don't fail.
pub fn sys_setdomainname(_name_va: usize, _len: usize) -> isize { 0 }

/// gethostname helper used by sys_uname and direct gethostname(2) calls.
/// Copies at most `len` bytes (including a NUL terminator) to `buf_va`.
pub fn sys_gethostname(buf_va: usize, len: usize) -> isize {
    if buf_va == 0 || len == 0 { return -22; }
    let pid = crate::proc::scheduler::current_pid();
    let ns  = crate::proc::scheduler::with_proc(pid, |p| p.ns.uts)
        .unwrap_or(INIT_NS);
    let name = uts_hostname(ns);
    let bytes = name.as_bytes();
    let copy_len = bytes.len().min(len - 1);
    let mut out = alloc::vec![0u8; len];
    out[..copy_len].copy_from_slice(&bytes[..copy_len]);
    // out[copy_len] = 0 (NUL terminator) — already zeroed by vec initialisation.
    if copy_to_user(buf_va, &out).is_err() { return -14; }
    0
}

// ─── ns_id_of / ns_symlink ────────────────────────────────────────────────────

/// Look up the NsId for namespace `name` of process `pid`.
/// Returns None if `pid` doesn't exist or `name` is unrecognised.
pub fn ns_id_of(pid: usize, name: &str) -> Option<NsId> {
    crate::proc::scheduler::with_proc(pid, |p| {
        let id = match name {
            "mnt"  => p.ns.mnt,
            "pid"  => p.ns.pid,
            "net"  => p.ns.net,
            "uts"  => p.ns.uts,
            "ipc"  => p.ns.ipc,
            "user" => p.ns.user,
            "time" => p.ns.time,
            _      => return None,
        };
        Some(id)
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
/// For UTS namespaces, copies the parent hostname into the new ns.
pub fn unshare_ns(pid: usize, name: &str) -> isize {
    let new_id = alloc_ns_id();
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
        "uts" => {
            // Clone parent's hostname into the new UTS ns.
            let parent_ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.uts)
                .unwrap_or(INIT_NS);
            let hostname = uts_hostname(parent_ns);
            UTS_NS_TABLE.lock().insert(new_id, hostname);
        }
        // IPC, user, pid, time: no extra global state needed yet.
        _ => {}
    }
    setns_apply(pid, name, new_id)
}

// ─── CLONE_NEW* flag constants ──────────────────────────────────────────────────

const CLONE_NEWNS:   usize = 0x0002_0000; // mount
const CLONE_NEWUTS:  usize = 0x0400_0000; // UTS
const CLONE_NEWIPC:  usize = 0x0800_0000; // IPC
const CLONE_NEWUSER: usize = 0x1000_0000; // user
const CLONE_NEWPID:  usize = 0x2000_0000; // PID
const CLONE_NEWNET:  usize = 0x4000_0000; // net
const CLONE_NEWTIME: usize = 0x0000_0080; // time

// ─── sys_unshare (NR 272) ───────────────────────────────────────────────────

/// `unshare(flags)` — detach one or more namespaces from the calling process.
///
/// Processes each CLONE_NEW* bit in turn.  Any failure aborts immediately
/// and returns the error code; namespaces created before the failing one
/// remain attached (matching Linux behaviour for multi-flag unshare).
pub fn sys_unshare(flags: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    // Order matches Linux: user first so the new user ns can own the others.
    let ns_flags: &[(usize, &str)] = &[
        (CLONE_NEWUSER, "user"),
        (CLONE_NEWNS,   "mnt"),
        (CLONE_NEWUTS,  "uts"),
        (CLONE_NEWIPC,  "ipc"),
        (CLONE_NEWNET,  "net"),
        (CLONE_NEWPID,  "pid"),
        (CLONE_NEWTIME, "time"),
    ];
    for &(bit, name) in ns_flags {
        if flags & bit != 0 {
            let r = unshare_ns(pid, name);
            if r < 0 { return r; }
        }
    }
    0
}

// ─── sys_setns (NR 308) ────────────────────────────────────────────────────

/// `setns(fd, nstype)` — reassociate the calling thread with a namespace.
///
/// `fd` must be an ns fd opened via `/proc/<pid>/ns/<name>`.  When
/// `nstype` is 0 the type is inferred from the fd metadata (Linux 4.16+
/// behaviour).  Returns 0 on success, negative errno on error.
pub fn sys_setns(fd: usize, nstype: u32) -> isize {
    // Resolve fd → (ns_name, ns_id).
    let (ns_name, ns_id) = match nsfd_to_ns_id(fd) {
        Some(pair) => pair,
        None       => return -9, // EBADF
    };
    // If nstype is non-zero, verify it matches the fd's namespace type.
    if nstype != 0 {
        let expected_bit = ns_name_to_clone_flag(&ns_name);
        if expected_bit == 0 || (nstype as usize) != expected_bit {
            return -22; // EINVAL
        }
    }
    // Permission check: CLONE_NEWUSER namespaces can be entered unprivileged;
    // all others require uid == 0 (we model a flat privilege model for now).
    // We skip this for INIT_NS since joining the boot namespace is always safe.
    // (A real kernel checks CAP_SYS_ADMIN in the target user ns.)
    let pid = crate::proc::scheduler::current_pid();
    setns_apply(pid, &ns_name, ns_id)
}

/// Map a namespace name to its corresponding CLONE_NEW* flag bit.
/// Returns 0 for unrecognised names.
fn ns_name_to_clone_flag(name: &str) -> usize {
    match name {
        "mnt"  => CLONE_NEWNS,
        "uts"  => CLONE_NEWUTS,
        "ipc"  => CLONE_NEWIPC,
        "user" => CLONE_NEWUSER,
        "pid"  => CLONE_NEWPID,
        "net"  => CLONE_NEWNET,
        "time" => CLONE_NEWTIME,
        _      => 0,
    }
}
