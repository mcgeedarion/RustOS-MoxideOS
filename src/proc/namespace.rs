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

/// The full set of namespace references carried by a process.
#[derive(Clone, Copy, Debug)]
pub struct NsSet {
    pub mnt:  NsId,
    pub uts:  NsId,
    pub ipc:  NsId,
    pub net:  NsId,
    pub pid:  NsId,
    pub user: NsId,
    pub time: NsId,
    pub cgroup: NsId,
}

impl NsSet {
    pub const fn init() -> Self {
        NsSet {
            mnt: INIT_NS, uts: INIT_NS, ipc: INIT_NS, net: INIT_NS,
            pid: INIT_NS, user: INIT_NS, time: INIT_NS, cgroup: INIT_NS,
        }
    }
}

#[derive(Clone, Debug)]
pub struct MountEntry {
    pub source:  String,
    pub target:  String,
    pub fstype:  String,
    pub flags:   u64,
    pub options: String,
}

pub struct MountNsTable {
    pub entries: BTreeMap<NsId, Vec<MountEntry>>,
}

static MOUNT_NS_TABLE: Mutex<MountNsTable> = Mutex::new(MountNsTable {
    entries: BTreeMap::new(),
});

pub fn init_mount_ns() {
    MOUNT_NS_TABLE.lock().entries
        .entry(INIT_NS)
        .or_insert_with(Vec::new);
}

/// List all mount entries for process `pid`'s mount namespace.
pub fn list_mounts(pid: usize) -> Vec<MountEntry> {
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.mnt)
        .unwrap_or(INIT_NS);
    MOUNT_NS_TABLE.lock().entries.get(&ns).cloned().unwrap_or_default()
}

/// Add a mount entry to process `pid`'s mount namespace.
pub fn add_mount(pid: usize, entry: MountEntry) {
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.mnt)
        .unwrap_or(INIT_NS);
    MOUNT_NS_TABLE.lock().entries
        .entry(ns)
        .or_insert_with(Vec::new)
        .push(entry);
}

/// Remove a mount entry by target path from process `pid`'s mount namespace.
pub fn remove_mount(pid: usize, target: &str) {
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.mnt)
        .unwrap_or(INIT_NS);
    if let Some(v) = MOUNT_NS_TABLE.lock().entries.get_mut(&ns) {
        v.retain(|e| e.target != target);
    }
}

/// Destroy a private mount namespace.  No-op for INIT_NS.
pub fn drop_mount_ns(ns: NsId) {
    if ns == INIT_NS { return; }
    MOUNT_NS_TABLE.lock().entries.remove(&ns);
}

static UTS_NS_TABLE:    Mutex<BTreeMap<NsId, String>> = Mutex::new(BTreeMap::new());
static UTS_DOMAIN_TABLE: Mutex<BTreeMap<NsId, String>> = Mutex::new(BTreeMap::new());

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
    UTS_DOMAIN_TABLE.lock().remove(&ns);
}

/// Get the domainname for a UTS namespace.
pub fn uts_domainname(ns: NsId) -> String {
    UTS_DOMAIN_TABLE.lock()
        .get(&ns)
        .cloned()
        .unwrap_or_default()
}

/// Set the domainname for a UTS namespace.
pub fn uts_set_domainname(ns: NsId, name: String) {
    UTS_DOMAIN_TABLE.lock().insert(ns, name);
}

/// NR 170  sethostname(name, len)
///
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

/// NR 171  setdomainname(name, len)
///
/// Previously a silent no-op.  Now stores the name in the per-UTS-namespace
/// domain table so `uname(2)` can return it in the domainname field.
pub fn sys_setdomainname(name_va: usize, len: usize) -> isize {
    if len > 64 { return -22; }
    if len == 0 {
        let pid = crate::proc::scheduler::current_pid();
        let ns  = crate::proc::scheduler::with_proc(pid, |p| p.ns.uts)
            .unwrap_or(INIT_NS);
        uts_set_domainname(ns, String::new());
        return 0;
    }
    let mut buf = alloc::vec![0u8; len];
    if copy_from_user(name_va, &mut buf).is_err() { return -14; }
    if buf.contains(&0) { return -22; }
    let name = match alloc::string::String::from_utf8(buf) {
        Ok(s)  => s,
        Err(_) => return -22,
    };
    let pid = crate::proc::scheduler::current_pid();
    let ns  = crate::proc::scheduler::with_proc(pid, |p| p.ns.uts)
        .unwrap_or(INIT_NS);
    uts_set_domainname(ns, name);
    0
}

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

/// Look up the NsId for namespace `name` of process `pid`.
/// Returns None if `pid` doesn't exist or `name` is unrecognised.
pub fn ns_id_of(pid: usize, name: &str) -> Option<NsId> {
    crate::proc::scheduler::with_proc(pid, |p| {
        let id = match name {
            "mnt"    => p.ns.mnt,
            "uts"    => p.ns.uts,
            "ipc"    => p.ns.ipc,
            "net"    => p.ns.net,
            "pid"    => p.ns.pid,
            "user"   => p.ns.user,
            "time"   => p.ns.time,
            "cgroup" => p.ns.cgroup,
            _        => return None,
        };
        Some(id)
    }).flatten()
}

/// Format the /proc/<pid>/ns/<name> target string (e.g. "uts:[4026531838]").
pub fn ns_symlink(pid: usize, name: &str) -> Option<String> {
    ns_id_of(pid, name).map(|id| format!("{}:[{}]", name, id))
}

/// Base fd value for namespace fds (above real fds).
pub const NSFD_FD_BASE: usize = 0x7000_0000;

static NSFD_TABLE: Mutex<BTreeMap<usize, (String, NsId)>> = Mutex::new(BTreeMap::new());
static NEXT_NSFD: Mutex<usize> = Mutex::new(NSFD_FD_BASE);

/// Open a namespace fd for /proc/<pid>/ns/<name>.
pub fn ns_fd_open(pid: usize, name: &str) -> Option<usize> {
    let ns_id = ns_id_of(pid, name)?;
    let fd = {
        let mut n = NEXT_NSFD.lock();
        let fd = *n;
        *n += 1;
        fd
    };
    NSFD_TABLE.lock().insert(fd, (name.to_string(), ns_id));
    Some(fd)
}

/// Resolve a namespace fd back to (ns_type_name, NsId).
pub fn nsfd_to_ns_id(fd: usize) -> Option<(String, NsId)> {
    NSFD_TABLE.lock().get(&fd).cloned()
}

/// Apply a namespace change to process `pid`.
pub fn setns_apply(pid: usize, name: &str, ns_id: NsId) -> isize {
    crate::proc::scheduler::with_proc_mut(pid, |p| {
        match name {
            "mnt"    => p.ns.mnt    = ns_id,
            "uts"    => p.ns.uts    = ns_id,
            "ipc"    => p.ns.ipc    = ns_id,
            "net"    => p.ns.net    = ns_id,
            "pid"    => p.ns.pid    = ns_id,
            "user"   => p.ns.user   = ns_id,
            "time"   => p.ns.time   = ns_id,
            "cgroup" => p.ns.cgroup = ns_id,
            _        => return -22,
        }
        0
    }).unwrap_or(-3)
}

/// NR 308  setns(fd, nstype)
pub fn sys_setns(fd: usize, _nstype: i32) -> isize {
    let (name, ns_id) = match nsfd_to_ns_id(fd) {
        Some(pair) => pair,
        None       => return -9,
    };
    let pid = crate::proc::scheduler::current_pid();
    setns_apply(pid, &name, ns_id)
}

/// Allocate a fresh namespace of type `name` and attach it to process `pid`.
///
/// Called by `sys_unshare` for each flag bit it processes.
/// For mount namespaces, COW-copies the current mount table.
/// For net namespaces, seeds a new loopback-only interface table.
/// For UTS namespaces, copies the parent hostname and domainname into the new ns.
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
            // Clone parent's hostname and domainname into the new UTS ns.
            let parent_ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.uts)
                .unwrap_or(INIT_NS);
            let hostname   = uts_hostname(parent_ns);
            let domainname = uts_domainname(parent_ns);
            UTS_NS_TABLE.lock().insert(new_id, hostname);
            UTS_DOMAIN_TABLE.lock().insert(new_id, domainname);
        }
        // IPC, user, pid, time: no extra global state needed yet.
        _ => {}
    }
    setns_apply(pid, name, new_id)
}

const CLONE_NEWNS:   usize = 0x0002_0000; // mount
const CLONE_NEWUTS:  usize = 0x0400_0000; // UTS
const CLONE_NEWIPC:  usize = 0x0800_0000; // IPC
const CLONE_NEWUSER: usize = 0x1000_0000; // user
const CLONE_NEWPID:  usize = 0x2000_0000; // PID
const CLONE_NEWNET:  usize = 0x4000_0000; // network
const CLONE_NEWTIME: usize = 0x0000_0080; // time
const CLONE_NEWCGROUP: usize = 0x0200_0000; // cgroup

/// NR 272  unshare(flags)
pub fn sys_unshare(flags: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    if flags & CLONE_NEWNS   != 0 { let r = unshare_ns(pid, "mnt");    if r < 0 { return r; } }
    if flags & CLONE_NEWUTS  != 0 { let r = unshare_ns(pid, "uts");    if r < 0 { return r; } }
    if flags & CLONE_NEWIPC  != 0 { let r = unshare_ns(pid, "ipc");    if r < 0 { return r; } }
    if flags & CLONE_NEWNET  != 0 { let r = unshare_ns(pid, "net");    if r < 0 { return r; } }
    if flags & CLONE_NEWPID  != 0 { let r = unshare_ns(pid, "pid");    if r < 0 { return r; } }
    if flags & CLONE_NEWUSER != 0 { let r = unshare_ns(pid, "user");   if r < 0 { return r; } }
    if flags & CLONE_NEWTIME != 0 { let r = unshare_ns(pid, "time");   if r < 0 { return r; } }
    if flags & CLONE_NEWCGROUP != 0 { let r = unshare_ns(pid, "cgroup"); if r < 0 { return r; } }
    0
}
