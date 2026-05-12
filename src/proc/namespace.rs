//! Linux namespaces — mount (NEWNS), PID (NEWPID), network (NEWNET),
//! UTS (NEWUTS), IPC (NEWIPC), and user (NEWUSER).
//!
//! ## Syscalls implemented
//!   unshare(flags)         [NR 272] — detach the current process from
//!                                     one or more shared namespaces.
//!   setns(fd, nstype)      [NR 308] — attach to an existing namespace
//!                                     via a namespace fd (/proc/<pid>/ns/*)
//!
//! ## Semantic enforcement (what's actually isolated)
//!
//! | Namespace | Isolation provided                                       |
//! |-----------|----------------------------------------------------------|
//! | NEWNS     | Private mount table cloned from parent on unshare.        |
//! |           | vfs_ops resolves paths through per-process ns.mnt id.     |
//! | NEWPID    | Children get local PIDs starting from 2; first child = 1. |
//! |           | getpid()/getppid() translate via pid_ns::local_pid().     |
//! | NEWNET    | Per-ns interface registry; socket isolation via           |
//! |           | net_ns::check_socket_ns().  New ns starts with lo only.   |
//! | NEWUTS    | NsId tracked; hostname/domainname per-ns (future).        |
//! | NEWIPC    | NsId tracked; SysV/POSIX IPC per-ns (future).            |
//! | NEWUSER   | NsId tracked; uid/gid mapping per-ns (future).           |
//!
//! ## Mount namespace implementation
//! `MOUNT_NS_TABLE` maps NsId → private `MountTable` snapshot.
//! INIT_NS processes always use the global `MOUNT_TABLE` in mount.rs.
//! On `unshare(CLONE_NEWNS)` the caller's current effective mount table
//! is deep-copied into a new entry for the fresh NsId.
//!
//! `resolve_for_ns(ns, path)` is the single entry point used by
//! `vfs_ops` to resolve paths — it selects the right table automatically.
//!
//! On `mount(2)` / `umount2(2)`, the per-process ns.mnt is passed so
//! the mutation lands in the correct table.
//!
//! ## /proc/<pid>/ns/ file descriptors
//! `ns_fd_open(pid, nstype)` produces a synthetic fd ≥ NSFD_FD_BASE.
//! `setns` resolves the fd → (NsId, nstype) and installs it in the PCB.
//!
//! ## setns(2) restrictions enforced
//! * CAP_SYS_ADMIN (capability 21) is required for all ns types except
//!   NSTYPE_USER when the caller already owns a user namespace.
//! * Joining NSTYPE_PID or NSTYPE_USER from a multi-threaded process
//!   returns EINVAL, matching Linux kernel behaviour.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::fs::mount::{MountEntry, FsHandle};

// ─── CLONE_NEW* flag constants ───────────────────────────────────────────────

pub const CLONE_NEWTIME:  u64 = 0x0000_0080;
pub const CLONE_NEWNS:    u64 = 0x0002_0000;  // mount
pub const CLONE_NEWUTS:   u64 = 0x0400_0000;
pub const CLONE_NEWIPC:   u64 = 0x0800_0000;
pub const CLONE_NEWUSER:  u64 = 0x1000_0000;
pub const CLONE_NEWPID:   u64 = 0x2000_0000;
pub const CLONE_NEWNET:   u64 = 0x4000_0000;

pub const ALL_NS_FLAGS: u64 =
    CLONE_NEWTIME | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
    CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;

// ─── nstype constants used by setns(2) ──────────────────────────────────────

pub const NSTYPE_ANY:    u32 = 0;
pub const NSTYPE_MNT:    u32 = 0x0002_0000;
pub const NSTYPE_UTS:    u32 = 0x0400_0000;
pub const NSTYPE_IPC:    u32 = 0x0800_0000;
pub const NSTYPE_USER:   u32 = 0x1000_0000;
pub const NSTYPE_PID:    u32 = 0x2000_0000;
pub const NSTYPE_NET:    u32 = 0x4000_0000;
pub const NSTYPE_TIME:   u32 = 0x0000_0080;

// ─── NsId ────────────────────────────────────────────────────────────────────

pub type NsId = u64;

static NS_COUNTER: AtomicU64 = AtomicU64::new(2); // 1 = initial namespace

pub fn alloc_ns_id() -> NsId {
    NS_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The initial (root) namespace id shared by all boot-time processes.
pub const INIT_NS: NsId = 1;

// ─── Per-process namespace set ───────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NsSet {
    pub mnt:  NsId,
    pub uts:  NsId,
    pub ipc:  NsId,
    pub user: NsId,
    pub pid:  NsId,
    pub net:  NsId,
    pub time: NsId,
}

impl Default for NsSet {
    fn default() -> Self {
        NsSet {
            mnt: INIT_NS, uts: INIT_NS, ipc: INIT_NS,
            user: INIT_NS, pid: INIT_NS, net: INIT_NS, time: INIT_NS,
        }
    }
}

impl NsSet {
    pub fn inherit(parent: &NsSet) -> Self { parent.clone() }

    /// Allocate fresh NsIds for CLONE_NEW* bits.  Side-effects: also
    /// creates the backing state for mount, pid, and net namespaces.
    pub fn unshare_flags(&mut self, flags: u64) {
        if flags & CLONE_NEWNS != 0 {
            let new_id = alloc_ns_id();
            // Deep-copy the caller's current mount table into the new ns.
            fork_mount_ns(self.mnt, new_id);
            self.mnt = new_id;
        }
        if flags & CLONE_NEWUTS  != 0 { self.uts  = alloc_ns_id(); }
        if flags & CLONE_NEWIPC  != 0 { self.ipc  = alloc_ns_id(); }
        if flags & CLONE_NEWUSER != 0 { self.user = alloc_ns_id(); }
        if flags & CLONE_NEWPID  != 0 {
            // PID ns takes effect for children; record the new id.
            self.pid = alloc_ns_id();
            // No explicit create needed — pid_ns creates on first register.
        }
        if flags & CLONE_NEWNET != 0 {
            let new_id = alloc_ns_id();
            crate::proc::net_ns::create_net_ns(new_id);
            self.net = new_id;
        }
        if flags & CLONE_NEWTIME != 0 { self.time = alloc_ns_id(); }
    }

    pub fn is_user_ns(&self) -> bool { self.user != INIT_NS }
}

// ─── Mount namespace table ───────────────────────────────────────────────────
//
// Maps NsId → Vec<MountEntry> (a private snapshot of the mount table).
// INIT_NS is NOT stored here; reads for INIT_NS fall through to
// crate::fs::mount::resolve() and list_mounts() directly.

struct MountNsTable {
    entries: BTreeMap<NsId, alloc::vec::Vec<MountEntry>>,
}

impl MountNsTable {
    const fn new() -> Self { MountNsTable { entries: BTreeMap::new() } }

    /// Fork: copy `src_ns`'s table into `dst_ns`.
    /// If `src_ns == INIT_NS`, snapshot the global table.
    fn fork(&mut self, src_ns: NsId, dst_ns: NsId) {
        let snapshot: alloc::vec::Vec<MountEntry> = if src_ns == INIT_NS {
            crate::fs::mount::list_mounts()
        } else {
            self.entries.get(&src_ns).cloned().unwrap_or_default()
        };
        self.entries.insert(dst_ns, snapshot);
    }

    /// Mount: add or update an entry in ns `id`.
    fn mount(&mut self, ns: NsId, entry: MountEntry) -> Result<(), isize> {
        let vec = self.entries.entry(ns).or_insert_with(|| {
            crate::fs::mount::list_mounts()
        });
        // Reject duplicate mountpoints (caller handles MS_REMOUNT).
        if vec.iter().any(|e| e.mountpoint == entry.mountpoint) {
            return Err(-16); // EBUSY
        }
        vec.push(entry);
        // Sort: longest mountpoint first for correct prefix matching.
        vec.sort_by(|a, b| b.mountpoint.len().cmp(&a.mountpoint.len()));
        Ok(())
    }

    /// Remount: update flags on an existing entry.
    fn remount(&mut self, ns: NsId, mountpoint: &str, new_flags: u64) -> Result<(), isize> {
        let vec = match self.entries.get_mut(&ns) {
            Some(v) => v,
            None    => return Err(-22), // EINVAL — no private table
        };
        for e in vec.iter_mut() {
            if e.mountpoint == mountpoint {
                e.flags = new_flags & !crate::fs::mount::MS_REMOUNT;
                return Ok(());
            }
        }
        Err(-22)
    }

    /// Umount: remove an entry from ns `id`.
    fn umount(&mut self, ns: NsId, mountpoint: &str) -> Result<(), isize> {
        let vec = match self.entries.get_mut(&ns) {
            Some(v) => v,
            None    => return Err(-22),
        };
        let before = vec.len();
        vec.retain(|e| e.mountpoint != mountpoint);
        if vec.len() == before { Err(-22) } else { Ok(()) }
    }

    /// Resolve a path to an FsHandle using ns `id`'s table.
    fn resolve(&self, ns: NsId, path: &str) -> Option<FsHandle> {
        let vec = self.entries.get(&ns)?;
        crate::fs::mount::resolve_from_list(vec, path)
    }

    /// List all mount entries for ns `id`.
    fn list(&self, ns: NsId) -> alloc::vec::Vec<MountEntry> {
        self.entries.get(&ns).cloned().unwrap_or_default()
    }

    /// Lazily seed `ns` from the global table if it has no private entry.
    fn ensure_seeded(&mut self, ns: NsId) {
        if ns != INIT_NS && !self.entries.contains_key(&ns) {
            let snapshot = crate::fs::mount::list_mounts();
            self.entries.insert(ns, snapshot);
        }
    }
}

static MOUNT_NS_TABLE: Mutex<MountNsTable> = Mutex::new(MountNsTable::new());

// ─── Mount-ns public helpers ─────────────────────────────────────────────────

/// Deep-copy `src_ns`'s mount table into a new `dst_ns` entry.
/// Called by `NsSet::unshare_flags` and from clone with CLONE_NEWNS.
pub fn fork_mount_ns(src_ns: NsId, dst_ns: NsId) {
    MOUNT_NS_TABLE.lock().fork(src_ns, dst_ns);
}

/// Resolve `path` in mount namespace `ns`.
/// Falls back to the global table for INIT_NS.
pub fn resolve_for_ns(ns: NsId, path: &str) -> Result<FsHandle, isize> {
    if ns == INIT_NS {
        return crate::fs::mount::resolve(path);
    }
    let tbl = MOUNT_NS_TABLE.lock();
    match tbl.resolve(ns, path) {
        Some(h) => Ok(h),
        None    => {
            // Private table exists but path not found — try global fallback
            // (this handles paths that were mounted before the namespace fork
            // but for which the private snapshot is stale).
            drop(tbl);
            crate::fs::mount::resolve(path)
        }
    }
}

/// Resolve the current process's path in its own mount namespace.
/// This is the primary entry point for all vfs_ops path resolution.
pub fn resolve_path(path: &str) -> Result<FsHandle, isize> {
    let ns = current_mnt_ns();
    resolve_for_ns(ns, path)
}

/// Return the mount namespace id of the calling process.
pub fn current_mnt_ns() -> NsId {
    let pid = crate::proc::scheduler::current_pid();
    crate::proc::scheduler::with_proc(pid, |p| p.ns.mnt)
        .unwrap_or(INIT_NS)
}

/// Perform a mount(2) in the given ns.  For INIT_NS, delegates to
/// the global mount table; for other ns, mutates the private snapshot.
pub fn ns_mount(
    ns:       NsId,
    source:   &str,
    target:   &str,
    fstype_s: &str,
    flags:    u64,
    data:     &str,
) -> isize {
    // Always delegate INIT_NS (and remounts on INIT_NS) to the global table.
    if ns == INIT_NS {
        return crate::fs::mount::sys_mount(source, target, fstype_s, flags, data);
    }
    // For private namespaces, also handle MS_REMOUNT.
    if flags & crate::fs::mount::MS_REMOUNT != 0 {
        let mp = target.trim_end_matches('/').to_string();
        let mp = if mp.is_empty() { "/".to_string() } else { mp };
        return match MOUNT_NS_TABLE.lock().remount(ns, &mp, flags) {
            Ok(())  => 0,
            Err(e)  => e,
        };
    }
    // Parse the fstype and build a MountEntry.
    let fstype = match crate::fs::mount::FsType::from_str(fstype_s) {
        Some(t) => t,
        None    => return -22,
    };
    let overlay = if fstype == crate::fs::mount::FsType::Overlayfs {
        let mut lower = alloc::string::String::new();
        let mut upper = alloc::string::String::new();
        let mut work  = alloc::string::String::new();
        for kv in data.split(',') {
            if let Some(v) = kv.strip_prefix("lowerdir=") { lower = v.to_string(); }
            if let Some(v) = kv.strip_prefix("upperdir=") { upper = v.to_string(); }
            if let Some(v) = kv.strip_prefix("workdir=")  { work  = v.to_string(); }
        }
        if lower.is_empty() { return -22; }
        Some(crate::fs::mount::OverlayOpts { lower, upper, work })
    } else {
        None
    };
    let mp = target.trim_end_matches('/');
    let mp = if mp.is_empty() { "/".to_string() } else { mp.to_string() };
    let entry = MountEntry {
        mountpoint: mp,
        fstype,
        source: source.to_string(),
        flags,
        overlay,
    };
    match MOUNT_NS_TABLE.lock().mount(ns, entry) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

/// Perform umount2 in the given ns.
pub fn ns_umount(ns: NsId, target: &str, flags: u32) -> isize {
    if ns == INIT_NS {
        return crate::fs::mount::sys_umount2(target, flags);
    }
    let mp = target.trim_end_matches('/');
    let mp = if mp.is_empty() { "/".to_string() } else { mp.to_string() };
    match MOUNT_NS_TABLE.lock().umount(ns, &mp) {
        Ok(())  => 0,
        Err(e)  => e,
    }
}

/// List mount entries for the calling process's mount namespace.
/// Used by procfs to render /proc/mounts and /proc/self/mountinfo.
pub fn list_mounts_for_current() -> alloc::vec::Vec<MountEntry> {
    let ns = current_mnt_ns();
    if ns == INIT_NS {
        return crate::fs::mount::list_mounts();
    }
    MOUNT_NS_TABLE.lock().list(ns)
}

// ─── Namespace fd table ──────────────────────────────────────────────────────

pub const NSFD_FD_BASE: usize = 0x9000_0000;

#[derive(Clone)]
struct NsFdEntry {
    ns_id:  NsId,
    nstype: u32,
}

static NSFD_TABLE: Mutex<BTreeMap<usize, NsFdEntry>> =
    Mutex::new(BTreeMap::new());
static NSFD_COUNTER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Open a namespace fd for the given pid and ns type string.
pub fn ns_fd_open(pid: usize, nstype_str: &str) -> isize {
    let ns_set = match crate::proc::scheduler::with_proc(pid, |p| p.ns.clone()) {
        Some(n) => n,
        None    => return -3, // ESRCH
    };
    let (ns_id, nstype) = match nstype_str {
        "mnt"  | "mount" => (ns_set.mnt,  NSTYPE_MNT),
        "pid"            => (ns_set.pid,  NSTYPE_PID),
        "net"            => (ns_set.net,  NSTYPE_NET),
        "uts"            => (ns_set.uts,  NSTYPE_UTS),
        "ipc"            => (ns_set.ipc,  NSTYPE_IPC),
        "user"           => (ns_set.user, NSTYPE_USER),
        "time"           => (ns_set.time, NSTYPE_TIME),
        _                => return -22,
    };
    let id = NSFD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let fd = NSFD_FD_BASE + id;
    NSFD_TABLE.lock().insert(fd, NsFdEntry { ns_id, nstype });
    fd as isize
}

pub fn is_ns_fd(fdno: usize) -> bool {
    fdno >= NSFD_FD_BASE && NSFD_TABLE.lock().contains_key(&fdno)
}

pub fn ns_fd_close(fdno: usize) {
    NSFD_TABLE.lock().remove(&fdno);
}

// ─── sys_unshare ─────────────────────────────────────────────────────────────

/// unshare(flags)  [NR 272]
pub fn sys_unshare(flags: usize) -> isize {
    let flags = flags as u64;
    let valid = ALL_NS_FLAGS
        | crate::proc::clone::CLONE_FILES
        | crate::proc::clone::CLONE_FS
        | crate::proc::clone::CLONE_SYSVSEM;
    if flags & !valid != 0 { return -22; }

    let pid = crate::proc::scheduler::current_pid();
    if pid == 0 { return -1; }

    // CLONE_NEWUSER requires CAP_SYS_ADMIN unless already in a user ns.
    if flags & CLONE_NEWUSER != 0 {
        let in_user_ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.is_user_ns())
            .unwrap_or(false);
        if !in_user_ns && !crate::security::check_capability(21) {
            return -1; // EPERM
        }
    }

    let ns_flags = flags & ALL_NS_FLAGS;
    if ns_flags != 0 {
        crate::proc::scheduler::with_proc_mut(pid, |p| {
            p.ns.unshare_flags(ns_flags);
        });
    }
    0
}

// ─── sys_setns ───────────────────────────────────────────────────────────────

/// setns(fd, nstype)  [NR 308]
///
/// Restrictions enforced (matching Linux setns(2)):
///  1. fd must be a valid namespace fd (EBADF otherwise).
///  2. nstype, if non-zero, must match the fd's ns type (EINVAL).
///  3. CAP_SYS_ADMIN is required for every type except NSTYPE_USER when
///     the caller already lives in a non-initial user namespace (EPERM).
///  4. Joining NSTYPE_PID or NSTYPE_USER from a multi-threaded process
///     is rejected with EINVAL.
///  5. For NSTYPE_MNT, the target ns's mount table is lazily seeded
///     *before* taking the proc lock to avoid lock-order inversion.
pub fn sys_setns(fd: usize, nstype: u32) -> isize {
    // ── 1. Resolve the namespace fd ──────────────────────────────────────
    let entry = {
        let tbl = NSFD_TABLE.lock();
        match tbl.get(&fd) {
            Some(e) => e.clone(),
            None    => return -9, // EBADF
        }
    };

    // ── 2. nstype consistency check ──────────────────────────────────────
    if nstype != NSTYPE_ANY && nstype != entry.nstype {
        return -22; // EINVAL
    }

    let pid = crate::proc::scheduler::current_pid();
    if pid == 0 { return -1; }

    // ── 3. CAP_SYS_ADMIN check ───────────────────────────────────────────
    // NSTYPE_USER is exempt when the caller already owns a user namespace.
    let in_user_ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.is_user_ns())
        .unwrap_or(false);
    let needs_cap = entry.nstype != NSTYPE_USER || !in_user_ns;
    if needs_cap && !crate::security::check_capability(21) {
        return -1; // EPERM
    }

    // ── 4. Multi-thread guard for PID and USER namespaces ────────────────
    if entry.nstype == NSTYPE_PID || entry.nstype == NSTYPE_USER {
        let nthreads = crate::proc::scheduler::thread_count_of(pid).unwrap_or(1);
        if nthreads > 1 {
            return -22; // EINVAL
        }
    }

    // ── 5. NSTYPE_MNT: lazy-seed the target mount table *outside* the
    //       proc lock to prevent lock-order inversion with MOUNT_NS_TABLE.
    if entry.nstype == NSTYPE_MNT {
        let target = entry.ns_id;
        if target != INIT_NS {
            MOUNT_NS_TABLE.lock().ensure_seeded(target);
        }
    }
    // Similarly, ensure net-ns exists before taking the proc lock.
    if entry.nstype == NSTYPE_NET {
        crate::proc::net_ns::create_net_ns(entry.ns_id);
    }

    // ── 6. Install the new ns id into the PCB ────────────────────────────
    crate::proc::scheduler::with_proc_mut(pid, |p| {
        match entry.nstype {
            NSTYPE_MNT  => p.ns.mnt  = entry.ns_id,
            NSTYPE_PID  => p.ns.pid  = entry.ns_id,
            NSTYPE_NET  => p.ns.net  = entry.ns_id,
            NSTYPE_UTS  => p.ns.uts  = entry.ns_id,
            NSTYPE_IPC  => p.ns.ipc  = entry.ns_id,
            NSTYPE_USER => p.ns.user = entry.ns_id,
            NSTYPE_TIME => p.ns.time = entry.ns_id,
            _           => {}
        }
    });
    0
}

// ─── Helpers for /proc/<pid>/ns/ ─────────────────────────────────────────────

pub fn ns_id_of(pid: usize, nstype: &str) -> Option<NsId> {
    let ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.clone())?;
    Some(match nstype {
        "mnt"  => ns.mnt,
        "pid"  => ns.pid,
        "net"  => ns.net,
        "uts"  => ns.uts,
        "ipc"  => ns.ipc,
        "user" => ns.user,
        "time" => ns.time,
        _      => return None,
    })
}

pub fn ns_symlink(nstype: &str, id: NsId) -> String {
    let mut s = String::from(nstype);
    s.push_str(":[" );
    let mut buf = [0u8; 20];
    let mut n = id;
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    let digits = core::str::from_utf8(&buf[i..]).unwrap_or("0");
    s.push_str(digits);
    s.push(']');
    s
}
