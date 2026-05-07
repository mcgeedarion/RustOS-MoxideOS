//! Linux namespaces — mount (NEWNS), PID (NEWPID), network (NEWNET),
//! UTS (NEWUTS), IPC (NEWIPC), and user (NEWUSER).
//!
//! ## Syscalls implemented
//!   unshare(flags)         [NR 272] — detach the current process from
//!                                     one or more shared namespaces
//!   setns(fd, nstype)      [NR 308] — attach to an existing namespace
//!                                     via a namespace fd (/proc/<pid>/ns/*)
//!
//! ## Namespace ids
//!   Each namespace instance is identified by a `NsId` (u64 counter).
//!   A process carries one id per namespace type in its `NsSet`.
//!   Processes that share a namespace have the same id for that type.
//!
//! ## Namespace types and CLONE_NEW* flags
//!   CLONE_NEWNS    0x0002_0000  mount namespace
//!   CLONE_NEWUTS   0x0400_0000  hostname / domainname
//!   CLONE_NEWIPC   0x0800_0000  SysV IPC, POSIX MQ
//!   CLONE_NEWUSER  0x1000_0000  UID/GID mappings
//!   CLONE_NEWPID   0x2000_0000  PID namespace (child sees pid=1)
//!   CLONE_NEWNET   0x4000_0000  network stack
//!   CLONE_NEWTIME  0x0000_0080  clock offsets (Linux 5.6+)
//!
//! ## /proc/<pid>/ns/ file descriptors
//!   `ns_fd_open(pid, nstype)` produces a synthetic fd in the
//!   NSFD_FD_BASE range.  `setns` resolves the fd back to a NsId
//!   and installs it into the calling process.
//!
//! ## Integration with clone / fork
//!   fork.rs and clone.rs call `NsSet::inherit(&parent_ns)` to copy
//!   the parent's namespace ids into the child.  When CLONE_NEW* flags
//!   are set, they call `NsSet::unshare(flags)` on the child's NsSet
//!   before enqueuing it.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};

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

pub const NSTYPE_ANY:    u32 = 0;             // accept any type
pub const NSTYPE_MNT:    u32 = 0x0002_0000;  // CLONE_NEWNS
pub const NSTYPE_UTS:    u32 = 0x0400_0000;
pub const NSTYPE_IPC:    u32 = 0x0800_0000;
pub const NSTYPE_USER:   u32 = 0x1000_0000;
pub const NSTYPE_PID:    u32 = 0x2000_0000;
pub const NSTYPE_NET:    u32 = 0x4000_0000;
pub const NSTYPE_TIME:   u32 = 0x0000_0080;

// ─── NsId ────────────────────────────────────────────────────────────────────

pub type NsId = u64;

static NS_COUNTER: AtomicU64 = AtomicU64::new(2); // 1 = initial namespace

fn alloc_ns_id() -> NsId {
    NS_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// The initial (root) namespace id shared by all boot-time processes.
pub const INIT_NS: NsId = 1;

// ─── Per-process namespace set ───────────────────────────────────────────────

/// One namespace id per namespace type, stored in the PCB.
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
    /// Inherit all namespace ids from a parent.
    pub fn inherit(parent: &NsSet) -> Self { parent.clone() }

    /// Allocate fresh namespace ids for each CLONE_NEW* bit set in `flags`.
    /// Called by clone/fork after copying the parent's NsSet.
    pub fn unshare_flags(&mut self, flags: u64) {
        if flags & CLONE_NEWNS   != 0 { self.mnt  = alloc_ns_id(); }
        if flags & CLONE_NEWUTS  != 0 { self.uts  = alloc_ns_id(); }
        if flags & CLONE_NEWIPC  != 0 { self.ipc  = alloc_ns_id(); }
        if flags & CLONE_NEWUSER != 0 { self.user = alloc_ns_id(); }
        if flags & CLONE_NEWPID  != 0 { self.pid  = alloc_ns_id(); }
        if flags & CLONE_NEWNET  != 0 { self.net  = alloc_ns_id(); }
        if flags & CLONE_NEWTIME != 0 { self.time = alloc_ns_id(); }
    }

    /// Check whether this process is in a user namespace other than the root.
    pub fn is_user_ns(&self) -> bool { self.user != INIT_NS }
}

// ─── Namespace fd table ──────────────────────────────────────────────────────
//
// Maps a synthetic fd → (NsId, nstype u32).
// These fds are produced by open("/proc/<pid>/ns/mnt") etc. and consumed by setns.

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

/// Open a namespace fd for the given pid and ns type string
/// ("mnt", "pid", "net", "uts", "ipc", "user", "time").
/// Returns the synthetic fd, or -1 if pid/type is unknown.
pub fn ns_fd_open(pid: usize, nstype_str: &str) -> isize {
    let ns_set = match crate::proc::scheduler::with_proc(pid, |p| p.ns.clone()) {
        Some(n) => n,
        None    => return -3, // ESRCH
    };
    let (ns_id, nstype) = match nstype_str {
        "mnt"  | "mount"   => (ns_set.mnt,  NSTYPE_MNT),
        "pid"              => (ns_set.pid,  NSTYPE_PID),
        "net"              => (ns_set.net,  NSTYPE_NET),
        "uts"              => (ns_set.uts,  NSTYPE_UTS),
        "ipc"              => (ns_set.ipc,  NSTYPE_IPC),
        "user"             => (ns_set.user, NSTYPE_USER),
        "time"             => (ns_set.time, NSTYPE_TIME),
        _                  => return -22, // EINVAL
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
///
/// Detach the calling process from shared namespaces specified in flags.
/// Each CLONE_NEW* bit allocates a fresh NsId for that namespace type.
/// CLONE_FILES and CLONE_FS are accepted for completeness but are no-ops
/// because this kernel's fd table is already per-process.
pub fn sys_unshare(flags: usize) -> isize {
    let flags = flags as u64;
    // Reject unknown flag bits.
    let valid = ALL_NS_FLAGS
        | crate::proc::clone::CLONE_FILES
        | crate::proc::clone::CLONE_FS
        | crate::proc::clone::CLONE_SYSVSEM;
    if flags & !valid != 0 { return -22; } // EINVAL

    let pid = crate::proc::scheduler::current_pid();
    if pid == 0 { return -1; }

    // CLONE_NEWUSER requires CAP_SYS_ADMIN (or being in a user namespace).
    if flags & CLONE_NEWUSER != 0 {
        let in_user_ns = crate::proc::scheduler::with_proc(pid, |p| p.ns.is_user_ns())
            .unwrap_or(false);
        if !in_user_ns && !crate::security::check_capability(21 /* CAP_SYS_ADMIN */) {
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
/// Attach the calling process to the namespace referred to by `fd`
/// (a namespace fd opened via /proc/<pid>/ns/*).
/// `nstype` is a CLONE_NEW* flag that constrains which type of namespace
/// the fd may refer to (0 = accept any).
pub fn sys_setns(fd: usize, nstype: u32) -> isize {
    let entry = {
        let tbl = NSFD_TABLE.lock();
        match tbl.get(&fd) {
            Some(e) => e.clone(),
            None    => return -9, // EBADF
        }
    };
    // Validate nstype constraint.
    if nstype != NSTYPE_ANY && nstype != entry.nstype {
        return -22; // EINVAL
    }
    // Joining a PID namespace only affects children, not the calling process.
    // We record it in the PCB so that the next fork/clone uses the new pid ns.
    let pid = crate::proc::scheduler::current_pid();
    if pid == 0 { return -1; }

    crate::proc::scheduler::with_proc_mut(pid, |p| {
        match entry.nstype {
            NSTYPE_MNT  => p.ns.mnt  = entry.ns_id,
            NSTYPE_UTS  => p.ns.uts  = entry.ns_id,
            NSTYPE_IPC  => p.ns.ipc  = entry.ns_id,
            NSTYPE_USER => p.ns.user = entry.ns_id,
            NSTYPE_PID  => p.ns.pid  = entry.ns_id,
            NSTYPE_NET  => p.ns.net  = entry.ns_id,
            NSTYPE_TIME => p.ns.time = entry.ns_id,
            _           => {}
        }
    });
    0
}

// ─── Helpers for /proc/<pid>/ns/ procfs paths ────────────────────────────────

/// Returns the namespace id for a given pid and type string.
/// Used by procfs to render /proc/<pid>/ns/<type> as a symlink target.
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

/// Format a namespace symlink value like Linux does:
///   mnt:[4026531840]
pub fn ns_symlink(nstype: &str, id: NsId) -> String {
    let mut s = String::from(nstype);
    s.push_str(":[" );
    // Format id as decimal without alloc::format! (no std).
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
