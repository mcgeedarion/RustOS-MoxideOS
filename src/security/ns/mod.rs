//! Linux-compatible namespace subsystem.
//!
//! ## Implemented namespace types
//!
//! | Type  | Flag (clone/unshare) | Isolation |
//! |-------|----------------------|----------|
//! | PID   | `CLONE_NEWPID`       | PID number space; init=1 per ns |
//! | Mount | `CLONE_NEWNS`        | VFS mount-point table |
//! | Net   | `CLONE_NEWNET`       | Network interfaces + routing table |
//! | UTS   | `CLONE_NEWUTS`       | hostname + domainname |
//! | User  | `CLONE_NEWUSER`      | UID/GID mapping |
//!
//! IPC and Time namespaces are reserved stubs.
//!
//! ## Syscall surface
//!
//!   clone(2)   — CLONE_NEW* flags create a child inside a new ns
//!   unshare(2) — detach calling process into a new ns
//!   setns(2)   — attach to an existing ns via fd
//!   /proc/self/ns/{pid,mnt,net,uts,user} — nsfs inodes

pub mod mnt_ns;
pub mod net_ns;
pub mod pid_ns;
pub mod user_ns;
pub mod uts_ns;

extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

// ─────────────────────────────────────────────────────────────────────────────
// Clone / unshare flags  (match Linux UAPI)
// ─────────────────────────────────────────────────────────────────────────────

pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
pub const CLONE_NEWPID: u64 = 0x2000_0000;
pub const CLONE_NEWNET: u64 = 0x4000_0000;
pub const CLONE_NEWTIME: u64 = 0x0000_0080;

// ─────────────────────────────────────────────────────────────────────────────
// Namespace handle — Arc<NsHandle> is what a process holds
// ─────────────────────────────────────────────────────────────────────────────

/// Unique namespace ID (monotonically increasing).
static NEXT_NS_ID: AtomicU64 = AtomicU64::new(1);
pub fn alloc_ns_id() -> u64 {
    NEXT_NS_ID.fetch_add(1, Ordering::SeqCst)
}

/// The complete set of namespace references a process holds.
/// Cloned on fork; individual fields replaced by clone/unshare.
#[derive(Clone)]
pub struct NsSet {
    pub pid: Arc<pid_ns::PidNs>,
    pub mnt: Arc<mnt_ns::MntNs>,
    pub net: Arc<net_ns::NetNs>,
    pub uts: Arc<uts_ns::UtsNs>,
    pub user: Arc<user_ns::UserNs>,
}

impl NsSet {
    /// The initial (host) namespace set, created at boot.
    pub fn init_ns() -> Self {
        NsSet {
            pid: Arc::new(pid_ns::PidNs::new_init()),
            mnt: Arc::new(mnt_ns::MntNs::new_init()),
            net: Arc::new(net_ns::NetNs::new_init()),
            uts: Arc::new(uts_ns::UtsNs::new_init()),
            user: Arc::new(user_ns::UserNs::new_init()),
        }
    }

    /// Clone this NsSet, creating new namespaces for every bit set in `flags`.
    /// Used by `clone(2)` and `unshare(2)`.
    pub fn clone_with_flags(&self, flags: u64) -> Self {
        NsSet {
            pid: if flags & CLONE_NEWPID != 0 {
                Arc::new(pid_ns::PidNs::new_child())
            } else {
                self.pid.clone()
            },
            mnt: if flags & CLONE_NEWNS != 0 {
                Arc::new(mnt_ns::MntNs::copy_of(&self.mnt))
            } else {
                self.mnt.clone()
            },
            net: if flags & CLONE_NEWNET != 0 {
                Arc::new(net_ns::NetNs::new_empty())
            } else {
                self.net.clone()
            },
            uts: if flags & CLONE_NEWUTS != 0 {
                Arc::new(uts_ns::UtsNs::copy_of(&self.uts))
            } else {
                self.uts.clone()
            },
            user: if flags & CLONE_NEWUSER != 0 {
                Arc::new(user_ns::UserNs::new_child(&self.user))
            } else {
                self.user.clone()
            },
        }
    }
}

/// Global initial NsSet (populated by `init()`).
static INIT_NS: Mutex<Option<NsSet>> = Mutex::new(None);

pub fn init() {
    *INIT_NS.lock() = Some(NsSet::init_ns());
}

pub fn init_ns() -> NsSet {
    INIT_NS.lock().clone().expect("ns::init() not called")
}
