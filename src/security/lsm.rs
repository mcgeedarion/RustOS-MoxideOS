//! Linux Security Module (LSM) hook layer.
//!
//! ## Architecture
//!
//! This file defines the `LsmHooks` trait — a set of 21 hook functions that
//! any MAC/DAC module can implement — plus a static registry that dispatches
//! each hook through every registered module in order.  The first module that
//! returns `LsmVerdict::Deny` short-circuits the remaining modules and the
//! denial is propagated back to the callsite.
//!
//! ## Hooks implemented
//!
//! File / inode:
//!   file_open, file_read, file_write, file_exec
//!   inode_create, inode_unlink, inode_rename, inode_setattr, inode_getattr
//!   mmap_file
//!
//! Process:
//!   task_create, task_exec, task_kill, task_setuid, task_setgid
//!
//! Network:
//!   socket_create, socket_connect, socket_bind, socket_accept
//!
//! IPC:
//!   ipc_permission
//!
//! VFS:
//!   sb_mount
//!
//! ## Usage at callsites
//!
//! ```rust
//! use crate::security::lsm::{lsm_check, LsmCtx, Hook};
//!
//! let ctx = LsmCtx::for_current_task("/etc/passwd", inode_uid, inode_mode);
//! lsm_check!(Hook::FileOpen, ctx)?;   // returns Err(errno) on denial
//! ```
//!
//! ## Registering a module
//!
//! ```rust
//! use crate::security::lsm::register_lsm;
//! register_lsm(&MY_MODULE);   // &'static dyn LsmHooks
//! ```

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::sync::spinlock::SpinLock;

// ─── Verdict ─────────────────────────────────────────────────────────────────

/// Decision returned by each LSM hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmVerdict {
    /// Access is granted — proceed to the next module.
    Allow,
    /// Access is denied.  The contained value is the negative errno
    /// that will be returned to userspace (e.g. -13 = EACCES, -1 = EPERM).
    Deny(i32),
    /// Allow but emit a kernel log entry (used by audit / logging modules).
    Log,
}

impl LsmVerdict {
    #[inline]
    pub fn is_allow(&self) -> bool {
        matches!(self, LsmVerdict::Allow | LsmVerdict::Log)
    }
    #[inline]
    pub fn errno(&self) -> i32 {
        match self {
            LsmVerdict::Deny(e) => *e,
            _ => 0,
        }
    }
}

// ─── Per-hook context ─────────────────────────────────────────────────────────

/// File/inode permission bits (rwxrwxrwx in the low 9 bits, suid/sgid/sticky
/// in bits 9-11 — identical to the Unix `st_mode & 0o7777` layout).
pub type Mode = u16;

/// Socket type constants (matches Linux SOCK_* values).
pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM:  u32 = 2;
pub const SOCK_RAW:    u32 = 3;

/// Context passed to every LSM hook.  Callsites fill in what they know;
/// unused fields are zeroed / empty.
#[derive(Clone)]
pub struct LsmCtx {
    // ── task credentials ────────────────────────────────────────────────────
    pub pid:   usize,
    pub euid:  u32,
    pub egid:  u32,
    /// Effective capability set bitmask (64-bit, matches Linux cap_t layout).
    pub caps:  u64,

    // ── object identity ─────────────────────────────────────────────────────
    /// Inode owner UID (0 for non-inode hooks).
    pub inode_uid:  u32,
    /// Inode owner GID.
    pub inode_gid:  u32,
    /// Unix permission mode bits (`st_mode & 0o7777`).
    pub inode_mode: Mode,
    /// Path of the object being accessed (may be empty for non-path hooks).
    pub path: &'static str,

    // ── hook-specific fields ────────────────────────────────────────────────
    /// Signal number (for task_kill hook).
    pub signo: i32,
    /// Target UID (for task_setuid) or socket domain (for socket_*).
    pub arg0:  u64,
    /// Socket type (for socket_create/connect/bind).
    pub arg1:  u64,
    /// Requested mmap protection flags (PROT_READ | PROT_WRITE | PROT_EXEC).
    pub prot:  u32,
    /// Requested mmap flags (MAP_SHARED etc.).
    pub flags: u32,
    /// IPC object permissions (low 9 bits, like inode_mode).
    pub ipc_mode: Mode,
    /// IPC object creator UID.
    pub ipc_uid: u32,
}

impl LsmCtx {
    /// Build a context from the currently running task and a known inode.
    /// Returns a zeroed-out context if the scheduler has no current process.
    pub fn for_current_task(path: &'static str, inode_uid: u32, inode_mode: Mode) -> Self {
        let pid = crate::proc::scheduler::current_pid();
        let (euid, egid, caps) = if pid != 0 {
            crate::proc::scheduler::with_proc(pid, |p| {
                (p.creds.euid, p.creds.egid, p.creds.caps_effective)
            }).unwrap_or((0, 0, u64::MAX))
        } else {
            (0, 0, u64::MAX) // kernel context: root, all caps
        };
        Self {
            pid, euid, egid, caps,
            inode_uid,
            inode_gid: 0,
            inode_mode,
            path,
            signo: 0, arg0: 0, arg1: 0,
            prot: 0, flags: 0,
            ipc_mode: 0, ipc_uid: 0,
        }
    }

    /// Convenience: build a context with explicit uid/gid/caps (used in tests
    /// and hooks that already have creds in scope).
    pub fn with_creds(
        pid: usize, euid: u32, egid: u32, caps: u64,
        inode_uid: u32, inode_gid: u32, inode_mode: Mode,
    ) -> Self {
        Self {
            pid, euid, egid, caps,
            inode_uid, inode_gid, inode_mode,
            path: "",
            signo: 0, arg0: 0, arg1: 0,
            prot: 0, flags: 0,
            ipc_mode: 0, ipc_uid: 0,
        }
    }
}

// ─── Hook enum ────────────────────────────────────────────────────────────────

/// Discriminant passed to `lsm_check!` to select the correct hook function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    // File
    FileOpen,
    FileRead,
    FileWrite,
    FileExec,
    // Inode
    InodeCreate,
    InodeUnlink,
    InodeRename,
    InodeSetattr,
    InodeGetattr,
    // Memory
    MmapFile,
    // Task
    TaskCreate,
    TaskExec,
    TaskKill,
    TaskSetuid,
    TaskSetgid,
    // Network
    SocketCreate,
    SocketConnect,
    SocketBind,
    SocketAccept,
    // IPC
    IpcPermission,
    // VFS
    SbMount,
}

// ─── LsmHooks trait ──────────────────────────────────────────────────────────

/// Every security module must implement this trait.  The default
/// implementation of every method returns `LsmVerdict::Allow`, so a new
/// module only needs to override the hooks it cares about.
pub trait LsmHooks: Send + Sync {
    fn name(&self) -> &'static str;

    // ── File hooks ──────────────────────────────────────────────────────────
    fn file_open    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn file_read    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn file_write   (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn file_exec    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }

    // ── Inode hooks ─────────────────────────────────────────────────────────
    fn inode_create (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn inode_unlink (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn inode_rename (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn inode_setattr(&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn inode_getattr(&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }

    // ── Memory hooks ────────────────────────────────────────────────────────
    fn mmap_file    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }

    // ── Task hooks ──────────────────────────────────────────────────────────
    fn task_create  (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn task_exec    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn task_kill    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn task_setuid  (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn task_setgid  (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }

    // ── Network hooks ───────────────────────────────────────────────────────
    fn socket_create (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_connect(&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_bind   (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_accept (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }

    // ── IPC hooks ───────────────────────────────────────────────────────────
    fn ipc_permission(&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }

    // ── VFS hooks ───────────────────────────────────────────────────────────
    fn sb_mount      (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

/// Maximum number of simultaneously registered LSM modules.
const MAX_LSM_MODULES: usize = 8;

struct LsmRegistry {
    modules: [Option<&'static dyn LsmHooks>; MAX_LSM_MODULES],
    count:   usize,
}

impl LsmRegistry {
    const fn empty() -> Self {
        Self {
            modules: [None; MAX_LSM_MODULES],
            count:   0,
        }
    }

    fn register(&mut self, module: &'static dyn LsmHooks) {
        if self.count < MAX_LSM_MODULES {
            self.modules[self.count] = Some(module);
            self.count += 1;
        }
    }

    /// Invoke `hook` against all registered modules.
    /// Returns the first `Deny` verdict, or `Allow` if all modules allow.
    fn dispatch(&self, hook: Hook, ctx: &LsmCtx) -> LsmVerdict {
        for i in 0..self.count {
            if let Some(m) = self.modules[i] {
                let v = match hook {
                    Hook::FileOpen      => m.file_open(ctx),
                    Hook::FileRead      => m.file_read(ctx),
                    Hook::FileWrite     => m.file_write(ctx),
                    Hook::FileExec      => m.file_exec(ctx),
                    Hook::InodeCreate   => m.inode_create(ctx),
                    Hook::InodeUnlink   => m.inode_unlink(ctx),
                    Hook::InodeRename   => m.inode_rename(ctx),
                    Hook::InodeSetattr  => m.inode_setattr(ctx),
                    Hook::InodeGetattr  => m.inode_getattr(ctx),
                    Hook::MmapFile      => m.mmap_file(ctx),
                    Hook::TaskCreate    => m.task_create(ctx),
                    Hook::TaskExec      => m.task_exec(ctx),
                    Hook::TaskKill      => m.task_kill(ctx),
                    Hook::TaskSetuid    => m.task_setuid(ctx),
                    Hook::TaskSetgid    => m.task_setgid(ctx),
                    Hook::SocketCreate  => m.socket_create(ctx),
                    Hook::SocketConnect => m.socket_connect(ctx),
                    Hook::SocketBind    => m.socket_bind(ctx),
                    Hook::SocketAccept  => m.socket_accept(ctx),
                    Hook::IpcPermission => m.ipc_permission(ctx),
                    Hook::SbMount       => m.sb_mount(ctx),
                };
                if let LsmVerdict::Deny(_) = v {
                    return v;
                }
            }
        }
        LsmVerdict::Allow
    }
}

static REGISTRY: SpinLock<LsmRegistry> = SpinLock::new(LsmRegistry::empty());

/// Register a security module.  Modules are consulted in registration order.
/// Must be called before the first user process is created; safe to call
/// during kernel init from a single CPU before SMP is enabled.
pub fn register_lsm(module: &'static dyn LsmHooks) {
    REGISTRY.lock().register(module);
}

/// Dispatch `hook` with `ctx` through all registered modules.
/// Returns `Ok(())` on Allow/Log, `Err(errno)` on Deny.
#[inline]
pub fn lsm_dispatch(hook: Hook, ctx: &LsmCtx) -> Result<(), i32> {
    let v = REGISTRY.lock().dispatch(hook, ctx);
    if v.is_allow() { Ok(()) } else { Err(v.errno()) }
}

/// Convenience macro: `lsm_check!(Hook::FileOpen, ctx)` expands to
/// `lsm_dispatch(Hook::FileOpen, &ctx)?` — uses the `?` operator so
/// the surrounding function must return `Result<_, i32>`.
#[macro_export]
macro_rules! lsm_check {
    ($hook:expr, $ctx:expr) => {
        $crate::security::lsm::lsm_dispatch($hook, &$ctx)?
    };
}

/// Initialise the LSM subsystem: register the built-in DAC module.
/// Called once from `kernel_main` before launching init.
pub fn lsm_init() {
    register_lsm(&crate::security::dac::DAC_MODULE);
}
