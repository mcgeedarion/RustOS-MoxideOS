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

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use crate::sync::spinlock::SpinLock;

// ─── Verdict ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsmVerdict {
    Allow,
    Deny(i32),
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

pub type Mode = u16;

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM:  u32 = 2;
pub const SOCK_RAW:    u32 = 3;

/// Context passed to every LSM hook.
#[derive(Clone)]
pub struct LsmCtx {
    // ── task credentials ─────────────────────────────────────────────────
    pub pid:   usize,
    pub euid:  u32,
    pub egid:  u32,
    pub caps:  u64,
    pub supp_groups: Vec<u32>,

    // ── inode identity ───────────────────────────────────────────────────
    pub inode_uid:  u32,
    pub inode_gid:  u32,
    pub inode_mode: Mode,
    pub path: &'static str,

    // ── hook-specific fields ─────────────────────────────────────────────
    pub signo: i32,
    pub arg0:  u64,
    pub arg1:  u64,
    pub prot:  u32,
    pub flags: u32,
    pub ipc_mode: Mode,
    pub ipc_uid:  u32,
    /// H3 fix: IPC object creator GID — was missing, causing ipc_permission
    /// to always use ctx.inode_gid (0) instead of the IPC object's group.
    pub ipc_gid:  u32,
}

impl LsmCtx {
    pub fn for_current_task(path: &'static str, inode_uid: u32, inode_mode: Mode) -> Self {
        let pid = crate::proc::scheduler::current_pid();
        let (euid, egid, caps, supp_groups) = if pid != 0 {
            crate::proc::scheduler::with_proc(pid, |p| {
                (p.euid, p.egid, p.caps.effective, p.supp_groups.clone())
            }).unwrap_or((0, 0, u64::MAX, Vec::new()))
        } else {
            (0, 0, u64::MAX, Vec::new())
        };
        Self {
            pid, euid, egid, caps, supp_groups,
            inode_uid,
            inode_gid: 0,
            inode_mode,
            path,
            signo: 0, arg0: 0, arg1: 0,
            prot: 0, flags: 0,
            ipc_mode: 0, ipc_uid: 0, ipc_gid: 0,
        }
    }

    pub fn with_creds(
        pid: usize, euid: u32, egid: u32, caps: u64,
        inode_uid: u32, inode_gid: u32, inode_mode: Mode,
    ) -> Self {
        Self {
            pid, euid, egid, caps, supp_groups: Vec::new(),
            inode_uid, inode_gid, inode_mode,
            path: "",
            signo: 0, arg0: 0, arg1: 0,
            prot: 0, flags: 0,
            ipc_mode: 0, ipc_uid: 0, ipc_gid: 0,
        }
    }
}

// ─── Hook enum ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    FileOpen, FileRead, FileWrite, FileExec,
    InodeCreate, InodeUnlink, InodeRename, InodeSetattr, InodeGetattr,
    MmapFile,
    TaskCreate, TaskExec, TaskKill, TaskSetuid, TaskSetgid,
    SocketCreate, SocketConnect, SocketBind, SocketAccept,
    IpcPermission,
    SbMount,
}

// ─── LsmHooks trait ──────────────────────────────────────────────────────────

pub trait LsmHooks: Send + Sync {
    fn name(&self) -> &'static str;
    fn file_open    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn file_read    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn file_write   (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn file_exec    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn inode_create (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn inode_unlink (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn inode_rename (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn inode_setattr(&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn inode_getattr(&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn mmap_file    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn task_create  (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn task_exec    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn task_kill    (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn task_setuid  (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn task_setgid  (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_create (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_connect(&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_bind   (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_accept (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn ipc_permission(&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn sb_mount      (&self, ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
}

// ─── Registry ─────────────────────────────────────────────────────────────────

const MAX_LSM_MODULES: usize = 8;

struct LsmRegistry {
    modules: [Option<&'static dyn LsmHooks>; MAX_LSM_MODULES],
    count:   usize,
}

impl LsmRegistry {
    const fn empty() -> Self {
        Self { modules: [None; MAX_LSM_MODULES], count: 0 }
    }

    fn register(&mut self, module: &'static dyn LsmHooks) {
        if self.count < MAX_LSM_MODULES {
            self.modules[self.count] = Some(module);
            self.count += 1;
        }
    }

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
                if let LsmVerdict::Deny(_) = v { return v; }
            }
        }
        LsmVerdict::Allow
    }
}

static REGISTRY: SpinLock<LsmRegistry> = SpinLock::new(LsmRegistry::empty());

pub fn register_lsm(module: &'static dyn LsmHooks) {
    REGISTRY.lock().register(module);
}

#[inline]
pub fn lsm_dispatch(hook: Hook, ctx: &LsmCtx) -> Result<(), i32> {
    let v = REGISTRY.lock().dispatch(hook, ctx);
    if v.is_allow() { Ok(()) } else { Err(v.errno()) }
}

#[macro_export]
macro_rules! lsm_check {
    ($hook:expr, $ctx:expr) => {
        $crate::security::lsm::lsm_dispatch($hook, &$ctx)?
    };
}

pub fn lsm_init() {
    register_lsm(&crate::security::dac::DAC_MODULE);
}
