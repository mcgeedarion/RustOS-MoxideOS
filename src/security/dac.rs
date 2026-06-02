//! Discretionary Access Control (DAC) LSM module.
//!
//! Implements standard Unix DAC semantics as an LSM backend.
//!
//! ## Fixes in this revision
//!
//! H1 — exec_transform: new_permitted was over-broad.
//!      Old:  (file_permitted | file_inheritable) & self.permitted
//!      New:  (file_permitted | (file_inheritable & self.inheritable)) & self.permitted
//!      The old formula allowed any file-inheritable capability to bypass
//!      the task's own inheritable mask, enabling privilege escalation via
//!      a crafted binary with file capabilities.
//!
//! H2 — ipc_permission: group check used ctx.inode_gid (always 0 for IPC
//!      hooks) instead of ctx.ipc_gid.  This caused the group branch to
//!      never match, making group-restricted IPC objects accessible to
//!      all processes via the 'other' bits.

use super::lsm::{LsmHooks, LsmVerdict, LsmCtx, SOCK_RAW};

const CAP_DAC_OVERRIDE:    u64 = 1 << 1;
const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
const CAP_FOWNER:          u64 = 1 << 3;
const CAP_SETUID:          u64 = 1 << 7;
const CAP_SETGID:          u64 = 1 << 6;
const CAP_KILL:            u64 = 1 << 5;
const CAP_NET_RAW:         u64 = 1 << 13;
const CAP_SYS_ADMIN:       u64 = 1 << 21;

const S_IRUSR: u16 = 0o0400;
const S_IWUSR: u16 = 0o0200;
const S_IXUSR: u16 = 0o0100;
const S_IRGRP: u16 = 0o0040;
const S_IWGRP: u16 = 0o0020;
const S_IXGRP: u16 = 0o0010;
const S_IROTH: u16 = 0o0004;
const S_IWOTH: u16 = 0o0002;
const S_IXOTH: u16 = 0o0001;

const PROT_EXEC: u32 = 0x4;

#[inline]
fn has_cap(caps: u64, cap: u64) -> bool { caps & cap != 0 }

#[inline]
fn in_group(ctx: &LsmCtx, gid: u32) -> bool {
    ctx.egid == gid || ctx.supp_groups.iter().any(|&g| g == gid)
}

fn check_read(ctx: &LsmCtx) -> LsmVerdict {
    if ctx.euid == 0 || has_cap(ctx.caps, CAP_DAC_OVERRIDE) { return LsmVerdict::Allow; }
    if has_cap(ctx.caps, CAP_DAC_READ_SEARCH)               { return LsmVerdict::Allow; }
    let ok = if ctx.euid == ctx.inode_uid {
        ctx.inode_mode & S_IRUSR != 0
    } else if in_group(ctx, ctx.inode_gid) {
        ctx.inode_mode & S_IRGRP != 0
    } else {
        ctx.inode_mode & S_IROTH != 0
    };
    if ok { LsmVerdict::Allow } else { LsmVerdict::Deny(-13) }
}

fn check_write(ctx: &LsmCtx) -> LsmVerdict {
    if ctx.euid == 0 || has_cap(ctx.caps, CAP_DAC_OVERRIDE) { return LsmVerdict::Allow; }
    let ok = if ctx.euid == ctx.inode_uid {
        ctx.inode_mode & S_IWUSR != 0
    } else if in_group(ctx, ctx.inode_gid) {
        ctx.inode_mode & S_IWGRP != 0
    } else {
        ctx.inode_mode & S_IWOTH != 0
    };
    if ok { LsmVerdict::Allow } else { LsmVerdict::Deny(-13) }
}

fn check_exec(ctx: &LsmCtx) -> LsmVerdict {
    if ctx.euid == 0 || has_cap(ctx.caps, CAP_DAC_OVERRIDE) {
        let any_x = ctx.inode_mode & (S_IXUSR | S_IXGRP | S_IXOTH) != 0;
        return if any_x { LsmVerdict::Allow } else { LsmVerdict::Deny(-13) };
    }
    let ok = if ctx.euid == ctx.inode_uid {
        ctx.inode_mode & S_IXUSR != 0
    } else if in_group(ctx, ctx.inode_gid) {
        ctx.inode_mode & S_IXGRP != 0
    } else {
        ctx.inode_mode & S_IXOTH != 0
    };
    if ok { LsmVerdict::Allow } else { LsmVerdict::Deny(-13) }
}

pub struct DacModule;

impl LsmHooks for DacModule {
    fn name(&self) -> &'static str { "dac" }

    fn file_open (&self, ctx: &LsmCtx) -> LsmVerdict { check_read(ctx) }
    fn file_read (&self, ctx: &LsmCtx) -> LsmVerdict { check_read(ctx) }
    fn file_write(&self, ctx: &LsmCtx) -> LsmVerdict { check_write(ctx) }
    fn file_exec (&self, ctx: &LsmCtx) -> LsmVerdict { check_exec(ctx) }

    fn inode_create(&self, ctx: &LsmCtx) -> LsmVerdict { check_write(ctx) }

    fn inode_unlink(&self, ctx: &LsmCtx) -> LsmVerdict {
        if has_cap(ctx.caps, CAP_FOWNER) { return LsmVerdict::Allow; }
        let sticky = ctx.inode_mode & 0o1000 != 0;
        if sticky && ctx.euid != ctx.inode_uid { return LsmVerdict::Deny(-13); }
        check_write(ctx)
    }

    fn inode_rename (&self, ctx: &LsmCtx) -> LsmVerdict {
        if has_cap(ctx.caps, CAP_FOWNER) { return LsmVerdict::Allow; }
        check_write(ctx)
    }

    fn inode_setattr(&self, ctx: &LsmCtx) -> LsmVerdict {
        if ctx.euid == ctx.inode_uid || has_cap(ctx.caps, CAP_FOWNER) {
            LsmVerdict::Allow
        } else {
            LsmVerdict::Deny(-1)
        }
    }

    fn inode_getattr(&self, ctx: &LsmCtx) -> LsmVerdict {
        if has_cap(ctx.caps, CAP_DAC_READ_SEARCH) { return LsmVerdict::Allow; }
        check_read(ctx)
    }

    fn mmap_file(&self, ctx: &LsmCtx) -> LsmVerdict {
        if ctx.prot & PROT_EXEC != 0 { return check_exec(ctx); }
        if ctx.prot & 0x2 != 0       { return check_write(ctx); }
        if ctx.prot & 0x1 != 0       { return check_read(ctx); }
        LsmVerdict::Allow
    }

    fn task_create(&self, _ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn task_exec  (&self, ctx: &LsmCtx)  -> LsmVerdict { check_exec(ctx) }

    fn task_kill(&self, ctx: &LsmCtx) -> LsmVerdict {
        let target_uid = ctx.arg0 as u32;
        let signo = ctx.signo;
        if (signo == 9 || signo == 19) && ctx.euid != target_uid {
            if !has_cap(ctx.caps, CAP_KILL) { return LsmVerdict::Deny(-1); }
        }
        if ctx.euid == target_uid || ctx.euid == 0 || has_cap(ctx.caps, CAP_KILL) {
            LsmVerdict::Allow
        } else {
            LsmVerdict::Deny(-1)
        }
    }

    fn task_setuid(&self, ctx: &LsmCtx) -> LsmVerdict {
        let new_uid = ctx.arg0 as u32;
        if ctx.euid == new_uid || has_cap(ctx.caps, CAP_SETUID) {
            LsmVerdict::Allow
        } else {
            LsmVerdict::Deny(-1)
        }
    }

    fn task_setgid(&self, ctx: &LsmCtx) -> LsmVerdict {
        let new_gid = ctx.arg0 as u32;
        if ctx.egid == new_gid || has_cap(ctx.caps, CAP_SETGID) {
            LsmVerdict::Allow
        } else {
            LsmVerdict::Deny(-1)
        }
    }

    fn socket_create(&self, ctx: &LsmCtx) -> LsmVerdict {
        if ctx.arg1 as u32 == SOCK_RAW && !has_cap(ctx.caps, CAP_NET_RAW) {
            return LsmVerdict::Deny(-1);
        }
        LsmVerdict::Allow
    }

    fn socket_connect(&self, _ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_bind   (&self, _ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_accept (&self, _ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }

    fn ipc_permission(&self, ctx: &LsmCtx) -> LsmVerdict {
        if ctx.euid == 0 || has_cap(ctx.caps, CAP_DAC_OVERRIDE) {
            return LsmVerdict::Allow;
        }
        // H2 fix: use ctx.ipc_gid (the IPC object's group) rather than
        // ctx.inode_gid (which is always 0 for IPC hooks, causing the group
        // branch to never match and every process to fall through to 'other').
        let ok = if ctx.euid == ctx.ipc_uid {
            ctx.ipc_mode & S_IRUSR != 0
        } else if in_group(ctx, ctx.ipc_gid) {
            ctx.ipc_mode & S_IRGRP != 0
        } else {
            ctx.ipc_mode & S_IROTH != 0
        };
        if ok { LsmVerdict::Allow } else { LsmVerdict::Deny(-13) }
    }

    fn sb_mount(&self, ctx: &LsmCtx) -> LsmVerdict {
        if ctx.euid == 0 || has_cap(ctx.caps, CAP_SYS_ADMIN) {
            LsmVerdict::Allow
        } else {
            LsmVerdict::Deny(-1)
        }
    }
}

pub static DAC_MODULE: DacModule = DacModule;

// The original exec_transform was on capset.rs/CapSet; the formula is
// re-exposed here as a free function so callers that build LsmCtx can use it.
// The correct POSIX/Linux formula for the new permitted set is:
//   P' = (F_permitted | (F_inheritable & P_inheritable)) & P_permitted
// where F = file caps, P = process caps.
// The old code used (F_permitted | F_inheritable) & P_permitted which omitted
// the intersection with P_inheritable, letting any file-inheritable cap slip
// through regardless of whether the process had it in its inheritable set.

/// Apply the Linux file-capability exec transformation to a (permitted,
/// effective, inheritable) triple.
///
/// Returns (new_permitted, new_effective, new_inheritable).
#[inline]
pub fn exec_cap_transform(
    proc_permitted:   u64,
    proc_effective:   u64,
    proc_inheritable: u64,
    file_permitted:   u64,
    file_inheritable: u64,
    file_effective_bit: bool,  // fE in POSIX — single bit, not a mask
) -> (u64, u64, u64) {
    // H1 fix: intersection with proc_inheritable prevents file-inheritable
    // caps from being granted beyond what the process already has.
    let new_permitted   = (file_permitted | (file_inheritable & proc_inheritable))
                          & proc_permitted;
    // new_effective: if fE bit set, all permitted; otherwise zero (ambient
    // caps would be added here when ambient support is implemented).
    let new_effective   = if file_effective_bit { new_permitted } else { 0 };
    let new_inheritable = proc_inheritable;
    (new_permitted, new_effective, new_inheritable)
}
