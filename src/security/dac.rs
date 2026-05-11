//! Discretionary Access Control (DAC) LSM module.
//!
//! This module implements standard Unix DAC semantics as an LSM backend,
//! consulting inode ownership and mode bits together with the task's
//! effective UID/GID and capability set.
//!
//! ## Rules enforced
//!
//! file_open / file_read / file_write / file_exec:
//!   Classic 9-bit rwxrwxrwx check.  Owner bits apply when euid == inode_uid;
//!   group bits when egid == inode_gid; other bits otherwise.
//!   CAP_DAC_OVERRIDE bypasses read/write/exec on all files.
//!   CAP_DAC_READ_SEARCH bypasses read and directory-search checks.
//!
//! inode_unlink / inode_rename:
//!   Requires write permission on the parent directory.
//!   CAP_FOWNER overrides the owner check.
//!
//! inode_setattr:
//!   Only the file owner (or CAP_FOWNER) may change mode/owner/times.
//!
//! mmap_file:
//!   PROT_EXEC requires execute permission on the file unless
//!   CAP_DAC_OVERRIDE is held.
//!
//! task_kill:
//!   A process may only send a signal to another if it shares the same
//!   real/effective UID, or holds CAP_KILL.  SIGKILL/SIGSTOP additionally
//!   require CAP_KILL when targeting a different UID.
//!
//! socket_create:
//!   SOCK_RAW requires CAP_NET_RAW.
//!
//! ipc_permission:
//!   Checks the IPC object's mode bits (stored in ctx.ipc_mode) and
//!   owner UID (ctx.ipc_uid) against the task's euid/egid.
//!
//! sb_mount:
//!   Requires CAP_SYS_ADMIN.
//!
//! task_setuid / task_setgid:
//!   setuid to a different user requires CAP_SETUID.
//!   setgid to a different group requires CAP_SETGID.

use super::lsm::{LsmHooks, LsmVerdict, LsmCtx, SOCK_RAW};

// ─── Capability bit positions (Linux-compatible) ──────────────────────────────

const CAP_DAC_OVERRIDE:    u64 = 1 << 1;
const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
const CAP_FOWNER:          u64 = 1 << 3;
const CAP_SETUID:          u64 = 1 << 7;
const CAP_SETGID:          u64 = 1 << 6;
const CAP_KILL:            u64 = 1 << 5;
const CAP_NET_RAW:         u64 = 1 << 13;
const CAP_SYS_ADMIN:       u64 = 1 << 21;

// ─── Mode bit helpers ─────────────────────────────────────────────────────────

// Owner bits
const S_IRUSR: u16 = 0o0400;
const S_IWUSR: u16 = 0o0200;
const S_IXUSR: u16 = 0o0100;
// Group bits
const S_IRGRP: u16 = 0o0040;
const S_IWGRP: u16 = 0o0020;
const S_IXGRP: u16 = 0o0010;
// Other bits
const S_IROTH: u16 = 0o0004;
const S_IWOTH: u16 = 0o0002;
const S_IXOTH: u16 = 0o0001;

// mmap protection bits
const PROT_EXEC: u32 = 0x4;

// ─── DAC helpers ─────────────────────────────────────────────────────────────

#[inline]
fn has_cap(caps: u64, cap: u64) -> bool {
    caps & cap != 0
}

/// Check read permission on an inode described by `ctx`.
fn check_read(ctx: &LsmCtx) -> LsmVerdict {
    if ctx.euid == 0 || has_cap(ctx.caps, CAP_DAC_OVERRIDE) {
        return LsmVerdict::Allow;
    }
    if has_cap(ctx.caps, CAP_DAC_READ_SEARCH) {
        return LsmVerdict::Allow;
    }
    let ok = if ctx.euid == ctx.inode_uid {
        ctx.inode_mode & S_IRUSR != 0
    } else if ctx.egid == ctx.inode_gid {
        ctx.inode_mode & S_IRGRP != 0
    } else {
        ctx.inode_mode & S_IROTH != 0
    };
    if ok { LsmVerdict::Allow } else { LsmVerdict::Deny(-13) } // EACCES
}

/// Check write permission on an inode described by `ctx`.
fn check_write(ctx: &LsmCtx) -> LsmVerdict {
    if ctx.euid == 0 || has_cap(ctx.caps, CAP_DAC_OVERRIDE) {
        return LsmVerdict::Allow;
    }
    let ok = if ctx.euid == ctx.inode_uid {
        ctx.inode_mode & S_IWUSR != 0
    } else if ctx.egid == ctx.inode_gid {
        ctx.inode_mode & S_IWGRP != 0
    } else {
        ctx.inode_mode & S_IWOTH != 0
    };
    if ok { LsmVerdict::Allow } else { LsmVerdict::Deny(-13) }
}

/// Check execute permission on an inode described by `ctx`.
fn check_exec(ctx: &LsmCtx) -> LsmVerdict {
    if ctx.euid == 0 || has_cap(ctx.caps, CAP_DAC_OVERRIDE) {
        // Root still needs at least one exec bit set to exec a file
        // (matches Linux: if no exec bit, even root gets EACCES on execve).
        let any_x = ctx.inode_mode & (S_IXUSR | S_IXGRP | S_IXOTH) != 0;
        return if any_x { LsmVerdict::Allow } else { LsmVerdict::Deny(-13) };
    }
    let ok = if ctx.euid == ctx.inode_uid {
        ctx.inode_mode & S_IXUSR != 0
    } else if ctx.egid == ctx.inode_gid {
        ctx.inode_mode & S_IXGRP != 0
    } else {
        ctx.inode_mode & S_IXOTH != 0
    };
    if ok { LsmVerdict::Allow } else { LsmVerdict::Deny(-13) }
}

// ─── DacModule ───────────────────────────────────────────────────────────────

pub struct DacModule;

impl LsmHooks for DacModule {
    fn name(&self) -> &'static str { "dac" }

    // ── File ─────────────────────────────────────────────────────────────────

    fn file_open(&self, ctx: &LsmCtx) -> LsmVerdict {
        // open(2) requires read or write (checked individually on read/write);
        // here we only verify the path exists and the task is allowed to stat it.
        check_read(ctx)
    }

    fn file_read(&self, ctx: &LsmCtx) -> LsmVerdict {
        check_read(ctx)
    }

    fn file_write(&self, ctx: &LsmCtx) -> LsmVerdict {
        check_write(ctx)
    }

    fn file_exec(&self, ctx: &LsmCtx) -> LsmVerdict {
        check_exec(ctx)
    }

    // ── Inode ────────────────────────────────────────────────────────────────

    fn inode_create(&self, ctx: &LsmCtx) -> LsmVerdict {
        // Creating a file requires write+execute on the parent directory.
        check_write(ctx)
    }

    fn inode_unlink(&self, ctx: &LsmCtx) -> LsmVerdict {
        if has_cap(ctx.caps, CAP_FOWNER) { return LsmVerdict::Allow; }
        // Unlink requires write on the parent directory, and the sticky bit
        // rule: if parent has sticky (S_ISVTX = 0o1000), only the file owner
        // or directory owner may unlink.
        let sticky = ctx.inode_mode & 0o1000 != 0;
        if sticky && ctx.euid != ctx.inode_uid {
            return LsmVerdict::Deny(-13);
        }
        check_write(ctx)
    }

    fn inode_rename(&self, ctx: &LsmCtx) -> LsmVerdict {
        if has_cap(ctx.caps, CAP_FOWNER) { return LsmVerdict::Allow; }
        check_write(ctx)
    }

    fn inode_setattr(&self, ctx: &LsmCtx) -> LsmVerdict {
        // Only owner or CAP_FOWNER may change attributes.
        if ctx.euid == ctx.inode_uid || has_cap(ctx.caps, CAP_FOWNER) {
            LsmVerdict::Allow
        } else {
            LsmVerdict::Deny(-1) // EPERM
        }
    }

    fn inode_getattr(&self, ctx: &LsmCtx) -> LsmVerdict {
        // stat(2) requires execute (search) on the directory containing the
        // inode.  Here we use read as a conservative proxy since we don't
        // receive the parent directory context.
        if has_cap(ctx.caps, CAP_DAC_READ_SEARCH) {
            return LsmVerdict::Allow;
        }
        check_read(ctx)
    }

    // ── Memory ───────────────────────────────────────────────────────────────

    fn mmap_file(&self, ctx: &LsmCtx) -> LsmVerdict {
        if ctx.prot & PROT_EXEC != 0 {
            return check_exec(ctx);
        }
        if ctx.prot & 0x2 != 0 { // PROT_WRITE
            return check_write(ctx);
        }
        if ctx.prot & 0x1 != 0 { // PROT_READ
            return check_read(ctx);
        }
        LsmVerdict::Allow
    }

    // ── Task ─────────────────────────────────────────────────────────────────

    fn task_create(&self, _ctx: &LsmCtx) -> LsmVerdict {
        // fork/clone: no DAC restriction beyond the caller's own privileges.
        LsmVerdict::Allow
    }

    fn task_exec(&self, ctx: &LsmCtx) -> LsmVerdict {
        check_exec(ctx)
    }

    fn task_kill(&self, ctx: &LsmCtx) -> LsmVerdict {
        // ctx.arg0 = target euid, ctx.signo = signal number.
        let target_uid = ctx.arg0 as u32;
        let signo = ctx.signo;
        // SIGKILL / SIGSTOP: require CAP_KILL when UIDs differ.
        if (signo == 9 || signo == 19) && ctx.euid != target_uid {
            if !has_cap(ctx.caps, CAP_KILL) {
                return LsmVerdict::Deny(-1); // EPERM
            }
        }
        // General rule: same euid or CAP_KILL.
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

    // ── Network ──────────────────────────────────────────────────────────────

    fn socket_create(&self, ctx: &LsmCtx) -> LsmVerdict {
        // ctx.arg1 = socket type
        if ctx.arg1 as u32 == SOCK_RAW && !has_cap(ctx.caps, CAP_NET_RAW) {
            return LsmVerdict::Deny(-1); // EPERM
        }
        LsmVerdict::Allow
    }

    fn socket_connect(&self, _ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_bind   (&self, _ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }
    fn socket_accept (&self, _ctx: &LsmCtx) -> LsmVerdict { LsmVerdict::Allow }

    // ── IPC ──────────────────────────────────────────────────────────────────

    fn ipc_permission(&self, ctx: &LsmCtx) -> LsmVerdict {
        // ctx.ipc_mode and ctx.ipc_uid describe the IPC object;
        // ctx.euid/egid describe the accessing task.
        if ctx.euid == 0 || has_cap(ctx.caps, CAP_DAC_OVERRIDE) {
            return LsmVerdict::Allow;
        }
        // For simplicity we check read bits as a proxy for any IPC access.
        let ok = if ctx.euid == ctx.ipc_uid {
            ctx.ipc_mode & S_IRUSR != 0
        } else if ctx.egid == ctx.inode_gid {
            ctx.ipc_mode & S_IRGRP != 0
        } else {
            ctx.ipc_mode & S_IROTH != 0
        };
        if ok { LsmVerdict::Allow } else { LsmVerdict::Deny(-13) }
    }

    // ── VFS ──────────────────────────────────────────────────────────────────

    fn sb_mount(&self, ctx: &LsmCtx) -> LsmVerdict {
        if ctx.euid == 0 || has_cap(ctx.caps, CAP_SYS_ADMIN) {
            LsmVerdict::Allow
        } else {
            LsmVerdict::Deny(-1) // EPERM
        }
    }
}

/// Static singleton registered by `lsm_init()`.
pub static DAC_MODULE: DacModule = DacModule;
