//! Credential and session management syscalls.
//!
//! Implements the POSIX saved-set-uid model for set*uid/gid,
//! session/process-group management (setsid, setpgid/getpgrp/getsid),
//! and supplemental group operations.
//!
//! ## Per-process credential fields (in Pcb)
//!
//! ```
//!   uid   – real user ID
//!   euid  – effective user ID
//!   suid  – saved set-user-ID
//!   gid   – real group ID
//!   egid  – effective group ID
//!   sgid  – saved set-group-ID
//!   sid   – session ID (pid of session leader)
//! ```
//!
//! All of these are initialised in Pcb::zeroed() as 0 (root) and
//! inherited on fork.  execve resets euid/egid from the binary's
//! set-uid/set-gid bits (not yet implemented; treated as 0/root).

extern crate alloc;
use crate::uaccess::{copy_from_user, copy_to_user, copy_to_user_value};
use alloc::vec::Vec;

#[inline]
fn current_pid() -> usize {
    crate::proc::scheduler::current_pid()
}

pub fn sys_getuid() -> isize {
    crate::proc::scheduler::with_proc(current_pid(), |p| p.uid as isize).unwrap_or(0)
}

pub fn sys_geteuid() -> isize {
    crate::proc::scheduler::with_proc(current_pid(), |p| p.euid as isize).unwrap_or(0)
}

pub fn sys_getgid() -> isize {
    crate::proc::scheduler::with_proc(current_pid(), |p| p.gid as isize).unwrap_or(0)
}

pub fn sys_getegid() -> isize {
    crate::proc::scheduler::with_proc(current_pid(), |p| p.egid as isize).unwrap_or(0)
}

// Linux setreuid(ruid, euid) semantics (POSIX §8.1):
//   - If euid is not -1, it becomes the new effective UID.
//   - If ruid is not -1, it becomes the new real UID.
//   - The saved-set-user-ID is set to the new euid if:
//       * ruid != -1, OR
//       * euid != -1 and euid != old ruid
//   - Unprivileged (euid != 0): new ruid must be old ruid, euid, or suid; new
//     euid must be old ruid, euid, or suid.
// We are a single-user-root kernel so euid==0 is always privileged.

pub fn sys_setreuid(ruid: u32, euid: u32) -> isize {
    let neg1: u32 = u32::MAX;
    crate::proc::scheduler::with_proc_mut(current_pid(), |p, _| {
        let privileged = p.euid == 0;
        let new_ruid = if ruid == neg1 { p.uid } else { ruid };
        let new_euid = if euid == neg1 { p.euid } else { euid };
        if !privileged {
            let ok_ruid = new_ruid == p.uid || new_ruid == p.euid || new_ruid == p.suid;
            let ok_euid = new_euid == p.uid || new_euid == p.euid || new_euid == p.suid;
            if !ok_ruid || !ok_euid {
                return -1isize;
            } // EPERM
        }
        // Update saved-set-uid per POSIX.
        if ruid != neg1 || (euid != neg1 && new_euid != p.uid) {
            p.suid = new_euid;
        }
        p.uid = new_ruid;
        p.euid = new_euid;
        0isize
    })
    .unwrap_or(-1)
}

pub fn sys_setregid(rgid: u32, egid: u32) -> isize {
    let neg1: u32 = u32::MAX;
    crate::proc::scheduler::with_proc_mut(current_pid(), |p, _| {
        let privileged = p.euid == 0;
        let new_rgid = if rgid == neg1 { p.gid } else { rgid };
        let new_egid = if egid == neg1 { p.egid } else { egid };
        if !privileged {
            let ok_rgid = new_rgid == p.gid || new_rgid == p.egid || new_rgid == p.sgid;
            let ok_egid = new_egid == p.gid || new_egid == p.egid || new_egid == p.sgid;
            if !ok_rgid || !ok_egid {
                return -1isize;
            }
        }
        if rgid != neg1 || (egid != neg1 && new_egid != p.gid) {
            p.sgid = new_egid;
        }
        p.gid = new_rgid;
        p.egid = new_egid;
        0isize
    })
    .unwrap_or(-1)
}

// setresuid(ruid, euid, suid): all three independently settable.
// -1 means "leave unchanged".
// Unprivileged: each new value must be one of old {ruid, euid, suid}.

pub fn sys_setresuid(ruid: u32, euid: u32, suid: u32) -> isize {
    let neg1: u32 = u32::MAX;
    crate::proc::scheduler::with_proc_mut(current_pid(), |p, _| {
        let privileged = p.euid == 0;
        let new_r = if ruid == neg1 { p.uid } else { ruid };
        let new_e = if euid == neg1 { p.euid } else { euid };
        let new_s = if suid == neg1 { p.suid } else { suid };
        if !privileged {
            let valid = |v: u32| v == p.uid || v == p.euid || v == p.suid;
            if !valid(new_r) || !valid(new_e) || !valid(new_s) {
                return -1isize;
            }
        }
        p.uid = new_r;
        p.euid = new_e;
        p.suid = new_s;
        0isize
    })
    .unwrap_or(-1)
}

pub fn sys_setresgid(rgid: u32, egid: u32, sgid: u32) -> isize {
    let neg1: u32 = u32::MAX;
    crate::proc::scheduler::with_proc_mut(current_pid(), |p, _| {
        let privileged = p.euid == 0;
        let new_r = if rgid == neg1 { p.gid } else { rgid };
        let new_e = if egid == neg1 { p.egid } else { egid };
        let new_s = if sgid == neg1 { p.sgid } else { sgid };
        if !privileged {
            let valid = |v: u32| v == p.gid || v == p.egid || v == p.sgid;
            if !valid(new_r) || !valid(new_e) || !valid(new_s) {
                return -1isize;
            }
        }
        p.gid = new_r;
        p.egid = new_e;
        p.sgid = new_s;
        0isize
    })
    .unwrap_or(-1)
}

pub fn sys_getresuid(ruid_va: usize, euid_va: usize, suid_va: usize) -> isize {
    let (r, e, s) = crate::proc::scheduler::with_proc(current_pid(), |p| (p.uid, p.euid, p.suid))
        .unwrap_or((0, 0, 0));
    if crate::uaccess::copy_to_user_value(ruid_va, &r.to_le_bytes()).is_err() {
        return -14;
    }
    if crate::uaccess::copy_to_user_value(euid_va, &e.to_le_bytes()).is_err() {
        return -14;
    }
    if crate::uaccess::copy_to_user_value(suid_va, &s.to_le_bytes()).is_err() {
        return -14;
    }
    0
}

pub fn sys_getresgid(rgid_va: usize, egid_va: usize, sgid_va: usize) -> isize {
    let (r, e, s) = crate::proc::scheduler::with_proc(current_pid(), |p| (p.gid, p.egid, p.sgid))
        .unwrap_or((0, 0, 0));
    if crate::uaccess::copy_to_user_value(rgid_va, &r.to_le_bytes()).is_err() {
        return -14;
    }
    if crate::uaccess::copy_to_user_value(egid_va, &e.to_le_bytes()).is_err() {
        return -14;
    }
    if crate::uaccess::copy_to_user_value(sgid_va, &s.to_le_bytes()).is_err() {
        return -14;
    }
    0
}

// POSIX setuid(uid):
//   - If euid == 0: sets all of ruid, euid, suid to uid.
//   - Otherwise: sets only euid (and ruid if uid == ruid or suid).

pub fn sys_setuid(uid: u32) -> isize {
    crate::proc::scheduler::with_proc_mut(current_pid(), |p, _| {
        if p.euid == 0 {
            p.uid = uid;
            p.euid = uid;
            p.suid = uid;
        } else {
            if uid != p.uid && uid != p.suid {
                return -1isize;
            }
            p.euid = uid;
        }
        0isize
    })
    .unwrap_or(-1)
}

pub fn sys_setgid(gid: u32) -> isize {
    crate::proc::scheduler::with_proc_mut(current_pid(), |p, _| {
        if p.euid == 0 {
            p.gid = gid;
            p.egid = gid;
            p.sgid = gid;
        } else {
            if gid != p.gid && gid != p.sgid {
                return -1isize;
            }
            p.egid = gid;
        }
        0isize
    })
    .unwrap_or(-1)
}

pub fn sys_getgroups(size: i32, list_va: usize) -> isize {
    let groups: Vec<u32> =
        crate::proc::scheduler::with_proc(current_pid(), |p| p.supp_groups.clone())
            .unwrap_or_default();

    let n = groups.len() as i32;
    if size == 0 {
        return n as isize;
    }
    if size < n {
        return -22;
    } // EINVAL

    for (i, &gid) in groups.iter().enumerate() {
        if crate::uaccess::copy_to_user_value(list_va + i * 4, &gid.to_le_bytes()).is_err() {
            return -14;
        }
    }
    n as isize
}

pub fn sys_setgroups(size: i32, list_va: usize) -> isize {
    if size < 0 || size > 65536 {
        return -22;
    }
    // Only root (euid==0) may call setgroups.
    let privileged =
        crate::proc::scheduler::with_proc(current_pid(), |p| p.euid == 0).unwrap_or(false);
    if !privileged {
        return -1;
    } // EPERM

    let mut groups = Vec::with_capacity(size as usize);
    for i in 0..(size as usize) {
        let mut buf = [0u8; 4];
        if copy_from_user(&mut buf, list_va + i * 4).is_err() {
            return -14;
        }
        groups.push(u32::from_le_bytes(buf));
    }

    crate::proc::scheduler::with_proc_mut(current_pid(), |p, _| {
        p.supp_groups = groups.clone();
        0isize
    })
    .unwrap_or(-1)
}

// Create a new session.
//   - Fails with EPERM if the caller is already a process-group leader.
//   - The caller becomes the session leader; sid = pid = pgid.

pub fn sys_setsid() -> isize {
    let pid = current_pid();
    crate::proc::scheduler::with_proc_mut(pid, |p, _| {
        // A process group leader (pid == pgid) cannot create a new session.
        if p.pid == p.pgid {
            return -1isize; // EPERM
        }
        p.sid = p.pid;
        p.pgid = p.pid;
        p.pid as isize
    })
    .unwrap_or(-1)
}

pub fn sys_getsid(target_pid: u32) -> isize {
    let pid = if target_pid == 0 {
        current_pid()
    } else {
        target_pid as usize
    };
    crate::proc::scheduler::with_proc(pid, |p| p.sid as isize).unwrap_or(-3) // ESRCH
}

pub fn sys_getpgrp() -> isize {
    crate::proc::scheduler::with_proc(current_pid(), |p| p.pgid as isize).unwrap_or(0)
}

/// setpgid(pid, pgid)
///
/// Sets the process group of `pid` to `pgid`.
///
/// Rules:
///   - pid == 0 means the calling process.
///   - pgid == 0 means use pid as pgid (make a new group).
///   - The target must be the caller or a child in the same session.
///   - A session leader cannot change its pgid.
///   - pgid must be an existing pgid in the same session, or == pid.
pub fn sys_setpgid(pid: u32, pgid: u32) -> isize {
    let caller_pid = current_pid();
    let target_pid = if pid == 0 { caller_pid } else { pid as usize };
    let target_pgid = if pgid == 0 { target_pid as u32 } else { pgid };

    // Fetch caller's sid.
    let caller_sid = crate::proc::scheduler::with_proc(caller_pid, |p| p.sid).unwrap_or(0);

    crate::proc::scheduler::with_proc_mut(target_pid, |p, _| {
        // Must be caller or a direct child.
        if target_pid != caller_pid && p.ppid != caller_pid {
            return -1isize; // EPERM
        }
        // Session leaders cannot move to a different group.
        if p.pid == p.sid {
            return -1isize; // EPERM
        }
        // Target must be in the same session as caller.
        if p.sid != caller_sid {
            return -1isize; // EPERM
        }
        p.pgid = target_pgid as usize;
        0isize
    })
    .unwrap_or(-3) // ESRCH
}
