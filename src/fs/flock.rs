//! Advisory file locking: `flock(2)` and `fcntl(F_SETLK/F_SETLKW/F_GETLK)`.
//!
//! ## What we implement
//!
//! - **BSD locks** (`flock(2)`): whole-file LOCK_SH, LOCK_EX, LOCK_UN,
//!   optionally non-blocking (`LOCK_NB`).
//! - **POSIX record locks** (`fcntl F_SETLK`, `F_SETLKW`, `F_GETLK`):
//!   byte-range shared/exclusive locks identified by (pid, fd).
//!
//! ## RLIMIT_LOCKS enforcement
//!
//! The total number of **held** POSIX locks (flock + fcntl) for a process is
//! charged against `RLIMIT_LOCKS`.  When the soft limit is exceeded,
//! `ENOLCK` (-37) is returned.
//!
//! BSD `flock` locks are counted as one lock per fd.
//! POSIX `fcntl` locks are counted individually.
//!
//! ## Storage
//!
//! All locks are stored in a single global `LOCK_TABLE` keyed by inode id.
//! Each entry holds the list of current holders (shared) or the single
//! exclusive holder.  No kernel memory is allocated per-lock beyond the
//! `LockEntry` struct.
//!
//! ## Liveness / deadlock detection
//!
//! `F_SETLKW` spin-waits (yielding the CPU) until the lock is available.
//! Deadlock detection is not yet implemented — a process can hang if it
//! creates a circular wait.  This matches early-Linux behaviour.

extern crate alloc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use spin::Mutex;

use crate::proc::scheduler::{current_pid, with_proc};
use crate::proc::rlimit::{RLIMIT_LOCKS, RLIM_INFINITY};

// flock(2) operations
pub const LOCK_SH: i32 = 1;
pub const LOCK_EX: i32 = 2;
pub const LOCK_UN: i32 = 8;
pub const LOCK_NB: i32 = 4;

// fcntl(2) lock types
pub const F_RDLCK: i16 = 0;
pub const F_WRLCK: i16 = 1;
pub const F_UNLCK: i16 = 2;

// fcntl(2) commands (only the lock-related subset)
pub const F_GETLK:  i32 = 5;
pub const F_SETLK:  i32 = 6;
pub const F_SETLKW: i32 = 7;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Flock {
    pub l_type:   i16,
    pub l_whence: i16,
    pub _pad:     u32,
    pub l_start:  i64,
    pub l_len:    i64,
    pub l_pid:    u32,
}

#[derive(Clone, Debug)]
struct LockEntry {
    /// Owner PID.
    pid:    usize,
    /// `F_RDLCK` or `F_WRLCK`.
    ltype:  i16,
    /// Byte range: [start, end).  For `flock` the range is [0, u64::MAX).
    start:  u64,
    end:    u64,
    /// True if this came from `flock(2)` (whole-file BSD lock).
    is_bsd: bool,
}

/// Per-inode lock list.
type InodeLocks = Vec<LockEntry>;

// Global lock table: inode_id -> list of locks on that inode.
static LOCK_TABLE: Mutex<BTreeMap<u64, InodeLocks>> = Mutex::new(BTreeMap::new());

/// Returns the current lock count held by `pid` across all inodes.
fn count_locks_for(pid: usize) -> usize {
    let tbl = LOCK_TABLE.lock();
    tbl.values().flat_map(|v| v.iter()).filter(|e| e.pid == pid).count()
}

/// Check whether adding one more lock for `pid` would exceed the soft
/// `RLIMIT_LOCKS`.  Returns -ENOLCK (-37) if exceeded, 0 otherwise.
fn check_lock_limit(pid: usize) -> isize {
    let (soft, _) = with_proc(pid, |p| p.rlimits.get(RLIMIT_LOCKS))
        .unwrap_or((RLIM_INFINITY, RLIM_INFINITY));
    if soft == RLIM_INFINITY { return 0; }
    let current = count_locks_for(pid) as u64;
    if current >= soft { -37 } else { 0 } // ENOLCK
}

/// True if `a` and `b` overlap in byte range.
fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

/// True if `entry` (held by someone else) conflicts with a new lock of `ltype`
/// on range `[start, end)` by `pid`.
fn conflicts(entry: &LockEntry, pid: usize, ltype: i16, start: u64, end: u64) -> bool {
    if entry.pid == pid { return false; } // same owner never conflicts
    if !ranges_overlap(entry.start, entry.end, start, end) { return false; }
    // Two shared locks never conflict.
    if entry.ltype == F_RDLCK && ltype == F_RDLCK { return false; }
    true
}

/// `sys_flock(fd, operation)` — NR 73
///
/// `inode_id` must be resolved by the caller from the fd before calling here.
pub fn sys_flock(inode_id: u64, operation: i32) -> isize {
    let pid    = current_pid();
    let nb     = operation & LOCK_NB != 0;
    let op     = operation & !LOCK_NB;

    if op == LOCK_UN {
        // Release any BSD lock held by this pid on this inode.
        let mut tbl = LOCK_TABLE.lock();
        if let Some(list) = tbl.get_mut(&inode_id) {
            list.retain(|e| !(e.pid == pid && e.is_bsd));
        }
        return 0;
    }

    let ltype = match op {
        x if x == LOCK_SH => F_RDLCK,
        x if x == LOCK_EX => F_WRLCK,
        _ => return -22, // EINVAL
    };

    // Limit check.
    // First release any existing BSD lock from this pid (upgrade/downgrade
    // counts as one lock, not two).
    {
        let mut tbl = LOCK_TABLE.lock();
        if let Some(list) = tbl.get_mut(&inode_id) {
            let had = list.iter().any(|e| e.pid == pid && e.is_bsd);
            if !had {
                drop(tbl);
                let rc = check_lock_limit(pid);
                if rc < 0 { return rc; }
            } else {
                list.retain(|e| !(e.pid == pid && e.is_bsd));
            }
        } else {
            drop(tbl);
            let rc = check_lock_limit(pid);
            if rc < 0 { return rc; }
        }
    }

    loop {
        let mut tbl = LOCK_TABLE.lock();
        let list = tbl.entry(inode_id).or_insert_with(Vec::new);
        let blocked = list.iter().any(|e| conflicts(e, pid, ltype, 0, u64::MAX));
        if !blocked {
            list.push(LockEntry { pid, ltype, start: 0, end: u64::MAX, is_bsd: true });
            return 0;
        }
        if nb {
            return -11; // EAGAIN / EWOULDBLOCK
        }
        drop(tbl);
        crate::proc::scheduler::schedule();
    }
}

/// Handle `fcntl(fd, F_GETLK / F_SETLK / F_SETLKW, flock_ptr)`.
///
/// `inode_id` must be resolved by the caller.  `flock_uptr` is a userspace
/// pointer to `struct flock`.
pub fn sys_fcntl_lock(
    inode_id:   u64,
    cmd:        i32,
    flock_uptr: usize,
) -> isize {
    use crate::uaccess::{copy_from_user, copy_to_user};
    let pid = current_pid();

    let mut fl = Flock::default();
    if copy_from_user(flock_uptr as *const Flock, &mut fl).is_err() {
        return -14; // EFAULT
    }

    let (start, end) = lock_range(&fl);
    let ltype = fl.l_type;

    if cmd == F_GETLK {
        let tbl = LOCK_TABLE.lock();
        if let Some(list) = tbl.get(&inode_id) {
            for e in list.iter() {
                if conflicts(e, pid, ltype, start, end) {
                    let mut out = fl;
                    out.l_type   = e.ltype;
                    out.l_whence = 0; // SEEK_SET
                    out.l_start  = e.start as i64;
                    out.l_len    = (e.end - e.start) as i64;
                    out.l_pid    = e.pid as u32;
                    let _ = copy_to_user(flock_uptr as *mut Flock, &out);
                    return 0;
                }
            }
        }
        // No conflicting lock.
        fl.l_type = F_UNLCK;
        let _ = copy_to_user(flock_uptr as *mut Flock, &fl);
        return 0;
    }

    if ltype == F_UNLCK {
        let mut tbl = LOCK_TABLE.lock();
        if let Some(list) = tbl.get_mut(&inode_id) {
            list.retain(|e| {
                !(e.pid == pid && ranges_overlap(e.start, e.end, start, end))
            });
        }
        return 0;
    }

    // F_SETLK / F_SETLKW: acquire.
    // Check limit before trying (only for a brand-new lock — reuse of
    // existing range by same pid is allowed without consuming quota).
    {
        let has_existing = {
            let tbl = LOCK_TABLE.lock();
            tbl.get(&inode_id).map(|l| l.iter().any(|e| e.pid == pid
                && ranges_overlap(e.start, e.end, start, end))).unwrap_or(false)
        };
        if !has_existing {
            let rc = check_lock_limit(pid);
            if rc < 0 { return rc; }
        }
    }

    let nb = cmd == F_SETLK; // F_SETLKW blocks
    loop {
        let mut tbl = LOCK_TABLE.lock();
        let list = tbl.entry(inode_id).or_insert_with(Vec::new);
        let blocked = list.iter().any(|e| conflicts(e, pid, ltype, start, end));
        if !blocked {
            // Remove any existing lock from this pid that overlaps, then insert.
            list.retain(|e| !(e.pid == pid && ranges_overlap(e.start, e.end, start, end)));
            list.push(LockEntry { pid, ltype, start, end, is_bsd: false });
            return 0;
        }
        if nb {
            return -11; // EAGAIN
        }
        drop(tbl);
        crate::proc::scheduler::schedule();
    }
}

/// Release **all** locks held by `pid` on **all** inodes.
/// Called from `exit.rs` and `close()` (for BSD locks on the closed fd).
pub fn release_all_locks(pid: usize) {
    let mut tbl = LOCK_TABLE.lock();
    for list in tbl.values_mut() {
        list.retain(|e| e.pid != pid);
    }
}

/// Release BSD locks held by `pid` on `inode_id` (called from `close()`).
pub fn release_bsd_lock(pid: usize, inode_id: u64) {
    let mut tbl = LOCK_TABLE.lock();
    if let Some(list) = tbl.get_mut(&inode_id) {
        list.retain(|e| !(e.pid == pid && e.is_bsd));
    }
}

fn lock_range(fl: &Flock) -> (u64, u64) {
    // For simplicity: treat l_whence=SEEK_SET (0) only.
    // l_len == 0 means "to end of file" → we model as u64::MAX.
    let start = fl.l_start.max(0) as u64;
    let end = if fl.l_len == 0 {
        u64::MAX
    } else {
        start.saturating_add(fl.l_len.unsigned_abs())
    };
    (start, end)
}
