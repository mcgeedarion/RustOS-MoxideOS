//! pidfd — process file descriptors (Linux 5.3+, extended in 5.6+).
//!
//! A pidfd is a stable, race-free handle to a process.  Unlike raw PIDs
//! it cannot be recycled: if the process exits the fd remains valid and
//! operations return ESRCH rather than silently targeting a new process.
//!
//! ## Syscalls implemented
//!   pidfd_open(pid, flags)               [NR 434] -> pidfd
//!   pidfd_send_signal(pidfd, sig, info, flags) [NR 424] -> 0/-errno
//!   pidfd_getfd(pidfd, targetfd, flags)  [NR 438] -> new_fd/-errno
//!
//! ## Design
//! pidfd fds occupy numbers PID_FD_BASE (1024) .. PID_FD_MAX (2048),
//! stored in a separate PIDFD_TABLE (BTreeMap<fd, pid>).
//! is_pidfd(fd) lets close() dispatch to free() without touching FdBacking.
//! PIDFD_NONBLOCK and O_CLOEXEC stored in FD_META via fcntl helpers.

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex;

const PID_FD_BASE:    usize = 1024;
const PID_FD_MAX:     usize = 2048;
const PIDFD_NONBLOCK: u32   = 0x800;
const SIGKILL:  u32 =  9;
const SIGSTOP:  u32 = 19;
const SIGCONT:  u32 = 18;

/// Maps pidfd number -> target pid.
static PIDFD_TABLE: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
/// Pending signal queue: maps pid -> pending signal (one slot; SIGKILL wins).
static PENDING_SIGNAL: Mutex<BTreeMap<usize, u32>> = Mutex::new(BTreeMap::new());

// ── Allocation ──────────────────────────────────────────────────────────

/// Allocate a fresh pidfd pointing at `pid`. Returns fd# or -EMFILE.
pub fn alloc(pid: usize) -> isize {
    let mut tbl = PIDFD_TABLE.lock();
    for fd in PID_FD_BASE..PID_FD_MAX {
        if !tbl.contains_key(&fd) {
            tbl.insert(fd, pid);
            return fd as isize;
        }
    }
    -24 // EMFILE
}

/// Release a pidfd (called from sys_close_fd dispatch).
pub fn free(fd: usize) {
    PIDFD_TABLE.lock().remove(&fd);
}

/// True if `fd` is a live pidfd.
pub fn is_pidfd(fd: usize) -> bool {
    PIDFD_TABLE.lock().contains_key(&fd)
}

/// Resolve pidfd -> target pid (None if fd invalid or process is zombie).
fn resolve(pidfd: usize) -> Option<usize> {
    let pid = *PIDFD_TABLE.lock().get(&pidfd)?;
    let procs = crate::proc::scheduler::procs_lock();
    let alive = procs.iter().any(|p| {
        p.pid == pid && p.state != crate::proc::process::State::Zombie
    });
    crate::proc::scheduler::procs_unlock();
    if alive { Some(pid) } else { None }
}

// ── sys_pidfd_open ───────────────────────────────────────────────────────
/// pidfd_open(pid, flags) -> pidfd  [NR 434]
///
/// flags: 0 or PIDFD_NONBLOCK (0x800). All other bits -> EINVAL.
/// Returns ESRCH if pid does not exist or is a zombie.
pub fn sys_pidfd_open(pid: usize, flags: u32) -> isize {
    if flags & !(PIDFD_NONBLOCK) != 0 { return -22; } // EINVAL
    if pid == 0 { return -3; }                         // ESRCH

    let procs = crate::proc::scheduler::procs_lock();
    let alive = procs.iter().any(|p| {
        p.pid == pid && p.state != crate::proc::process::State::Zombie
    });
    crate::proc::scheduler::procs_unlock();
    if !alive { return -3; } // ESRCH

    let fd = alloc(pid);
    if fd < 0 { return fd; }

    if flags & PIDFD_NONBLOCK != 0 {
        crate::fs::fcntl::set_nonblock(fd as usize, true);
    }
    // pidfd is always FD_CLOEXEC per spec
    crate::fs::fcntl::set_cloexec(fd as usize, true);
    fd
}

// ── sys_pidfd_send_signal ────────────────────────────────────────────────
/// pidfd_send_signal(pidfd, sig, info_va, flags) -> 0/-errno  [NR 424]
///
/// sig == 0: existence check only.
/// SIGKILL: immediate Zombie + notify_exit wakes waitpid.
/// SIGSTOP: Blocked. SIGCONT: wake_pid. Others: queued in PENDING_SIGNAL.
pub fn sys_pidfd_send_signal(
    pidfd: usize, sig: u32, _info_va: usize, flags: u32,
) -> isize {
    if flags != 0 { return -22; }
    if sig > 64   { return -22; }

    let pid = match resolve(pidfd) {
        Some(p) => p,
        None    => return if !is_pidfd(pidfd) { -9 } else { -3 }, // EBADF / ESRCH
    };

    if sig == 0 { return 0; } // existence check

    match sig {
        SIGKILL => {
            let procs = crate::proc::scheduler::procs_lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.state     = crate::proc::process::State::Zombie;
                p.exit_code = -(sig as i32);
            }
            crate::proc::scheduler::procs_unlock();
            crate::proc::wait::notify_exit(pid);
            0
        }
        SIGSTOP => {
            let procs = crate::proc::scheduler::procs_lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.state = crate::proc::process::State::Blocked;
            }
            crate::proc::scheduler::procs_unlock();
            0
        }
        SIGCONT => { crate::proc::scheduler::wake_pid(pid); 0 }
        _ => {
            PENDING_SIGNAL.lock().insert(pid, sig);
            0
        }
    }
}

/// Check and consume one pending signal for `pid`.
/// Called by the syscall dispatcher before returning to userspace.
pub fn check_pending_signal(pid: usize) -> u32 {
    PENDING_SIGNAL.lock().remove(&pid).unwrap_or(0)
}

// ── sys_pidfd_getfd ──────────────────────────────────────────────────────
/// pidfd_getfd(pidfd, targetfd, flags) -> new_fd/-errno  [NR 438]
///
/// Dups `targetfd` from the process identified by `pidfd` into the caller.
/// New fd always has FD_CLOEXEC set (per spec).
/// Requires CAP_SYS_PTRACE or caller == target (same PID).
pub fn sys_pidfd_getfd(pidfd: usize, targetfd: usize, flags: u32) -> isize {
    if flags != 0 { return -22; } // EINVAL

    let target_pid = match resolve(pidfd) {
        Some(p) => p,
        None    => return if !is_pidfd(pidfd) { -9 } else { -3 },
    };

    let caller_pid = crate::proc::scheduler::current_pid();
    // Allow if same process OR if capability check passes (always true in stub)
    let has_ptrace = crate::security::check_capability(19 /* CAP_SYS_PTRACE */);
    if !has_ptrace && caller_pid != target_pid {
        return -1; // EPERM
    }

    // Validate fd belongs to target (or is unowned in legacy flat table)
    let owner = crate::fs::fcntl::fd_owner(targetfd);
    if owner != 0 && owner != target_pid {
        return -9; // EBADF
    }

    let new_fd = crate::fs::vfs::dup_from(targetfd, 3);
    if new_fd < 0 { return new_fd; }

    crate::fs::fcntl::set_fd_owner(new_fd as usize, caller_pid);
    crate::fs::fcntl::set_cloexec(new_fd as usize, true);
    new_fd
}
