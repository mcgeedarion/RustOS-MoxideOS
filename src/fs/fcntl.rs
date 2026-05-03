//! fcntl — file descriptor control operations.
//!
//! ## Commands implemented
//!   F_DUPFD   (0)  — duplicate fd, using lowest fd >= arg
//!   F_DUPFD_CLOEXEC (1030) — same + set FD_CLOEXEC
//!   F_GETFD   (1)  — get fd flags (FD_CLOEXEC)
//!   F_SETFD   (2)  — set fd flags
//!   F_GETFL   (3)  — get file status flags (O_RDONLY/O_WRONLY/O_RDWR/O_NONBLOCK)
//!   F_SETFL   (4)  — set file status flags (only O_NONBLOCK honoured)
//!   F_GETLK   (5)  — get lock (stub: always "unlocked")
//!   F_SETLK   (6)  — set lock (stub: always succeeds)
//!   F_SETLKW  (7)  — set lock, wait (stub)
//!   F_SETOWN  (8)  — set process receiving SIGIO/SIGURG (stored, not acted upon)
//!   F_GETOWN  (9)  — get owner
//!   F_SETSIG  (10) — real-time signal to use instead of SIGIO
//!   F_ADD_SEALS (1033) / F_GET_SEALS (1034) — memfd sealing
//!
//! ## FD_CLOEXEC
//!   When set, the fd is closed across execve().  All fds created with
//!   O_CLOEXEC / SFD_CLOEXEC / EFD_CLOEXEC / TFD_CLOEXEC already have
//!   the flag set at creation.  fcntl(F_SETFD, FD_CLOEXEC) lets callers
//!   set it retroactively — used by libraries that open fds before exec.

extern crate alloc;
use crate::fs::vfs;
use alloc::collections::BTreeMap;
use spin::Mutex;

// fcntl commands
pub const F_DUPFD:          i32 = 0;
pub const F_GETFD:          i32 = 1;
pub const F_SETFD:          i32 = 2;
pub const F_GETFL:          i32 = 3;
pub const F_SETFL:          i32 = 4;
pub const F_GETLK:          i32 = 5;
pub const F_SETLK:          i32 = 6;
pub const F_SETLKW:         i32 = 7;
pub const F_SETOWN:         i32 = 8;
pub const F_GETOWN:         i32 = 9;
pub const F_SETSIG:         i32 = 10;
pub const F_DUPFD_CLOEXEC:  i32 = 1030;
pub const F_ADD_SEALS:      i32 = 1033;
pub const F_GET_SEALS:      i32 = 1034;

// fd flags
pub const FD_CLOEXEC: i32 = 1;

// file status flags (O_*)
pub const O_RDONLY:   i32 = 0;
pub const O_WRONLY:   i32 = 1;
pub const O_RDWR:     i32 = 2;
pub const O_NONBLOCK: i32 = 2048;
pub const O_APPEND:   i32 = 1024;
pub const O_CLOEXEC:  i32 = 524288;

// Per-fd metadata (cloexec flag, nonblock flag, file status flags, owner)
#[derive(Clone, Default)]
struct FdMeta {
    pub cloexec:   bool,
    pub nonblock:  bool,
    pub fl_flags:  i32,
    pub owner_pid: i32,
}

static FD_META:  Mutex<BTreeMap<usize, FdMeta>>  = Mutex::new(BTreeMap::new());
/// Maps fd# -> owning process pid (0 = unowned / legacy).
static FD_OWNER: Mutex<BTreeMap<usize, usize>>   = Mutex::new(BTreeMap::new());

// ── cloexec / nonblock / fl_flags ─────────────────────────────────────────

pub fn set_cloexec(fd: usize, val: bool) {
    FD_META.lock().entry(fd).or_default().cloexec = val;
}
pub fn is_cloexec(fd: usize) -> bool {
    FD_META.lock().get(&fd).map(|m| m.cloexec).unwrap_or(false)
}
pub fn get_fl(fd: usize) -> i32 {
    FD_META.lock().get(&fd).map(|m| m.fl_flags).unwrap_or(O_RDWR)
}
pub fn set_fl(fd: usize, flags: i32) {
    FD_META.lock().entry(fd).or_default().fl_flags = flags;
}
pub fn close_fd_meta(fd: usize) {
    FD_META.lock().remove(&fd);
    FD_OWNER.lock().remove(&fd);
}

// ── fd ownership (used by pidfd_getfd) ────────────────────────────────────

/// Record that `fd` is owned by `pid`.
pub fn set_fd_owner(fd: usize, pid: usize) {
    FD_OWNER.lock().insert(fd, pid);
}
/// Return the owning pid of `fd`, or 0 if unowned (any process may access).
pub fn fd_owner(fd: usize) -> usize {
    FD_OWNER.lock().get(&fd).copied().unwrap_or(0)
}
/// Clear ownership record on close.
pub fn clear_fd_owner(fd: usize) {
    FD_OWNER.lock().remove(&fd);
}

/// Close all fds that have FD_CLOEXEC set (called from execve).
pub fn close_on_exec() {
    let cloexec_fds: alloc::vec::Vec<usize> = FD_META.lock()
        .iter()
        .filter(|(_, m)| m.cloexec)
        .map(|(fd, _)| *fd)
        .collect();
    for fd in cloexec_fds {
        sys_close_fd(fd);
    }
}

fn sys_close_fd(fd: usize) {
    // pidfd check first: pidfd fds (1024+) are not in the vfs FD_TABLE
    if crate::fs::pidfd::is_pidfd(fd) {
        crate::fs::pidfd::free(fd);
        clear_fd_owner(fd);
        close_fd_meta(fd);
        return;
    }
    if crate::fs::timerfd::is_timerfd(fd) { crate::fs::timerfd::sys_close_tfd(fd); return; }
    if crate::fs::signalfd::is_signalfd(fd) { crate::fs::signalfd::sys_close_sfd(fd); return; }
    if crate::fs::eventfd::is_eventfd(fd) { crate::fs::eventfd::sys_close_efd(fd); return; }
    if crate::fs::pipe::is_pipe(fd) { crate::fs::pipe::sys_close_pipe(fd); return; }
    vfs::close(fd);
}

pub fn sys_fcntl(fd: usize, cmd: i32, arg: usize) -> isize {
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let new_fd = vfs::dup_from(fd, arg) as usize;
            if cmd == F_DUPFD_CLOEXEC { set_cloexec(new_fd, true); }
            new_fd as isize
        }
        F_GETFD => {
            if is_cloexec(fd) { FD_CLOEXEC as isize } else { 0 }
        }
        F_SETFD => {
            set_cloexec(fd, arg & FD_CLOEXEC as usize != 0);
            0
        }
        F_GETFL => get_fl(fd) as isize,
        F_SETFL => {
            set_fl(fd, arg as i32);
            if arg as i32 & O_NONBLOCK != 0 { set_nonblock(fd, true); }
            0
        }
        F_GETLK => {
            if arg != 0 {
                unsafe { core::ptr::write_bytes(arg as *mut u8, 0, 32); }
                unsafe { *(arg as *mut u16) = 2; } // F_UNLCK
            }
            0
        }
        F_SETLK | F_SETLKW => 0,
        F_SETOWN => {
            FD_META.lock().entry(fd).or_default().owner_pid = arg as i32;
            0
        }
        F_GETOWN => {
            FD_META.lock().get(&fd).map(|m| m.owner_pid as isize).unwrap_or(0)
        }
        F_ADD_SEALS => {
            if crate::mm::memfd::is_memfd(fd) {
                crate::mm::memfd::sys_memfd_add_seals(fd, arg as u32)
            } else { -22 }
        }
        F_GET_SEALS => {
            if crate::mm::memfd::is_memfd(fd) {
                crate::mm::memfd::sys_memfd_get_seals(fd)
            } else { 0 }
        }
        _ => -22,
    }
}

pub fn sys_dup2(oldfd: usize, newfd: usize) -> isize {
    if oldfd == newfd { return oldfd as isize; }
    sys_close_fd(newfd);
    let r = vfs::dup_as(oldfd, newfd);
    if r >= 0 {
        let cloexec = is_cloexec(oldfd);
        set_cloexec(newfd, cloexec);
    }
    r
}

pub fn sys_dup3(oldfd: usize, newfd: usize, flags: i32) -> isize {
    if oldfd == newfd { return -22; }
    let r = sys_dup2(oldfd, newfd);
    if r >= 0 && flags & O_CLOEXEC != 0 { set_cloexec(newfd, true); }
    r
}

/// Set O_NONBLOCK flag on fd.
pub fn set_nonblock(fd: usize, val: bool) {
    FD_META.lock().entry(fd).or_default().nonblock = val;
}

/// Check whether O_NONBLOCK is set on fd.
pub fn is_nonblock(fd: usize) -> bool {
    FD_META.lock().get(&fd).map(|m| m.nonblock).unwrap_or(false)
}
