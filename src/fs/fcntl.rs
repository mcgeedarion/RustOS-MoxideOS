//! fcntl — file descriptor control operations.
//!
//! ## Commands implemented
//!   F_DUPFD   (0)  — duplicate fd, using lowest fd >= arg
//!   F_DUPFD_CLOEXEC (1030) — same + set FD_CLOEXEC
//!   F_GETFD   (1)  — get fd flags (FD_CLOEXEC)
//!   F_SETFD   (2)  — set fd flags (FD_CLOEXEC) — synced to ProcFdTable
//!   F_GETFL   (3)  — get file status flags (O_RDONLY/O_WRONLY/O_RDWR/O_NONBLOCK)
//!   F_SETFL   (4)  — set file status flags — synced to ProcFdTable
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
//!   set it retroactively.
//!
//! ## RLIMIT_NOFILE enforcement
//!   fd_open checks the current process soft NOFILE limit before allocating
//!   a new fd.  F_DUPFD also checks the limit because dup produces a new fd.
//!
//! ## Dual-store synchronisation
//!   `FD_META` tracks backing-fd metadata used by kernel subsystems.
//!   `ProcFdTable` (process_fd.rs) tracks per-process-local fd metadata
//!   visible to syscalls like sys_write (O_APPEND) and sys_close_on_exec.
//!   F_SETFL and F_SETFD must update BOTH stores so they remain consistent.

extern crate alloc;
use crate::fs::vfs;
use crate::uaccess::{copy_to_user, validate_user_ptr};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

// fcntl commands
pub const F_DUPFD:         i32 = 0;
pub const F_GETFD:         i32 = 1;
pub const F_SETFD:         i32 = 2;
pub const F_GETFL:         i32 = 3;
pub const F_SETFL:         i32 = 4;
pub const F_GETLK:         i32 = 5;
pub const F_SETLK:         i32 = 6;
pub const F_SETLKW:        i32 = 7;
pub const F_SETOWN:        i32 = 8;
pub const F_GETOWN:        i32 = 9;
pub const F_SETSIG:        i32 = 10;
pub const F_DUPFD_CLOEXEC: i32 = 1030;
pub const F_ADD_SEALS:     i32 = 1033;
pub const F_GET_SEALS:     i32 = 1034;

// fd flags
pub const FD_CLOEXEC: i32 = 1;

// file status flags (O_*)
pub const O_RDONLY:   i32 = 0;
pub const O_WRONLY:   i32 = 1;
pub const O_RDWR:     i32 = 2;
pub const O_NONBLOCK: i32 = 2048;   // 0o4000
pub const O_APPEND:   i32 = 1024;   // 0o2000
pub const O_CLOEXEC:  i32 = 524288; // 0o2000000

// seek whence constants  (re-exported by vfs.rs)
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

const F_UNLCK: u16 = 2;

#[derive(Clone, Default)]
struct FdMeta {
    pub cloexec:    bool,
    pub nonblock:   bool,
    pub fl_flags:   i32,
    pub owner_pid:  i32,
    pub debug_name: Option<alloc::string::String>,
}

static FD_META: Mutex<BTreeMap<usize, FdMeta>> = Mutex::new(BTreeMap::new());

// ── RLIMIT_NOFILE helpers ─────────────────────────────────────────────────────

#[inline]
fn count_open_fds() -> usize {
    FD_META.lock().len()
}

fn check_nofile_limit() -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let would_exceed = crate::proc::scheduler::with_proc(pid, |p| {
        p.rlimits.exceeds_nofile(count_open_fds())
    }).unwrap_or(false);
    if would_exceed { -24 } else { 0 }
}

// ── cloexec / nonblock / fl_flags ──────────────────────────────────────────────
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
/// Remove all metadata for `fd`. Called on close and by close_range.
pub fn close_fd_meta(fd: usize) {
    FD_META.lock().remove(&fd);
}

// ── fd ownership ─────────────────────────────────────────────────────────────
pub fn set_fd_owner(fd: usize, pid: usize) {
    FD_META.lock().entry(fd).or_default().owner_pid = pid as i32;
}
pub fn fd_owner(fd: usize) -> usize {
    FD_META.lock().get(&fd).map(|m| m.owner_pid as usize).unwrap_or(0)
}
pub fn clear_fd_owner(fd: usize) {
    if let Some(m) = FD_META.lock().get_mut(&fd) {
        m.owner_pid = 0;
    }
}

// ── fd debug names ──────────────────────────────────────────────────────────────

pub fn fd_set_debug_name(fd: usize, name: alloc::string::String) {
    FD_META.lock().entry(fd).or_default().debug_name = Some(name);
}

pub fn fd_get_debug_name(fd: usize) -> Option<alloc::string::String> {
    FD_META.lock().get(&fd).and_then(|m| m.debug_name.clone())
}

// ── close_on_exec ─────────────────────────────────────────────────────────────

pub fn close_on_exec() {
    let cloexec_fds: Vec<usize> = {
        let mut meta = FD_META.lock();
        let fds: Vec<usize> = meta.iter()
            .filter(|(_, m)| m.cloexec)
            .map(|(fd, _)| *fd)
            .collect();
        for fd in &fds { meta.remove(fd); }
        fds
    };
    for fd in cloexec_fds {
        close_fd_no_meta(fd);
    }
}

pub fn cloexec_range(lo: usize, hi: usize) {
    let mut meta = FD_META.lock();
    for (fd, m) in meta.iter_mut() {
        if *fd >= lo && *fd <= hi {
            m.cloexec = true;
        }
    }
}

pub fn close_fd_no_meta(fd: usize) {
    if crate::fs::pidfd::is_pidfd(fd)           { crate::fs::pidfd::free(fd);                    return; }
    if crate::fs::timerfd::is_timerfd(fd)       { crate::fs::timerfd::sys_close_tfd(fd);         return; }
    if crate::fs::signalfd::is_signalfd(fd)     { crate::fs::signalfd::sys_close_sfd(fd);        return; }
    if crate::fs::eventfd::is_eventfd(fd)       { crate::fs::eventfd::sys_close_efd(fd);         return; }
    if crate::fs::pipe::is_pipe(fd)             { crate::fs::pipe::sys_close_pipe(fd);           return; }
    if crate::net::socket::is_socket_fd(fd)     { crate::net::socket::sys_close_socket(fd);      return; }
    vfs::close(fd);
}

fn sys_close_fd(fd: usize) {
    close_fd_meta(fd);
    close_fd_no_meta(fd);
}

// ── fd_open ─────────────────────────────────────────────────────────────────

pub fn fd_open(path: &str, flags: i32) -> Result<usize, isize> {
    let limit_check = check_nofile_limit();
    if limit_check < 0 { return Err(limit_check); }

    let fd = vfs::open_raw(path, flags as u32)?;

    FD_META.lock().entry(fd).or_default();

    if flags & O_CLOEXEC != 0 {
        FD_META.lock().entry(fd).or_default().cloexec = true;
    }

    Ok(fd)
}

pub fn fd_read(fd: usize, buf: &mut [u8]) -> isize {
    vfs::read_raw(fd, buf)
}

pub fn fd_write(fd: usize, buf: &[u8]) -> isize {
    vfs::write_raw(fd, buf)
}

pub fn fd_seek(fd: usize, offset: i64, whence: i32) -> isize {
    vfs::seek_raw(fd, offset, whence)
}

pub fn fd_close(fd: usize) {
    sys_close_fd(fd);
}

pub fn fd_get_path(fd: usize) -> Option<alloc::string::String> {
    vfs::path_of_raw(fd)
}

pub fn fd_size(fd: usize) -> Option<usize> {
    vfs::size_of_raw(fd)
}

// ── sys_fcntl ────────────────────────────────────────────────────────────────

pub fn sys_fcntl(fd: usize, cmd: i32, arg: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let limit_check = check_nofile_limit();
            if limit_check < 0 { return limit_check; }

            let new_fd = vfs::dup_from(fd, arg) as usize;
            FD_META.lock().entry(new_fd).or_default();
            if cmd == F_DUPFD_CLOEXEC { set_cloexec(new_fd, true); }
            new_fd as isize
        }
        F_GETFD => {
            if is_cloexec(fd) { FD_CLOEXEC as isize } else { 0 }
        }
        F_SETFD => {
            let cloexec = arg & FD_CLOEXEC as usize != 0;
            // Update FD_META (legacy backing-fd metadata).
            set_cloexec(fd, cloexec);
            // Update ProcFdTable (per-process-local fd metadata).
            // `fd` here is the *user-visible* fd number == the process-local fd
            // because fcntl is always called with the user fd.
            crate::fs::process_fd::proc_fd_set_cloexec(pid, fd, cloexec);
            0
        }
        F_GETFL => get_fl(fd) as isize,
        F_SETFL => {
            let flags = arg as i32;
            // Update FD_META.
            set_fl(fd, flags);
            if flags & O_NONBLOCK != 0 { set_nonblock(fd, true); }
            // Update ProcFdTable so proc_fd_getfl (used by sys_write O_APPEND
            // and other flag-aware paths) sees the new flags immediately.
            crate::fs::process_fd::proc_fd_setfl(pid, fd, flags);
            0
        }
        F_GETLK => {
            if arg == 0 { return 0; }
            if !validate_user_ptr(arg, 32) { return -14; }
            let mut buf = [0u8; 32];
            buf[0..2].copy_from_slice(&F_UNLCK.to_le_bytes());
            if copy_to_user(arg, &buf).is_err() { return -14; }
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

// ── dup2 / dup3 ──────────────────────────────────────────────────────────────

pub fn sys_dup2(oldfd: usize, newfd: usize) -> isize {
    if oldfd == newfd { return oldfd as isize; }
    let newfd_open = FD_META.lock().contains_key(&newfd);
    if !newfd_open {
        let limit_check = check_nofile_limit();
        if limit_check < 0 { return limit_check; }
    }
    sys_close_fd(newfd);
    let r = vfs::dup_as(oldfd, newfd);
    if r >= 0 {
        FD_META.lock().entry(newfd).or_default();
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

// ── nonblock ────────────────────────────────────────────────────────────────

pub fn set_nonblock(fd: usize, val: bool) {
    FD_META.lock().entry(fd).or_default().nonblock = val;
}
pub fn is_nonblock(fd: usize) -> bool {
    FD_META.lock().get(&fd).map(|m| m.nonblock).unwrap_or(false)
}
