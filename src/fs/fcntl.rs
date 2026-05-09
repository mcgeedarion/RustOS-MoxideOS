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
//!   set it retroactively.
//!
//! ## RLIMIT_NOFILE enforcement
//!   fd_open checks the current process soft NOFILE limit before allocating
//!   a new fd.  F_DUPFD also checks the limit because dup produces a new fd.

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
pub const O_NONBLOCK: i32 = 2048;
pub const O_APPEND:   i32 = 1024;
pub const O_CLOEXEC:  i32 = 524288;

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

/// Returns the number of currently open fds tracked in FD_META.
/// Used to enforce RLIMIT_NOFILE before opening/duping a new fd.
#[inline]
fn count_open_fds() -> usize {
    FD_META.lock().len()
}

/// Check RLIMIT_NOFILE for the current process.
/// Returns -24 (EMFILE) if the limit would be exceeded, 0 if OK.
fn check_nofile_limit() -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let would_exceed = crate::proc::scheduler::with_proc(pid, |p| {
        p.rlimits.exceeds_nofile(count_open_fds())
    }).unwrap_or(false);
    if would_exceed { -24 } else { 0 }
}

// ── cloexec / nonblock / fl_flags ────────────────────────────────────────────
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

// ── fd debug names ────────────────────────────────────────────────────────────

pub fn fd_set_debug_name(fd: usize, name: alloc::string::String) {
    FD_META.lock().entry(fd).or_default().debug_name = Some(name);
}

pub fn fd_get_debug_name(fd: usize) -> Option<alloc::string::String> {
    FD_META.lock().get(&fd).and_then(|m| m.debug_name.clone())
}

// ── close_on_exec ────────────────────────────────────────────────────────────

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

// ── fd_open — RLIMIT_NOFILE enforced here ─────────────────────────────────────
//
// This is the single choke point for all new fd allocations that go through
// the VFS path (open, openat, creat, memfd_create, pipe, socket, etc.).
// The fd number is assigned by the underlying layer (ext2/tmpfs/ramfs/etc.),
// so we check *before* calling through and register the metadata afterwards.
//
// NOTE: pipe(2), socket(2), eventfd, timerfd, signalfd, pidfd all call
// their own alloc helpers which bypass fd_open.  Those paths register
// their fds via set_cloexec / set_fd_owner etc., but they do NOT touch
// FD_META directly on creation.  For now RLIMIT_NOFILE is only enforced
// on the vfs::open path (open/openat/creat).  The special-fd paths can
// be wired in a follow-up.

/// Open a path and register the resulting fd in FD_META.
/// Returns Err(-24) (EMFILE) if RLIMIT_NOFILE would be exceeded.
pub fn fd_open(path: &str, flags: i32) -> Result<usize, isize> {
    // Enforce RLIMIT_NOFILE before allocating.
    let limit_check = check_nofile_limit();
    if limit_check < 0 { return Err(limit_check); }

    let fd = vfs::open_raw(path, flags as u32)?;

    // Register in FD_META so future limit checks include this fd.
    FD_META.lock().entry(fd).or_default();

    if flags & O_CLOEXEC != 0 {
        FD_META.lock().entry(fd).or_default().cloexec = true;
    }

    Ok(fd)
}

/// Read from fd (thin forwarder, no limit check needed).
pub fn fd_read(fd: usize, buf: &mut [u8]) -> isize {
    vfs::read_raw(fd, buf)
}

/// Write to fd.
pub fn fd_write(fd: usize, buf: &[u8]) -> isize {
    vfs::write_raw(fd, buf)
}

/// Seek on fd.
pub fn fd_seek(fd: usize, offset: i64, whence: i32) -> isize {
    vfs::seek_raw(fd, offset, whence)
}

/// Close fd and remove metadata.
pub fn fd_close(fd: usize) {
    sys_close_fd(fd);
}

/// Return the path registered for fd, if any.
pub fn fd_get_path(fd: usize) -> Option<alloc::string::String> {
    vfs::path_of_raw(fd)
}

/// Return the size of the file underlying fd.
pub fn fd_size(fd: usize) -> Option<usize> {
    vfs::size_of_raw(fd)
}

// ── sys_fcntl ────────────────────────────────────────────────────────────────

pub fn sys_fcntl(fd: usize, cmd: i32, arg: usize) -> isize {
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            // RLIMIT_NOFILE applies to dup as well (POSIX).
            let limit_check = check_nofile_limit();
            if limit_check < 0 { return limit_check; }

            let new_fd = vfs::dup_from(fd, arg) as usize;
            // Register new_fd in FD_META.
            FD_META.lock().entry(new_fd).or_default();
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
    // dup2 replaces newfd — not a new allocation if newfd was already open.
    // Only check the limit when newfd is not already open.
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

// ── nonblock ─────────────────────────────────────────────────────────────────

pub fn set_nonblock(fd: usize, val: bool) {
    FD_META.lock().entry(fd).or_default().nonblock = val;
}
pub fn is_nonblock(fd: usize) -> bool {
    FD_META.lock().get(&fd).map(|m| m.nonblock).unwrap_or(false)
}
