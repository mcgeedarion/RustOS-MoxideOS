//! fcntl — file descriptor control operations.

extern crate alloc;
use crate::fs::vfs;
use crate::uaccess::{copy_to_user, validate_user_ptr};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

// fcntl commands
pub const F_DUPFD: i32 = 0;
pub const F_GETFD: i32 = 1;
pub const F_SETFD: i32 = 2;
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
pub const F_GETLK: i32 = 5;
pub const F_SETLK: i32 = 6;
pub const F_SETLKW: i32 = 7;
pub const F_SETOWN: i32 = 8;
pub const F_GETOWN: i32 = 9;
pub const F_SETSIG: i32 = 10;
pub const F_DUPFD_CLOEXEC: i32 = 1030;
pub const F_ADD_SEALS: i32 = 1033;
pub const F_GET_SEALS: i32 = 1034;

// fd flags
pub const FD_CLOEXEC: i32 = 1;

// file status flags (O_*)
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_NONBLOCK: i32 = 2048; // 0o4000
pub const O_APPEND: i32 = 1024; // 0o2000
pub const O_CLOEXEC: i32 = 524288; // 0o2000000

// seek whence constants  (re-exported by vfs.rs)
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

const F_RDLCK: i16 = 0;
const F_WRLCK: i16 = 1;
const F_UNLCK: i16 = 2;

#[derive(Clone, Default)]
struct FdMeta {
    pub cloexec: bool,
    pub nonblock: bool,
    pub fl_flags: i32,
    pub owner_pid: i32,
    pub debug_name: Option<alloc::string::String>,
}

static FD_META: Mutex<BTreeMap<usize, FdMeta>> = Mutex::new(BTreeMap::new());
static FD_LOCKS: Mutex<BTreeMap<usize, i16>> = Mutex::new(BTreeMap::new());

#[inline]
fn count_open_fds() -> usize {
    FD_META.lock().len()
}

fn check_nofile_limit() -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let would_exceed =
        crate::proc::scheduler::with_proc(pid, |p| p.rlimits.exceeds_nofile(count_open_fds()))
            .unwrap_or(false);
    if would_exceed {
        -24
    } else {
        0
    }
}

pub fn set_cloexec(fd: usize, val: bool) {
    FD_META.lock().entry(fd).or_default().cloexec = val;
}
pub fn is_cloexec(fd: usize) -> bool {
    FD_META.lock().get(&fd).map(|m| m.cloexec).unwrap_or(false)
}
pub fn get_fl(fd: usize) -> i32 {
    FD_META
        .lock()
        .get(&fd)
        .map(|m| m.fl_flags)
        .unwrap_or(O_RDWR)
}
pub fn set_fl(fd: usize, flags: i32) {
    FD_META.lock().entry(fd).or_default().fl_flags = flags;
}
/// Remove all metadata for `fd`. Called on close and by close_range.
pub fn close_fd_meta(fd: usize) {
    FD_META.lock().remove(&fd);
}

pub fn set_fd_owner(fd: usize, pid: usize) {
    FD_META.lock().entry(fd).or_default().owner_pid = pid as i32;
}
pub fn fd_owner(fd: usize) -> usize {
    FD_META
        .lock()
        .get(&fd)
        .map(|m| m.owner_pid as usize)
        .unwrap_or(0)
}
pub fn clear_fd_owner(fd: usize) {
    if let Some(m) = FD_META.lock().get_mut(&fd) {
        m.owner_pid = 0;
    }
}

pub fn fd_set_debug_name(fd: usize, name: alloc::string::String) {
    FD_META.lock().entry(fd).or_default().debug_name = Some(name);
}

pub fn fd_get_debug_name(fd: usize) -> Option<alloc::string::String> {
    FD_META.lock().get(&fd).and_then(|m| m.debug_name.clone())
}

pub fn close_on_exec() {
    let cloexec_fds: Vec<usize> = {
        let mut meta = FD_META.lock();
        let fds: Vec<usize> = meta
            .iter()
            .filter(|(_, m)| m.cloexec)
            .map(|(fd, _)| *fd)
            .collect();
        for fd in &fds {
            meta.remove(fd);
        }
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
    if crate::fs::pidfd::is_pidfd(fd) {
        crate::fs::pidfd::free(fd);
        return;
    }
    if crate::fs::timerfd::is_timerfd(fd) {
        crate::fs::timerfd::sys_close_tfd(fd);
        return;
    }
    if crate::fs::signalfd::is_signalfd(fd) {
        crate::fs::signalfd::sys_close_sfd(fd);
        return;
    }
    if crate::fs::eventfd::is_eventfd(fd) {
        crate::fs::eventfd::sys_close_efd(fd);
        return;
    }
    if crate::fs::pipe::is_pipe(fd) {
        crate::fs::pipe::sys_close_pipe(fd);
        return;
    }
    if crate::net::socket::is_socket_fd(fd) {
        crate::net::socket::sys_close_socket(fd);
        return;
    }
    vfs::close(fd);
}

fn sys_close_fd(fd: usize) {
    close_fd_meta(fd);
    close_fd_no_meta(fd);
}

pub fn fd_open(path: &str, flags: i32) -> Result<usize, isize> {
    let limit_check = check_nofile_limit();
    if limit_check < 0 {
        return Err(limit_check);
    }

    let fd = vfs::open_raw(path, flags as u32)?;
    FD_META.lock().entry(fd).or_default().fl_flags = flags;

    if flags & O_CLOEXEC != 0 {
        FD_META.lock().entry(fd).or_default().cloexec = true;
    }
    if flags & O_NONBLOCK != 0 {
        FD_META.lock().entry(fd).or_default().nonblock = true;
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

pub fn fd_create(path: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::create(path)
}
pub fn fd_unlink(path: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::unlink(path)
}
pub fn fd_link(old: &str, new: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::link(old, new)
}
pub fn fd_rmdir(path: &str) -> Result<(), isize> {
    crate::fs::vfs_ops::rmdir(path)
}
pub fn dup_as_raw(old_fd: usize, new_fd: usize) -> isize {
    vfs::dup_as_raw(old_fd, new_fd)
}
pub fn dup_from_raw(fd: usize, min_fd: usize) -> isize {
    vfs::dup_from_raw(fd, min_fd)
}

fn current_proc_entry(fd: usize) -> Result<crate::fs::process_fd::FdEntry, isize> {
    let pid = crate::proc::scheduler::current_pid();
    crate::fs::process_fd::proc_fd_get(pid, fd).ok_or(-9)
}

fn duplicate_backing_fd(bfd: usize) -> Result<usize, isize> {
    if crate::fs::pipe::is_pipe(bfd) {
        crate::fs::pipe::pipe_dup(bfd);
        Ok(bfd)
    } else if crate::net::socket::is_socket_fd(bfd) {
        crate::net::socket::socket_dup(bfd);
        Ok(bfd)
    } else if crate::fs::eventfd::is_eventfd(bfd) {
        crate::fs::eventfd::efd_dup(bfd);
        Ok(bfd)
    } else if crate::fs::timerfd::is_timerfd(bfd) {
        crate::fs::timerfd::tfd_dup(bfd);
        Ok(bfd)
    } else if crate::fs::inotify::is_inotify_fd(bfd) {
        crate::fs::inotify::inotify_dup(bfd);
        Ok(bfd)
    } else if crate::fs::fanotify::is_fanotify_fd(bfd) {
        crate::fs::fanotify::fanotify_dup(bfd);
        Ok(bfd)
    } else if crate::fs::devfs::get_dev_fd(bfd).is_some()
        || crate::fs::procfs::is_procfs_fd(bfd)
        || crate::fs::sysfs::is_sysfs_fd(bfd)
        || crate::fs::cgroupfs::is_cgroupfs_fd(bfd)
        || crate::fs::scheme_fd::is_scheme_fd(bfd)
    {
        Ok(bfd)
    } else {
        let r = vfs::dup_from(bfd, bfd);
        if r < 0 {
            Err(r)
        } else {
            Ok(r as usize)
        }
    }
}

pub fn sys_fcntl(fd: usize, cmd: i32, arg: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    let entry = match current_proc_entry(fd) {
        Ok(e) => e,
        Err(e) => return e,
    };
    let bfd = entry.backing_fd;

    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let limit_check = check_nofile_limit();
            if limit_check < 0 {
                return limit_check;
            }

            let new_fd = {
                let mut candidate = arg;
                loop {
                    if crate::fs::process_fd::proc_fd_get(pid, candidate).is_none() {
                        break candidate;
                    }
                    candidate = candidate.saturating_add(1);
                    if candidate == usize::MAX {
                        return -24;
                    }
                }
            };

            let new_bfd = match duplicate_backing_fd(bfd) {
                Ok(n) => n,
                Err(e) => return e,
            };
            let flags = if cmd == F_DUPFD_CLOEXEC {
                (entry.fl_flags as u32) | O_CLOEXEC as u32
            } else {
                entry.fl_flags as u32
            };
            let installed = crate::fs::process_fd::proc_fd_install(
                pid,
                new_bfd,
                entry.path.clone(),
                flags,
                Some(new_fd),
            );
            FD_META.lock().entry(new_bfd).or_default().fl_flags = entry.fl_flags;
            if cmd == F_DUPFD_CLOEXEC {
                crate::fs::process_fd::proc_fd_set_cloexec(pid, installed, true);
                set_cloexec(new_bfd, true);
            }
            installed as isize
        },
        F_GETFD => {
            if entry.cloexec {
                FD_CLOEXEC as isize
            } else {
                0
            }
        },
        F_SETFD => {
            let cloexec = arg & FD_CLOEXEC as usize != 0;
            set_cloexec(bfd, cloexec);
            crate::fs::process_fd::proc_fd_set_cloexec(pid, fd, cloexec);
            0
        },
        F_GETFL => entry.fl_flags as isize,
        F_SETFL => {
            let flags = arg as i32;
            set_fl(bfd, flags);
            set_nonblock(bfd, flags & O_NONBLOCK != 0);
            crate::fs::process_fd::proc_fd_setfl(pid, fd, flags);
            0
        },
        F_GETLK => {
            if arg == 0 {
                return 0;
            }
            if !validate_user_ptr(arg, 32) {
                return -14;
            }
            let mut buf = [0u8; 32];
            let lock_ty = FD_LOCKS.lock().get(&bfd).copied().unwrap_or(F_UNLCK);
            buf[0..2].copy_from_slice(&lock_ty.to_le_bytes());
            if !copy_to_user(arg, &buf) {
                return -14;
            }
            0
        },
        F_SETLK | F_SETLKW => {
            if arg == 0 || !validate_user_ptr(arg, 2) {
                return -14;
            }
            let mut t = [0u8; 2];
            if crate::uaccess::copy_from_user(&mut t, arg).is_err() {
                return -14;
            }
            let req = i16::from_le_bytes(t);
            let mut locks = FD_LOCKS.lock();
            match req {
                F_UNLCK => {
                    locks.remove(&bfd);
                    0
                },
                F_RDLCK | F_WRLCK => {
                    if let Some(curr) = locks.get(&bfd).copied() {
                        if curr != req {
                            return -11; // EAGAIN
                        }
                    }
                    locks.insert(bfd, req);
                    0
                },
                _ => -22,
            }
        },
        F_SETOWN => {
            FD_META.lock().entry(bfd).or_default().owner_pid = arg as i32;
            0
        },
        F_GETOWN => FD_META
            .lock()
            .get(&bfd)
            .map(|m| m.owner_pid as isize)
            .unwrap_or(0),
        F_ADD_SEALS => {
            if crate::mm::memfd::is_memfd(fd) {
                crate::mm::memfd::sys_memfd_add_seals(fd, arg as u32)
            } else {
                -22
            }
        },
        F_GET_SEALS => {
            if crate::mm::memfd::is_memfd(fd) {
                crate::mm::memfd::sys_memfd_get_seals(fd)
            } else {
                0
            }
        },
        _ => -22,
    }
}

pub fn sys_dup2(oldfd: usize, newfd: usize) -> isize {
    crate::fs::process_fd::proc_fd_dup2(crate::proc::scheduler::current_pid(), oldfd, newfd)
}

pub fn sys_dup3(oldfd: usize, newfd: usize, flags: i32) -> isize {
    if oldfd == newfd {
        return -22;
    }
    let r = sys_dup2(oldfd, newfd);
    if r >= 0 && flags & O_CLOEXEC != 0 {
        crate::fs::process_fd::proc_fd_set_cloexec(crate::proc::scheduler::current_pid(), newfd, true);
    }
    r
}

pub fn set_nonblock(fd: usize, val: bool) {
    FD_META.lock().entry(fd).or_default().nonblock = val;
}
pub fn is_nonblock(fd: usize) -> bool {
    FD_META.lock().get(&fd).map(|m| m.nonblock).unwrap_or(false)
}
