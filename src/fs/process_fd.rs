//! Per-process file descriptor table.
//!
//! Each process has a `ProcFdTable` stored in `PROC_FD_TABLES`, keyed by pid.
//! A process-local fd number maps to a `FdEntry` that holds the kernel-
//! internal *backing fd* (used with vfs / devfs / pipe / socket internals),
//! the VFS path (for AT_FDCWD resolution and /proc readlink), cloexec,
//! nonblock, and open-file status flags.
//!
//! # Relationship to fcntl::FD_META
//!
//! `FD_META` (fcntl.rs) tracks metadata for *backing* fds that are directly
//! visible to kernel subsystems (devfs, pipe, socket, inotify, …).  The
//! per-process table in this file adds a second layer: user-space sees
//! process-local fd numbers; the dispatch functions below translate them to
//! backing fds before forwarding to the existing subsystem helpers.
//!
//! Both stores are kept in sync by fcntl::sys_fcntl (F_SETFL, F_SETFD) so
//! flag-aware paths (sys_write O_APPEND, proc_fd_close_on_exec) always see
//! current values regardless of which store they query.
//!
//! # Lifecycle
//!
//! | Event            | Call                          |
//! |------------------|-------------------------------|
//! | process created  | `proc_fd_alloc(pid)`          |
//! | fork()           | `proc_fd_fork(parent, child)` |
//! | execve()         | `proc_fd_close_on_exec(pid)`  |
//! | exit()           | `proc_fd_free(pid)`           |

extern crate alloc;
use crate::core::fast_hash::KernelFastMap;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
const O_CREAT: u32 = 0o100;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;
const O_NONBLOCK: u32 = 0o4000;
/// Public alias for O_CLOEXEC, used by io_syscalls::sys_dup.
pub const O_CLOEXEC_FLAG: u32 = 0o2000000;

// RLIMIT_NOFILE index
const RLIMIT_NOFILE: usize = 7;

/// One entry in a process's fd table.
#[derive(Clone, Debug)]
pub struct FdEntry {
    /// Kernel-internal backing fd (used with vfs/devfs/pipe/socket helpers).
    pub backing_fd: usize,
    /// VFS path, if this is a path-backed file (regular, directory, procfs, …).
    pub path: Option<String>,
    /// FD_CLOEXEC — closed across execve.
    pub cloexec: bool,
    /// O_NONBLOCK
    pub nonblock: bool,
    /// Open-file status flags (O_RDONLY / O_WRONLY / O_RDWR / O_APPEND).
    pub fl_flags: i32,
}

impl FdEntry {
    fn new(backing_fd: usize, path: Option<String>, flags: u32) -> Self {
        let fl = match flags & 3 {
            0 => O_RDONLY,
            1 => O_WRONLY,
            _ => O_RDWR,
        };
        let fl = if flags & O_APPEND != 0 {
            fl | 0o2000
        } else {
            fl
        };
        FdEntry {
            backing_fd,
            path,
            cloexec: flags & O_CLOEXEC_FLAG != 0,
            nonblock: flags & O_NONBLOCK != 0,
            fl_flags: fl,
        }
    }
}

#[derive(Clone, Default)]
struct ProcFdTable {
    fds: BTreeMap<usize, FdEntry>,
}

impl ProcFdTable {
    fn alloc_fd(&self, min: usize) -> usize {
        let mut n = min;
        while self.fds.contains_key(&n) {
            n += 1;
        }
        n
    }

    fn get(&self, fd: usize) -> Option<&FdEntry> {
        self.fds.get(&fd)
    }
    fn get_mut(&mut self, fd: usize) -> Option<&mut FdEntry> {
        self.fds.get_mut(&fd)
    }
    fn insert(&mut self, fd: usize, e: FdEntry) {
        self.fds.insert(fd, e);
    }
    fn remove(&mut self, fd: usize) -> Option<FdEntry> {
        self.fds.remove(&fd)
    }
    fn len(&self) -> usize {
        self.fds.len()
    }
    fn fds_vec(&self) -> Vec<usize> {
        self.fds.keys().cloned().collect()
    }
}

/// Fast map is safe here: keys are kernel-assigned pids and the global table is
/// not iterated for deterministic user-visible output.
static PROC_FD_TABLES: Mutex<KernelFastMap<usize, ProcFdTable>> = Mutex::new(KernelFastMap::new());

#[inline]
fn current_pid() -> usize {
    crate::proc::scheduler::current_pid()
}

fn check_nofile(pid: usize, table: &ProcFdTable) -> bool {
    crate::proc::scheduler::with_proc(pid, |p| p.rlimits.exceeds_nofile(table.len()))
        .unwrap_or(false)
}

fn dup_backing(bfd: usize) -> usize {
    if crate::fs::pipe::is_pipe(bfd) {
        crate::fs::pipe::pipe_dup(bfd);
        bfd
    } else if crate::net::socket::is_socket_fd(bfd) {
        crate::net::socket::socket_dup(bfd);
        bfd
    } else if crate::fs::eventfd::is_eventfd(bfd) {
        crate::fs::eventfd::efd_dup(bfd);
        bfd
    } else if crate::fs::timerfd::is_timerfd(bfd) {
        crate::fs::timerfd::tfd_dup(bfd);
        bfd
    } else if crate::fs::inotify::is_inotify_fd(bfd) {
        crate::fs::inotify::inotify_dup(bfd);
        bfd
    } else if crate::fs::fanotify::is_fanotify_fd(bfd) {
        crate::fs::fanotify::fanotify_dup(bfd);
        bfd
    } else if crate::fs::devfs::get_dev_fd(bfd).is_some() {
        bfd
    } else if crate::fs::procfs::is_procfs_fd(bfd)
        || crate::fs::sysfs::is_sysfs_fd(bfd)
        || crate::fs::cgroupfs::is_cgroupfs_fd(bfd)
    {
        bfd
    } else {
        let r = crate::fs::vfs::dup_from(bfd, bfd);
        if r >= 0 {
            r as usize
        } else {
            bfd
        }
    }
}

pub fn proc_fd_alloc(pid: usize, stdin_bfd: usize, stdout_bfd: usize, stderr_bfd: usize) {
    let mut table = ProcFdTable::default();
    table.insert(
        0,
        FdEntry {
            backing_fd: stdin_bfd,
            path: None,
            cloexec: false,
            nonblock: false,
            fl_flags: O_RDONLY,
        },
    );
    table.insert(
        1,
        FdEntry {
            backing_fd: stdout_bfd,
            path: None,
            cloexec: false,
            nonblock: false,
            fl_flags: O_WRONLY,
        },
    );
    table.insert(
        2,
        FdEntry {
            backing_fd: stderr_bfd,
            path: None,
            cloexec: false,
            nonblock: false,
            fl_flags: O_WRONLY,
        },
    );
    PROC_FD_TABLES.lock().insert(pid, table);
}

pub fn proc_fd_fork(parent_pid: usize, child_pid: usize) {
    let parent_clone: Option<ProcFdTable> = { PROC_FD_TABLES.lock().get(&parent_pid).cloned() };
    let parent = match parent_clone {
        Some(t) => t,
        None => return,
    };

    let mut child_table = ProcFdTable::default();
    for (fd, entry) in &parent.fds {
        let new_bfd = if *fd <= 2 {
            entry.backing_fd
        } else {
            dup_backing(entry.backing_fd)
        };
        child_table.insert(
            *fd,
            FdEntry {
                backing_fd: new_bfd,
                path: entry.path.clone(),
                cloexec: entry.cloexec,
                nonblock: entry.nonblock,
                fl_flags: entry.fl_flags,
            },
        );
    }
    PROC_FD_TABLES.lock().insert(child_pid, child_table);
}

pub fn proc_fd_close_on_exec(pid: usize) {
    let cloexec_fds: Vec<(usize, usize)> = {
        let lock = PROC_FD_TABLES.lock();
        match lock.get(&pid) {
            None => return,
            Some(t) => t
                .fds
                .iter()
                .filter(|(_, e)| e.cloexec)
                .map(|(fd, e)| (*fd, e.backing_fd))
                .collect(),
        }
    };
    for (fd, bfd) in cloexec_fds {
        close_backing(bfd);
        PROC_FD_TABLES.lock().get_mut(&pid).map(|t| t.remove(fd));
    }
}

pub fn proc_fd_free(pid: usize) {
    let table = PROC_FD_TABLES.lock().remove(&pid);
    if let Some(t) = table {
        for (_, entry) in t.fds {
            close_backing(entry.backing_fd);
        }
    }
}

pub fn proc_fd_open(pid: usize, path: &str, flags: u32, _mode: u32) -> isize {
    {
        let lock = PROC_FD_TABLES.lock();
        if let Some(t) = lock.get(&pid) {
            if check_nofile(pid, t) {
                return -24;
            }
        }
    }

    let (bfd, stored_path): (isize, Option<String>) =
        // If the path looks like `scheme:rest` (no leading '/'), dispatch it
        // through the registered scheme table instead of the POSIX VFS.  This
        // is the core of Redox's "everything is a URL" model and lets drivers
        // such as `tcp:`, `blk:`, `net:` be opened exactly like regular files.
        if crate::fs::scheme_table::is_scheme_url(path) {
            use scheme_api::OpenFlags;
            let open_flags = OpenFlags::from_bits_truncate(flags);
            match crate::fs::scheme_table::SCHEME_TABLE.open(path, open_flags) {
                Ok((scheme, fid)) => {
                    // Allocate a synthetic backing-fd in the 0x8000_0000+ range
                    // so it never collides with POSIX VFS inodes.
                    let bfd = crate::fs::scheme_fd::alloc_scheme_backing_fd();
                    crate::fs::scheme_fd::scheme_fd_register(
                        bfd,
                        scheme,
                        fid,
                    );
                    // Tag with the original URL so /proc/<pid>/fd/<n> readlink
                    // returns something human-readable (e.g. "tcp:127.0.0.1:80").
                    crate::fs::vfs::fd_set_debug_name(
                        bfd,
                        alloc::string::String::from(path),
                    );
                    (bfd as isize, Some(alloc::string::String::from(path)))
                }
                Err(e) => {
                    use scheme_api::SchemeError;
                    let errno = match e {
                        SchemeError::NoSuchScheme     => -2,  // ENOENT
                        SchemeError::NotFound         => -2,
                        SchemeError::PermissionDenied => -13, // EACCES
                        SchemeError::InvalidArg       => -22, // EINVAL
                        SchemeError::WouldBlock        => -11, // EAGAIN
                        _                             => -5,  // EIO
                    };
                    (errno, None)
                }
            }
        } else if let Some(fd) = crate::fs::devfs::try_open(path, flags) {
            (fd as isize, None)
        } else if path.starts_with("/proc") {
            let fd = crate::fs::procfs::procfs_open(path, flags);
            (fd, Some(path.into()))
        } else if path.starts_with("/sys/fs/cgroup") {
            // cgroupfs lives under /sys but is handled separately so it gets
            // full read/write/mkdir/rmdir support.
            let fd = crate::fs::cgroupfs::cgroupfs_open(path);
            (fd, Some(path.into()))
        } else if path.starts_with("/sys") {
            let fd = crate::fs::sysfs::sysfs_open(path, flags);
            (fd, Some(path.into()))
        } else {
            match crate::fs::vfs::open(path, flags) {
                Ok(fd) => (fd as isize, Some(path.into())),
                Err(e) => {
                    if flags & O_CREAT != 0 && e == -2 {
                        if crate::fs::vfs::create(path).is_ok() {
                            match crate::fs::vfs::open(path, flags & !O_CREAT) {
                                Ok(fd) => (fd as isize, Some(path.into())),
                                Err(e2) => (e2, None),
                            }
                        } else {
                            (-13, None)
                        }
                    } else {
                        (e, None)
                    }
                }
            }
        };

    if bfd < 0 {
        return bfd;
    }
    let bfd = bfd as usize;

    if flags & O_TRUNC != 0 && stored_path.is_some() {
        let _ = crate::fs::vfs_ops::truncate_fd(bfd, 0);
    }

    let entry = FdEntry::new(bfd, stored_path, flags);
    let local_fd = {
        let mut lock = PROC_FD_TABLES.lock();
        if !lock.contains_key(&pid) {
            lock.insert(pid, ProcFdTable::default());
        }
        let table = lock.get_mut(&pid).expect("proc fd table inserted");
        let fd = table.alloc_fd(3);
        table.insert(fd, entry);
        fd
    };

    local_fd as isize
}

pub fn proc_fd_close(pid: usize, fd: usize) -> isize {
    let entry = PROC_FD_TABLES
        .lock()
        .get_mut(&pid)
        .and_then(|t| t.remove(fd));

    match entry {
        None => -9,
        Some(e) => {
            if fd > 2 {
                close_backing(e.backing_fd);
            }
            crate::fs::fcntl::close_fd_meta(e.backing_fd);
            0
        }
    }
}

pub fn proc_fd_dup2(pid: usize, old_fd: usize, new_fd: usize) -> isize {
    if old_fd == new_fd {
        return old_fd as isize;
    }

    let old_entry = {
        let lock = PROC_FD_TABLES.lock();
        match lock.get(&pid).and_then(|t| t.get(old_fd)).cloned() {
            Some(e) => e,
            None => return -9,
        }
    };

    let new_bfd = dup_backing(old_entry.backing_fd);
    let _ = proc_fd_close(pid, new_fd);

    let new_entry = FdEntry {
        backing_fd: new_bfd,
        path: old_entry.path.clone(),
        cloexec: false,
        nonblock: old_entry.nonblock,
        fl_flags: old_entry.fl_flags,
    };

    let mut lock = PROC_FD_TABLES.lock();
    if !lock.contains_key(&pid) {
        lock.insert(pid, ProcFdTable::default());
    }
    lock.get_mut(&pid)
        .expect("proc fd table inserted")
        .insert(new_fd, new_entry);

    new_fd as isize
}

pub fn proc_fd_get(pid: usize, fd: usize) -> Option<FdEntry> {
    PROC_FD_TABLES.lock().get(&pid)?.get(fd).cloned()
}

pub fn proc_fd_backing(pid: usize, fd: usize) -> isize {
    match proc_fd_get(pid, fd) {
        Some(e) => e.backing_fd as isize,
        None => -9,
    }
}

pub fn proc_fd_set_cloexec(pid: usize, fd: usize, val: bool) {
    PROC_FD_TABLES
        .lock()
        .get_mut(&pid)
        .and_then(|t| t.get_mut(fd))
        .map(|e| e.cloexec = val);
}

pub fn proc_fd_set_nonblock(pid: usize, fd: usize, val: bool) {
    PROC_FD_TABLES
        .lock()
        .get_mut(&pid)
        .and_then(|t| t.get_mut(fd))
        .map(|e| e.nonblock = val);
}

pub fn proc_fd_getfl(pid: usize, fd: usize) -> i32 {
    PROC_FD_TABLES
        .lock()
        .get(&pid)
        .and_then(|t| t.get(fd))
        .map(|e| e.fl_flags)
        .unwrap_or(O_RDWR)
}

pub fn proc_fd_setfl(pid: usize, fd: usize, flags: i32) {
    PROC_FD_TABLES
        .lock()
        .get_mut(&pid)
        .and_then(|t| t.get_mut(fd))
        .map(|e| {
            e.fl_flags = flags;
            e.nonblock = flags & 0o4000 != 0;
        });
}

pub fn proc_fd_path(pid: usize, fd: usize) -> Option<String> {
    PROC_FD_TABLES.lock().get(&pid)?.get(fd)?.path.clone()
}

pub fn proc_fd_list(pid: usize) -> Vec<usize> {
    PROC_FD_TABLES
        .lock()
        .get(&pid)
        .map(|t| t.fds_vec())
        .unwrap_or_default()
}

pub fn proc_fd_install(
    pid: usize,
    bfd: usize,
    path: Option<String>,
    flags: u32,
    preferred: Option<usize>,
) -> usize {
    let entry = FdEntry::new(bfd, path, flags);
    let mut lock = PROC_FD_TABLES.lock();
    if !lock.contains_key(&pid) {
        lock.insert(pid, ProcFdTable::default());
    }
    let table = lock.get_mut(&pid).expect("proc fd table inserted");
    let fd = match preferred {
        Some(n) => n,
        None => table.alloc_fd(3),
    };
    table.insert(fd, entry);
    fd
}

fn close_backing(bfd: usize) {
    if crate::fs::devfs::get_dev_fd(bfd).is_some() {
        crate::fs::devfs::close(bfd);
    } else if crate::fs::cgroupfs::is_cgroupfs_fd(bfd) {
        crate::fs::cgroupfs::cgroupfs_close(bfd);
    } else if crate::fs::procfs::is_procfs_fd(bfd) {
    } else if crate::fs::sysfs::is_sysfs_fd(bfd) {
    } else if crate::fs::inotify::is_inotify_fd(bfd) {
        crate::fs::inotify::inotify_close(bfd);
    } else if crate::fs::fanotify::is_fanotify_fd(bfd) {
        crate::fs::fanotify::fanotify_close(bfd);
    } else if crate::fs::eventfd::is_eventfd(bfd) {
        crate::fs::eventfd::sys_close_efd(bfd);
    } else if crate::fs::timerfd::is_timerfd(bfd) {
        crate::fs::timerfd::sys_close_tfd(bfd);
    } else if crate::fs::pipe::is_pipe(bfd) {
        crate::fs::pipe::sys_close_pipe(bfd);
    } else if crate::net::socket::is_socket_fd(bfd) {
        crate::net::socket::sys_close_socket(bfd);
    // Backing fds in the 0x8000_0000+ range registered by proc_fd_open's
    // scheme-URL arm are closed here, forwarding the close() to the driver
    // via IpcProxyScheme.  Without this arm, closing a scheme fd was a no-op
    // and the driver-side SchemeFileId was leaked forever.
    } else if crate::fs::scheme_fd::is_scheme_fd(bfd) {
        crate::fs::scheme_fd::scheme_fd_close(bfd);
    } else {
        crate::fs::vfs::close(bfd);
    }
}
