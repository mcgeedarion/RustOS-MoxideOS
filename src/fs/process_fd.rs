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
//! # Lifecycle
//!
//! | Event            | Call                          |
//! |------------------|-------------------------------|
//! | process created  | `proc_fd_alloc(pid)`          |
//! | fork()           | `proc_fd_fork(parent, child)` |
//! | execve()         | `proc_fd_close_on_exec(pid)`  |
//! | exit()           | `proc_fd_free(pid)`           |

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

// ── O_* constants ───────────────────────────────────────────────────────────────
const O_RDONLY:   i32 = 0;
const O_WRONLY:   i32 = 1;
const O_RDWR:     i32 = 2;
const O_CREAT:    u32 = 0o100;
const O_TRUNC:    u32 = 0o1000;
const O_APPEND:   u32 = 0o2000;
const O_NONBLOCK: u32 = 0o4000;
const O_CLOEXEC:  u32 = 0o2000000;

// RLIMIT_NOFILE index
const RLIMIT_NOFILE: usize = 7;

// ── FdEntry ───────────────────────────────────────────────────────────────────

/// One entry in a process's fd table.
#[derive(Clone, Debug)]
pub struct FdEntry {
    /// Kernel-internal backing fd (used with vfs/devfs/pipe/socket helpers).
    pub backing_fd: usize,
    /// VFS path, if this is a path-backed file (regular, directory, procfs, …).
    pub path:       Option<String>,
    /// FD_CLOEXEC — closed across execve.
    pub cloexec:    bool,
    /// O_NONBLOCK
    pub nonblock:   bool,
    /// Open-file status flags (O_RDONLY / O_WRONLY / O_RDWR / O_APPEND).
    pub fl_flags:   i32,
}

impl FdEntry {
    fn new(backing_fd: usize, path: Option<String>, flags: u32) -> Self {
        let fl = match flags & 3 {
            0 => O_RDONLY,
            1 => O_WRONLY,
            _ => O_RDWR,
        };
        let fl = if flags & O_APPEND != 0 { fl | 0o2000 } else { fl };
        FdEntry {
            backing_fd,
            path,
            cloexec:  flags & O_CLOEXEC  != 0,
            nonblock: flags & O_NONBLOCK != 0,
            fl_flags: fl,
        }
    }
}

// ── ProcFdTable ───────────────────────────────────────────────────────────────

/// Per-process fd table: maps process-local fd → FdEntry.
#[derive(Clone, Default)]
struct ProcFdTable {
    fds: BTreeMap<usize, FdEntry>,
}

impl ProcFdTable {
    /// Return the lowest fd >= `min` not already in use.
    fn alloc_fd(&self, min: usize) -> usize {
        let mut n = min;
        while self.fds.contains_key(&n) { n += 1; }
        n
    }

    fn get(&self, fd: usize) -> Option<&FdEntry> { self.fds.get(&fd) }
    fn get_mut(&mut self, fd: usize) -> Option<&mut FdEntry> { self.fds.get_mut(&fd) }
    fn insert(&mut self, fd: usize, e: FdEntry) { self.fds.insert(fd, e); }
    fn remove(&mut self, fd: usize) -> Option<FdEntry> { self.fds.remove(&fd) }
    fn len(&self) -> usize { self.fds.len() }
    fn fds_vec(&self) -> Vec<usize> { self.fds.keys().cloned().collect() }
}

// ── Global table: pid → ProcFdTable ─────────────────────────────────────────────

static PROC_FD_TABLES: Mutex<BTreeMap<usize, ProcFdTable>> =
    Mutex::new(BTreeMap::new());

// ── Helper: current pid ─────────────────────────────────────────────────────────────

#[inline]
fn current_pid() -> usize {
    crate::proc::scheduler::current_pid()
}

// ── RLIMIT_NOFILE check ───────────────────────────────────────────────────────────

fn check_nofile(pid: usize, table: &ProcFdTable) -> bool {
    crate::proc::scheduler::with_proc(pid, |p| {
        p.rlimits.exceeds_nofile(table.len())
    }).unwrap_or(false)
}

// ── dup_backing: subsystem-aware backing-fd duplication ───────────────────────
//
// Centralises the "how do I duplicate this backing fd" decision that fork,
// dup2, and future callers all need.  Each subsystem has its own refcount
// model; routing everything through vfs::dup_from was wrong for non-VFS fds.

/// Duplicate a backing fd, incrementing the appropriate subsystem refcount.
///
/// Returns the backing fd the child/duplicate should use:
///   - For pipe / socket / eventfd / timerfd / inotify / fanotify: same bfd,
///     refcount incremented via the subsystem's own dup helper.
///   - For devfs / procfs / sysfs: same bfd, no explicit refcount (singletons
///     or stateless).
///   - For VFS fds: a new backing fd from vfs::dup_from (independent seek pos).
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
        // devfs fds are device singletons; share the same bfd.
        bfd
    } else if crate::fs::procfs::is_procfs_fd(bfd)
           || crate::fs::sysfs::is_sysfs_fd(bfd) {
        // stateless virtual fs; share the same bfd.
        bfd
    } else {
        // VFS: allocate a new backing fd with an independent seek position.
        let r = crate::fs::vfs::dup_from(bfd, bfd);
        if r >= 0 { r as usize } else { bfd }
    }
}

// ── Public lifecycle API ───────────────────────────────────────────────────────────

/// Allocate a fresh fd table for `pid` and pre-install stdin/stdout/stderr.
///
/// `stdin_bfd`, `stdout_bfd`, `stderr_bfd` are the kernel-internal backing
/// fds for the standard streams.  Pass 0 / 1 / 2 for the initial process;
/// after fork they are cloned by `proc_fd_fork`.
pub fn proc_fd_alloc(pid: usize, stdin_bfd: usize, stdout_bfd: usize, stderr_bfd: usize) {
    let mut table = ProcFdTable::default();
    table.insert(0, FdEntry { backing_fd: stdin_bfd,  path: None, cloexec: false, nonblock: false, fl_flags: O_RDONLY });
    table.insert(1, FdEntry { backing_fd: stdout_bfd, path: None, cloexec: false, nonblock: false, fl_flags: O_WRONLY });
    table.insert(2, FdEntry { backing_fd: stderr_bfd, path: None, cloexec: false, nonblock: false, fl_flags: O_WRONLY });
    PROC_FD_TABLES.lock().insert(pid, table);
}

/// Fork the parent's fd table into the child.
///
/// Each entry is duplicated via `dup_backing`, which routes to the correct
/// subsystem:
///   - Pipe / socket / eventfd / timerfd / inotify / fanotify: same bfd,
///     subsystem refcount incremented (e.g. pipe_dup bumps read_open /
///     write_open so the last close of *any* fd on that end signals EOF /
///     SIGPIPE).
///   - VFS fds: new backing fd with an independent seek position.
///   - stdin / stdout / stderr (fd 0-2): shared directly, no dup needed.
///
/// cloexec is preserved in the child; exec will clear those fds.
pub fn proc_fd_fork(parent_pid: usize, child_pid: usize) {
    let parent_clone: Option<ProcFdTable> = {
        PROC_FD_TABLES.lock().get(&parent_pid).cloned()
    };
    let parent = match parent_clone { Some(t) => t, None => return };

    let mut child_table = ProcFdTable::default();
    for (fd, entry) in &parent.fds {
        // fd 0-2: standard streams are tty-backed singletons; share bfd directly.
        let new_bfd = if *fd <= 2 {
            entry.backing_fd
        } else {
            dup_backing(entry.backing_fd)
        };
        child_table.insert(*fd, FdEntry {
            backing_fd: new_bfd,
            path:    entry.path.clone(),
            cloexec: entry.cloexec,
            nonblock: entry.nonblock,
            fl_flags: entry.fl_flags,
        });
    }
    PROC_FD_TABLES.lock().insert(child_pid, child_table);
}

/// Close all FD_CLOEXEC fds for `pid`.  Called just before loading the new
/// ELF image in execve so the child does not inherit parent fds.
pub fn proc_fd_close_on_exec(pid: usize) {
    let cloexec_fds: Vec<(usize, usize)> = {
        let lock = PROC_FD_TABLES.lock();
        match lock.get(&pid) {
            None => return,
            Some(t) => t.fds.iter()
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

/// Close every fd and remove the table.  Called from sys_exit / sys_exit_group.
pub fn proc_fd_free(pid: usize) {
    let table = PROC_FD_TABLES.lock().remove(&pid);
    if let Some(t) = table {
        for (_, entry) in t.fds {
            close_backing(entry.backing_fd);
        }
    }
}

// ── Public fd-operation API ──────────────────────────────────────────────────────────

/// Open a file for `pid`, enforcing RLIMIT_NOFILE.
///
/// Returns the process-local fd on success, or a negative errno.
///
/// Dispatch order (mirrors io_syscalls::sys_open):
///   1. /dev/…    → devfs
///   2. /proc/…   → procfs
///   3. /sys/…    → sysfs
///   4. everything → vfs (ext2 / ramfs / fat32 / overlayfs / tmpfs)
///      O_CREAT: create then reopen if ENOENT.
///      O_TRUNC:  zero file after open.
pub fn proc_fd_open(pid: usize, path: &str, flags: u32, _mode: u32) -> isize {
    // --- RLIMIT_NOFILE check ---
    {
        let lock = PROC_FD_TABLES.lock();
        if let Some(t) = lock.get(&pid) {
            if check_nofile(pid, t) { return -24; } // EMFILE
        }
    }

    // --- resolve backing fd ---
    let (bfd, stored_path): (isize, Option<String>) =
        if let Some(fd) = crate::fs::devfs::try_open(path, flags) {
            (fd as isize, None)
        } else if path.starts_with("/proc") {
            let fd = crate::fs::procfs::procfs_open(path, flags);
            (fd, Some(path.into()))
        } else if path.starts_with("/sys") {
            let fd = crate::fs::sysfs::sysfs_open(path, flags);
            (fd, Some(path.into()))
        } else {
            // VFS path
            match crate::fs::vfs::open(path, flags) {
                Ok(fd) => (fd as isize, Some(path.into())),
                Err(e) => {
                    if flags & O_CREAT != 0 && e == -2 {
                        // ENOENT + O_CREAT: create then reopen.
                        if crate::fs::vfs::create(path).is_ok() {
                            match crate::fs::vfs::open(path, flags & !O_CREAT) {
                                Ok(fd) => (fd as isize, Some(path.into())),
                                Err(e2) => (e2, None),
                            }
                        } else {
                            (-13, None) // EACCES
                        }
                    } else {
                        (e, None)
                    }
                }
            }
        };

    if bfd < 0 { return bfd; }
    let bfd = bfd as usize;

    // O_TRUNC: zero the file if it is a regular VFS file.
    if flags & O_TRUNC != 0 && stored_path.is_some() {
        let _ = crate::fs::vfs_ops::truncate_fd(bfd, 0);
    }

    // --- allocate process-local fd ---
    let entry = FdEntry::new(bfd, stored_path, flags);
    let local_fd = {
        let mut lock = PROC_FD_TABLES.lock();
        // Insert a fresh table if there isn’t one (kernel threads, early boot).
        let table = lock.entry(pid).or_default();
        let fd = table.alloc_fd(3); // 0/1/2 reserved for stdio
        table.insert(fd, entry);
        fd
    };

    local_fd as isize
}

/// Close a single fd for `pid`.
///
/// Returns 0 on success, -9 (EBADF) if the fd is not open.
pub fn proc_fd_close(pid: usize, fd: usize) -> isize {
    let entry = PROC_FD_TABLES.lock()
        .get_mut(&pid)
        .and_then(|t| t.remove(fd));

    match entry {
        None => -9, // EBADF
        Some(e) => {
            // Don't close backing fds for stdin/stdout/stderr;
            // they are shared with the tty and must stay alive.
            if fd > 2 { close_backing(e.backing_fd); }
            // Also remove from the legacy FD_META table.
            crate::fs::fcntl::close_fd_meta(e.backing_fd);
            0
        }
    }
}

/// Duplicate `old_fd` as `new_fd` (dup2 semantics).
///
/// If `new_fd` is already open it is closed first.  If `old_fd == new_fd`
/// returns `new_fd` unchanged.
pub fn proc_fd_dup2(pid: usize, old_fd: usize, new_fd: usize) -> isize {
    if old_fd == new_fd { return old_fd as isize; }

    // Get old entry.
    let old_entry = {
        let lock = PROC_FD_TABLES.lock();
        match lock.get(&pid).and_then(|t| t.get(old_fd)).cloned() {
            Some(e) => e,
            None    => return -9, // EBADF
        }
    };

    // Duplicate the backing fd via the subsystem-aware helper.
    let new_bfd = dup_backing(old_entry.backing_fd);

    // Close new_fd if open.
    let _ = proc_fd_close(pid, new_fd);

    let new_entry = FdEntry {
        backing_fd: new_bfd,
        path:       old_entry.path.clone(),
        cloexec:    false, // dup clears cloexec (POSIX)
        nonblock:   old_entry.nonblock,
        fl_flags:   old_entry.fl_flags,
    };

    PROC_FD_TABLES.lock()
        .entry(pid).or_default()
        .insert(new_fd, new_entry);

    new_fd as isize
}

/// Return the FdEntry for `(pid, fd)`, or None if not open.
pub fn proc_fd_get(pid: usize, fd: usize) -> Option<FdEntry> {
    PROC_FD_TABLES.lock().get(&pid)?.get(fd).cloned()
}

/// Return the backing fd for `(pid, fd)`, or -9 (EBADF).
pub fn proc_fd_backing(pid: usize, fd: usize) -> isize {
    match proc_fd_get(pid, fd) {
        Some(e) => e.backing_fd as isize,
        None    => -9,
    }
}

/// Set O_CLOEXEC flag on a process-local fd.
pub fn proc_fd_set_cloexec(pid: usize, fd: usize, val: bool) {
    PROC_FD_TABLES.lock()
        .get_mut(&pid)
        .and_then(|t| t.get_mut(fd))
        .map(|e| e.cloexec = val);
}

/// Set O_NONBLOCK flag on a process-local fd.
pub fn proc_fd_set_nonblock(pid: usize, fd: usize, val: bool) {
    PROC_FD_TABLES.lock()
        .get_mut(&pid)
        .and_then(|t| t.get_mut(fd))
        .map(|e| e.nonblock = val);
}

/// Get the open-file status flags (F_GETFL) for a process-local fd.
pub fn proc_fd_getfl(pid: usize, fd: usize) -> i32 {
    PROC_FD_TABLES.lock()
        .get(&pid)
        .and_then(|t| t.get(fd))
        .map(|e| e.fl_flags)
        .unwrap_or(O_RDWR)
}

/// Set open-file status flags (F_SETFL) for a process-local fd.
pub fn proc_fd_setfl(pid: usize, fd: usize, flags: i32) {
    PROC_FD_TABLES.lock()
        .get_mut(&pid)
        .and_then(|t| t.get_mut(fd))
        .map(|e| {
            e.fl_flags = flags;
            e.nonblock = flags & 0o4000 != 0;
        });
}

/// Return the VFS path for `(pid, fd)`, used by AT_FDCWD resolution and
/// /proc/<pid>/fd/<n> readlink.
pub fn proc_fd_path(pid: usize, fd: usize) -> Option<String> {
    PROC_FD_TABLES.lock()
        .get(&pid)?
        .get(fd)?
        .path
        .clone()
}

/// Return all open fd numbers for `pid` (used by close_range, procfs, …).
pub fn proc_fd_list(pid: usize) -> Vec<usize> {
    PROC_FD_TABLES.lock()
        .get(&pid)
        .map(|t| t.fds_vec())
        .unwrap_or_default()
}

/// Install a pre-allocated backing fd (e.g. a pipe end, socket, eventfd) as
/// the given process-local fd, or the lowest available if `preferred` is None.
///
/// Called by pipe(2), socket(2), and similar that produce a backing fd
/// outside the normal open path.
pub fn proc_fd_install(
    pid:    usize,
    bfd:    usize,
    path:   Option<String>,
    flags:  u32,
    preferred: Option<usize>,
) -> usize {
    let entry = FdEntry::new(bfd, path, flags);
    let mut lock = PROC_FD_TABLES.lock();
    let table = lock.entry(pid).or_default();
    let fd = match preferred {
        Some(n) => n,
        None    => table.alloc_fd(3),
    };
    table.insert(fd, entry);
    fd
}

// ── Internal: close a backing fd through the right subsystem ─────────────────

fn close_backing(bfd: usize) {
    if crate::fs::devfs::get_dev_fd(bfd).is_some() {
        crate::fs::devfs::close(bfd);
    } else if crate::fs::procfs::is_procfs_fd(bfd) {
        // procfs fds have no explicit close; drop is sufficient.
    } else if crate::fs::sysfs::is_sysfs_fd(bfd) {
        // same
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
    } else {
        crate::fs::vfs::close(bfd);
    }
}
