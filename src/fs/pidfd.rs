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
//! ## Scheme integration
//!
//! `sys_pidfd_open` now allocates a scheme backing fd via
//! `alloc_scheme_backing_fd` and registers a `PidFdScheme` in
//! `SCHEME_FD_STORE`.  The scheme backing fd is installed into the process
//! fd table; the raw PIDFD_TABLE entry is still inserted first so that
//! `is_pidfd()` and `resolve()` never see a gap.
//!
//! `sys_pidfd_send_signal` and `sys_pidfd_getfd` receive the scheme backing
//! fd (resolved from the user fd by the syscall dispatch) and use
//! `scheme_bfd_to_table_fdno` to recover the raw PIDFD_TABLE key.

extern crate alloc;
use crate::core::fast_hash::KernelFastMap;
use spin::Mutex;

use crate::fs::scheme_table::Scheme;
use scheme_api::{OpenFlags, SchemeError, SchemeFileId};

const PIDFD_NONBLOCK: u32 = 0x800;
const SIGKILL: u32 = 9;
const SIGSTOP: u32 = 19;
const SIGCONT: u32 = 18;

// Raw PIDFD_TABLE fdno namespace — still used by is_pidfd / resolve.
const PID_FD_BASE: usize = 1024;
const PID_FD_MAX: usize = 2048;

/// Maps raw PIDFD_TABLE fdno -> target pid.
/// Fast map is safe here: keys are bounded raw pidfd table fd numbers assigned
/// by the kernel and are not exposed through deterministic iteration.
static PIDFD_TABLE: Mutex<KernelFastMap<usize, usize>> = Mutex::new(KernelFastMap::new());
/// Pending signal queue: maps pid -> pending signal (one slot; SIGKILL wins).
/// Fast map is safe here: keys are kernel pid values and this one-slot pending
/// signal cache is not an authorization or ordering boundary.
static PENDING_SIGNAL: Mutex<KernelFastMap<usize, u32>> = Mutex::new(KernelFastMap::new());

/// Translate a scheme backing fd to the PIDFD_TABLE fdno.
/// Returns None if `scheme_bfd` is not a registered pidfd scheme fd.
pub fn scheme_bfd_to_table_fdno(scheme_bfd: usize) -> Option<usize> {
    let (_, fid) = crate::fs::scheme_fd::scheme_fd_get_fid(scheme_bfd)?;
    let table_fdno = fid.0 as usize;
    if table_fdno >= PID_FD_BASE
        && table_fdno < PID_FD_MAX
        && PIDFD_TABLE.lock().contains_key(&table_fdno)
    {
        Some(table_fdno)
    } else {
        None
    }
}

pub struct PidFdScheme;

impl Scheme for PidFdScheme {
    fn open(&self, _url: &str, _flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        Err(SchemeError::InvalidArg) // created via pidfd_open only
    }

    /// pidfds are not directly readable (poll for POLLIN signals child exit).
    fn read(&self, _fid: SchemeFileId, _buf: &mut [u8]) -> Result<usize, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn write(&self, _fid: SchemeFileId, _buf: &[u8]) -> Result<usize, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn seek(&self, _fid: SchemeFileId, _offset: i64, _whence: u8) -> Result<u64, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn ioctl(&self, _fid: SchemeFileId, _cmd: u64, _arg: usize) -> Result<usize, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        let table_fdno = fid.0 as usize;
        free(table_fdno);
        Ok(())
    }
}

/// Allocate a raw PIDFD_TABLE fdno for `pid`. Returns fdno or -EMFILE.
fn alloc_table_fdno(pid: usize) -> Result<usize, isize> {
    let mut tbl = PIDFD_TABLE.lock();
    for fd in PID_FD_BASE..PID_FD_MAX {
        if !tbl.contains_key(&fd) {
            tbl.insert(fd, pid);
            return Ok(fd);
        }
    }
    Err(-24) // EMFILE
}

/// Release a raw PIDFD_TABLE entry.
pub fn free(fd: usize) {
    PIDFD_TABLE.lock().remove(&fd);
}

/// True if `fd` is a live raw PIDFD_TABLE fdno.
pub fn is_pidfd(fd: usize) -> bool {
    PIDFD_TABLE.lock().contains_key(&fd)
}

/// Resolve raw PIDFD_TABLE fdno -> target pid.
/// Returns None if the entry is missing or the process is a zombie.
fn resolve(table_fdno: usize) -> Option<usize> {
    let pid = *PIDFD_TABLE.lock().get(&table_fdno)?;
    let procs = crate::proc::scheduler::procs_lock();
    let alive = procs
        .iter()
        .any(|p| p.pid == pid && p.state != crate::proc::process::State::Zombie);
    crate::proc::scheduler::procs_unlock();
    if alive {
        Some(pid)
    } else {
        None
    }
}

pub fn sys_pidfd_open(pid: usize, flags: u32) -> isize {
    use crate::fs::process_fd::proc_fd_install;
    use crate::fs::scheme_fd::{alloc_scheme_backing_fd, scheme_fd_register};
    use alloc::sync::Arc;

    if flags & !(PIDFD_NONBLOCK) != 0 {
        return -22;
    } // EINVAL
    if pid == 0 {
        return -3;
    } // ESRCH

    let procs = crate::proc::scheduler::procs_lock();
    let alive = procs
        .iter()
        .any(|p| p.pid == pid && p.state != crate::proc::process::State::Zombie);
    crate::proc::scheduler::procs_unlock();
    if !alive {
        return -3;
    } // ESRCH

    let table_fdno = match alloc_table_fdno(pid) {
        Ok(f) => f,
        Err(e) => return e,
    };

    let scheme: Arc<dyn Scheme> = Arc::new(PidFdScheme);
    let scheme_bfd = alloc_scheme_backing_fd();
    scheme_fd_register(scheme_bfd, scheme, SchemeFileId(table_fdno as u64));

    let pid_caller = crate::proc::scheduler::current_pid();
    let nonblock_fl = if flags & PIDFD_NONBLOCK != 0 {
        PIDFD_NONBLOCK
    } else {
        0
    };
    // FD_CLOEXEC flag value is 1 in the install flags convention.
    let user_fd = proc_fd_install(
        pid_caller,
        scheme_bfd,
        None,
        nonblock_fl | 1, /* FD_CLOEXEC */
        None,
    );
    user_fd as isize
}

// The syscall dispatch resolves the user-visible fd to a scheme bfd before
// calling this.  We translate to the PIDFD_TABLE fdno via
// scheme_bfd_to_table_fdno.

pub fn sys_pidfd_send_signal(scheme_bfd: usize, sig: u32, _info_va: usize, flags: u32) -> isize {
    if flags != 0 {
        return -22;
    }
    if sig > 64 {
        return -22;
    }

    let table_fdno = match scheme_bfd_to_table_fdno(scheme_bfd) {
        Some(f) => f,
        None => return -9, // EBADF
    };
    let pid = match resolve(table_fdno) {
        Some(p) => p,
        None => return -3, // ESRCH
    };

    if sig == 0 {
        return 0;
    } // existence check

    match sig {
        SIGKILL => {
            let procs = crate::proc::scheduler::procs_lock();
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.state = crate::proc::process::State::Zombie;
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
        SIGCONT => {
            crate::proc::scheduler::wake_pid(pid);
            0
        }
        _ => {
            PENDING_SIGNAL.lock().insert(pid, sig);
            0
        }
    }
}

/// Check and consume one pending signal for `pid`.
pub fn check_pending_signal(pid: usize) -> u32 {
    PENDING_SIGNAL.lock().remove(&pid).unwrap_or(0)
}

pub fn sys_pidfd_getfd(scheme_bfd: usize, targetfd: usize, flags: u32) -> isize {
    if flags != 0 {
        return -22;
    }

    let table_fdno = match scheme_bfd_to_table_fdno(scheme_bfd) {
        Some(f) => f,
        None => return -9,
    };
    let target_pid = match resolve(table_fdno) {
        Some(p) => p,
        None => return -3,
    };

    let caller_pid = crate::proc::scheduler::current_pid();
    let has_ptrace = crate::security::check_capability(19 /* CAP_SYS_PTRACE */);
    if !has_ptrace && caller_pid != target_pid {
        return -1;
    } // EPERM

    let owner = crate::fs::fcntl::fd_owner(targetfd);
    if owner != 0 && owner != target_pid {
        return -9;
    } // EBADF

    let new_fd = crate::fs::vfs::dup_from(targetfd, 3);
    if new_fd < 0 {
        return new_fd;
    }

    crate::fs::fcntl::set_fd_owner(new_fd as usize, caller_pid);
    crate::fs::fcntl::set_cloexec(new_fd as usize, true);
    new_fd
}
