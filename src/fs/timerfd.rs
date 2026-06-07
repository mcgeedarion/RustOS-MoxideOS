//! timerfd — Linux-compatible interval timer fds.
//!
//! ## Linux syscall numbers (x86-64)
//!   NR 283  timerfd_create(clockid, flags)
//!   NR 286  timerfd_settime(fd, flags, new_value, old_value)
//!   NR 287  timerfd_gettime(fd, curr_value)
//!   NR 288  timerfd_gettime64 (same on x86-64; alias of 287)
//!
//! ## Semantics
//!
//!   A timerfd holds an `itimerspec`:
//!     it_interval — repeat interval (0 → one-shot)
//!     it_value    — time until next expiry (0 → disarmed)
//!
//!   Once armed, the kernel counts expirations.  read(fd, buf, 8) returns
//!   the number of expirations since the last read as a little-endian u64.
//!   If no expirations have occurred: blocks (or EAGAIN if TFD_NONBLOCK).
//!
//!   poll/epoll: POLLIN when expirations > 0.
//!
//! ## Clocks supported
//!   CLOCK_REALTIME  (0) — mapped to monotonic_ns() for simplicity
//!   CLOCK_MONOTONIC (1) — monotonic_ns()
//!   Others          — returns EINVAL
//!
//! ## Flags
//!   TFD_NONBLOCK  (O_NONBLOCK = 2048)
//!   TFD_CLOEXEC   (O_CLOEXEC  = 524288)
//!   TFD_TIMER_ABSTIME (1) — it_value is absolute, not relative
//!
//! ## Scheme integration
//!
//! `sys_timerfd_create` now allocates a scheme backing fd via
//! `alloc_scheme_backing_fd` and registers a `TimerFdScheme` in
//! `SCHEME_FD_STORE`.  All subsequent read/close on the user-visible fd
//! flows through `scheme_fd_read` / `scheme_fd_close`.
//!
//! `sys_timerfd_settime` and `sys_timerfd_gettime` receive the scheme
//! backing fd (already resolved from the user fd by the syscall dispatch)
//! and need the raw TABLE fdno.  `scheme_bfd_to_table_fdno` provides that
//! translation by walking SCHEME_FD_STORE to extract the SchemeFileId,
//! which carries the TABLE fdno directly.

extern crate alloc;
use crate::core::fast_hash::KernelFastMap;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};
use spin::Mutex;

use crate::fs::scheme_table::Scheme;
use scheme_api::{OpenFlags, SchemeError, SchemeFileId};

/// Raw fdno namespace for the TABLE.
pub const TIMERFD_FD_BASE: usize = 0x6000_0000;

pub const TFD_NONBLOCK: u32 = 2048;
pub const TFD_CLOEXEC: u32 = 524288;
pub const TFD_TIMER_ABSTIME: i32 = 1;

const CLOCK_REALTIME: u32 = 0;
const CLOCK_MONOTONIC: u32 = 1;

#[derive(Clone, Copy, Default)]
pub struct ItimerspecNs {
    pub interval_ns: u64,
    pub next_ns: u64,
}

#[derive(Clone, Copy)]
pub struct TimerFdEntry {
    pub spec: ItimerspecNs,
    pub expirations: u64,
    pub nonblocking: bool,
}

/// Fast map is safe here: keys are monotonic kernel-assigned timerfd table
/// numbers and the table is never iterated for user-visible ordering.
static TABLE: Mutex<KernelFastMap<usize, TimerFdEntry>> = Mutex::new(KernelFastMap::new());
static COUNTER: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

// `sys_timerfd_settime` and `sys_timerfd_gettime` are called from the
// syscall dispatch table with the *scheme* backing fd (already resolved
// from the user-visible fd).  They need the raw TABLE fdno to look up
// the timer state.  We retrieve it by reading the SchemeFileId that was
// stored at registration time (which holds the TABLE fdno directly).

/// Translate a scheme backing fd to the TABLE fdno for this timerfd.
///
/// Returns `None` if `scheme_bfd` is not a registered timerfd scheme fd.
pub fn scheme_bfd_to_table_fdno(scheme_bfd: usize) -> Option<usize> {
    let (_, fid) = crate::fs::scheme_fd::scheme_fd_get_fid(scheme_bfd)?;
    // The TABLE fdno is stored verbatim in SchemeFileId.0.
    let table_fdno = fid.0 as usize;
    if table_fdno >= TIMERFD_FD_BASE && TABLE.lock().contains_key(&table_fdno) {
        Some(table_fdno)
    } else {
        None
    }
}

pub struct TimerFdScheme;

impl Scheme for TimerFdScheme {
    fn open(&self, _url: &str, _flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        Err(SchemeError::InvalidArg)
    }

    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let fdno = fid.0 as usize;
        let n = timerfd_read(fdno, buf);
        if n < 0 {
            Err(SchemeError::Io)
        } else {
            Ok(n as usize)
        }
    }

    /// timerfds are not writable.
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
        let fdno = fid.0 as usize;
        timerfd_close(fdno);
        Ok(())
    }
}

#[inline]
fn now_ns() -> u64 {
    crate::time::monotonic_ns()
}

fn read_itimerspec(va: usize) -> Result<(u64, u64), isize> {
    if !validate_user_ptr(va, 32) {
        return Err(-14);
    }
    let mut buf = [0u8; 32];
    copy_from_user(&mut buf, va).map_err(|_| -14isize)?;
    let interval_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let interval_nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    let value_sec = i64::from_le_bytes(buf[16..24].try_into().unwrap());
    let value_nsec = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    let interval_ns = (interval_sec.max(0) as u64) * 1_000_000_000 + (interval_nsec.max(0) as u64);
    let value_ns = (value_sec.max(0) as u64) * 1_000_000_000 + (value_nsec.max(0) as u64);
    Ok((interval_ns, value_ns))
}

fn write_itimerspec(va: usize, interval_ns: u64, remaining_ns: u64) {
    if va == 0 {
        return;
    }
    let isec = (interval_ns / 1_000_000_000) as i64;
    let insec = (interval_ns % 1_000_000_000) as i64;
    let rsec = (remaining_ns / 1_000_000_000) as i64;
    let rnsec = (remaining_ns % 1_000_000_000) as i64;
    let mut buf = [0u8; 32];
    buf[0..8].copy_from_slice(&isec.to_le_bytes());
    buf[8..16].copy_from_slice(&insec.to_le_bytes());
    buf[16..24].copy_from_slice(&rsec.to_le_bytes());
    buf[24..32].copy_from_slice(&rnsec.to_le_bytes());
    let _ = copy_to_user(va, &buf);
}

fn tick(entry: &mut TimerFdEntry) {
    if entry.spec.next_ns == 0 {
        return;
    }
    let now = now_ns();
    if now < entry.spec.next_ns {
        return;
    }
    if entry.spec.interval_ns == 0 {
        entry.expirations += 1;
        entry.spec.next_ns = 0;
    } else {
        let elapsed = now - entry.spec.next_ns;
        let full = elapsed / entry.spec.interval_ns;
        entry.expirations += full + 1;
        entry.spec.next_ns += (full + 1) * entry.spec.interval_ns;
    }
}

pub fn is_timerfd(fdno: usize) -> bool {
    fdno >= TIMERFD_FD_BASE && TABLE.lock().contains_key(&fdno)
}

pub fn sys_timerfd_create(clockid: u32, flags: u32) -> isize {
    use crate::fs::process_fd::proc_fd_install;
    use crate::fs::scheme_fd::{alloc_scheme_backing_fd, scheme_fd_register};
    use alloc::sync::Arc;

    match clockid {
        CLOCK_REALTIME | CLOCK_MONOTONIC => {},
        _ => return -22, // EINVAL
    }

    let id = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let table_fdno = TIMERFD_FD_BASE + id;

    TABLE.lock().insert(
        table_fdno,
        TimerFdEntry {
            spec: ItimerspecNs::default(),
            expirations: 0,
            nonblocking: flags & TFD_NONBLOCK != 0,
        },
    );

    // SchemeFileId carries the TABLE fdno for reverse lookup in
    // scheme_bfd_to_table_fdno (used by settime/gettime).
    let scheme: Arc<dyn Scheme> = Arc::new(TimerFdScheme);
    let scheme_bfd = alloc_scheme_backing_fd();
    scheme_fd_register(scheme_bfd, scheme, SchemeFileId(table_fdno as u64));

    let pid = crate::proc::scheduler::current_pid();
    let install_flags = if flags & TFD_CLOEXEC != 0 {
        TFD_CLOEXEC
    } else {
        0
    };
    let user_fd = proc_fd_install(pid, scheme_bfd, None, install_flags, None);

    user_fd as isize
}

// The syscall dispatch calls this with the scheme backing fd already
// resolved from the user-visible fd.  We translate to the TABLE fdno
// via scheme_bfd_to_table_fdno.

pub fn sys_timerfd_settime(scheme_bfd: usize, flags: i32, new_va: usize, old_va: usize) -> isize {
    let fdno = match scheme_bfd_to_table_fdno(scheme_bfd) {
        Some(f) => f,
        None => return -9, // EBADF
    };
    let (interval_ns, value_ns) = match read_itimerspec(new_va) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut tbl = TABLE.lock();
    let entry = match tbl.get_mut(&fdno) {
        Some(e) => e,
        None => return -9,
    };
    if old_va != 0 {
        let remaining = if entry.spec.next_ns > 0 {
            entry.spec.next_ns.saturating_sub(now_ns())
        } else {
            0
        };
        let old_interval = entry.spec.interval_ns;
        drop(tbl);
        write_itimerspec(old_va, old_interval, remaining);
        tbl = TABLE.lock();
        if let Some(e) = tbl.get_mut(&fdno) {
            entry_settime(e, flags, interval_ns, value_ns);
        }
    } else {
        entry_settime(entry, flags, interval_ns, value_ns);
    }
    0
}

fn entry_settime(entry: &mut TimerFdEntry, flags: i32, interval_ns: u64, value_ns: u64) {
    entry.expirations = 0;
    if value_ns == 0 {
        entry.spec = ItimerspecNs::default();
        return;
    }
    entry.spec.interval_ns = interval_ns;
    entry.spec.next_ns = if flags & TFD_TIMER_ABSTIME != 0 {
        value_ns
    } else {
        now_ns() + value_ns
    };
}

pub fn sys_timerfd_gettime(scheme_bfd: usize, curr_va: usize) -> isize {
    if !validate_user_ptr(curr_va, 32) {
        return -14;
    }
    let fdno = match scheme_bfd_to_table_fdno(scheme_bfd) {
        Some(f) => f,
        None => return -9,
    };
    let mut tbl = TABLE.lock();
    let entry = match tbl.get_mut(&fdno) {
        Some(e) => e,
        None => return -9,
    };
    tick(entry);
    let interval_ns = entry.spec.interval_ns;
    let remaining_ns = if entry.spec.next_ns > 0 {
        entry.spec.next_ns.saturating_sub(now_ns())
    } else {
        0
    };
    drop(tbl);
    write_itimerspec(curr_va, interval_ns, remaining_ns);
    0
}

pub fn timerfd_read(fdno: usize, buf: &mut [u8]) -> isize {
    if buf.len() < 8 {
        return -22;
    }
    let deadline = now_ns() + 5_000_000_000;
    loop {
        {
            let mut tbl = TABLE.lock();
            if let Some(entry) = tbl.get_mut(&fdno) {
                tick(entry);
                if entry.expirations > 0 {
                    let val = entry.expirations;
                    entry.expirations = 0;
                    buf[..8].copy_from_slice(&val.to_le_bytes());
                    return 8;
                }
                if entry.nonblocking {
                    return -11;
                }
            } else {
                return -9;
            }
        }
        if now_ns() >= deadline {
            return -110;
        }
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

/// `fdno` here is the raw TABLE fdno (not the scheme bfd).
pub fn timerfd_poll(fdno: usize, events: u32) -> u32 {
    let mut tbl = TABLE.lock();
    match tbl.get_mut(&fdno) {
        None => crate::fs::poll::POLLNVAL,
        Some(entry) => {
            tick(entry);
            if events & crate::fs::poll::POLLIN != 0 && entry.expirations > 0 {
                crate::fs::poll::POLLIN
            } else {
                0
            }
        },
    }
}

pub fn timerfd_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}

/// Compatibility close hook used by generic fd lifecycle code.
pub fn sys_close_tfd(fdno: usize) {
    if crate::fs::scheme_fd::is_scheme_fd(fdno) {
        crate::fs::scheme_fd::scheme_fd_close(fdno);
    } else {
        timerfd_close(fdno);
    }
}

/// Duplicate hook for process-local fd aliases. Timerfd state is shared by the
/// backing fd.
pub fn tfd_dup(_fdno: usize) {}
