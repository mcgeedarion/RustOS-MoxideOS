//! eventfd2 (NR 290) — proper counter-based semantics.
//!
//! ## Linux semantics (eventfd(2))
//!
//!   The fd holds a single `u64` counter.  All operations are on that counter.
//!
//!   write(fd, &val, 8):
//!     Adds val to the counter.  If the counter would overflow u64::MAX-1,
//!     blocks (or returns EAGAIN if EFD_NONBLOCK).  We cap at u64::MAX-1.
//!
//!   read(fd, buf, 8):
//!     If counter > 0: copies counter (or 1 for EFD_SEMAPHORE) to buf,
//!     resets counter to 0 (or decrements by 1 for EFD_SEMAPHORE),
//!     returns 8.
//!     If counter == 0: blocks (or returns EAGAIN if EFD_NONBLOCK).
//!
//!   poll/select/epoll:
//!     POLLIN   ↔  counter > 0
//!     POLLOUT  ↔  counter < u64::MAX-1  (always true in practice)
//!
//!   EFD_SEMAPHORE (flag 1): read decrements by 1 and returns 1.
//!   EFD_NONBLOCK  (flag 2048 / O_NONBLOCK): non-blocking I/O.
//!   EFD_CLOEXEC   (flag 524288): sets FD_CLOEXEC.
//!
//! ## Scheme integration
//!
//! `sys_eventfd2` now allocates a scheme backing fd via
//! `alloc_scheme_backing_fd` and registers an `EventFdScheme` in
//! `SCHEME_FD_STORE`.  The scheme backing fd (not the raw TABLE fdno) is
//! installed into the process fd table, so all subsequent read/write/close
//! on the user-visible fd flows through `scheme_fd_read` / `scheme_fd_write`
//! / `scheme_fd_close`.
//!
//! The raw TABLE fdno is still inserted so that `is_eventfd()`,
//! `eventfd_poll()`, and the poll layer continue to work unchanged.
//! `EventFdScheme` reconstructs the TABLE fdno from the `SchemeFileId`
//! (which stores the fdno directly) on every I/O call.

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex;

use scheme_api::{OpenFlags, SchemeError, SchemeFileId};
use crate::fs::scheme_table::Scheme;

// ── eventfd table ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct EventFdEntry {
    pub counter:     u64,
    pub flags:       u32,
    pub nonblocking: bool,
    pub semaphore:   bool,
}

/// Raw fdno namespace for the TABLE.  Not exposed as user-visible fds any more;
/// kept solely so `is_eventfd` / `eventfd_poll` can key off it.
pub const EVENTFD_FD_BASE: usize = 0x5000_0000;

static TABLE: Mutex<BTreeMap<usize, EventFdEntry>> =
    Mutex::new(BTreeMap::new());
static COUNTER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

pub const EFD_SEMAPHORE: u32 = 1;
pub const EFD_NONBLOCK:  u32 = 2048;
pub const EFD_CLOEXEC:   u32 = 524288;
const MAX_COUNTER: u64 = u64::MAX - 1;

// ── EventFdScheme — Scheme trait wrapper ───────────────────────────────────────
//
// SchemeFileId stores the raw TABLE fdno so we can reconstruct it on
// every I/O call without an extra indirection table.

pub struct EventFdScheme {
    /// The raw TABLE fdno allocated at creation time.
    table_fdno: usize,
}

impl EventFdScheme {
    fn new(table_fdno: usize) -> Self { Self { table_fdno } }
}

impl Scheme for EventFdScheme {
    fn open(&self, _url: &str, _flags: OpenFlags) -> Result<SchemeFileId, SchemeError> {
        // eventfds are created by sys_eventfd2, not opened by URL.
        Err(SchemeError::InvalidArg)
    }

    fn read(&self, fid: SchemeFileId, buf: &mut [u8]) -> Result<usize, SchemeError> {
        let fdno = fid.0 as usize;
        let n = eventfd_read(fdno, buf);
        if n < 0 { Err(SchemeError::Io) } else { Ok(n as usize) }
    }

    fn write(&self, fid: SchemeFileId, buf: &[u8]) -> Result<usize, SchemeError> {
        let fdno = fid.0 as usize;
        let n = eventfd_write(fdno, buf);
        if n < 0 { Err(SchemeError::Io) } else { Ok(n as usize) }
    }

    fn seek(&self, _fid: SchemeFileId, _offset: i64, _whence: u8)
        -> Result<u64, SchemeError>
    {
        Err(SchemeError::InvalidArg) // eventfds are not seekable
    }

    fn ioctl(&self, _fid: SchemeFileId, _cmd: u64, _arg: usize)
        -> Result<usize, SchemeError>
    {
        Err(SchemeError::InvalidArg)
    }

    fn close(&self, fid: SchemeFileId) -> Result<(), SchemeError> {
        let fdno = fid.0 as usize;
        eventfd_close(fdno);
        Ok(())
    }
}

// ── sys_eventfd2 [NR 290] ─────────────────────────────────────────────────────────

pub fn sys_eventfd2(initval: u32, flags: u32) -> isize {
    use alloc::sync::Arc;
    use crate::fs::scheme_fd::{alloc_scheme_backing_fd, scheme_fd_register};
    use crate::fs::process_fd::proc_fd_install;

    // ── 1. Allocate a raw TABLE fdno (still needed for poll/is_eventfd) ───
    let id     = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let table_fdno = EVENTFD_FD_BASE + id;

    TABLE.lock().insert(table_fdno, EventFdEntry {
        counter:     initval as u64,
        flags,
        nonblocking: flags & EFD_NONBLOCK  != 0,
        semaphore:   flags & EFD_SEMAPHORE != 0,
    });

    // ── 2. Register an EventFdScheme in SCHEME_FD_STORE ──────────────────
    //
    // SchemeFileId carries the raw table_fdno so EventFdScheme can
    // dispatch to eventfd_read/write/close without an extra lookup.
    let scheme: alloc::sync::Arc<dyn Scheme> =
        Arc::new(EventFdScheme::new(table_fdno));
    let scheme_bfd = alloc_scheme_backing_fd();
    scheme_fd_register(scheme_bfd, scheme, SchemeFileId(table_fdno as u64));

    // ── 3. Install the *scheme* bfd into the process fd table ────────────
    let pid = crate::proc::scheduler::current_pid();
    let install_flags = if flags & EFD_CLOEXEC != 0 { EFD_CLOEXEC } else { 0 };
    let user_fd = proc_fd_install(pid, scheme_bfd, None, install_flags, None);

    user_fd as isize
}

// ── Predicate (poll layer) ───────────────────────────────────────────────────

/// Returns true if `fdno` is a live eventfd TABLE entry.
/// Note: `fdno` here is the raw TABLE fdno, not the scheme backing fd.
pub fn is_eventfd(fdno: usize) -> bool {
    fdno >= EVENTFD_FD_BASE && TABLE.lock().contains_key(&fdno)
}

// ── read ───────────────────────────────────────────────────────────────────────

pub fn eventfd_read(fdno: usize, buf: &mut [u8]) -> isize {
    if buf.len() < 8 { return -22; }
    let deadline = crate::time::monotonic_ns() + 5_000_000_000;
    loop {
        {
            let mut tbl = TABLE.lock();
            if let Some(entry) = tbl.get_mut(&fdno) {
                if entry.counter > 0 {
                    let val: u64 = if entry.semaphore { 1 } else { entry.counter };
                    if entry.semaphore {
                        entry.counter -= 1;
                    } else {
                        entry.counter = 0;
                    }
                    buf[..8].copy_from_slice(&val.to_ne_bytes());
                    return 8;
                }
                if entry.nonblocking { return -11; }
            } else {
                return -9;
            }
        }
        if crate::time::monotonic_ns() >= deadline { return -110; }
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

// ── write ─────────────────────────────────────────────────────────────────────

pub fn eventfd_write(fdno: usize, buf: &[u8]) -> isize {
    if buf.len() < 8 { return -22; }
    let val = u64::from_ne_bytes(buf[..8].try_into().unwrap());
    if val == u64::MAX { return -22; }
    let deadline = crate::time::monotonic_ns() + 5_000_000_000;
    loop {
        {
            let mut tbl = TABLE.lock();
            if let Some(entry) = tbl.get_mut(&fdno) {
                if entry.counter <= MAX_COUNTER - val {
                    entry.counter += val;
                    return 8;
                }
                if entry.nonblocking { return -11; }
            } else {
                return -9;
            }
        }
        if crate::time::monotonic_ns() >= deadline { return -110; }
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

// ── poll readiness ─────────────────────────────────────────────────────────────

/// Returns POLLIN | POLLOUT bitmask for the eventfd.
/// `fdno` is the raw TABLE fdno.
pub fn eventfd_poll(fdno: usize, events: u32) -> u32 {
    let tbl = TABLE.lock();
    match tbl.get(&fdno) {
        None => crate::fs::poll::POLLNVAL,
        Some(entry) => {
            let mut ready = 0u32;
            if events & crate::fs::poll::POLLIN  != 0 && entry.counter > 0 {
                ready |= crate::fs::poll::POLLIN;
            }
            if events & crate::fs::poll::POLLOUT != 0
                && entry.counter < MAX_COUNTER
            {
                ready |= crate::fs::poll::POLLOUT;
            }
            ready
        }
    }
}

// ── close ──────────────────────────────────────────────────────────────────────

pub fn eventfd_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}
