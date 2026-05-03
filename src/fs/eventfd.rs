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

extern crate alloc;
use alloc::collections::BTreeMap;
use spin::Mutex;

// ── eventfd table ─────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct EventFdEntry {
    pub counter:    u64,
    pub flags:      u32,   // EFD_* flags
    pub nonblocking: bool,
    pub semaphore:  bool,
}

// eventfd fds start at EVENTFD_BASE so they don't collide with VFS or pipe fds.
pub const EVENTFD_FD_BASE: usize = 0x5000_0000;
const MAX_EVENTFDS: usize = 256;

static TABLE: Mutex<BTreeMap<usize, EventFdEntry>> = Mutex::new(BTreeMap::new());
static COUNTER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

pub const EFD_SEMAPHORE: u32 = 1;
pub const EFD_NONBLOCK:  u32 = 2048;
pub const EFD_CLOEXEC:   u32 = 524288;
const MAX_COUNTER: u64 = u64::MAX - 1;

// ── sys_eventfd2 [NR 290] ─────────────────────────────────────────────────

pub fn sys_eventfd2(initval: u32, flags: u32) -> isize {
    let id  = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let fdno = EVENTFD_FD_BASE + id;
    TABLE.lock().insert(fdno, EventFdEntry {
        counter:     initval as u64,
        flags,
        nonblocking: flags & EFD_NONBLOCK != 0,
        semaphore:   flags & EFD_SEMAPHORE != 0,
    });
    if flags & EFD_CLOEXEC != 0 {
        crate::fs::fcntl::set_cloexec(fdno, true);
    }
    fdno as isize
}

/// Returns true if fdno is an eventfd.
pub fn is_eventfd(fdno: usize) -> bool {
    fdno >= EVENTFD_FD_BASE && TABLE.lock().contains_key(&fdno)
}

// ── read ──────────────────────────────────────────────────────────────────

/// Implements read(2) on an eventfd.  buf must be exactly 8 bytes.
pub fn eventfd_read(fdno: usize, buf: &mut [u8]) -> isize {
    if buf.len() < 8 { return -22; } // EINVAL
    let deadline = crate::time::monotonic_ns() + 5_000_000_000; // 5s max spin
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
                if entry.nonblocking { return -11; } // EAGAIN
            } else {
                return -9; // EBADF
            }
        }
        // counter == 0 and blocking: spin-yield.
        if crate::time::monotonic_ns() >= deadline { return -110; } // ETIMEDOUT
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

// ── write ─────────────────────────────────────────────────────────────────

/// Implements write(2) on an eventfd.  buf must be exactly 8 bytes.
pub fn eventfd_write(fdno: usize, buf: &[u8]) -> isize {
    if buf.len() < 8 { return -22; } // EINVAL
    let val = u64::from_ne_bytes(buf[..8].try_into().unwrap());
    if val == u64::MAX { return -22; } // EINVAL: u64::MAX is reserved
    let deadline = crate::time::monotonic_ns() + 5_000_000_000;
    loop {
        {
            let mut tbl = TABLE.lock();
            if let Some(entry) = tbl.get_mut(&fdno) {
                if entry.counter <= MAX_COUNTER - val {
                    entry.counter += val;
                    return 8;
                }
                if entry.nonblocking { return -11; } // EAGAIN: would overflow
            } else {
                return -9; // EBADF
            }
        }
        if crate::time::monotonic_ns() >= deadline { return -110; }
        crate::proc::scheduler::schedule();
        core::hint::spin_loop();
    }
}

// ── poll readiness (called from fs/poll.rs fd_ready) ─────────────────────

/// Returns POLLIN | POLLOUT bitmask for the eventfd.
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

// ── close ─────────────────────────────────────────────────────────────────

pub fn eventfd_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}
