//! eventfd / eventfd2 — a file descriptor backed by a `u64` counter.
//!
//! ## Kernel-side contract
//!
//! * **`eventfd_register(fd, initval, flags)`** — called right after an anonymous VFS fd is
//!   allocated to attach the counter state.
//! * **`eventfd_read(fd, buf)`** — the VFS `read` path delegates here when `is_eventfd(fd)` is
//!   true.  `buf` must be ≥ 8 bytes; returns 8 on success or a negative errno.
//! * **`eventfd_write(fd, buf)`** — same for the `write` path.
//! * **`eventfd_poll(fd)`** — returns a bitmask of POLLIN (0x001) / POLLOUT (0x004) for use by the
//!   poll / epoll machinery.
//! * **`eventfd_close(fd)`** — removes state; must be called from the VFS close path.
//!
//! ## Flags
//!
//! | Flag | Value | Effect |
//! |---|---|---|
//! | `EFD_SEMAPHORE` | 1 | `read` returns 1 and decrements by 1 |
//! | `EFD_CLOEXEC`   | O_CLOEXEC | fd set close-on-exec |
//! | `EFD_NONBLOCK`  | O_NONBLOCK | `EAGAIN` instead of blocking |
//!
//! Blocking (`EAGAIN` → sleep) is not yet implemented because the
//! scheduler does not expose a wait-queue API; the non-blocking path
//! returns `EAGAIN` in both cases for now.  This is correct for all
//! callers that check `EFD_NONBLOCK` and is a known limitation for
//! blocking callers.

use crate::core::fast_hash::KernelFastMap;
use spin::Mutex;

pub const EFD_SEMAPHORE: u32 = 1;
pub const EFD_CLOEXEC: u32 = 0o2000000; // same as O_CLOEXEC
pub const EFD_NONBLOCK: u32 = 0o4000; // same as O_NONBLOCK

struct EventFd {
    counter: u64,
    semaphore: bool,
    nonblock: bool,
}

/// Fast map is safe here: keys are kernel-assigned fd numbers and eventfd
/// readiness is not exposed through deterministic iteration.
static EVENTFDS: Mutex<KernelFastMap<usize, EventFd>> = Mutex::new(KernelFastMap::new());

/// Attach eventfd state to an already-open VFS fd.
pub fn eventfd_register(fd: usize, initval: u64, flags: u32) {
    EVENTFDS.lock().insert(
        fd,
        EventFd {
            counter: initval,
            semaphore: flags & EFD_SEMAPHORE != 0,
            nonblock: flags & EFD_NONBLOCK != 0,
        },
    );
}

/// Called from the VFS read path.  `buf` must be exactly 8 bytes.
/// Returns 8 on success, or a negative errno.
pub fn eventfd_read(fd: usize, buf: &mut [u8]) -> isize {
    if buf.len() < 8 {
        return -22;
    } // EINVAL

    let mut map = EVENTFDS.lock();
    let efd = match map.get_mut(&fd) {
        Some(e) => e,
        None => return -9, // EBADF
    };

    if efd.counter == 0 {
        // Blocking sleep is NYI; return EAGAIN for both blocking and
        // non-blocking descriptors until wait-queues are available.
        return -11; // EAGAIN
    }

    let val = if efd.semaphore {
        efd.counter -= 1;
        1u64
    } else {
        let v = efd.counter;
        efd.counter = 0;
        v
    };

    buf[..8].copy_from_slice(&val.to_ne_bytes());
    8
}

/// Called from the VFS write path.  `buf` must be exactly 8 bytes.
/// Returns 8 on success, or a negative errno.
pub fn eventfd_write(fd: usize, buf: &[u8]) -> isize {
    if buf.len() < 8 {
        return -22;
    } // EINVAL

    let val = u64::from_ne_bytes(match buf[..8].try_into() {
        Ok(b) => b,
        Err(_) => return -22,
    });

    // Writing u64::MAX is explicitly forbidden by the Linux ABI.
    if val == u64::MAX {
        return -22;
    } // EINVAL

    let mut map = EVENTFDS.lock();
    let efd = match map.get_mut(&fd) {
        Some(e) => e,
        None => return -9, // EBADF
    };

    // Saturate at u64::MAX - 1 (the maximum readable value).
    efd.counter = efd.counter.saturating_add(val).min(u64::MAX - 1);

    8
}

/// Returns `true` when `fd` is a registered eventfd.
pub fn is_eventfd(fd: usize) -> bool {
    EVENTFDS.lock().contains_key(&fd)
}

/// Remove state when the fd is closed.
pub fn eventfd_close(fd: usize) {
    EVENTFDS.lock().remove(&fd);
}

/// Compatibility close hook used by generic fd lifecycle code.
pub fn sys_close_efd(fd: usize) {
    eventfd_close(fd);
}

/// Duplicate hook for process-local fd aliases. Eventfd state is shared by the
/// backing fd.
pub fn efd_dup(_fd: usize) {}

/// Poll readiness bitmask: bit 0 = POLLIN, bit 2 = POLLOUT.
pub fn eventfd_poll(fd: usize) -> u32 {
    let map = EVENTFDS.lock();
    let efd = match map.get(&fd) {
        Some(e) => e,
        None => return 0,
    };
    let mut mask = 0u32;
    if efd.counter > 0 {
        mask |= 0x001;
    } // POLLIN
    if efd.counter < u64::MAX - 1 {
        mask |= 0x004;
    } // POLLOUT
    mask
}

/// `eventfd(initval)` — NR 284.  Equivalent to `eventfd2(initval, 0)`.
pub fn sys_eventfd(initval: u32) -> isize {
    sys_eventfd2(initval, 0)
}

/// `eventfd2(initval, flags)` — NR 290.
pub fn sys_eventfd2(initval: u32, flags: u32) -> isize {
    let open_flags = if flags & EFD_CLOEXEC != 0 {
        crate::fs::vfs::O_CLOEXEC
    } else {
        0
    };

    let fd = match crate::fs::vfs::open_anon(open_flags) {
        Ok(fd) => fd,
        Err(_) => return -24, // EMFILE
    };

    eventfd_register(fd, initval as u64, flags);
    fd as isize
}
