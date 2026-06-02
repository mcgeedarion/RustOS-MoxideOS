//! Syscall entry points for io_uring.
//!
//! | NR  | Name               | Description                                  |
//! |-----|--------------------|----------------------------------------------|
//! | 425 | `io_uring_setup`   | Allocate ring, map pages, write params back  |
//! | 426 | `io_uring_enter`   | Submit SQEs, optionally wait for CQEs        |
//! | 427 | `io_uring_register`| Register/unregister buffers, fds, eventfd    |
//!
//! ## Blocking model (`io_uring_enter` + GETEVENTS)
//!
//! When `min_complete > 0` and `IORING_ENTER_GETEVENTS` is set, the task
//! sleeps on `ring.cq_wq` until enough CQEs are available.  Each call to
//! `ring.post_cqe()` wakes the queue, so the task unblocks with O(1) latency
//! instead of burning CPU in a spin loop.
//!
//! Wakeup sources:
//!   - A CQE is posted (`post_cqe` → `cq_wq.wake(CQ_READY)`)
//!   - Deadline elapsed (`WaitQueue::wait` returns `WakeReason::Timeout`)
//!   - Signal delivered (`WakeReason::Cancelled`) → returns `-EINTR`
//!
//! ## `io_uring_register` opcodes
//!
//! | Value | Name                           |
//! |-------|--------------------------------|
//! |     0 | IORING_REGISTER_BUFFERS        |
//! |     1 | IORING_UNREGISTER_BUFFERS      |
//! |     2 | IORING_REGISTER_FILES          |
//! |     3 | IORING_UNREGISTER_FILES        |
//! |     4 | IORING_REGISTER_EVENTFD        |
//! |     5 | IORING_UNREGISTER_EVENTFD      |
//! |     6 | IORING_REGISTER_FILES_UPDATE   |
//! |     7 | IORING_REGISTER_IOWQ_AFF       |
//! |     8 | IORING_UNREGISTER_IOWQ_AFF     |
//! |     9 | IORING_REGISTER_IOWQ_MAX_WORKERS |

extern crate alloc;
use crate::io_uring::ops;
use crate::io_uring::ring::{self, IoUringParams};
use crate::mm::mmap;
use crate::proc::scheduler;
use crate::sync::wait_queue::{WakeReason, CancellationToken};
use crate::uaccess::{copy_from_user, copy_to_user};
use alloc::sync::Arc;

const IORING_REGISTER_BUFFERS:           u32 = 0;
const IORING_UNREGISTER_BUFFERS:         u32 = 1;
const IORING_REGISTER_FILES:             u32 = 2;
const IORING_UNREGISTER_FILES:           u32 = 3;
const IORING_REGISTER_EVENTFD:           u32 = 4;
const IORING_UNREGISTER_EVENTFD:         u32 = 5;
const IORING_REGISTER_FILES_UPDATE:      u32 = 6;
const IORING_REGISTER_IOWQ_AFF:          u32 = 7;
const IORING_UNREGISTER_IOWQ_AFF:        u32 = 8;
const IORING_REGISTER_IOWQ_MAX_WORKERS:  u32 = 9;

#[inline]
fn current_cancel() -> Option<Arc<CancellationToken>> {
    let pid = scheduler::current_pid();
    scheduler::task_cancel_token(pid)
}

/// `io_uring_setup(entries, params_va)` → fd
pub fn sys_io_uring_setup(entries: u32, params_va: usize) -> isize {
    if entries == 0 || entries > ring::MAX_ENTRIES { return -22; }
    if params_va == 0 { return -14; }

    let mut params = IoUringParams::default();
    if copy_from_user(params_va, unsafe {
        core::slice::from_raw_parts_mut(
            &mut params as *mut _ as *mut u8,
            core::mem::size_of::<IoUringParams>(),
        )
    }).is_err() { return -14; }

    let pid = scheduler::current_pid() as u32;

    let ring_idx = match ring::alloc_ring(pid, entries) {
        Ok(i)  => i,
        Err(e) => return e,
    };

    let fd = match crate::fs::vfs::alloc_fd_for_uring(ring_idx) {
        Some(fd) => fd,
        None => {
            ring::free_ring(ring_idx);
            return -24;
        }
    };

    ring::with_ring_mut(ring_idx, |r| { r.fd = fd; });

    let (sq_pa, cq_pa) = ring::with_ring(ring_idx, |r| (r.sq_pa, r.cq_pa)).unwrap();
    let page_size = 4096usize;

    let sq_va = mmap::sys_mmap(
        0, page_size,
        mmap::PROT_READ | mmap::PROT_WRITE,
        mmap::MAP_SHARED | mmap::MAP_ANONYMOUS,
        usize::MAX, sq_pa,
    );
    if sq_va < 0 {
        ring::free_ring(ring_idx);
        crate::fs::vfs::close_fd(fd);
        return sq_va;
    }

    let cq_va = mmap::sys_mmap(
        0, page_size,
        mmap::PROT_READ | mmap::PROT_WRITE,
        mmap::MAP_SHARED | mmap::MAP_ANONYMOUS,
        usize::MAX, cq_pa,
    );
    if cq_va < 0 {
        ring::free_ring(ring_idx);
        crate::fs::vfs::close_fd(fd);
        return cq_va;
    }

    let filled = ring::with_ring(ring_idx, |r| r.build_params()).unwrap();
    let params_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &filled as *const IoUringParams as *const u8,
            core::mem::size_of::<IoUringParams>(),
        )
    };
    if !copy_to_user(params_va, params_bytes) {
        ring::free_ring(ring_idx);
        crate::fs::vfs::close_fd(fd);
        return -14;
    }

    fd as isize
}

/// `io_uring_enter(fd, to_submit, min_complete, flags, sig_va, sig_sz)` → submitted
///
/// Phase 1: drain and execute SQEs.
/// Phase 2 (GETEVENTS): sleep on `cq_wq` until `min_complete` CQEs are ready.
///   - Wakes on each `post_cqe()` call; re-checks count; sleeps again if needed.
///   - Returns `-EINTR` (-4) if a signal cancels the wait.
pub fn sys_io_uring_enter(
    fd:           usize,
    to_submit:    u32,
    min_complete: u32,
    flags:        u32,
    _sig_va:      usize,
    _sig_sz:      usize,
) -> isize {
    let pid = scheduler::current_pid() as u32;
    let Some(ring_idx) = ring::ring_idx_for_fd(pid, fd) else { return -9; };

    let sqes          = ring::with_ring(ring_idx, |r| r.drain_sq()).unwrap_or_default();
    let submit_count  = (to_submit as usize).min(sqes.len());
    let mut submitted = 0u32;

    for sqe in sqes.iter().take(submit_count) {
        let (res, cqe_flags) = ops::dispatch(sqe, ring_idx);
        // post_cqe wakes cq_wq internally — no extra wake() needed here.
        ring::with_ring(ring_idx, |r| r.post_cqe(sqe.user_data, res, cqe_flags));
        submitted += 1;
    }

    if flags & ops::IORING_ENTER_GETEVENTS != 0 && min_complete > 0 {
        // Clone the wait queue Arc before entering the wait so we never hold
        // the RING_TABLE lock while sleeping.
        let cq_wq = match ring::cq_wq_for(ring_idx) {
            Some(wq) => wq,
            None     => return -9,
        };
        let cancel = current_cancel();
        let cancel_ref = cancel.as_deref();
        // 5-second ceiling matches the rest of the poll subsystem.
        let deadline_ns = crate::time::monotonic_ns() + 5_000_000_000;

        loop {
            let available = ring::with_ring(ring_idx, |r| r.cq_available())
                .unwrap_or(0);
            if available >= min_complete { break; }

            // Sleep until a CQE is posted, deadline fires, or signal arrives.
            let reason = cq_wq.wait(0x0001 /*CQ_READY*/, cancel_ref, Some(deadline_ns));
            match reason {
                WakeReason::Cancelled => return -4, // EINTR
                WakeReason::Timeout   => break,     // deadline — return what we have
                WakeReason::Ready(_)  => {}          // re-check count
            }
        }
    }

    submitted as isize
}

/// `io_uring_register(fd, opcode, arg_va, nr_args)` → 0 or -errno
pub fn sys_io_uring_register(
    fd:      usize,
    opcode:  u32,
    arg_va:  usize,
    nr_args: u32,
) -> isize {
    let pid = scheduler::current_pid() as u32;
    let Some(ring_idx) = ring::ring_idx_for_fd(pid, fd) else { return -9; };
    let nr = nr_args as usize;

    match opcode {
        IORING_REGISTER_BUFFERS => {
            if arg_va == 0 || nr == 0 { return -22; }
            let iovec_size  = 2 * core::mem::size_of::<usize>();
            let mut buf     = alloc::vec![0u8; nr * iovec_size];
            if copy_from_user(&mut buf, arg_va).is_err() { return -14; }
            ring::with_ring_mut(ring_idx, |r| {
                r.reg_bufs.clear();
                for i in 0..nr {
                    let off  = i * iovec_size;
                    let base = usize::from_ne_bytes(buf[off..off+8].try_into().unwrap_or([0;8]));
                    let len  = usize::from_ne_bytes(buf[off+8..off+16].try_into().unwrap_or([0;8]));
                    r.reg_bufs.push((base, len));
                }
                0isize
            }).unwrap_or(-9)
        }

        IORING_UNREGISTER_BUFFERS => {
            ring::with_ring_mut(ring_idx, |r| { r.reg_bufs.clear(); 0isize }).unwrap_or(-9)
        }

        IORING_REGISTER_FILES => {
            if arg_va == 0 || nr == 0 { return -22; }
            let mut fds = alloc::vec![0i32; nr];
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(fds.as_mut_ptr() as *mut u8, nr * 4)
            };
            if copy_from_user(bytes, arg_va).is_err() { return -14; }
            ring::with_ring_mut(ring_idx, |r| { r.reg_fds = fds.clone(); 0isize }).unwrap_or(-9)
        }

        IORING_UNREGISTER_FILES => {
            ring::with_ring_mut(ring_idx, |r| { r.reg_fds.clear(); 0isize }).unwrap_or(-9)
        }

        IORING_REGISTER_EVENTFD => {
            if arg_va == 0 { return -22; }
            let mut efd_bytes = [0u8; 4];
            if copy_from_user(&mut efd_bytes, arg_va).is_err() { return -14; }
            let _efd = i32::from_ne_bytes(efd_bytes);
            0
        }

        IORING_UNREGISTER_EVENTFD => 0,

        IORING_REGISTER_FILES_UPDATE => {
            if arg_va == 0 || nr == 0 { return -22; }
            let mut raw = alloc::vec![0u8; 8 + nr * 4];
            if copy_from_user(&mut raw, arg_va).is_err() { return -14; }
            let offset = u32::from_ne_bytes(raw[0..4].try_into().unwrap_or([0;4])) as usize;
            ring::with_ring_mut(ring_idx, |r| {
                for i in 0..nr {
                    let new_fd = i32::from_ne_bytes(
                        raw[8 + i*4 .. 8 + i*4 + 4].try_into().unwrap_or([0;4])
                    );
                    let slot = offset + i;
                    if slot < r.reg_fds.len() {
                        r.reg_fds[slot] = new_fd;
                    } else {
                        r.reg_fds.resize(slot + 1, -1);
                        r.reg_fds[slot] = new_fd;
                    }
                }
                nr as isize
            }).unwrap_or(-9)
        }

        IORING_REGISTER_IOWQ_AFF | IORING_UNREGISTER_IOWQ_AFF
        | IORING_REGISTER_IOWQ_MAX_WORKERS => 0,

        _ => -22,
    }
}

/// Close an io_uring fd — called from the VFS close path.
pub fn io_uring_close(fd: usize) {
    let pid = scheduler::current_pid() as u32;
    if let Some(idx) = ring::ring_idx_for_fd(pid, fd) {
        ring::free_ring(idx);
    }
}
