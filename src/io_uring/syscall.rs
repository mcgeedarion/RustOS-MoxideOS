//! Syscall entry points for io_uring.
//!
//! # NR 425 — io_uring_setup(entries, params_va)
//!
//! Allocates a new ring, maps SQ and CQ pages into the calling process's
//! address space, and writes `IoUringParams` back to userspace.
//! Returns a file descriptor on success.
//!
//! # NR 426 — io_uring_enter(fd, to_submit, min_complete, flags, sig, sigsz)
//!
//! Drains up to `to_submit` SQEs from the ring, executes them synchronously,
//! and posts CQEs.  If `IORING_ENTER_GETEVENTS` is set and
//! `min_complete > available_cqes`, the call blocks (spin-waits) until
//! enough completions are available.  Returns the number of SQEs consumed.
//!
//! # NR 427 — io_uring_register(fd, opcode, arg, nr_args)
//!
//! Registers or unregisters resources (buffers, FDs) with the ring.
//! Supported opcodes:
//!
//! | Value | Name                       |
//! |-------|----------------------------|
//! | 0     | IORING_REGISTER_BUFFERS    |
//! | 1     | IORING_UNREGISTER_BUFFERS  |
//! | 2     | IORING_REGISTER_FILES      |
//! | 3     | IORING_UNREGISTER_FILES    |
//! | 4     | IORING_REGISTER_EVENTFD    |
//! | 5     | IORING_UNREGISTER_EVENTFD  |
//! | 6     | IORING_REGISTER_FILES_UPDATE |
//! | 7     | IORING_REGISTER_IOWQ_AFF   |
//! | 8     | IORING_UNREGISTER_IOWQ_AFF |
//! | 9     | IORING_REGISTER_IOWQ_MAX_WORKERS |

extern crate alloc;
use alloc::vec;
use crate::io_uring::ring::{self, IoUringParams};
use crate::io_uring::ops;
use crate::uaccess::{copy_from_user, copy_to_user};
use crate::proc::scheduler;
use crate::mm::mmap;

// ── IORING_REGISTER opcodes ───────────────────────────────────────────────────

const IORING_REGISTER_BUFFERS:         u32 = 0;
const IORING_UNREGISTER_BUFFERS:       u32 = 1;
const IORING_REGISTER_FILES:           u32 = 2;
const IORING_UNREGISTER_FILES:         u32 = 3;
const IORING_REGISTER_EVENTFD:         u32 = 4;
const IORING_UNREGISTER_EVENTFD:       u32 = 5;
const IORING_REGISTER_FILES_UPDATE:    u32 = 6;
const IORING_REGISTER_IOWQ_AFF:        u32 = 7;
const IORING_UNREGISTER_IOWQ_AFF:      u32 = 8;
const IORING_REGISTER_IOWQ_MAX_WORKERS: u32 = 9;

/// `io_uring_setup(entries, params_va)` → fd
///
/// Allocates ring memory, maps it into the calling process,
/// and writes `IoUringParams` back to userspace.
pub fn sys_io_uring_setup(entries: u32, params_va: usize) -> isize {
    if entries == 0 || entries > ring::MAX_ENTRIES { return -22; } // EINVAL
    if params_va == 0 { return -14; } // EFAULT

    // Read user params (we only look at `flags` for now).
    let mut params = IoUringParams::default();
    if copy_from_user(params_va,
        unsafe { core::slice::from_raw_parts_mut(
            &mut params as *mut _ as *mut u8,
            core::mem::size_of::<IoUringParams>(),
        )}
    ).is_err() { return -14; }

    let pid = scheduler::current_pid() as u32;

    // Allocate the ring.
    let ring_idx = match ring::alloc_ring(pid, entries) {
        Ok(i)  => i,
        Err(e) => return e,
    };

    // Allocate a file descriptor for the ring.
    let fd = match crate::fs::vfs::alloc_fd_for_uring(ring_idx) {
        Some(fd) => fd,
        None => {
            ring::free_ring(ring_idx);
            return -24; // EMFILE
        }
    };

    // Record the fd in the ring descriptor.
    ring::with_ring_mut(ring_idx, |r| { r.fd = fd; });

    // Map SQ and CQ pages into user VA space (two consecutive mmap calls).
    // The process can subsequently call mmap(IORING_OFF_SQ_RING) and
    // mmap(IORING_OFF_CQ_RING) — we do it here eagerly for simplicity.
    let (sq_pa, cq_pa) = ring::with_ring(ring_idx, |r| (r.sq_pa, r.cq_pa)).unwrap();
    let page_size = 4096usize;

    let sq_va = mmap::sys_mmap(
        0, page_size,
        mmap::PROT_READ | mmap::PROT_WRITE,
        mmap::MAP_SHARED | mmap::MAP_ANONYMOUS,
        usize::MAX, // signal: use provided phys addr
        sq_pa,
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
        usize::MAX,
        cq_pa,
    );
    if cq_va < 0 {
        ring::free_ring(ring_idx);
        crate::fs::vfs::close_fd(fd);
        return cq_va;
    }

    // Build and write back params.
    let filled = ring::with_ring(ring_idx, |r| r.build_params()).unwrap();
    let params_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &filled as *const IoUringParams as *const u8,
            core::mem::size_of::<IoUringParams>(),
        )
    };
    if copy_to_user(params_va, params_bytes).is_err() {
        ring::free_ring(ring_idx);
        crate::fs::vfs::close_fd(fd);
        return -14;
    }

    fd as isize
}

/// `io_uring_enter(fd, to_submit, min_complete, flags, sig_va, sig_sz)` → submitted
pub fn sys_io_uring_enter(
    fd:          usize,
    to_submit:   u32,
    min_complete: u32,
    flags:       u32,
    _sig_va:     usize,
    _sig_sz:     usize,
) -> isize {
    let pid = scheduler::current_pid() as u32;
    let ring_idx = match ring::ring_idx_for_fd(pid, fd) {
        Some(i) => i,
        None    => return -9, // EBADF
    };

    // ── 1. Drain and execute SQEs ─────────────────────────────────────────────
    let sqes = ring::with_ring(ring_idx, |r| r.drain_sq())
        .unwrap_or_default();
    let total = sqes.len();
    let submit_count = (to_submit as usize).min(total);

    let mut submitted = 0u32;
    for sqe in sqes.iter().take(submit_count) {
        let (res, cqe_flags) = ops::dispatch(sqe, ring_idx);
        ring::with_ring(ring_idx, |r| {
            r.post_cqe(sqe.user_data, res, cqe_flags);
        });
        submitted += 1;
    }

    // ── 2. Wait for min_complete CQEs (GETEVENTS) ─────────────────────────────
    if flags & ops::IORING_ENTER_GETEVENTS != 0 && min_complete > 0 {
        // In synchronous mode all ops complete immediately, so we just
        // check the CQ tail.  A spin-wait is added for robustness.
        let mut spins = 0u32;
        loop {
            let available = ring::with_ring(ring_idx, |r| {
                let hdr = unsafe { &*(r.cq_pa as *const super::ring::CqRingHdrPub) };
                hdr.tail.load(core::sync::atomic::Ordering::Acquire)
                    .wrapping_sub(hdr.head.load(core::sync::atomic::Ordering::Acquire))
            }).unwrap_or(0);
            if available >= min_complete { break; }
            spins += 1;
            if spins > 1_000_000 { break; } // avoid infinite spin
            core::hint::spin_loop();
        }
    }

    submitted as isize
}

/// `io_uring_register(fd, opcode, arg_va, nr_args)` → 0 or -errno
pub fn sys_io_uring_register(
    fd:     usize,
    opcode: u32,
    arg_va: usize,
    nr_args: u32,
) -> isize {
    let pid = scheduler::current_pid() as u32;
    let ring_idx = match ring::ring_idx_for_fd(pid, fd) {
        Some(i) => i,
        None    => return -9, // EBADF
    };
    let nr = nr_args as usize;

    match opcode {
        // ── Register fixed buffers ─────────────────────────────────────────────
        IORING_REGISTER_BUFFERS => {
            // arg_va → array of `struct iovec { void *iov_base; size_t iov_len }`
            if arg_va == 0 || nr == 0 { return -22; }
            let iovec_size = 2 * core::mem::size_of::<usize>(); // base + len
            let total_bytes = nr * iovec_size;
            let mut buf = alloc::vec![0u8; total_bytes];
            if copy_from_user(arg_va, &mut buf).is_err() { return -14; }
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
            ring::with_ring_mut(ring_idx, |r| {
                r.reg_bufs.clear();
                0isize
            }).unwrap_or(-9)
        }

        // ── Register fixed files ───────────────────────────────────────────────
        IORING_REGISTER_FILES => {
            if arg_va == 0 || nr == 0 { return -22; }
            let mut fds = alloc::vec![0i32; nr];
            let bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    fds.as_mut_ptr() as *mut u8,
                    nr * 4,
                )
            };
            if copy_from_user(arg_va, bytes).is_err() { return -14; }
            ring::with_ring_mut(ring_idx, |r| {
                r.reg_fds = fds.clone();
                0isize
            }).unwrap_or(-9)
        }

        IORING_UNREGISTER_FILES => {
            ring::with_ring_mut(ring_idx, |r| {
                r.reg_fds.clear();
                0isize
            }).unwrap_or(-9)
        }

        // ── Register eventfd for completion notification ───────────────────────
        IORING_REGISTER_EVENTFD => {
            // arg_va is a pointer to an int (the eventfd fd number).
            if arg_va == 0 { return -22; }
            let mut efd_bytes = [0u8; 4];
            if copy_from_user(arg_va, &mut efd_bytes).is_err() { return -14; }
            let _efd = i32::from_ne_bytes(efd_bytes);
            // eventfd notification on CQE post — stored for future use.
            // Full integration requires writing to eventfd on post_cqe;
            // for now we accept the registration and return success.
            0
        }

        IORING_UNREGISTER_EVENTFD => 0,

        // ── Update registered files in-place ──────────────────────────────────
        IORING_REGISTER_FILES_UPDATE => {
            // arg_va → struct io_uring_files_update { offset, resv, fds* }
            if arg_va == 0 || nr == 0 { return -22; }
            let mut raw = alloc::vec![0u8; 8 + nr * 4];
            if copy_from_user(arg_va, &mut raw).is_err() { return -14; }
            let offset = u32::from_ne_bytes(raw[0..4].try_into().unwrap_or([0;4])) as usize;
            ring::with_ring_mut(ring_idx, |r| {
                for i in 0..nr {
                    let fd_bytes: [u8; 4] = raw[8 + i*4 .. 8 + i*4 + 4].try_into().unwrap_or([0;4]);
                    let new_fd = i32::from_ne_bytes(fd_bytes);
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

        // ── I/O-worker affinity / max-workers (no-op stubs) ───────────────────
        IORING_REGISTER_IOWQ_AFF | IORING_UNREGISTER_IOWQ_AFF
        | IORING_REGISTER_IOWQ_MAX_WORKERS => 0,

        _ => -22, // EINVAL — unknown opcode
    }
}

// ── `sys_io_uring_setup` helper re-exported for splice.rs compatibility ────────

/// Close an io_uring fd — called from vfs close path.
pub fn io_uring_close(fd: usize) {
    let pid = scheduler::current_pid() as u32;
    if let Some(idx) = ring::ring_idx_for_fd(pid, fd) {
        ring::free_ring(idx);
    }
}
