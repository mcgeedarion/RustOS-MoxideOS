//! io_uring opcode dispatch — maps SQE opcodes to kernel VFS/socket calls.
//!
//! Every opcode handler returns `(res: i32, flags: u32)`.  `res` is the
//! POSIX return value (negative = errno negated).  `flags` is written into
//! `cqe.flags` — currently 0 for all opcodes.

use crate::io_uring::ring::IoUringSqe;

// ── Opcode constants ──────────────────────────────────────────────────────────

pub const IORING_OP_NOP:            u8 = 0;
pub const IORING_OP_READV:          u8 = 1;
pub const IORING_OP_WRITEV:         u8 = 2;
pub const IORING_OP_FSYNC:          u8 = 3;
pub const IORING_OP_READ_FIXED:     u8 = 4;
pub const IORING_OP_WRITE_FIXED:    u8 = 5;
pub const IORING_OP_POLL_ADD:       u8 = 6;
pub const IORING_OP_POLL_REMOVE:    u8 = 7;
pub const IORING_OP_SYNC_FILE_RANGE: u8 = 8;
pub const IORING_OP_SENDMSG:        u8 = 9;
pub const IORING_OP_RECVMSG:        u8 = 10;
pub const IORING_OP_TIMEOUT:        u8 = 11;
pub const IORING_OP_TIMEOUT_REMOVE: u8 = 12;
pub const IORING_OP_ACCEPT:         u8 = 13;
pub const IORING_OP_ASYNC_CANCEL:   u8 = 14;
pub const IORING_OP_LINK_TIMEOUT:   u8 = 15;
pub const IORING_OP_CONNECT:        u8 = 16;
pub const IORING_OP_FALLOCATE:      u8 = 17;
pub const IORING_OP_OPENAT:         u8 = 18;
pub const IORING_OP_CLOSE:          u8 = 19;
pub const IORING_OP_STATX:          u8 = 20;
pub const IORING_OP_READ:           u8 = 21;
pub const IORING_OP_WRITE:          u8 = 22;
pub const IORING_OP_FADVISE:        u8 = 23;
pub const IORING_OP_MADVISE:        u8 = 24;
pub const IORING_OP_SEND:           u8 = 25;
pub const IORING_OP_RECV:           u8 = 26;
pub const IORING_OP_OPENAT2:        u8 = 27;
pub const IORING_OP_EPOLL_CTL:      u8 = 28;
pub const IORING_OP_SPLICE:         u8 = 29;
pub const IORING_OP_PROVIDE_BUFFERS: u8 = 30;
pub const IORING_OP_REMOVE_BUFFERS: u8 = 31;

// ── SQE flags ─────────────────────────────────────────────────────────────────
pub const IOSQE_FIXED_FILE:     u8 = 1 << 0;
pub const IOSQE_IO_DRAIN:       u8 = 1 << 1;
pub const IOSQE_IO_LINK:        u8 = 1 << 2;
pub const IOSQE_IO_HARDLINK:    u8 = 1 << 3;
pub const IOSQE_ASYNC:          u8 = 1 << 4;
pub const IOSQE_BUFFER_SELECT:  u8 = 1 << 5;

// ── IORING_ENTER_* flags ─────────────────────────────────────────────────────
pub const IORING_ENTER_GETEVENTS:  u32 = 1 << 0;
pub const IORING_ENTER_SQ_WAKEUP:  u32 = 1 << 1;

// ── Main dispatch ─────────────────────────────────────────────────────────────

/// Execute one SQE synchronously in the context of the calling process.
///
/// Returns `(result, cqe_flags)`.  All I/O is currently synchronous;
/// a future implementation can push ops to a work queue here.
pub fn dispatch(sqe: &IoUringSqe, ring_idx: usize) -> (i32, u32) {
    let fd   = sqe.fd as usize;
    let addr = sqe.addr_or_splice_fd_in as usize;
    let len  = sqe.len as usize;
    let off  = sqe.off_or_addr2;
    let flags = sqe.op_flags;

    let res: isize = match sqe.opcode {
        // ── NOP ───────────────────────────────────────────────────────────────
        IORING_OP_NOP => 0,

        // ── READV ─────────────────────────────────────────────────────────────
        IORING_OP_READV => {
            crate::fs::io_syscalls::sys_readv_va(fd, addr, len)
        }

        // ── WRITEV ────────────────────────────────────────────────────────────
        IORING_OP_WRITEV => {
            crate::fs::io_syscalls::sys_writev_va(fd, addr, len)
        }

        // ── READ ──────────────────────────────────────────────────────────────
        IORING_OP_READ => {
            crate::fs::io_syscalls::sys_pread64(fd, addr, len, off as i64)
        }

        // ── WRITE ─────────────────────────────────────────────────────────────
        IORING_OP_WRITE => {
            crate::fs::io_syscalls::sys_pwrite64(fd, addr, len, off as i64)
        }

        // ── READ_FIXED / WRITE_FIXED ──────────────────────────────────────────
        // Registered-buffer I/O: buf_index selects a pre-pinned buffer.
        IORING_OP_READ_FIXED => {
            let buf_va = resolve_fixed_buf(ring_idx, sqe.buf_index as usize, len);
            match buf_va {
                Some(va) => crate::fs::io_syscalls::sys_pread64(fd, va, len, off as i64),
                None     => -9, // EBADF
            }
        }

        IORING_OP_WRITE_FIXED => {
            let buf_va = resolve_fixed_buf(ring_idx, sqe.buf_index as usize, len);
            match buf_va {
                Some(va) => crate::fs::io_syscalls::sys_pwrite64(fd, va, len, off as i64),
                None     => -9,
            }
        }

        // ── FSYNC ─────────────────────────────────────────────────────────────
        IORING_OP_FSYNC | IORING_OP_SYNC_FILE_RANGE => {
            crate::fs::vfs::fsync(fd)
        }

        // ── OPENAT ────────────────────────────────────────────────────────────
        IORING_OP_OPENAT => {
            // addr = path (user VA), fd = dirfd, len = mode, op_flags = flags
            crate::syscall::sys_openat_impl(sqe.fd, addr, flags as i32, len as u32)
        }

        // ── CLOSE ─────────────────────────────────────────────────────────────
        IORING_OP_CLOSE => {
            crate::fs::io_syscalls::sys_close(fd)
        }

        // ── STATX ─────────────────────────────────────────────────────────────
        IORING_OP_STATX => {
            // addr2 = statxbuf VA, addr = path VA
            let statxbuf = sqe.off_or_addr2 as usize;
            crate::syscall::sys_statx_impl(
                sqe.fd,
                addr,
                flags,
                sqe.len,
                statxbuf,
            )
        }

        // ── FALLOCATE ─────────────────────────────────────────────────────────
        IORING_OP_FALLOCATE => {
            crate::syscall::sys_fallocate_impl(fd, flags as i32, off as i64, len as i64)
        }

        // ── POLL_ADD / POLL_REMOVE ────────────────────────────────────────────
        IORING_OP_POLL_ADD => {
            // One-shot poll: immediately check readiness and return.
            let events = flags as i16;
            crate::fs::poll::poll_fd_once(fd, events).map(|e| e as isize).unwrap_or(-9)
        }
        IORING_OP_POLL_REMOVE => {
            // Nothing to cancel in synchronous mode; return success.
            0
        }

        // ── SENDMSG ───────────────────────────────────────────────────────────
        IORING_OP_SENDMSG | IORING_OP_SEND => {
            crate::net::socket::sys_sendmsg(fd, addr, flags as i32)
        }

        // ── RECVMSG ───────────────────────────────────────────────────────────
        IORING_OP_RECVMSG | IORING_OP_RECV => {
            crate::net::socket::sys_recvmsg(fd, addr, flags as i32)
        }

        // ── ACCEPT ────────────────────────────────────────────────────────────
        IORING_OP_ACCEPT => {
            crate::net::socket::sys_accept(fd, addr, off as usize)
        }

        // ── CONNECT ───────────────────────────────────────────────────────────
        IORING_OP_CONNECT => {
            crate::net::socket::sys_connect(fd, addr, len as u32)
        }

        // ── TIMEOUT ───────────────────────────────────────────────────────────
        // addr points to a struct __kernel_timespec { tv_sec, tv_nsec }.
        IORING_OP_TIMEOUT => {
            crate::proc::nanosleep::sys_nanosleep(addr, 0)
        }
        IORING_OP_TIMEOUT_REMOVE | IORING_OP_LINK_TIMEOUT
        | IORING_OP_ASYNC_CANCEL => {
            // In synchronous mode there are no inflight ops to cancel.
            0
        }

        // ── FADVISE ───────────────────────────────────────────────────────────
        IORING_OP_FADVISE => 0,  // hint only; no-op is correct

        // ── MADVISE ───────────────────────────────────────────────────────────
        IORING_OP_MADVISE => {
            crate::mm::mmap::sys_madvise(addr, len, flags as i32)
        }

        // ── OPENAT2 ───────────────────────────────────────────────────────────
        IORING_OP_OPENAT2 => {
            // addr = path, off = open_how VA, len = sizeof(open_how)
            crate::syscall::sys_openat2_impl(sqe.fd, addr, off as usize, len)
        }

        // ── EPOLL_CTL ─────────────────────────────────────────────────────────
        IORING_OP_EPOLL_CTL => {
            // fd = epfd, addr = event VA, len = op, off = target fd
            crate::fs::poll::sys_epoll_ctl(fd, flags as i32, off as i32, addr)
        }

        // ── SPLICE ────────────────────────────────────────────────────────────
        IORING_OP_SPLICE => {
            // fd = fd_out, splice_fd_in = fd_in, addr = off_in, off = off_out
            let fd_in  = sqe.splice_fd_in as usize;
            let off_in = addr as i64;
            let off_out = off as i64;
            crate::fs::splice::sys_splice(fd_in, off_in, fd, off_out, len, flags)
        }

        // ── PROVIDE_BUFFERS / REMOVE_BUFFERS ─────────────────────────────────
        IORING_OP_PROVIDE_BUFFERS => {
            // addr = base VA, len = buf size, fd = nr_bufs, buf_index = bgid
            provide_buffers(ring_idx, addr, len, sqe.fd as usize, sqe.buf_index as usize)
        }
        IORING_OP_REMOVE_BUFFERS => {
            remove_buffers(ring_idx, sqe.fd as usize, sqe.buf_index as usize)
        }

        _ => -95, // EOPNOTSUPP
    };

    (res as i32, 0)
}

// ── Fixed-buffer helpers ──────────────────────────────────────────────────────

/// Resolve a registered-buffer index to a kernel-virtual address.
fn resolve_fixed_buf(ring_idx: usize, buf_index: usize, len: usize) -> Option<usize> {
    crate::io_uring::ring::with_ring(ring_idx, |ring| {
        let (va, sz) = *ring.reg_bufs.get(buf_index)?;
        if len > sz { return None; }
        Some(va)
    }).flatten()
}

/// Register `nr` buffers of size `buf_len` each starting at `base_va`.
fn provide_buffers(ring_idx: usize, base_va: usize, buf_len: usize,
                   nr: usize, _bgid: usize) -> isize {
    crate::io_uring::ring::with_ring_mut(ring_idx, |ring| {
        for i in 0..nr {
            ring.reg_bufs.push((base_va + i * buf_len, buf_len));
        }
        0isize
    }).unwrap_or(-9)
}

fn remove_buffers(ring_idx: usize, nr: usize, _bgid: usize) -> isize {
    crate::io_uring::ring::with_ring_mut(ring_idx, |ring| {
        let to_remove = nr.min(ring.reg_bufs.len());
        let new_len = ring.reg_bufs.len().saturating_sub(to_remove);
        ring.reg_bufs.truncate(new_len);
        to_remove as isize
    }).unwrap_or(0)
}
