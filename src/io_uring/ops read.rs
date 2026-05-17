// src/io_uring/ops/read.rs
//
// IORING_OP_READ handler.
//
// Reads up to `sqe.len` bytes from the file/socket described by `sqe.fd`
// into the buffer at virtual address `sqe.addr`, starting at file offset
// `sqe.off` (ignored for sockets/pipes).
//
// Returns the number of bytes read on success, or a negated errno on failure.
//
// This is intentionally written as a *synchronous* stub that the SQ dispatch
// loop calls directly.  Actual async suspension is handled at the Future layer
// (see the `IoRead` future below) — the opcode handler here does the real work
// (or queues it to a driver), then the Future polls / re-polls using the CQE
// result stored in the waker table.

use crate::io_uring::{cqe::errno, sqe::Sqe};

/// Synchronous kernel-side handler for IORING_OP_READ.
pub fn handle(sqe: &Sqe) -> i32 {
    let fd     = sqe.fd;
    let buf_va = sqe.addr;
    let len    = sqe.len as usize;
    let offset = sqe.off;

    // ── Validate ─────────────────────────────────────────────────────────────

    if fd < 0 {
        log::warn!("[io_uring::read] invalid fd={}", fd);
        return errno::E_BADF;
    }
    if buf_va == 0 {
        log::warn!("[io_uring::read] null buffer pointer fd={}", fd);
        return errno::E_INVAL;
    }
    if len == 0 {
        // Zero-length read is valid and returns 0.
        return 0;
    }

    log::trace!(
        "[io_uring::read] fd={} buf={:#x} len={} off={} token={:#x}",
        fd, buf_va, len, offset, sqe.user_data
    );

    // ── Dispatch to the appropriate driver ───────────────────────────────────
    //
    // The kernel fd table will eventually map `fd` → a concrete resource
    // (VFS file, socket, pipe, …).  For now we stub each branch.

    // TODO: look up fd in the process fd table.
    //   match fd_table::get(fd) {
    //       FdKind::File(inode) => vfs::read(inode, buf_va, len, offset),
    //       FdKind::Socket(sock) => net::recv(sock, buf_va, len),
    //       FdKind::Pipe(pipe)   => pipe::read(pipe, buf_va, len),
    //       None                 => errno::E_BADF,
    //   }

    // SAFETY stub: materialise the buffer slice and zero-fill it so callers
    // get defined memory.  In production this is replaced by the VFS call.
    let n = perform_read_stub(fd, buf_va, len, offset);
    n
}

/// Placeholder implementation that simulates a successful zero-byte read on
/// any fd.  Replace with real VFS / driver calls.
fn perform_read_stub(fd: i32, buf_va: u64, len: usize, _offset: u64) -> i32 {
    // SAFETY: caller must ensure `buf_va` is a valid writable kernel VA of
    // at least `len` bytes.  We trust the SQE validation above.
    let buf = unsafe { core::slice::from_raw_parts_mut(buf_va as *mut u8, len) };
    buf.fill(0);

    log::debug!("[io_uring::read] stub read {} bytes from fd={}", len, fd);

    // Simulate EOF (0 bytes) for files, or EAGAIN for sockets.
    // Real implementation returns actual bytes transferred.
    0
}

// ── Future-layer wrapper ──────────────────────────────────────────────────────
//
// Callers should use `IoRead` instead of submitting SQEs directly.
// It encapsulates the submit → poll → wake cycle.

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use crate::io_uring::{self as ring, IoUringError};

/// Async wrapper around IORING_OP_READ.
///
/// # Example
/// ```rust,no_run
/// let mut buf = [0u8; 4096];
/// let n = IoRead::new(fd, &mut buf, 0, token).await?;
/// ```
pub struct IoRead<'a> {
    fd: i32,
    buf: &'a mut [u8],
    offset: u64,
    token: u64,
    submitted: bool,
}

impl<'a> IoRead<'a> {
    pub fn new(fd: i32, buf: &'a mut [u8], offset: u64, token: u64) -> Self {
        IoRead { fd, buf, offset, token, submitted: false }
    }
}

impl<'a> Future for IoRead<'a> {
    type Output = Result<usize, IoUringError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Register waker before (re-)submitting so we never miss a completion.
        ring::register_waker(self.token, cx.waker().clone());

        if !self.submitted {
            let sqe = crate::io_uring::sqe::Sqe::read(
                self.fd,
                self.buf.as_ptr() as u64,
                self.buf.len() as u32,
                self.offset,
                self.token,
            );
            ring::submit(sqe)?;
            self.submitted = true;
        }

        // Check the CQ for our token.
        // In a real executor this is driven by `poll_completions()` in the
        // scheduler tick; we return Pending and wait to be woken.
        Poll::Pending
    }
}
