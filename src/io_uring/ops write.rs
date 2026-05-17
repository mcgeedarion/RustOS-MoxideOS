// src/io_uring/ops/write.rs
//
// IORING_OP_WRITE handler.
//
// Writes up to `sqe.len` bytes from the buffer at virtual address `sqe.addr`
// to the file/socket described by `sqe.fd`, starting at file offset `sqe.off`
// (ignored for sockets/pipes).
//
// Returns the number of bytes written on success, or a negated errno on failure.

use crate::io_uring::{cqe::errno, sqe::Sqe};

/// Synchronous kernel-side handler for IORING_OP_WRITE.
pub fn handle(sqe: &Sqe) -> i32 {
    let fd     = sqe.fd;
    let buf_va = sqe.addr;
    let len    = sqe.len as usize;
    let offset = sqe.off;

    // ── Validate ─────────────────────────────────────────────────────────────

    if fd < 0 {
        log::warn!("[io_uring::write] invalid fd={}", fd);
        return errno::E_BADF;
    }
    if buf_va == 0 {
        log::warn!("[io_uring::write] null buffer pointer fd={}", fd);
        return errno::E_INVAL;
    }
    if len == 0 {
        return 0;
    }

    log::trace!(
        "[io_uring::write] fd={} buf={:#x} len={} off={} token={:#x}",
        fd, buf_va, len, offset, sqe.user_data
    );

    // ── Dispatch to appropriate driver ────────────────────────────────────────

    // TODO: look up fd in fd table and dispatch:
    //   match fd_table::get(fd) {
    //       FdKind::File(inode) => vfs::write(inode, buf_va, len, offset),
    //       FdKind::Socket(sock) => net::send(sock, buf_va, len),
    //       FdKind::Pipe(pipe)   => pipe::write(pipe, buf_va, len),
    //       None                 => errno::E_BADF,
    //   }

    perform_write_stub(fd, buf_va, len, offset)
}

fn perform_write_stub(fd: i32, buf_va: u64, len: usize, _offset: u64) -> i32 {
    // SAFETY: caller validates buf_va is a readable kernel VA of `len` bytes.
    let buf = unsafe { core::slice::from_raw_parts(buf_va as *const u8, len) };

    // In a real kernel we'd push `buf` to the fd's backing resource.
    // Here we just log the first few bytes as a smoke-test.
    let preview_len = core::cmp::min(buf.len(), 16);
    log::debug!(
        "[io_uring::write] stub write {} bytes to fd={}, preview={:02x?}",
        len,
        fd,
        &buf[..preview_len]
    );

    // Report all bytes as "written".
    len as i32
}

// ── Future-layer wrapper ──────────────────────────────────────────────────────

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use crate::io_uring::{self as ring, IoUringError};

/// Async wrapper around IORING_OP_WRITE.
///
/// # Example
/// ```rust,no_run
/// let n = IoWrite::new(fd, b"hello\n", 0, token).await?;
/// ```
pub struct IoWrite<'a> {
    fd: i32,
    buf: &'a [u8],
    offset: u64,
    token: u64,
    submitted: bool,
}

impl<'a> IoWrite<'a> {
    pub fn new(fd: i32, buf: &'a [u8], offset: u64, token: u64) -> Self {
        IoWrite { fd, buf, offset, token, submitted: false }
    }
}

impl<'a> Future for IoWrite<'a> {
    type Output = Result<usize, IoUringError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        ring::register_waker(self.token, cx.waker().clone());

        if !self.submitted {
            let sqe = crate::io_uring::sqe::Sqe::write(
                self.fd,
                self.buf.as_ptr() as u64,
                self.buf.len() as u32,
                self.offset,
                self.token,
            );
            ring::submit(sqe)?;
            self.submitted = true;
        }

        Poll::Pending
    }
}
