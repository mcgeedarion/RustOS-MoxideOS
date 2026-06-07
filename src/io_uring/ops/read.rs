// src/io_uring/ops/read.rs

use crate::io_uring::{cqe::errno, sqe::Sqe};

/// Synchronous kernel-side handler for IORING_OP_READ.
pub fn handle(sqe: &Sqe) -> i32 {
    let fd = sqe.fd;
    let buf_va = sqe.addr;
    let len = sqe.len as usize;
    let offset = sqe.off;

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
        fd,
        buf_va,
        len,
        offset,
        sqe.user_data
    );

    // Core read dispatch now routes through the shared VFS/io path so io_uring
    // read semantics match synchronous read(2).
    let _ = offset; // positional read support is wired via IORING_OP_READV path later.
    crate::fs::io_syscalls::sys_read(fd as usize, buf_va as usize, len) as i32
}

// Callers should use `IoRead` instead of submitting SQEs directly.
// It encapsulates the submit → poll → wake cycle.

use crate::io_uring::{self as ring, IoUringError};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Async wrapper around IORING_OP_READ.
pub struct IoRead<'a> {
    fd: i32,
    buf: &'a mut [u8],
    offset: u64,
    token: u64,
    submitted: bool,
}

impl<'a> IoRead<'a> {
    pub fn new(fd: i32, buf: &'a mut [u8], offset: u64, token: u64) -> Self {
        IoRead {
            fd,
            buf,
            offset,
            token,
            submitted: false,
        }
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
