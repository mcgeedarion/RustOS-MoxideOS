// src/io_uring/ops/write.rs

use crate::io_uring::{cqe::errno, sqe::Sqe};

/// Synchronous kernel-side handler for IORING_OP_WRITE.
pub fn handle(sqe: &Sqe) -> i32 {
    let fd = sqe.fd;
    let buf_va = sqe.addr;
    let len = sqe.len as usize;
    let offset = sqe.off;

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
        fd,
        buf_va,
        len,
        offset,
        sqe.user_data
    );

    // Core write dispatch now routes through shared VFS/io syscalls.
    let _ = offset; // positional write support is wired via IORING_OP_WRITEV path later.
    crate::fs::io_syscalls::sys_write(fd as usize, buf_va as usize, len) as i32
}

use crate::io_uring::{self as ring, IoUringError};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// Async wrapper around IORING_OP_WRITE.
pub struct IoWrite<'a> {
    fd: i32,
    buf: &'a [u8],
    offset: u64,
    token: u64,
    submitted: bool,
}

impl<'a> IoWrite<'a> {
    pub fn new(fd: i32, buf: &'a [u8], offset: u64, token: u64) -> Self {
        IoWrite {
            fd,
            buf,
            offset,
            token,
            submitted: false,
        }
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
