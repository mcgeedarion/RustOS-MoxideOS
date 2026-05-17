// src/io_uring/ops/accept.rs
//
// IORING_OP_ACCEPT handler.
//
// Accepts an incoming connection on the listening socket `sqe.fd`.
//
// Field mapping:
//   sqe.fd      → listening socket fd
//   sqe.addr    → *mut sockaddr_storage (filled by the network stack)
//   sqe.addr3   → *mut socklen_t        (updated with actual addr length)
//   sqe.op_flags → accept4() flags (e.g. SOCK_NONBLOCK | SOCK_CLOEXEC)
//
// CQE result:
//   res >= 0 → new connected socket fd
//   res <  0 → negated errno (E_AGAIN if no connection pending)

use crate::io_uring::{cqe::errno, sqe::Sqe};

// Mirrored from Linux <sys/socket.h>
pub mod sock_flags {
    pub const SOCK_NONBLOCK: u32 = 0o0004000;
    pub const SOCK_CLOEXEC:  u32 = 0o2000000;
}

/// Synchronous kernel-side handler for IORING_OP_ACCEPT.
pub fn handle(sqe: &Sqe) -> i32 {
    let listen_fd = sqe.fd;
    let addr_va   = sqe.addr;       // *mut sockaddr_storage
    let addrlen_va = sqe.addr3;     // *mut socklen_t (u32)
    let flags     = sqe.op_flags;

    // ── Validate ─────────────────────────────────────────────────────────────────────

    if listen_fd < 0 {
        log::warn!("[io_uring::accept] invalid listen_fd={}", listen_fd);
        return errno::E_BADF;
    }

    log::trace!(
        "[io_uring::accept] listen_fd={} addr={:#x} addrlen={:#x} flags={:#x} token={:#x}",
        listen_fd, addr_va, addrlen_va, flags, sqe.user_data
    );

    // ── Dispatch to network stack ──────────────────────────────────────────────────

    // TODO: call net::accept(listen_fd, addr_va, addrlen_va, flags)
    // which should:
    //   1. Dequeue the first entry from the socket's accept queue.
    //   2. Fill *addr_va with the peer's sockaddr.
    //   3. Update *addrlen_va with the filled length.
    //   4. Allocate a new fd in the calling process's fd table.
    //   5. Return the new fd, or -EAGAIN if the accept queue is empty.

    perform_accept_stub(listen_fd, addr_va, addrlen_va, flags)
}

fn perform_accept_stub(
    listen_fd: i32,
    addr_va: u64,
    addrlen_va: u64,
    _flags: u32,
) -> i32 {
    // Simulate an empty accept queue (no pending connections).
    // The Future layer will re-submit on -EAGAIN.

    if addr_va != 0 && addrlen_va != 0 {
        // Zero out the sockaddr so callers don't read uninitialised memory.
        // A real implementation fills in AF_INET/AF_INET6 sockaddr here.
        // SAFETY: caller guarantees addr_va is a valid writable VA of at
        // least sizeof(sockaddr_storage) = 128 bytes.
        unsafe {
            core::ptr::write_bytes(addr_va as *mut u8, 0, 128);
            *(addrlen_va as *mut u32) = 0;
        }
    }

    log::debug!(
        "[io_uring::accept] stub: no connection pending on listen_fd={}",
        listen_fd
    );

    errno::E_AGAIN // would block — EAGAIN
}

// ── Future-layer wrapper ──────────────────────────────────────────────────────────────

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use crate::io_uring::{self as ring, IoUringError};

/// Async wrapper around IORING_OP_ACCEPT.
///
/// Suspends the calling task until an incoming connection is available.
///
/// # Example
/// ```rust,no_run
/// let mut peer_addr = SockaddrStorage::zeroed();
/// let mut addrlen: u32 = core::mem::size_of::<SockaddrStorage>() as u32;
/// let client_fd = IoAccept::new(listen_fd, &mut peer_addr, &mut addrlen, 0, token).await?;
/// ```
pub struct IoAccept {
    fd: i32,
    /// Virtual address of the caller-allocated sockaddr_storage buffer.
    addr_va: u64,
    /// Virtual address of the caller's socklen_t variable.
    addrlen_va: u64,
    flags: u32,
    token: u64,
    submitted: bool,
}

impl IoAccept {
    /// Create a new accept future.
    ///
    /// `addr_va` and `addrlen_va` are raw virtual addresses; they must remain
    /// valid and pinned for the lifetime of this future.
    pub fn new(
        fd: i32,
        addr_va: u64,
        addrlen_va: u64,
        flags: u32,
        token: u64,
    ) -> Self {
        IoAccept { fd, addr_va, addrlen_va, flags, token, submitted: false }
    }
}

impl Future for IoAccept {
    /// Ok(new_fd) on success.
    type Output = Result<i32, IoUringError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        ring::register_waker(self.token, cx.waker().clone());

        if !self.submitted {
            let sqe = crate::io_uring::sqe::Sqe::accept(
                self.fd,
                self.addr_va,
                self.addrlen_va,
                self.flags,
                self.token,
            );
            ring::submit(sqe)?;
            self.submitted = true;
        }

        // We return Pending here.  The scheduler's poll_completions() will
        // call wake() on our waker when the CQE arrives, which re-polls
        // this future.  On the second poll (submitted=true), the caller's
        // executor checks the CQE result — that flow is handled by a
        // higher-level combinator that wraps CQE storage.
        Poll::Pending
    }
}
