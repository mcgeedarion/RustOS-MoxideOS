// src/io_uring/ops/connect.rs
//
// IORING_OP_CONNECT handler.
//
// Initiates a connection on socket `sqe.fd` to the address described by the
// sockaddr at virtual address `sqe.addr` (length `sqe.len`).
//
// CQE result:
//   res == 0  → connected (or connection in progress for non-blocking sockets)
//   res <  0  → negated errno
//     -EINPROGRESS (-115): non-blocking connect is in flight (poll/epoll to complete)
//     -ECONNREFUSED (-111): remote refused
//     -ETIMEDOUT   (-110): connection timed out
//     -EADDRINUSE  (-98):  local address already in use

use crate::io_uring::{cqe::errno, sqe::Sqe};

/// Synchronous kernel-side handler for IORING_OP_CONNECT.
pub fn handle(sqe: &Sqe) -> i32 {
    let sock_fd   = sqe.fd;
    let addr_va   = sqe.addr;
    let addrlen   = sqe.len;

    // ── Validate ─────────────────────────────────────────────────────────────

    if sock_fd < 0 {
        log::warn!("[io_uring::connect] invalid sock_fd={}", sock_fd);
        return errno::E_BADF;
    }
    if addr_va == 0 {
        log::warn!("[io_uring::connect] null sockaddr pointer");
        return errno::E_INVAL;
    }
    // Minimum sockaddr size: sa_family (u16) + at least 2 bytes of address.
    if addrlen < 4 {
        log::warn!("[io_uring::connect] addrlen={} too small", addrlen);
        return errno::E_INVAL;
    }

    log::trace!(
        "[io_uring::connect] sock_fd={} addr={:#x} addrlen={} token={:#x}",
        sock_fd, addr_va, addrlen, sqe.user_data
    );

    // ── Parse the sockaddr family ─────────────────────────────────────────────

    // SAFETY: addr_va validated non-null and addrlen >= 4 above.
    let sa_family = unsafe { *(addr_va as *const u16) };

    match sa_family {
        AF_INET  => handle_connect_v4(sock_fd, addr_va, addrlen),
        AF_INET6 => handle_connect_v6(sock_fd, addr_va, addrlen),
        AF_UNIX  => handle_connect_unix(sock_fd, addr_va, addrlen),
        other => {
            log::warn!("[io_uring::connect] unsupported address family {}", other);
            errno::E_INVAL
        }
    }
}

// ── Address family constants (Linux ABI) ──────────────────────────────────────
const AF_UNIX:  u16 = 1;
const AF_INET:  u16 = 2;
const AF_INET6: u16 = 10;

// ── sockaddr_in layout ────────────────────────────────────────────────────────
#[repr(C)]
struct SockaddrIn {
    sin_family: u16,
    sin_port:   u16, // network byte order
    sin_addr:   u32, // IPv4 in network byte order
    _pad:       [u8; 8],
}

// ── sockaddr_in6 layout ───────────────────────────────────────────────────────
#[repr(C)]
struct SockaddrIn6 {
    sin6_family:   u16,
    sin6_port:     u16,
    sin6_flowinfo: u32,
    sin6_addr:     [u8; 16],
    sin6_scope_id: u32,
}

fn handle_connect_v4(sock_fd: i32, addr_va: u64, addrlen: u32) -> i32 {
    if addrlen < core::mem::size_of::<SockaddrIn>() as u32 {
        return errno::E_INVAL;
    }
    // SAFETY: validated above.
    let addr = unsafe { &*(addr_va as *const SockaddrIn) };
    let ip   = addr.sin_addr.to_be_bytes(); // convert back from NBO
    let port = u16::from_be(addr.sin_port);

    log::debug!(
        "[io_uring::connect] TCP/IPv4 sock_fd={} dst={}.{}.{}.{}:{} (stub)",
        sock_fd, ip[0], ip[1], ip[2], ip[3], port
    );

    // TODO: call net::tcp::connect(sock_fd, ip, port)
    // For non-blocking sockets return -EINPROGRESS; the caller registers a
    // poll completion and retries.

    // Stub: simulate a successful immediate connect.
    0
}

fn handle_connect_v6(sock_fd: i32, addr_va: u64, addrlen: u32) -> i32 {
    if addrlen < core::mem::size_of::<SockaddrIn6>() as u32 {
        return errno::E_INVAL;
    }
    let addr = unsafe { &*(addr_va as *const SockaddrIn6) };
    let port = u16::from_be(addr.sin6_port);

    log::debug!(
        "[io_uring::connect] TCP/IPv6 sock_fd={} port={} (stub)",
        sock_fd, port
    );

    // TODO: call net::tcp::connect_v6(sock_fd, &addr.sin6_addr, port)
    0
}

fn handle_connect_unix(sock_fd: i32, addr_va: u64, addrlen: u32) -> i32 {
    // sockaddr_un: sa_family (u16) + sun_path (up to 108 bytes, NUL-terminated).
    if addrlen < 3 {
        return errno::E_INVAL;
    }
    let path_len = (addrlen as usize).saturating_sub(2);
    let path_ptr = (addr_va + 2) as *const u8;
    // SAFETY: addrlen bounds-checked, ptr is non-null.
    let path_bytes = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
    let path_str = core::str::from_utf8(path_bytes).unwrap_or("<invalid utf8>");

    log::debug!(
        "[io_uring::connect] UNIX sock_fd={} path={:?} (stub)",
        sock_fd, path_str
    );

    // TODO: call vfs::socket::connect_unix(sock_fd, path)
    0
}

// ── Future-layer wrapper ──────────────────────────────────────────────────────

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use crate::io_uring::{self as ring, IoUringError};

/// Async wrapper around IORING_OP_CONNECT.
///
/// Suspends the calling task until the connection is established or fails.
///
/// # Example
/// ```rust,no_run
/// let addr = SockaddrIn { sin_family: AF_INET, sin_port: 80u16.to_be(), sin_addr: ... };
/// IoConnect::new(sock_fd, &addr as *const _ as u64, size_of::<SockaddrIn>() as u32, token)
///     .await?;
/// ```
pub struct IoConnect {
    fd: i32,
    addr_va: u64,
    addrlen: u32,
    token: u64,
    submitted: bool,
}

impl IoConnect {
    pub fn new(fd: i32, addr_va: u64, addrlen: u32, token: u64) -> Self {
        IoConnect { fd, addr_va, addrlen, token, submitted: false }
    }
}

impl Future for IoConnect {
    type Output = Result<(), IoUringError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        ring::register_waker(self.token, cx.waker().clone());

        if !self.submitted {
            let sqe = crate::io_uring::sqe::Sqe::connect(
                self.fd,
                self.addr_va,
                self.addrlen,
                self.token,
            );
            ring::submit(sqe)?;
            self.submitted = true;
        }

        Poll::Pending
    }
}
