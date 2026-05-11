//! Extra poll helpers consumed by io_uring.
//!
//! `poll_fd_once(fd, events)` performs a single non-blocking readiness check
//! on one fd, returning the ready event mask (0 = not ready).
//! It is a thin wrapper around `fd_ready` from poll.rs, exposed here so
//! io_uring::ops can call it without importing the full poll module.

pub fn poll_fd_once(fd: usize, events: u16) -> u32 {
    crate::fs::poll::fd_ready(fd, events as u32)
}
