//! Extra poll helpers consumed by io_uring.

pub fn poll_fd_once(fd: usize, events: u16) -> u32 {
    crate::fs::poll::fd_ready(fd, events as u32)
}
