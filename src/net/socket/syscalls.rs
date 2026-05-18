extern crate alloc;
use crate::uaccess::{copy_from_user, copy_to_user};
use super::SOCKETS;

pub fn sys_sendmsg(sockfd: usize, msg_uptr: usize, _flags: u32) -> isize {
    crate::net::socket::core::sys_sendto_inner(sockfd, msg_uptr, 0)
}

pub fn sys_recvmsg(sockfd: usize, msg_uptr: usize, _flags: u32) -> isize {
    crate::net::socket::core::sys_recvfrom_inner(sockfd, msg_uptr, 0)
}

pub fn sys_socketpair(domain: u32, ty: u32, _proto: u32, sv: usize) -> isize {
    use super::buffer::{UnixPipe, SharedPipe};
    use alloc::sync::Arc;
    use spin::Mutex;
    let pipe = Arc::new(Mutex::new(UnixPipe::new()));
    let fd0  = super::alloc_slot(super::Socket::unix_stream(
        Arc::clone(&pipe), false
    ));
    let fd1  = super::alloc_slot(super::Socket::unix_stream(
        Arc::clone(&pipe), true
    ));
    let (fd0, fd1) = match (fd0, fd1) { (Some(a), Some(b)) => (a, b), _ => return -12 };
    let arr = [(fd0 as u32).to_ne_bytes(), (fd1 as u32).to_ne_bytes()];
    copy_to_user(sv,     &arr[0]);
    copy_to_user(sv + 4, &arr[1]);
    0
}

pub fn sys_close_socket(fd: usize) -> bool {
    let mut socks = SOCKETS.lock();
    if let Some(slot) = socks.get_mut(fd) {
        if slot.is_some() { *slot = None; return true; }
    }
    false
}
