extern crate alloc;
use super::address::{read_sockaddr_in, write_sockaddr_in};
use super::buffer::UnixConn;
use super::core::SOCKETS;
use super::types::{SocketState, AF_UNIX, MSG_DONTWAIT, SOCK_STREAM};
use crate::uaccess::{copy_from_user, copy_to_user};
use alloc::vec::Vec;

pub fn sys_sendmsg(fd: usize, msg_va: usize, _flags: u32) -> isize {
    // Read msghdr: {*name, namelen, *iov, iovlen, ...}
    let mut hdr = [0u8; 48];
    copy_from_user(msg_va, &mut hdr);
    let iov_ptr = usize::from_ne_bytes(hdr[16..24].try_into().unwrap_or([0; 8]));
    let iov_len = usize::from_ne_bytes(hdr[24..32].try_into().unwrap_or([0; 8]));
    let mut total = 0isize;
    for i in 0..iov_len {
        let mut iov = [0u8; 16];
        copy_from_user(iov_ptr + i * 16, &mut iov);
        let base = usize::from_ne_bytes(iov[0..8].try_into().unwrap_or([0; 8]));
        let len = usize::from_ne_bytes(iov[8..16].try_into().unwrap_or([0; 8]));
        let mut buf = alloc::vec![0u8; len];
        copy_from_user(base, &mut buf);
        let r = super::poll::socket_write(fd, &buf);
        if r < 0 {
            return r;
        }
        total += r;
    }
    total
}

pub fn sys_recvmsg(fd: usize, msg_va: usize, flags: u32) -> isize {
    let mut hdr = [0u8; 48];
    copy_from_user(msg_va, &mut hdr);
    let iov_ptr = usize::from_ne_bytes(hdr[16..24].try_into().unwrap_or([0; 8]));
    let iov_len = usize::from_ne_bytes(hdr[24..32].try_into().unwrap_or([0; 8]));
    let mut total = 0isize;
    for i in 0..iov_len {
        let mut iov = [0u8; 16];
        copy_from_user(iov_ptr + i * 16, &mut iov);
        let base = usize::from_ne_bytes(iov[0..8].try_into().unwrap_or([0; 8]));
        let len = usize::from_ne_bytes(iov[8..16].try_into().unwrap_or([0; 8]));
        let mut buf = alloc::vec![0u8; len];
        let r = super::poll::socket_read(fd, &mut buf, flags);
        if r < 0 {
            return if total > 0 { total } else { r };
        }
        copy_to_user(base, &buf[..r as usize]);
        total += r;
    }
    total
}

pub fn sys_socketpair(domain: u16, kind: u16, _proto: u32, sv_va: usize) -> isize {
    if domain != AF_UNIX || kind != SOCK_STREAM {
        return -22;
    }
    let (ca, cb) = UnixConn::new_pair();
    let (fa, fb) = (alloc_socket_pair_slot(ca), alloc_socket_pair_slot(cb));
    if fa < 0 || fb < 0 {
        return -24;
    }
    let pair = [(fa as usize) as u32, (fb as usize) as u32];
    copy_to_user(sv_va, unsafe {
        core::slice::from_raw_parts(pair.as_ptr() as *const u8, 8)
    });
    0
}

fn alloc_socket_pair_slot(conn: UnixConn) -> isize {
    use alloc::sync::Arc;
    let mut sockets = SOCKETS.lock();
    for (i, slot) in sockets.iter_mut().enumerate() {
        if slot.is_none() {
            let mut s = super::core::new_socket(AF_UNIX, SOCK_STREAM, 0);
            s.state = SocketState::Connected;
            s.unix_conn = Some(Arc::new(conn));
            *slot = Some(s);
            return i as isize;
        }
    }
    -24
}

pub fn socket_close(fd: usize) {
    let mut sockets = SOCKETS.lock();
    if let Some(Some(sock)) = sockets.get_mut(fd) {
        if let Some(conn) = sock.unix_conn.take() {
            conn.close_tx();
        }
        if let Some(id) = sock.tcp_id.take() {
            crate::net::tcp::close(id);
        }
    }
    if let Some(slot) = sockets.get_mut(fd) {
        *slot = None;
    }
}
