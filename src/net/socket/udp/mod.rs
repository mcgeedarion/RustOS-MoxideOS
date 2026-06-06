extern crate alloc;
use super::address::{next_ephemeral, read_sockaddr_in, write_sockaddr_in};
use super::core::SOCKETS;
use super::types::{SockAddr, SocketState, AF_INET, SOCK_DGRAM};
use crate::net::{dhcp, dns, ip, udp};
use crate::uaccess::{copy_from_user, copy_to_user};
use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub fn demux_udp(src_ip: u32, src_port: u16, dst_port: u16, data: &[u8]) {
    let mut sockets = SOCKETS.lock();
    for slot in sockets.iter_mut() {
        let Some(s) = slot else {
            continue;
        };
        if s.domain != AF_INET || s.kind != SOCK_DGRAM {
            continue;
        }
        let bound_port = match &s.local {
            Some(SockAddr::V4 { port, .. }) => *port,
            _ => continue,
        };
        if bound_port == dst_port {
            s.udp_rx.push_back((src_ip, src_port, data.to_vec()));
            return;
        }
    }
}

pub fn sys_sendto(
    fd: usize,
    buf_va: usize,
    len: usize,
    _flags: u32,
    dest_va: usize,
    _dest_len: u32,
) -> isize {
    let mut buf = alloc::vec![0u8; len];
    copy_from_user(buf_va, &mut buf);

    let (dst_ip, dst_port) = {
        let sockets = SOCKETS.lock();
        let Some(Some(s)) = sockets.get(fd) else {
            return -9;
        };
        match s.peer {
            Some(SockAddr::V4 { ip, port }) => (ip, port),
            _ => {
                drop(sockets);
                read_sockaddr_in(dest_va).unwrap_or((0, 0))
            },
        }
    };

    if dst_port == 53 {
        if let Some(resp) = dns::resolve_raw(&buf) {
            let mut sockets = SOCKETS.lock();
            if let Some(Some(s)) = sockets.get_mut(fd) {
                s.udp_rx.push_back((dst_ip, dst_port, resp));
            }
            return len as isize;
        }
    }

    let src_port = {
        let sockets = SOCKETS.lock();
        match sockets
            .get(fd)
            .and_then(|s| s.as_ref())
            .and_then(|s| s.local.as_ref())
        {
            Some(SockAddr::V4 { port, .. }) => *port,
            _ => next_ephemeral(),
        }
    };

    udp::send(src_port, dst_ip, dst_port, &buf);
    len as isize
}

pub fn sys_recvfrom(
    fd: usize,
    buf_va: usize,
    len: usize,
    _flags: u32,
    src_addr_va: usize,
    src_len_va: usize,
) -> isize {
    let entry = {
        let mut sockets = SOCKETS.lock();
        let Some(Some(s)) = sockets.get_mut(fd) else {
            return -9;
        };
        s.udp_rx.pop_front()
    };
    let Some((src_ip, src_port, data)) = entry else {
        return -11;
    };
    let n = data.len().min(len);
    let mut out = alloc::vec![0u8; n];
    out.copy_from_slice(&data[..n]);
    copy_to_user(buf_va, &out);
    if src_addr_va != 0 {
        write_sockaddr_in(src_addr_va, src_ip, src_port);
    }
    if src_len_va != 0 {
        let sz: u32 = 16;
        copy_to_user(src_len_va, &sz.to_ne_bytes());
    }
    n as isize
}

pub fn sys_sendto_dhcp(fd: usize, buf: &[u8]) -> isize {
    let src_port = {
        let sockets = SOCKETS.lock();
        match sockets
            .get(fd)
            .and_then(|s| s.as_ref())
            .and_then(|s| s.local.as_ref())
        {
            Some(SockAddr::V4 { port, .. }) => *port,
            _ => 68,
        }
    };
    udp::send(src_port, 0xFFFFFFFF, 67, buf);
    buf.len() as isize
}

pub fn inject_dhcp_reply(fd: usize, data: Vec<u8>) {
    let mut sockets = SOCKETS.lock();
    if let Some(Some(s)) = sockets.get_mut(fd) {
        s.udp_rx.push_back((0xFFFFFFFF, 67, data));
    }
}
