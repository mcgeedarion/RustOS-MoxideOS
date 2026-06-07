extern crate alloc;
use super::address::{
    next_ephemeral, read_sockaddr_in, read_sockaddr_in6, write_sockaddr_in, write_sockaddr_in6,
};
use super::buffer::{UnixConn, UnixListener};
use super::types::*;
use super::unix::stream::{unix_accept, unix_bind, unix_connect, unix_listen};
use crate::net::{ip, tcp};
use crate::uaccess::{copy_from_user, copy_to_user, copy_to_user_value};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

pub static SOCKETS: Mutex<[Option<Socket>; MAX_SOCKETS]> =
    Mutex::new([const { None }; MAX_SOCKETS]);

pub fn new_socket(domain: u16, kind: u16, protocol: u32) -> Socket {
    Socket {
        domain,
        kind,
        protocol,
        state: SocketState::Unbound,
        local: None,
        peer: None,
        tcp_id: None,
        udp_rx: alloc::collections::VecDeque::new(),
        nonblock: false,
        reuse_addr: false,
        keepalive: false,
        unix_conn: None,
        unix_listener: None,
        so_error: 0,
        refs: 1,
    }
}

pub fn alloc_slot() -> Option<usize> {
    let mut sockets = SOCKETS.lock();
    sockets.iter().position(|s| s.is_none())
}

pub fn sys_socket(domain: u16, kind: u16, protocol: u32) -> isize {
    let mut sockets = SOCKETS.lock();
    for (i, slot) in sockets.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(new_socket(domain, kind, protocol));
            return i as isize;
        }
    }
    -24 // EMFILE
}

pub fn sys_bind(fd: usize, addr_va: usize, _addrlen: u32) -> isize {
    let domain = {
        let s = SOCKETS.lock();
        s.get(fd)
            .and_then(|x| x.as_ref())
            .map(|x| x.domain)
            .unwrap_or(0)
    };
    if domain == AF_UNIX {
        let mut path_buf = [0u8; 108];
        copy_from_user(addr_va + 2, &mut path_buf);
        let end = path_buf.iter().position(|&b| b == 0).unwrap_or(108);
        let path = String::from_utf8_lossy(&path_buf[..end]).into_owned();
        return unix_bind(fd, path);
    }
    if domain == AF_INET6 {
        let Some((port, ip6, _, _)) = super::address::read_sockaddr_in6(addr_va) else {
            return -22;
        };
        let port = if port == 0 { next_ephemeral() } else { port };
        let mut sockets = SOCKETS.lock();
        if let Some(Some(s)) = sockets.get_mut(fd) {
            s.local = Some(SockAddr::V6 {
                ip: ip6,
                port,
                flowinfo: 0,
                scope_id: 0,
            });
            s.state = SocketState::Bound;
        }
        return 0;
    }
    let Some((port, ip)) = read_sockaddr_in(addr_va) else {
        return -22;
    };
    let port = if port == 0 { next_ephemeral() } else { port };
    let mut sockets = SOCKETS.lock();
    if let Some(Some(s)) = sockets.get_mut(fd) {
        s.local = Some(SockAddr::V4 { ip, port });
        s.state = SocketState::Bound;
    }
    0
}

pub fn sys_listen(fd: usize, backlog: i32) -> isize {
    let domain = {
        let s = SOCKETS.lock();
        s.get(fd)
            .and_then(|x| x.as_ref())
            .map(|x| x.domain)
            .unwrap_or(0)
    };
    if domain == AF_UNIX {
        return unix_listen(fd, backlog as usize);
    }
    let local_port = {
        let s = SOCKETS.lock();
        match s
            .get(fd)
            .and_then(|x| x.as_ref())
            .and_then(|x| x.local.as_ref())
        {
            Some(SockAddr::V4 { port, .. }) => *port,
            _ => return -22,
        }
    };
    tcp::listen(fd, local_port);
    let mut sockets = SOCKETS.lock();
    if let Some(Some(s)) = sockets.get_mut(fd) {
        s.state = SocketState::Listening;
    }
    0
}

pub fn sys_accept(fd: usize, addr_va: usize, addrlen_va: usize) -> isize {
    let domain = {
        let s = SOCKETS.lock();
        s.get(fd)
            .and_then(|x| x.as_ref())
            .map(|x| x.domain)
            .unwrap_or(0)
    };
    if domain == AF_UNIX {
        return unix_accept(fd);
    }
    let new_id = tcp::accept(fd);
    if new_id < 0 {
        return new_id;
    }
    let (peer_ip, peer_port) = tcp::peer_addr(new_id as u64).unwrap_or((0, 0));
    if addr_va != 0 {
        write_sockaddr_in(addr_va, peer_ip, peer_port);
    }
    if addrlen_va != 0 {
        let sz: u32 = 16;
        crate::uaccess::copy_to_user_value(addrlen_va, &sz.to_ne_bytes());
    }
    let mut sockets = SOCKETS.lock();
    for (i, slot) in sockets.iter_mut().enumerate() {
        if slot.is_none() {
            let mut s = new_socket(AF_INET, SOCK_STREAM, 0);
            s.state = SocketState::Connected;
            s.tcp_id = Some(new_id as u64);
            s.peer = Some(SockAddr::V4 {
                ip: peer_ip,
                port: peer_port,
            });
            *slot = Some(s);
            return i as isize;
        }
    }
    -24
}

pub fn sys_connect(fd: usize, addr_va: usize, _addrlen: u32) -> isize {
    let domain = {
        let s = SOCKETS.lock();
        s.get(fd)
            .and_then(|x| x.as_ref())
            .map(|x| x.domain)
            .unwrap_or(0)
    };
    if domain == AF_UNIX {
        let mut path_buf = [0u8; 108];
        copy_from_user(addr_va + 2, &mut path_buf);
        let end = path_buf.iter().position(|&b| b == 0).unwrap_or(108);
        let path = String::from_utf8_lossy(&path_buf[..end]).into_owned();
        return unix_connect(fd, &path);
    }
    let peer = if domain == AF_INET6 {
        let Some((port, ip6, flowinfo, scope_id)) = super::address::read_sockaddr_in6(addr_va)
        else {
            return -22;
        };
        SockAddr::V6 {
            ip: ip6,
            port,
            flowinfo,
            scope_id,
        }
    } else {
        let Some((port, ip)) = read_sockaddr_in(addr_va) else {
            return -22;
        };
        SockAddr::V4 { ip, port }
    };
    super::tcp::connect::tcp_connect(fd, peer)
}

pub fn sys_getsockname(fd: usize, addr_va: usize, addrlen_va: usize) -> isize {
    let sockets = SOCKETS.lock();
    let Some(Some(s)) = sockets.get(fd) else {
        return -9;
    };
    match &s.local {
        Some(SockAddr::V4 { ip, port }) => {
            drop(sockets);
            write_sockaddr_in(addr_va, *ip, *port);
            if addrlen_va != 0 {
                let sz: u32 = 16;
                crate::uaccess::copy_to_user_value(addrlen_va, &sz.to_ne_bytes());
            }
        },
        Some(SockAddr::V6 {
            ip,
            port,
            flowinfo,
            scope_id,
        }) => {
            drop(sockets);
            write_sockaddr_in6(addr_va, ip, *port, *flowinfo, *scope_id);
            if addrlen_va != 0 {
                let sz: u32 = 28;
                crate::uaccess::copy_to_user_value(addrlen_va, &sz.to_ne_bytes());
            }
        },
        _ => {},
    }
    0
}

pub fn sys_getpeername(fd: usize, addr_va: usize, addrlen_va: usize) -> isize {
    let sockets = SOCKETS.lock();
    let Some(Some(s)) = sockets.get(fd) else {
        return -9;
    };
    match &s.peer {
        Some(SockAddr::V4 { ip, port }) => {
            drop(sockets);
            write_sockaddr_in(addr_va, *ip, *port);
            if addrlen_va != 0 {
                let sz: u32 = 16;
                crate::uaccess::copy_to_user_value(addrlen_va, &sz.to_ne_bytes());
            }
        },
        Some(SockAddr::V6 {
            ip,
            port,
            flowinfo,
            scope_id,
        }) => {
            drop(sockets);
            write_sockaddr_in6(addr_va, ip, *port, *flowinfo, *scope_id);
            if addrlen_va != 0 {
                let sz: u32 = 28;
                crate::uaccess::copy_to_user_value(addrlen_va, &sz.to_ne_bytes());
            }
        },
        _ => {},
    }
    0
}
