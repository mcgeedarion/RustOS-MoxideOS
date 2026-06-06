use super::core::SOCKETS;
use super::types::{
    SocketState, IPPROTO_TCP, SHUT_RD, SHUT_RDWR, SHUT_WR, SOL_SOCKET, SO_ERROR, SO_KEEPALIVE,
    SO_REUSEADDR,
};
use crate::net::tcp;
use crate::uaccess::{copy_from_user, copy_to_user};

pub fn sys_setsockopt(
    fd: usize,
    level: u32,
    optname: u32,
    optval_va: usize,
    _optlen: u32,
) -> isize {
    let mut sockets = SOCKETS.lock();
    let Some(Some(sock)) = sockets.get_mut(fd) else {
        return -9;
    };
    let mut val = [0u8; 4];
    copy_from_user(optval_va, &mut val);
    let v = u32::from_ne_bytes(val);
    match (level, optname) {
        (SOL_SOCKET, SO_REUSEADDR) => {
            sock.reuse_addr = v != 0;
        },
        (SOL_SOCKET, SO_KEEPALIVE) => {
            sock.keepalive = v != 0;
            if let Some(id) = sock.tcp_id {
                drop(sockets);
                tcp::set_keepalive(id, v != 0);
                return 0;
            }
        },
        (IPPROTO_TCP, 1) => {
            // TCP_NODELAY
            if let Some(id) = sock.tcp_id {
                drop(sockets);
                tcp::set_nodelay(id, v != 0);
                return 0;
            }
        },
        (IPPROTO_TCP, 4) => {
            // TCP_KEEPIDLE
            if let Some(id) = sock.tcp_id {
                let secs = v;
                drop(sockets);
                tcp::set_keepidle(id, secs);
                return 0;
            }
        },
        _ => {},
    }
    0
}

pub fn sys_getsockopt(
    fd: usize,
    level: u32,
    optname: u32,
    optval_va: usize,
    optlen_va: usize,
) -> isize {
    let sockets = SOCKETS.lock();
    let Some(Some(sock)) = sockets.get(fd) else {
        return -9;
    };
    let mut out = 0u32;
    match (level, optname) {
        (SOL_SOCKET, SO_REUSEADDR) => {
            out = sock.reuse_addr as u32;
        },
        (SOL_SOCKET, SO_KEEPALIVE) => {
            out = sock.keepalive as u32;
        },
        (SOL_SOCKET, SO_ERROR) => {
            out = sock.so_error as u32;
        },
        (IPPROTO_TCP, 1) => {
            if let Some(id) = sock.tcp_id {
                drop(sockets);
                out = tcp::get_nodelay(id) as u32;
            }
        },
        _ => {},
    }
    drop(sockets);
    copy_to_user(optval_va, &out.to_ne_bytes());
    let len: u32 = 4;
    copy_to_user(optlen_va, &len.to_ne_bytes());
    0
}

pub fn sys_shutdown(fd: usize, how: u32) -> isize {
    let mut sockets = SOCKETS.lock();
    let Some(Some(sock)) = sockets.get_mut(fd) else {
        return -9;
    };
    match how {
        SHUT_RD | SHUT_WR | SHUT_RDWR => {
            if let Some(id) = sock.tcp_id {
                drop(sockets);
                tcp::shutdown(id, how);
                return 0;
            }
            if let Some(conn) = &sock.unix_conn {
                if how == SHUT_WR || how == SHUT_RDWR {
                    conn.close_tx();
                }
            }
            sock.state = SocketState::Closed;
        },
        _ => return -22,
    }
    0
}
