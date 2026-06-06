use super::core::SOCKETS;
use super::types::{SockAddr, SocketState, MSG_PEEK};

pub fn is_socket_fd(fd: usize) -> bool {
    SOCKETS.lock().get(fd).map_or(false, |s| s.is_some())
}

pub fn socket_poll(fd: usize) -> u32 {
    let sockets = SOCKETS.lock();
    let Some(Some(sock)) = sockets.get(fd) else {
        return 0;
    };
    let mut events = 0u32;
    // POLLIN
    let readable = match &sock.state {
        SocketState::Connected => {
            if let Some(id) = sock.tcp_id {
                crate::net::tcp::bytes_available(id) > 0
            } else if let Some(conn) = &sock.unix_conn {
                conn.is_readable()
            } else {
                !sock.udp_rx.is_empty()
            }
        },
        SocketState::Listening => {
            if let Some(ul) = &sock.unix_listener {
                !ul.lock().backlog.is_empty()
            } else {
                crate::net::tcp::has_pending_accept(fd)
            }
        },
        _ => false,
    };
    if readable {
        events |= 1;
    } // POLLIN
    if sock.state == SocketState::Connected {
        events |= 4;
    } // POLLOUT
    if sock.so_error != 0 {
        events |= 8;
    } // POLLERR
    events
}

pub fn socket_read(fd: usize, buf: &mut [u8], flags: u32) -> isize {
    let peek = flags & MSG_PEEK != 0;
    let mut sockets = SOCKETS.lock();
    let Some(Some(sock)) = sockets.get_mut(fd) else {
        return -9;
    };
    if let Some(id) = sock.tcp_id {
        drop(sockets);
        if peek {
            return crate::net::tcp::peek(id, buf);
        }
        return crate::net::tcp::recv(id, buf);
    }
    if let Some(conn) = sock.unix_conn.clone() {
        drop(sockets);
        let data = conn.read(buf.len());
        let n = data.len();
        buf[..n].copy_from_slice(&data);
        return n as isize;
    }
    // UDP: pull next datagram
    if let Some((src_ip, src_port, data)) = if peek {
        sock.udp_rx.front().cloned()
    } else {
        sock.udp_rx.pop_front()
    } {
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        return n as isize;
    }
    -11 // EAGAIN
}

pub fn socket_write(fd: usize, buf: &[u8]) -> isize {
    let sockets = SOCKETS.lock();
    let Some(Some(sock)) = sockets.get(fd) else {
        return -9;
    };
    if let Some(id) = sock.tcp_id {
        drop(sockets);
        return crate::net::tcp::send(id, buf);
    }
    if let Some(conn) = sock.unix_conn.clone() {
        drop(sockets);
        conn.write(buf);
        return buf.len() as isize;
    }
    -9 // EBADF — unconnected UDP should use sendto
}
