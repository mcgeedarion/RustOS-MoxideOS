//! BSD socket layer — AF_INET SOCK_STREAM (TCP) and SOCK_DGRAM (UDP).
//!
//! Exposed via syscalls: socket, bind, listen, accept, connect,
//!                        send/sendto, recv/recvfrom, setsockopt, getsockname, getpeername.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use spin::Mutex;

use crate::net::{ip, tcp, udp};

// ── Socket types ──────────────────────────────────────────────────────────────

pub const AF_INET:    i32 = 2;
pub const AF_INET6:   i32 = 10;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM:  i32 = 2;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;

/// A kernel socket descriptor.
#[derive(Debug)]
pub enum SocketState {
    TcpActive  { conn_idx: usize },
    TcpListen  { listen_idx: usize },
    Udp        { local_port: u16, rx_queue: VecDeque<UdpDatagram> },
    Unbound,
}

/// Received UDP datagram.
#[derive(Debug)]
pub struct UdpDatagram {
    pub src_ip:   u32,
    pub src_port: u16,
    pub data:     Vec<u8>,
}

/// Kernel socket.
pub struct Socket {
    pub domain:   i32,
    pub kind:     i32,
    pub proto:    i32,
    pub state:    SocketState,
    pub local_port: u16,
    pub peer_ip:    u32,
    pub peer_port:  u16,
    pub nonblocking: bool,
}

impl Socket {
    fn new(domain: i32, kind: i32, proto: i32) -> Self {
        Socket {
            domain, kind, proto,
            state: SocketState::Unbound,
            local_port: 0,
            peer_ip: 0, peer_port: 0,
            nonblocking: false,
        }
    }
}

// ── Global socket table ───────────────────────────────────────────────────────

/// Maps kernel socket slot → Socket.  Index is the "socket fd" in the socket table.
/// The VFS fd table maps file descriptors to these indices via a SOCKET file type.
pub static UDP_SOCKETS: Mutex<Vec<Option<Socket>>> = Mutex::new(Vec::new());

static EPHEMERAL: Mutex<u16> = Mutex::new(49152);
fn next_ephemeral() -> u16 {
    let mut e = EPHEMERAL.lock();
    let p = *e;
    *e = if p >= 65534 { 49152 } else { p + 1 };
    p
}

// ── Syscall implementations ───────────────────────────────────────────────────

/// `socket(domain, type, protocol)` → slot index (≥0) or negative errno.
pub fn sys_socket(domain: i32, kind: i32, proto: i32) -> isize {
    if domain != AF_INET { return -97; } // EAFNOSUPPORT
    match kind & 0xF {
        k if k == SOCK_STREAM || k == SOCK_DGRAM => {}
        _ => return -22, // EINVAL
    }
    let sock = Socket::new(domain, kind & 0xF, proto);
    let mut table = UDP_SOCKETS.lock();
    // Find empty slot
    if let Some(idx) = table.iter().position(|s| s.is_none()) {
        table[idx] = Some(sock);
        return idx as isize;
    }
    table.push(Some(sock));
    (table.len() - 1) as isize
}

/// `bind(sockfd, addr, addrlen)` — addr is sockaddr_in: {u16 family, u16 port BE, u32 ip BE, [8]pad}
pub fn sys_bind(sock_idx: usize, addr_va: usize, _addrlen: u32) -> isize {
    let mut raw = [0u8; 16];
    if crate::uaccess::copy_from_user(&mut raw, addr_va).is_err() { return -14; }
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    let mut table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get_mut(sock_idx) {
        sock.local_port = port;
        return 0;
    }
    -9 // EBADF
}

/// `listen(sockfd, backlog)`
pub fn sys_listen(sock_idx: usize, _backlog: i32) -> isize {
    let mut table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get_mut(sock_idx) {
        if sock.kind != SOCK_STREAM { return -22; }
        let port = if sock.local_port == 0 { next_ephemeral() } else { sock.local_port };
        sock.local_port = port;
        let lidx = tcp::listen(port);
        sock.state = SocketState::TcpListen { listen_idx: lidx };
        return 0;
    }
    -9
}

/// `accept(sockfd, addr_va, addrlen_va)` → new sock_idx or errno.
pub fn sys_accept(sock_idx: usize, addr_va: usize, _addrlen_va: usize) -> isize {
    let mut table = UDP_SOCKETS.lock();
    let listen_idx = if let Some(Some(sock)) = table.get(sock_idx) {
        match sock.state {
            SocketState::TcpListen { listen_idx } => listen_idx,
            _ => return -22,
        }
    } else {
        return -9;
    };
    drop(table);

    // Wait for a connection — blocking (spin for now, TODO: sleep)
    let conn_idx = loop {
        if let Some(ci) = tcp::accept(listen_idx) { break ci; }
        // TODO: yield / block here
        core::hint::spin_loop();
    };

    // Write peer addr to user space
    if addr_va != 0 {
        let conns = tcp::TCP_CONNS.lock();
        if let Some(c) = conns.get(conn_idx) {
            let mut addr = [0u8; 16];
            addr[0] = 0;
            addr[1] = AF_INET as u8;
            addr[2] = (c.remote_port >> 8) as u8;
            addr[3] = c.remote_port as u8;
            addr[4..8].copy_from_slice(&c.remote_ip.to_be_bytes());
            let _ = crate::uaccess::copy_to_user(addr_va, &addr);
        }
    }

    // Allocate new socket for accepted conn
    let new_sock = Socket {
        domain: AF_INET, kind: SOCK_STREAM, proto: IPPROTO_TCP,
        state: SocketState::TcpActive { conn_idx },
        local_port: 0, peer_ip: 0, peer_port: 0,
        nonblocking: false,
    };
    let mut table = UDP_SOCKETS.lock();
    if let Some(slot) = table.iter().position(|s| s.is_none()) {
        table[slot] = Some(new_sock);
        return slot as isize;
    }
    table.push(Some(new_sock));
    (table.len() - 1) as isize
}

/// `connect(sockfd, addr_va, addrlen)`
pub fn sys_connect(sock_idx: usize, addr_va: usize, _addrlen: u32) -> isize {
    let mut raw = [0u8; 16];
    if crate::uaccess::copy_from_user(&mut raw, addr_va).is_err() { return -14; }
    let dst_port = u16::from_be_bytes([raw[2], raw[3]]);
    let dst_ip   = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);

    let mut table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get_mut(sock_idx) {
        if sock.kind == SOCK_DGRAM {
            sock.peer_ip   = dst_ip;
            sock.peer_port = dst_port;
            if sock.local_port == 0 { sock.local_port = next_ephemeral(); }
            sock.state = SocketState::Udp {
                local_port: sock.local_port,
                rx_queue:   VecDeque::new(),
            };
            return 0;
        }
        if sock.kind == SOCK_STREAM {
            if sock.local_port == 0 { sock.local_port = next_ephemeral(); }
            let lp = sock.local_port;
            let ci = tcp::connect(lp, dst_ip, dst_port);
            sock.state = SocketState::TcpActive { conn_idx: ci };
            sock.peer_ip   = dst_ip;
            sock.peer_port = dst_port;
            drop(table);
            // Spin until ESTABLISHED or error (TODO: wait queue)
            loop {
                let conns = tcp::TCP_CONNS.lock();
                let s = conns.get(ci).map(|c| c.state);
                drop(conns);
                match s {
                    Some(tcp::TcpState::Established) => return 0,
                    Some(tcp::TcpState::Closed)      => return -111, // ECONNREFUSED
                    None => return -9,
                    _ => core::hint::spin_loop(),
                }
            }
        }
    }
    -9
}

/// `send(sockfd, buf_va, len, flags)` / `write` on socket.
pub fn sys_send(sock_idx: usize, buf_va: usize, len: usize, _flags: i32) -> isize {
    let mut data = alloc::vec![0u8; len];
    if crate::uaccess::copy_from_user(&mut data, buf_va).is_err() { return -14; }
    let table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get(sock_idx) {
        match &sock.state {
            SocketState::TcpActive { conn_idx } => {
                let ci = *conn_idx;
                drop(table);
                let r = tcp::write(ci, &data);
                tcp::flush(ci);
                return r;
            }
            SocketState::Udp { local_port, .. } => {
                let lp = *local_port;
                let pip = sock.peer_ip;
                let pp = sock.peer_port;
                drop(table);
                udp::send(lp, pip, pp, &data);
                return len as isize;
            }
            _ => return -107, // ENOTCONN
        }
    }
    -9
}

/// `sendto(sockfd, buf_va, len, flags, addr_va, addrlen)`
pub fn sys_sendto(sock_idx: usize, buf_va: usize, len: usize, flags: i32,
                  addr_va: usize, _addrlen: u32) -> isize {
    if addr_va == 0 { return sys_send(sock_idx, buf_va, len, flags); }
    let mut raw = [0u8; 16];
    if crate::uaccess::copy_from_user(&mut raw, addr_va).is_err() { return -14; }
    let dst_port = u16::from_be_bytes([raw[2], raw[3]]);
    let dst_ip   = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);

    let mut data = alloc::vec![0u8; len];
    if crate::uaccess::copy_from_user(&mut data, buf_va).is_err() { return -14; }

    let mut table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get_mut(sock_idx) {
        if sock.kind == SOCK_DGRAM {
            if sock.local_port == 0 { sock.local_port = next_ephemeral(); }
            let lp = sock.local_port;
            if matches!(sock.state, SocketState::Unbound) {
                sock.state = SocketState::Udp { local_port: lp, rx_queue: VecDeque::new() };
            }
            drop(table);
            udp::send(lp, dst_ip, dst_port, &data);
            return len as isize;
        }
    }
    -9
}

/// `recv(sockfd, buf_va, len, flags)`
pub fn sys_recv(sock_idx: usize, buf_va: usize, len: usize, _flags: i32) -> isize {
    let table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get(sock_idx) {
        match &sock.state {
            SocketState::TcpActive { conn_idx } => {
                let ci = *conn_idx;
                drop(table);
                let mut buf = alloc::vec![0u8; len];
                loop {
                    let n = tcp::read(ci, &mut buf);
                    if n > 0 {
                        let _ = crate::uaccess::copy_to_user(buf_va, &buf[..n as usize]);
                        return n;
                    }
                    if n < 0 { return n; }
                    core::hint::spin_loop();
                }
            }
            SocketState::Udp { .. } => {
                drop(table);
                loop {
                    let mut t = UDP_SOCKETS.lock();
                    if let Some(Some(sock)) = t.get_mut(sock_idx) {
                        if let SocketState::Udp { rx_queue, .. } = &mut sock.state {
                            if let Some(dg) = rx_queue.pop_front() {
                                let n = dg.data.len().min(len);
                                let _ = crate::uaccess::copy_to_user(buf_va, &dg.data[..n]);
                                return n as isize;
                            }
                        }
                    }
                    drop(t);
                    core::hint::spin_loop();
                }
            }
            _ => return -107,
        }
    }
    -9
}

/// `recvfrom(sockfd, buf, len, flags, src_addr_va, addrlen_va)`
pub fn sys_recvfrom(sock_idx: usize, buf_va: usize, len: usize, flags: i32,
                    src_addr_va: usize, _addrlen_va: usize) -> isize {
    if src_addr_va == 0 { return sys_recv(sock_idx, buf_va, len, flags); }
    let mut t = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = t.get_mut(sock_idx) {
        if let SocketState::Udp { rx_queue, .. } = &mut sock.state {
            if let Some(dg) = rx_queue.pop_front() {
                drop(t);
                let n = dg.data.len().min(len);
                let _ = crate::uaccess::copy_to_user(buf_va, &dg.data[..n]);
                // Write source address
                let mut addr = [0u8; 16];
                addr[1] = AF_INET as u8;
                addr[2] = (dg.src_port >> 8) as u8;
                addr[3] = dg.src_port as u8;
                addr[4..8].copy_from_slice(&dg.src_ip.to_be_bytes());
                let _ = crate::uaccess::copy_to_user(src_addr_va, &addr);
                return n as isize;
            }
        }
    }
    drop(t);
    -11 // EAGAIN
}

/// `getsockname(sockfd, addr_va, addrlen_va)`
pub fn sys_getsockname(sock_idx: usize, addr_va: usize, _addrlen_va: usize) -> isize {
    let table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get(sock_idx) {
        let mut addr = [0u8; 16];
        addr[1] = AF_INET as u8;
        addr[2] = (sock.local_port >> 8) as u8;
        addr[3] = sock.local_port as u8;
        let ip = ip::our_ip();
        addr[4..8].copy_from_slice(&ip.to_be_bytes());
        drop(table);
        let _ = crate::uaccess::copy_to_user(addr_va, &addr);
        return 0;
    }
    -9
}

/// `getpeername(sockfd, addr_va, addrlen_va)`
pub fn sys_getpeername(sock_idx: usize, addr_va: usize, _addrlen_va: usize) -> isize {
    let table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get(sock_idx) {
        let mut addr = [0u8; 16];
        addr[1] = AF_INET as u8;
        addr[2] = (sock.peer_port >> 8) as u8;
        addr[3] = sock.peer_port as u8;
        addr[4..8].copy_from_slice(&sock.peer_ip.to_be_bytes());
        drop(table);
        let _ = crate::uaccess::copy_to_user(addr_va, &addr);
        return 0;
    }
    -9
}

/// `setsockopt(sockfd, level, optname, optval_va, optlen)`
/// Supports SO_REUSEADDR, SO_REUSEPORT, TCP_NODELAY — all silently accepted.
pub fn sys_setsockopt(_sock_idx: usize, _level: i32, _opt: i32,
                      _optval_va: usize, _optlen: u32) -> isize {
    0 // accept all options without error
}

/// `getsockopt`
pub fn sys_getsockopt(_sock_idx: usize, _level: i32, _opt: i32,
                       optval_va: usize, _optlen_va: usize) -> isize {
    if optval_va != 0 {
        let _ = crate::uaccess::copy_to_user(optval_va, &0u32.to_le_bytes());
    }
    0
}

/// Close a socket, freeing its slot.
pub fn sys_close_socket(sock_idx: usize) {
    let mut table = UDP_SOCKETS.lock();
    if let Some(slot) = table.get_mut(sock_idx) {
        if let Some(sock) = slot.take() {
            if let SocketState::TcpActive { conn_idx } = sock.state {
                drop(table);
                tcp::close(conn_idx);
                return;
            }
        }
    }
}

/// Demultiplex an incoming UDP datagram to a waiting socket.
pub fn demux_udp(src_ip: u32, src_port: u16, dst_port: u16, data: &[u8]) {
    let mut table = UDP_SOCKETS.lock();
    for slot in table.iter_mut() {
        if let Some(sock) = slot {
            if let SocketState::Udp { local_port, rx_queue } = &mut sock.state {
                if *local_port == dst_port {
                    rx_queue.push_back(UdpDatagram {
                        src_ip,
                        src_port,
                        data: data.to_vec(),
                    });
                    return;
                }
            }
        }
    }
    // No listener → ICMP Port Unreachable (best-effort)
}

/// poll(2) support: is the socket readable?
pub fn socket_poll(sock_idx: usize, events: u16) -> Option<u16> {
    const POLLIN:  u16 = 0x0001;
    const POLLOUT: u16 = 0x0004;
    const POLLERR: u16 = 0x0008;
    let table = UDP_SOCKETS.lock();
    let sock = table.get(sock_idx)?.as_ref()?;
    let mut revents = 0u16;
    match &sock.state {
        SocketState::TcpActive { conn_idx } => {
            if events & POLLIN  != 0 && tcp::rx_ready(*conn_idx) { revents |= POLLIN; }
            if events & POLLOUT != 0 && tcp::tx_ready(*conn_idx) { revents |= POLLOUT; }
        }
        SocketState::Udp { rx_queue, .. } => {
            if events & POLLIN  != 0 && !rx_queue.is_empty() { revents |= POLLIN; }
            if events & POLLOUT != 0 { revents |= POLLOUT; } // UDP always writable
        }
        SocketState::TcpListen { listen_idx } => {
            // Readable if there is an established connection in the backlog
            let conns = tcp::TCP_CONNS.lock();
            let has = conns.get(*listen_idx)
                .map(|c| c.backlog.iter().any(|bc| bc.state == tcp::TcpState::Established))
                .unwrap_or(false);
            if events & POLLIN != 0 && has { revents |= POLLIN; }
        }
        SocketState::Unbound => {}
    }
    Some(revents)
}
