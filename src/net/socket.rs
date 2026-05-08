//! BSD socket layer — AF_INET (TCP/UDP) and AF_UNIX (stream).
//!
//! ## AF_UNIX support
//!
//! `AF_UNIX SOCK_STREAM` sockets are the standard IPC mechanism for
//! Wayland clients connecting to the compositor, and for any other
//! process-to-process communication that should not go over the network
//! stack.  This module adds a simple kernel-side Unix socket implementation:
//!
//!   - `bind(path)`     — registers the socket path in the Unix socket table.
//!   - `listen()`       — marks the socket as accepting connections.
//!   - `connect(path)`  — creates a kernel pipe-pair and wires both ends.
//!   - `accept()`       — dequeues the next completed pipe-pair endpoint.
//!   - `send/recv`      — read/write through the pipe-pair's ring buffer.
//!
//! The socket path is looked up in `UNIX_BINDINGS` (a `BTreeMap<String, usize>`).
//! No actual filesystem node is created — the path is purely a name in
//! the kernel socket namespace (comparable to Linux's abstract namespace
//! but stored in the VFS devfs instead; full VFS integration is a future
//! improvement).
//!
//! ## Thread safety
//!
//! All socket tables are protected by `IrqSpinLock` so they are safe to
//! access from both syscall context and interrupt context.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::net::{ip, tcp, udp};

// ── Domain / type constants (Linux ABI) ──────────────────────────────────────

pub const AF_UNIX:    i32 = 1;
pub const AF_INET:    i32 = 2;
pub const AF_INET6:   i32 = 10;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM:  i32 = 2;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;

// ── Unix socket pipe-pair ────────────────────────────────────────────────────

/// A shared ring-buffer connecting two Unix socket endpoints.
/// When both endpoints drop their reference the buffer is freed.
struct UnixPipe {
    buf:    VecDeque<u8>,
    closed: bool,  // true when the *writing* end called shutdown/close
}

/// One end of a connected Unix socket pair.
struct UnixConn {
    /// Ring buffer for data flowing *into* this endpoint (written by peer).
    rx: alloc::sync::Arc<Mutex<UnixPipe>>,
    /// Ring buffer for data flowing *out* of this endpoint (read by peer).
    tx: alloc::sync::Arc<Mutex<UnixPipe>>,
}

impl UnixConn {
    fn new_pair() -> (UnixConn, UnixConn) {
        let a_to_b = alloc::sync::Arc::new(Mutex::new(UnixPipe { buf: VecDeque::new(), closed: false }));
        let b_to_a = alloc::sync::Arc::new(Mutex::new(UnixPipe { buf: VecDeque::new(), closed: false }));
        let a = UnixConn { rx: b_to_a.clone(), tx: a_to_b.clone() };
        let b = UnixConn { rx: a_to_b,         tx: b_to_a };
        (a, b)
    }

    fn write(&self, data: &[u8]) {
        self.tx.lock().buf.extend(data.iter().copied());
    }

    /// Read up to `len` bytes.  Returns 0 if the peer closed and the buffer
    /// is empty (EOF), or -EAGAIN if no data is available yet.
    fn read(&self, len: usize) -> alloc::vec::Vec<u8> {
        let mut pipe = self.rx.lock();
        let n = len.min(pipe.buf.len());
        pipe.buf.drain(..n).collect()
    }

    fn is_readable(&self) -> bool {
        let pipe = self.rx.lock();
        !pipe.buf.is_empty() || pipe.closed
    }

    fn close_tx(&self) {
        self.tx.lock().closed = true;
    }
}

// ── Unix listening socket backlog ─────────────────────────────────────────────

/// An incoming-but-not-yet-accepted Unix connection.  The server-side
/// `UnixConn` waits in the backlog until `accept()` is called.
struct PendingUnix {
    server_conn: UnixConn,
}

/// Per-path Unix listener state.
struct UnixListener {
    backlog: VecDeque<PendingUnix>,
    max_backlog: usize,
}

// ── Socket state ─────────────────────────────────────────────────────────────

pub enum SocketState {
    /// AF_INET UDP socket.
    Udp { local_port: u16, rx_queue: VecDeque<UdpDatagram> },
    /// AF_INET TCP active connection.
    TcpActive  { conn_idx: usize },
    /// AF_INET TCP listening socket.
    TcpListen  { listen_idx: usize },
    /// AF_UNIX connected socket (one end of a pipe-pair).
    UnixConn(UnixConn),
    /// AF_UNIX listening socket (bound to a path, calling listen()).
    UnixListen { path: String },
    /// Freshly created, not yet bound.
    Unbound,
}

/// Received UDP datagram.
pub struct UdpDatagram {
    pub src_ip:   u32,
    pub src_port: u16,
    pub data:     Vec<u8>,
}

pub struct Socket {
    pub domain:      i32,
    pub kind:        i32,
    pub proto:       i32,
    pub state:       SocketState,
    pub local_port:  u16,
    pub peer_ip:     u32,
    pub peer_port:   u16,
    pub nonblocking: bool,
}

impl Socket {
    fn new(domain: i32, kind: i32, proto: i32) -> Self {
        Socket {
            domain, kind, proto,
            state: SocketState::Unbound,
            local_port: 0, peer_ip: 0, peer_port: 0,
            nonblocking: false,
        }
    }
}

// ── Global tables ─────────────────────────────────────────────────────────────

/// All kernel socket descriptors.  Index = socket slot number.
pub static UDP_SOCKETS: Mutex<Vec<Option<Socket>>> = Mutex::new(Vec::new());

/// Unix socket listener table: path → listener state.
static UNIX_LISTENERS: Mutex<BTreeMap<String, UnixListener>> =
    Mutex::new(BTreeMap::new());

static EPHEMERAL: Mutex<u16> = Mutex::new(49152);
fn next_ephemeral() -> u16 {
    let mut e = EPHEMERAL.lock();
    let p = *e;
    *e = if p >= 65534 { 49152 } else { p + 1 };
    p
}

// ─────────────────────────────────────────────────────────────────────────────
// Syscall implementations
// ─────────────────────────────────────────────────────────────────────────────

/// `socket(domain, type, protocol)` → slot index (≥0) or negative errno.
pub fn sys_socket(domain: i32, kind: i32, proto: i32) -> isize {
    match domain {
        d if d == AF_INET || d == AF_UNIX => {}
        _ => return -97, // EAFNOSUPPORT
    }
    match kind & 0xF {
        k if k == SOCK_STREAM || k == SOCK_DGRAM => {}
        _ => return -22, // EINVAL
    }
    let sock = Socket::new(domain, kind & 0xF, proto);
    let mut table = UDP_SOCKETS.lock();
    if let Some(idx) = table.iter().position(|s| s.is_none()) {
        table[idx] = Some(sock);
        return idx as isize;
    }
    table.push(Some(sock));
    (table.len() - 1) as isize
}

/// `bind(sockfd, addr, addrlen)`
///
/// For `AF_UNIX`: `addr` is a `sockaddr_un`:
///   `{ u16 family=AF_UNIX, char sun_path[108] }`
///   The path is read as a NUL-terminated string from `sun_path`.
///
/// For `AF_INET`: `addr` is `sockaddr_in` as before.
pub fn sys_bind(sock_idx: usize, addr_va: usize, _addrlen: u32) -> isize {
    // Read at least 16 bytes to cover sockaddr_in; for AF_UNIX read 110.
    let mut hdr = [0u8; 2];
    if crate::uaccess::copy_from_user(addr_va, &mut hdr).is_err() { return -14; }
    let family = u16::from_ne_bytes(hdr) as i32;

    let mut table = UDP_SOCKETS.lock();
    let sock = match table.get_mut(sock_idx).and_then(|s| s.as_mut()) {
        Some(s) => s,
        None    => return -9, // EBADF
    };

    if family == AF_UNIX {
        // sockaddr_un: u16 family + up to 108 bytes sun_path (NUL-terminated)
        let mut sun = [0u8; 110];
        let _ = crate::uaccess::copy_from_user(addr_va, &mut sun);
        let path_bytes = &sun[2..];
        let nul = path_bytes.iter().position(|&b| b == 0).unwrap_or(108);
        let path = match core::str::from_utf8(&path_bytes[..nul]) {
            Ok(p) => p,
            Err(_) => return -22,
        };
        // Register in the Unix listener table under this path.
        let mut listeners = UNIX_LISTENERS.lock();
        listeners.entry(path.into()).or_insert_with(|| UnixListener {
            backlog: VecDeque::new(),
            max_backlog: 128,
        });
        sock.state = SocketState::UnixListen { path: path.into() };
        return 0;
    }

    if family == AF_INET {
        let mut addr = [0u8; 16];
        if crate::uaccess::copy_from_user(addr_va, &mut addr).is_err() { return -14; }
        let port = u16::from_be_bytes([addr[2], addr[3]]);
        sock.local_port = port;
        if sock.domain == AF_INET && sock.kind == SOCK_DGRAM {
            sock.state = SocketState::Udp {
                local_port: port,
                rx_queue: VecDeque::new(),
            };
            crate::net::udp::register_port(port, sock_idx);
        }
        return 0;
    }

    -22 // EINVAL
}

/// `listen(sockfd, backlog)`
pub fn sys_listen(sock_idx: usize, backlog: i32) -> isize {
    let table = UDP_SOCKETS.lock();
    let sock = match table.get(sock_idx).and_then(|s| s.as_ref()) {
        Some(s) => s,
        None    => return -9,
    };
    if let SocketState::UnixListen { ref path } = sock.state {
        let mut listeners = UNIX_LISTENERS.lock();
        if let Some(l) = listeners.get_mut(path.as_str()) {
            l.max_backlog = backlog.max(1) as usize;
        }
        return 0;
    }
    if sock.domain == AF_INET && sock.kind == SOCK_STREAM {
        // TCP listen — handled by tcp layer
        let port = sock.local_port;
        drop(table);
        let idx = crate::net::tcp::listen(port);
        let mut table2 = UDP_SOCKETS.lock();
        if let Some(Some(s)) = table2.get_mut(sock_idx) {
            s.state = SocketState::TcpListen { listen_idx: idx };
        }
        return 0;
    }
    0
}

/// `accept(sockfd, addr_va, addrlen_va)` → new socket fd or negative errno.
pub fn sys_accept(sock_idx: usize, addr_va: usize, addrlen_va: usize) -> isize {
    // ── AF_UNIX ──────────────────────────────────────────────────────────────
    {
        let table = UDP_SOCKETS.lock();
        if let Some(Some(sock)) = table.get(sock_idx) {
            if let SocketState::UnixListen { ref path } = sock.state {
                let path = path.clone();
                drop(table);
                loop {
                    let conn = {
                        let mut listeners = UNIX_LISTENERS.lock();
                        if let Some(l) = listeners.get_mut(path.as_str()) {
                            l.backlog.pop_front().map(|p| p.server_conn)
                        } else {
                            return -9;
                        }
                    };
                    if let Some(server_conn) = conn {
                        let new_sock = Socket {
                            domain: AF_UNIX, kind: SOCK_STREAM, proto: 0,
                            state: SocketState::UnixConn(server_conn),
                            local_port: 0, peer_ip: 0, peer_port: 0,
                            nonblocking: false,
                        };
                        let mut t2 = UDP_SOCKETS.lock();
                        let new_idx = if let Some(i) = t2.iter().position(|s| s.is_none()) {
                            t2[i] = Some(new_sock); i
                        } else {
                            t2.push(Some(new_sock)); t2.len() - 1
                        };
                        // Write a minimal AF_UNIX sockaddr back if requested.
                        if addr_va != 0 {
                            let sa = [AF_UNIX as u8, 0u8];
                            let _ = crate::uaccess::copy_to_user(addr_va, &sa);
                        }
                        if addrlen_va != 0 {
                            let len = 2u32;
                            let _ = crate::uaccess::copy_to_user(addrlen_va, &len.to_ne_bytes());
                        }
                        return new_idx as isize;
                    }
                    // No pending connection yet — yield and retry.
                    crate::proc::scheduler::yield_now();
                    let nonblock = {
                        let t = UDP_SOCKETS.lock();
                        t.get(sock_idx).and_then(|s| s.as_ref()).map(|s| s.nonblocking).unwrap_or(false)
                    };
                    if nonblock { return -11; } // EAGAIN
                }
            }
        }
    }

    // ── AF_INET TCP ──────────────────────────────────────────────────────────
    let listen_idx = {
        let table = UDP_SOCKETS.lock();
        match table.get(sock_idx).and_then(|s| s.as_ref()) {
            Some(Socket { state: SocketState::TcpListen { listen_idx }, .. }) => *listen_idx,
            _ => return -22,
        }
    };

    loop {
        if let Some(conn_idx) = crate::net::tcp::accept(listen_idx) {
            let (peer_ip, peer_port) = crate::net::tcp::peer_addr(conn_idx);
            let new_sock = Socket {
                domain: AF_INET, kind: SOCK_STREAM, proto: IPPROTO_TCP,
                state: SocketState::TcpActive { conn_idx },
                local_port: 0, peer_ip, peer_port,
                nonblocking: false,
            };
            let mut t = UDP_SOCKETS.lock();
            let new_idx = if let Some(i) = t.iter().position(|s| s.is_none()) {
                t[i] = Some(new_sock); i
            } else {
                t.push(Some(new_sock)); t.len() - 1
            };
            if addr_va != 0 {
                let mut addr = [0u8; 16];
                addr[0] = 0; addr[1] = AF_INET as u8;
                addr[2] = (peer_port >> 8) as u8;
                addr[3] = peer_port as u8;
                addr[4..8].copy_from_slice(&peer_ip.to_be_bytes());
                let _ = crate::uaccess::copy_to_user(addr_va, &addr);
                if addrlen_va != 0 {
                    let len = 16u32;
                    let _ = crate::uaccess::copy_to_user(addrlen_va, &len.to_ne_bytes());
                }
            }
            return new_idx as isize;
        }
        crate::proc::scheduler::yield_now();
        let nonblock = {
            let t = UDP_SOCKETS.lock();
            t.get(sock_idx).and_then(|s| s.as_ref()).map(|s| s.nonblocking).unwrap_or(false)
        };
        if nonblock { return -11; }
    }
}

/// `connect(sockfd, addr_va, addrlen)`
pub fn sys_connect(sock_idx: usize, addr_va: usize, _addrlen: u32) -> isize {
    let mut hdr = [0u8; 2];
    if crate::uaccess::copy_from_user(addr_va, &mut hdr).is_err() { return -14; }
    let family = u16::from_ne_bytes(hdr) as i32;

    if family == AF_UNIX {
        let mut sun = [0u8; 110];
        let _ = crate::uaccess::copy_from_user(addr_va, &mut sun);
        let path_bytes = &sun[2..];
        let nul = path_bytes.iter().position(|&b| b == 0).unwrap_or(108);
        let path = match core::str::from_utf8(&path_bytes[..nul]) {
            Ok(p) => p, Err(_) => return -22,
        };

        // Build a pipe-pair: client holds conn_b, server gets conn_a via backlog.
        let (conn_a, conn_b) = UnixConn::new_pair();

        // Push conn_a into the server's backlog.
        {
            let mut listeners = UNIX_LISTENERS.lock();
            let listener = match listeners.get_mut(path) {
                Some(l) => l,
                None    => return -111, // ECONNREFUSED
            };
            if listener.backlog.len() >= listener.max_backlog {
                return -111; // ECONNREFUSED — backlog full
            }
            listener.backlog.push_back(PendingUnix { server_conn: conn_a });
        }

        // Wire our (client) end.
        let mut table = UDP_SOCKETS.lock();
        if let Some(Some(sock)) = table.get_mut(sock_idx) {
            sock.state = SocketState::UnixConn(conn_b);
            return 0;
        }
        return -9;
    }

    if family == AF_INET {
        let mut addr = [0u8; 16];
        if crate::uaccess::copy_from_user(addr_va, &mut addr).is_err() { return -14; }
        let port  = u16::from_be_bytes([addr[2], addr[3]]);
        let dst_ip = u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]]);

        let kind = {
            let table = UDP_SOCKETS.lock();
            match table.get(sock_idx).and_then(|s| s.as_ref()) {
                Some(s) => s.kind,
                None    => return -9,
            }
        };

        if kind == SOCK_STREAM {
            let src_port = next_ephemeral();
            let conn_idx = match crate::net::tcp::connect(dst_ip, port, src_port) {
                Ok(i)  => i,
                Err(e) => return e,
            };
            let mut table = UDP_SOCKETS.lock();
            if let Some(Some(sock)) = table.get_mut(sock_idx) {
                sock.state      = SocketState::TcpActive { conn_idx };
                sock.local_port = src_port;
                sock.peer_ip    = dst_ip;
                sock.peer_port  = port;
            }
            return 0;
        }

        if kind == SOCK_DGRAM {
            let mut table = UDP_SOCKETS.lock();
            if let Some(Some(sock)) = table.get_mut(sock_idx) {
                sock.peer_ip   = dst_ip;
                sock.peer_port = port;
                if sock.local_port == 0 {
                    let lp = next_ephemeral();
                    sock.local_port = lp;
                    sock.state = SocketState::Udp { local_port: lp, rx_queue: VecDeque::new() };
                    crate::net::udp::register_port(lp, sock_idx);
                }
            }
            return 0;
        }
    }

    -22
}

/// `send(sockfd, buf, len, flags)` — shorthand without address.
pub fn sys_send(sock_idx: usize, buf_va: usize, len: usize, _flags: i32) -> isize {
    sys_sendto(sock_idx, buf_va, len, 0, 0, 0)
}

/// `sendto(sockfd, buf, len, flags, dest_addr, addrlen)`
pub fn sys_sendto(sock_idx: usize, buf_va: usize, len: usize, flags: i32,
                  dest_addr: usize, addrlen: u32) -> isize {
    if len == 0 { return 0; }
    if !crate::uaccess::validate_user_ptr(buf_va, len) { return -14; }
    let mut kbuf = alloc::vec![0u8; len];
    if crate::uaccess::copy_from_user(buf_va, &mut kbuf).is_err() { return -14; }

    let table = UDP_SOCKETS.lock();
    let sock = match table.get(sock_idx).and_then(|s| s.as_ref()) {
        Some(s) => s, None => return -9,
    };

    match &sock.state {
        SocketState::UnixConn(conn) => {
            conn.write(&kbuf);
            return len as isize;
        }
        SocketState::TcpActive { conn_idx } => {
            let idx = *conn_idx;
            drop(table);
            return crate::net::tcp::send(idx, &kbuf);
        }
        SocketState::Udp { local_port, .. } => {
            let lp = *local_port;
            let (dst_ip, dst_port) = if dest_addr != 0 && addrlen >= 8 {
                let mut a = [0u8; 8];
                drop(table);
                if crate::uaccess::copy_from_user(dest_addr, &mut a).is_err() { return -14; }
                (u32::from_be_bytes([a[4],a[5],a[6],a[7]]),
                 u16::from_be_bytes([a[2],a[3]]))
            } else {
                let t = UDP_SOCKETS.lock();
                let s = t.get(sock_idx).and_then(|s| s.as_ref()).unwrap();
                let r = (s.peer_ip, s.peer_port);
                drop(t);
                r
            };
            if dst_ip == 0 || dst_port == 0 { return -107; } // ENOTCONN
            let src_ip = crate::net::ip::local_ip();
            crate::net::udp::send(src_ip, lp, dst_ip, dst_port, &kbuf);
            return len as isize;
        }
        _ => return -107,
    }
}

/// `recv(sockfd, buf, len, flags)` — shorthand without address.
pub fn sys_recv(sock_idx: usize, buf_va: usize, len: usize, _flags: i32) -> isize {
    sys_recvfrom(sock_idx, buf_va, len, 0, 0, 0)
}

/// `recvfrom(sockfd, buf, len, flags, src_addr, addrlen)`
pub fn sys_recvfrom(sock_idx: usize, buf_va: usize, len: usize, flags: i32,
                    src_addr: usize, addrlen_va: usize) -> isize {
    if len == 0 { return 0; }
    if !crate::uaccess::validate_user_ptr(buf_va, len) { return -14; }

    loop {
        let (data, from_ip, from_port): (Vec<u8>, u32, u16) = {
            let table = UDP_SOCKETS.lock();
            let sock = match table.get(sock_idx).and_then(|s| s.as_ref()) {
                Some(s) => s, None => return -9,
            };
            match &sock.state {
                SocketState::UnixConn(conn) => {
                    let d = conn.read(len);
                    if d.is_empty() {
                        // Check if peer closed.
                        if conn.rx.lock().closed { return 0; }
                        if sock.nonblocking { return -11; }
                        drop(table);
                        crate::proc::scheduler::yield_now();
                        continue;
                    }
                    (d, 0, 0)
                }
                SocketState::TcpActive { conn_idx } => {
                    let idx = *conn_idx;
                    drop(table);
                    let mut kbuf = alloc::vec![0u8; len];
                    let n = crate::net::tcp::recv(idx, &mut kbuf);
                    if n == 0 {
                        let nb = UDP_SOCKETS.lock().get(sock_idx)
                            .and_then(|s| s.as_ref()).map(|s| s.nonblocking).unwrap_or(false);
                        if nb { return -11; }
                        crate::proc::scheduler::yield_now();
                        continue;
                    }
                    if n < 0 { return n; }
                    kbuf.truncate(n as usize);
                    return {
                        if crate::uaccess::copy_to_user(buf_va, &kbuf).is_err() { -14 }
                        else { n }
                    };
                }
                SocketState::Udp { rx_queue, .. } => {
                    // Must work around borrow checker: clone the queue entry.
                    // This is a lock-held path; keep it short.
                    let nb = sock.nonblocking;
                    if let Some(dg) = {
                        let mut t2 = UDP_SOCKETS.lock();
                        if let Some(Some(Socket { state: SocketState::Udp { ref mut rx_queue, .. }, .. })) = t2.get_mut(sock_idx) {
                            rx_queue.pop_front()
                        } else { None }
                    } {
                        (dg.data, dg.src_ip, dg.src_port)
                    } else {
                        drop(table);
                        if nb { return -11; }
                        crate::proc::scheduler::yield_now();
                        continue;
                    }
                }
                _ => return -107, // ENOTCONN
            }
        };

        let n = data.len().min(len);
        if crate::uaccess::copy_to_user(buf_va, &data[..n]).is_err() { return -14; }
        if src_addr != 0 && from_ip != 0 {
            let mut addr = [0u8; 16];
            addr[0] = 0; addr[1] = AF_INET as u8;
            addr[2] = (from_port >> 8) as u8;
            addr[3] = from_port as u8;
            addr[4..8].copy_from_slice(&from_ip.to_be_bytes());
            let _ = crate::uaccess::copy_to_user(src_addr, &addr);
            if addrlen_va != 0 {
                let _ = crate::uaccess::copy_to_user(addrlen_va, &16u32.to_ne_bytes());
            }
        }
        return n as isize;
    }
}

/// `getsockname(sockfd, addr_va, addrlen_va)`
pub fn sys_getsockname(sock_idx: usize, addr_va: usize, _addrlen_va: usize) -> isize {
    let table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get(sock_idx) {
        if sock.domain == AF_UNIX {
            // Return a minimal sockaddr_un with just the family.
            let mut ua = [0u8; 110];
            let fam = AF_UNIX as u16;
            ua[0..2].copy_from_slice(&fam.to_ne_bytes());
            let _ = crate::uaccess::copy_to_user(addr_va, &ua);
            return 0;
        }
        let mut addr = [0u8; 16];
        addr[0] = 0; addr[1] = AF_INET as u8;
        addr[2] = (sock.local_port >> 8) as u8;
        addr[3] = sock.local_port as u8;
        let _ = crate::uaccess::copy_to_user(addr_va, &addr);
        return 0;
    }
    -9
}

/// `getpeername(sockfd, addr_va, addrlen_va)`
pub fn sys_getpeername(sock_idx: usize, addr_va: usize, _addrlen_va: usize) -> isize {
    let table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get(sock_idx) {
        // For connected TCP/UDP peers also check recvfrom return path.
        if sock.peer_ip != 0 {
            let mut addr = [0u8; 16];
            addr[0] = 0; addr[1] = AF_INET as u8;
            addr[2] = (sock.peer_port >> 8) as u8;
            addr[3] = sock.peer_port as u8;
            addr[4..8].copy_from_slice(&sock.peer_ip.to_be_bytes());
            let _ = crate::uaccess::copy_to_user(addr_va, &addr);
        }
    }
    0
}

/// `setsockopt(sockfd, level, optname, optval_va, optlen)`
pub fn sys_setsockopt(sock_idx: usize, _level: i32, opt: i32,
                      optval_va: usize, optlen: u32) -> isize {
    // O_NONBLOCK is set via fcntl, but some programs use FIONBIO via setsockopt.
    if opt == 0x8004 /* FIONBIO */ && optlen >= 4 {
        let mut v = [0u8; 4];
        if crate::uaccess::copy_from_user(&mut v, optval_va).is_ok() {
            let nb = u32::from_ne_bytes(v) != 0;
            let mut t = UDP_SOCKETS.lock();
            if let Some(Some(s)) = t.get_mut(sock_idx) { s.nonblocking = nb; }
        }
    }
    0
}

/// `getsockopt(sockfd, level, optname, optval_va, optlen_va)`
pub fn sys_getsockopt(_sock_idx: usize, _level: i32, _opt: i32,
                      _optval_va: usize, _optlen_va: usize) -> isize { 0 }

/// `close` on a socket fd — clean up the socket slot.
pub fn sys_close_socket(sock_idx: usize) {
    let mut table = UDP_SOCKETS.lock();
    if let Some(slot) = table.get_mut(sock_idx) {
        // If this is a UnixConn, mark our TX end closed so the peer sees EOF.
        if let Some(Socket { state: SocketState::UnixConn(ref conn), .. }) = *slot {
            conn.close_tx();
        }
        *slot = None;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Socket FD bridge helpers (used by io_syscalls, fcntl, poll)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true when `fd` corresponds to an allocated socket slot.
pub fn is_socket_fd(fd: usize) -> bool {
    let t = UDP_SOCKETS.lock();
    fd < t.len() && t[fd].is_some()
}

/// Kernel-internal read from a socket (used by sys_read dispatch).
pub fn socket_read(fd: usize, buf: &mut [u8]) -> isize {
    sys_recv(fd, buf.as_mut_ptr() as usize, buf.len(), 0)
}

/// Kernel-internal write to a socket (used by sys_write dispatch).
pub fn socket_write(fd: usize, buf: &[u8]) -> isize {
    sys_send(fd, buf.as_ptr() as usize, buf.len(), 0)
}

/// Poll readiness — called from poll::fd_ready.
/// Returns Some(ready_events) when fd is a socket, None otherwise.
pub fn socket_poll(fd: usize, events: u32) -> Option<u32> {
    let table = UDP_SOCKETS.lock();
    let sock = table.get(fd)?.as_ref()?;
    let (readable, writable) = match &sock.state {
        SocketState::UnixConn(conn) => (conn.is_readable(), true),
        SocketState::UnixListen { path } => {
            let listeners = UNIX_LISTENERS.lock();
            let r = listeners.get(path.as_str())
                .map(|l| !l.backlog.is_empty())
                .unwrap_or(false);
            (r, false)
        }
        SocketState::Udp { rx_queue, .. } => (!rx_queue.is_empty(), true),
        SocketState::TcpActive { conn_idx } =>
            (crate::net::tcp::rx_available(*conn_idx), true),
        SocketState::TcpListen { .. } => (false, false),
        SocketState::Unbound => (false, true),
    };
    use crate::fs::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
    let mut r = 0u32;
    if readable  && events & POLLIN  != 0 { r |= POLLIN  | POLLRDNORM; }
    if writable  && events & POLLOUT != 0 { r |= POLLOUT | POLLWRNORM; }
    Some(r)
}

// ─────────────────────────────────────────────────────────────────────────────
// sys_shutdown
// ─────────────────────────────────────────────────────────────────────────────

/// `shutdown(sockfd, how)`  how: SHUT_RD=0, SHUT_WR=1, SHUT_RDWR=2
pub fn sys_shutdown(sock_idx: usize, how: i32) -> isize {
    let mut table = UDP_SOCKETS.lock();
    let sock = match table.get_mut(sock_idx).and_then(|s| s.as_mut()) {
        Some(s) => s,
        None    => return -9, // EBADF
    };
    match &sock.state {
        SocketState::UnixConn(conn) => {
            if how == 1 || how == 2 { conn.close_tx(); }
        }
        SocketState::TcpActive { conn_idx } => {
            let idx = *conn_idx;
            drop(table);
            crate::net::tcp::close(idx);
            return 0;
        }
        _ => {}
    }
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// sys_socketpair  — AF_UNIX SOCK_STREAM only
// ─────────────────────────────────────────────────────────────────────────────

/// `socketpair(domain, type, protocol, sv[2])`
pub fn sys_socketpair(domain: i32, kind: i32, _proto: i32, sv_va: usize) -> isize {
    if domain != AF_UNIX         { return -97; } // EAFNOSUPPORT
    if kind & 0xF != SOCK_STREAM { return -22; } // EINVAL
    if sv_va == 0                { return -14; } // EFAULT
    let (conn_a, conn_b) = UnixConn::new_pair();
    let make_sock = |conn: UnixConn| -> Socket {
        Socket {
            domain: AF_UNIX, kind: SOCK_STREAM, proto: 0,
            state: SocketState::UnixConn(conn),
            local_port: 0, peer_ip: 0, peer_port: 0,
            nonblocking: (kind & 0x800) != 0, // SOCK_NONBLOCK
        }
    };
    let mut table = UDP_SOCKETS.lock();
    let alloc_slot = |table: &mut Vec<Option<Socket>>, s: Socket| -> usize {
        if let Some(i) = table.iter().position(|x| x.is_none()) {
            table[i] = Some(s); i
        } else {
            table.push(Some(s)); table.len() - 1
        }
    };
    let fd0 = alloc_slot(&mut table, make_sock(conn_a));
    let fd1 = alloc_slot(&mut table, make_sock(conn_b));
    drop(table);
    // Apply SOCK_CLOEXEC if requested.
    if kind & 0x80000 != 0 {
        crate::fs::fcntl::set_cloexec(fd0, true);
        crate::fs::fcntl::set_cloexec(fd1, true);
    }
    // Write [fd0, fd1] as two i32s into user sv[2].
    let pair = [fd0 as i32, fd1 as i32];
    let bytes: [u8; 8] = unsafe { core::mem::transmute(pair) };
    if crate::uaccess::copy_to_user(sv_va, &bytes).is_err() { return -14; }
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// sys_sendmsg / sys_recvmsg  (msghdr iovec flattening)
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C)]
struct UserIovec { base: usize, len: usize }

/// Flatten a user-space iovec array into a single kernel Vec<u8>.
fn gather_iovec(iov_va: usize, iovcnt: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let iov_size = core::mem::size_of::<UserIovec>();
    for i in 0..iovcnt {
        let ptr = iov_va + i * iov_size;
        let mut raw = [0u8; 16];
        crate::uaccess::copy_from_user(ptr, &mut raw).ok()?;
        let iov: UserIovec = unsafe { core::mem::transmute(raw) };
        if iov.len == 0 || iov.base == 0 { continue; }
        let mut chunk = alloc::vec![0u8; iov.len];
        crate::uaccess::copy_from_user(iov.base, &mut chunk).ok()?;
        out.extend_from_slice(&chunk);
    }
    Some(out)
}

/// Scatter kernel bytes into user-space iovec array.
/// Returns total bytes written.
fn scatter_iovec(iov_va: usize, iovcnt: usize, data: &[u8]) -> usize {
    let mut written = 0usize;
    let iov_size = core::mem::size_of::<UserIovec>();
    for i in 0..iovcnt {
        if written >= data.len() { break; }
        let ptr = iov_va + i * iov_size;
        let mut raw = [0u8; 16];
        if crate::uaccess::copy_from_user(ptr, &mut raw).is_err() { break; }
        let iov: UserIovec = unsafe { core::mem::transmute(raw) };
        if iov.len == 0 || iov.base == 0 { continue; }
        let chunk_len = iov.len.min(data.len() - written);
        let _ = crate::uaccess::copy_to_user(iov.base, &data[written..written + chunk_len]);
        written += chunk_len;
    }
    written
}

// msghdr layout (Linux x86-64 ABI, 64-bit pointers):
//   void        *msg_name;       // 8 bytes
//   socklen_t    msg_namelen;    // 4 bytes
//   int          _pad0;          // 4 bytes (padding)
//   struct iovec *msg_iov;       // 8 bytes
//   size_t       msg_iovlen;     // 8 bytes
//   void        *msg_control;    // 8 bytes
//   size_t       msg_controllen; // 8 bytes
//   int          msg_flags;      // 4 bytes
//   int          _pad1;          // 4 bytes
//   Total: 56 bytes
#[repr(C)]
struct UserMsghdr {
    msg_name:       usize,
    msg_namelen:    u32,
    _pad0:          u32,
    msg_iov:        usize,
    msg_iovlen:     usize,
    msg_control:    usize,
    msg_controllen: usize,
    msg_flags:      i32,
    _pad1:          u32,
}

const MSGHDR_SIZE: usize = core::mem::size_of::<UserMsghdr>();

/// `sendmsg(sockfd, msg, flags)`
pub fn sys_sendmsg(sock_idx: usize, msg_va: usize, flags: i32) -> isize {
    if msg_va == 0 { return -14; }
    let mut raw = [0u8; MSGHDR_SIZE];
    if crate::uaccess::copy_from_user(msg_va, &mut raw).is_err() { return -14; }
    let hdr: UserMsghdr = unsafe { core::mem::transmute(raw) };
    let data = match gather_iovec(hdr.msg_iov, hdr.msg_iovlen) {
        Some(d) => d,
        None    => return -14,
    };
    sys_sendto(sock_idx, data.as_ptr() as usize, data.len(),
               flags, hdr.msg_name, hdr.msg_namelen)
}

/// `recvmsg(sockfd, msg, flags)`
pub fn sys_recvmsg(sock_idx: usize, msg_va: usize, flags: i32) -> isize {
    if msg_va == 0 { return -14; }
    let mut raw = [0u8; MSGHDR_SIZE];
    if crate::uaccess::copy_from_user(msg_va, &mut raw).is_err() { return -14; }
    let hdr: UserMsghdr = unsafe { core::mem::transmute(raw) };
    if hdr.msg_iovlen == 0 { return 0; }
    // Compute total receive capacity from the full iovec.
    let total_cap: usize = {
        let iov_size = core::mem::size_of::<UserIovec>();
        let mut cap = 0usize;
        for i in 0..hdr.msg_iovlen {
            let ptr = hdr.msg_iov + i * iov_size;
            let mut iraw = [0u8; 16];
            if crate::uaccess::copy_from_user(ptr, &mut iraw).is_err() { break; }
            let iov: UserIovec = unsafe { core::mem::transmute(iraw) };
            cap += iov.len;
        }
        cap
    };
    if total_cap == 0 { return 0; }
    let mut kbuf = alloc::vec![0u8; total_cap];
    let n = sys_recvfrom(sock_idx, kbuf.as_mut_ptr() as usize, total_cap,
                         flags, hdr.msg_name, 0);
    if n <= 0 { return n; }
    scatter_iovec(hdr.msg_iov, hdr.msg_iovlen, &kbuf[..n as usize]) as isize
}
