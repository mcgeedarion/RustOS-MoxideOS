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
    let mut raw = [0u8; 110]; // sizeof sockaddr_un = 110
    if crate::uaccess::copy_from_user(&mut raw, addr_va).is_err() { return -14; }
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as i32;

    let mut table = UDP_SOCKETS.lock();
    let sock = match table.get_mut(sock_idx).and_then(|s| s.as_mut()) {
        Some(s) => s,
        None    => return -9, // EBADF
    };

    if family == AF_UNIX {
        // Parse sun_path (NUL-terminated, starts at raw[2])
        let path_bytes = &raw[2..];
        let nul = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
        let path = match core::str::from_utf8(&path_bytes[..nul]) {
            Ok(p) if !p.is_empty() => p,
            _ => return -22, // EINVAL
        };
        let path = String::from(path);
        sock.state = SocketState::UnixListen { path };
        return 0;
    }

    // AF_INET: sockaddr_in {u16 family, u16 port BE, u32 ip BE, [8]pad}
    let port = u16::from_be_bytes([raw[2], raw[3]]);
    sock.local_port = port;
    0
}

/// `listen(sockfd, backlog)`
pub fn sys_listen(sock_idx: usize, backlog: i32) -> isize {
    let mut table = UDP_SOCKETS.lock();
    let sock = match table.get_mut(sock_idx).and_then(|s| s.as_mut()) {
        Some(s) => s,
        None    => return -9,
    };
    if sock.kind != SOCK_STREAM { return -22; }

    match &sock.state {
        SocketState::UnixListen { path } => {
            let path = path.clone();
            let max = (backlog.max(1) as usize).min(1024);
            drop(table);
            UNIX_LISTENERS.lock().insert(path, UnixListener {
                backlog:    VecDeque::new(),
                max_backlog: max,
            });
            return 0;
        }
        _ => {}
    }

    // AF_INET TCP
    let port = if sock.local_port == 0 { next_ephemeral() } else { sock.local_port };
    sock.local_port = port;
    let lidx = tcp::listen(port);
    sock.state = SocketState::TcpListen { listen_idx: lidx };
    0
}

/// `accept(sockfd, addr_va, addrlen_va)` → new sock_idx or errno.
pub fn sys_accept(sock_idx: usize, addr_va: usize, addrlen_va: usize) -> isize {
    let table = UDP_SOCKETS.lock();
    let (is_unix, path_or_idx) = match table.get(sock_idx).and_then(|s| s.as_ref()) {
        Some(s) => match &s.state {
            SocketState::UnixListen { path } => (true, Ok(path.clone())),
            SocketState::TcpListen { listen_idx } => (false, Err(*listen_idx)),
            _ => return -22,
        },
        None => return -9,
    };
    drop(table);

    if is_unix {
        let path = path_or_idx.unwrap();
        // Non-blocking: dequeue the next pending connection from the backlog.
        // If none is ready and the socket is O_NONBLOCK, return -EAGAIN.
        // If blocking (the common case) we yield and retry.
        loop {
            {
                let mut listeners = UNIX_LISTENERS.lock();
                if let Some(listener) = listeners.get_mut(&path) {
                    if let Some(pending) = listener.backlog.pop_front() {
                        // Allocate a new socket slot for the server end.
                        let new_sock = Socket {
                            domain: AF_UNIX, kind: SOCK_STREAM, proto: 0,
                            state: SocketState::UnixConn(pending.server_conn),
                            local_port: 0, peer_ip: 0, peer_port: 0,
                            nonblocking: false,
                        };
                        let mut tbl = UDP_SOCKETS.lock();
                        let idx = if let Some(i) = tbl.iter().position(|s| s.is_none()) {
                            tbl[i] = Some(new_sock); i
                        } else {
                            tbl.push(Some(new_sock)); tbl.len() - 1
                        };
                        // Write a minimal sockaddr_un to user space if requested.
                        if addr_va != 0 {
                            let mut ua = [0u8; 110];
                            let family = AF_UNIX as u16;
                            ua[0..2].copy_from_slice(&family.to_ne_bytes());
                            let _ = crate::uaccess::copy_to_user(addr_va, &ua);
                            if addrlen_va != 0 {
                                let _ = crate::uaccess::copy_to_user(
                                    addrlen_va, &2u32.to_ne_bytes());
                            }
                        }
                        return idx as isize;
                    }
                }
            }
            // Check if socket is O_NONBLOCK.
            {
                let t = UDP_SOCKETS.lock();
                if let Some(Some(s)) = t.get(sock_idx) {
                    if s.nonblocking { return -11; } // EAGAIN
                }
            }
            // Blocking: yield and retry.
            crate::proc::scheduler::schedule();
        }
    }

    // AF_INET TCP
    let listen_idx = path_or_idx.unwrap_err();
    let conn_idx = loop {
        if let Some(ci) = tcp::accept(listen_idx) { break ci; }
        {
            let t = UDP_SOCKETS.lock();
            if let Some(Some(s)) = t.get(sock_idx) {
                if s.nonblocking { return -11; }
            }
        }
        crate::proc::scheduler::schedule();
    };

    if addr_va != 0 {
        let conns = tcp::TCP_CONNS.lock();
        if let Some(c) = conns.get(conn_idx) {
            let mut addr = [0u8; 16];
            addr[0] = 0; addr[1] = AF_INET as u8;
            addr[2] = (c.remote_port >> 8) as u8;
            addr[3] = c.remote_port as u8;
            addr[4..8].copy_from_slice(&c.remote_ip.to_be_bytes());
            let _ = crate::uaccess::copy_to_user(addr_va, &addr);
        }
    }
    let new_sock = Socket {
        domain: AF_INET, kind: SOCK_STREAM, proto: IPPROTO_TCP,
        state: SocketState::TcpActive { conn_idx },
        local_port: 0, peer_ip: 0, peer_port: 0,
        nonblocking: false,
    };
    let mut table = UDP_SOCKETS.lock();
    if let Some(slot) = table.iter().position(|s| s.is_none()) {
        table[slot] = Some(new_sock); return slot as isize;
    }
    table.push(Some(new_sock));
    (table.len() - 1) as isize
}

/// `connect(sockfd, addr_va, addrlen)`
///
/// For `AF_UNIX`: looks up the server path, creates a pipe-pair, pushes
/// the server-side `UnixConn` into the listener's backlog (so `accept()`
/// can dequeue it), and returns the client-side `UnixConn` in `sock.state`.
pub fn sys_connect(sock_idx: usize, addr_va: usize, _addrlen: u32) -> isize {
    let mut raw = [0u8; 110];
    if crate::uaccess::copy_from_user(&mut raw, addr_va).is_err() { return -14; }
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as i32;

    if family == AF_UNIX {
        let path_bytes = &raw[2..];
        let nul = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
        let path = match core::str::from_utf8(&path_bytes[..nul]) {
            Ok(p) if !p.is_empty() => p,
            _ => return -22,
        };
        let (client_conn, server_conn) = UnixConn::new_pair();
        {
            let mut listeners = UNIX_LISTENERS.lock();
            let listener = match listeners.get_mut(path) {
                Some(l) => l,
                None    => return -111, // ECONNREFUSED — no one is listening
            };
            if listener.backlog.len() >= listener.max_backlog {
                return -111; // ECONNREFUSED — backlog full
            }
            listener.backlog.push_back(PendingUnix { server_conn });
        }
        let mut table = UDP_SOCKETS.lock();
        if let Some(Some(sock)) = table.get_mut(sock_idx) {
            sock.state = SocketState::UnixConn(client_conn);
            return 0;
        }
        return -9;
    }

    // AF_INET
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
            let nb = sock.nonblocking;
            drop(table);
            if nb { return -115; } // EINPROGRESS
            loop {
                let conns = tcp::TCP_CONNS.lock();
                let s = conns.get(ci).map(|c| c.state);
                drop(conns);
                match s {
                    Some(tcp::TcpState::Established) => return 0,
                    Some(tcp::TcpState::Closed)      => return -111,
                    None => return -9,
                    _ => crate::proc::scheduler::schedule(),
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
            SocketState::UnixConn(conn) => {
                conn.write(&data);
                return len as isize;
            }
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
                let pp  = sock.peer_port;
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
                  addr_va: usize, addrlen: u32) -> isize {
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
    loop {
        let table = UDP_SOCKETS.lock();
        if let Some(Some(sock)) = table.get(sock_idx) {
            match &sock.state {
                SocketState::UnixConn(conn) => {
                    let data = conn.read(len);
                    if !data.is_empty() {
                        let _ = crate::uaccess::copy_to_user(buf_va, &data);
                        return data.len() as isize;
                    }
                    // Check for EOF (peer closed)
                    if conn.rx.lock().closed { return 0; }
                    let nb = sock.nonblocking;
                    drop(table);
                    if nb { return -11; } // EAGAIN
                    crate::proc::scheduler::schedule();
                    continue;
                }
                SocketState::TcpActive { conn_idx } => {
                    let ci = *conn_idx;
                    drop(table);
                    let mut buf = alloc::vec![0u8; len];
                    let n = tcp::read(ci, &mut buf);
                    if n > 0 {
                        let _ = crate::uaccess::copy_to_user(buf_va, &buf[..n as usize]);
                        return n;
                    }
                    let nb = { let t = UDP_SOCKETS.lock(); t.get(sock_idx).and_then(|s| s.as_ref()).map(|s| s.nonblocking).unwrap_or(false) };
                    if nb { return -11; }
                    crate::proc::scheduler::schedule();
                    continue;
                }
                SocketState::Udp { local_port, .. } => {
                    let lp = *local_port;
                    drop(table);
                    let mut buf = alloc::vec![0u8; len];
                    let n = udp::read(lp, &mut buf);
                    if n > 0 {
                        let _ = crate::uaccess::copy_to_user(buf_va, &buf[..n as usize]);
                        return n;
                    }
                    return -11; // EAGAIN
                }
                _ => return -107,
            }
        }
        return -9;
    }
}

/// `recvfrom(sockfd, buf_va, len, flags, addr_va, addrlen_va)`
pub fn sys_recvfrom(sock_idx: usize, buf_va: usize, len: usize, flags: i32,
                    addr_va: usize, _addrlen_va: usize) -> isize {
    let n = sys_recv(sock_idx, buf_va, len, flags);
    if n <= 0 || addr_va == 0 { return n; }
    let table = UDP_SOCKETS.lock();
    if let Some(Some(sock)) = table.get(sock_idx) {
        if sock.peer_ip != 0 {
            let mut addr = [0u8; 16];
            addr[0] = 0; addr[1] = AF_INET as u8;
            addr[2] = (sock.peer_port >> 8) as u8;
            addr[3] = sock.peer_port as u8;
            addr[4..8].copy_from_slice(&sock.peer_ip.to_be_bytes());
            let _ = crate::uaccess::copy_to_user(addr_va, &addr);
        }
    }
    n
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
        let mut addr = [0u8; 16];
        addr[0] = 0; addr[1] = AF_INET as u8;
        addr[2] = (sock.peer_port >> 8) as u8;
        addr[3] = sock.peer_port as u8;
        addr[4..8].copy_from_slice(&sock.peer_ip.to_be_bytes());
        let _ = crate::uaccess::copy_to_user(addr_va, &addr);
        return 0;
    }
    -9
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
