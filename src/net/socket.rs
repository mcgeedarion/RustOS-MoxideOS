//! BSD socket layer.
//!
//! ## Supported address families
//!
//!   AF_UNIX   (1) — SOCK_STREAM unix socket pairs (Wayland, IPC)
//!   AF_INET   (2) — SOCK_STREAM (TCP) + SOCK_DGRAM (UDP) over IPv4
//!   AF_INET6  (10) — SOCK_STREAM (TCP stub) + SOCK_DGRAM (UDP) over IPv6
//!
//! ## Dual-stack
//!
//! IPv6 sockets use `sockaddr_in6` (28 bytes).  The `SockAddr` enum unifies
//! the address representation internally so all send/recv paths can branch
//! on `AF_INET` vs `AF_INET6` without storing separate fields.
//!
//! IPv6 UDP send/recv is fully functional.  IPv6 TCP is a stub that returns
//! -ENOSYS until a tcp6 module is added.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::net::{ip, tcp, udp, ipv6};

// ── Domain / type constants (Linux ABI) ──────────────────────────────────────

pub const AF_UNIX:    i32 = 1;
pub const AF_INET:    i32 = 2;
pub const AF_INET6:   i32 = 10;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM:  i32 = 2;
pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;
pub const IPPROTO_IPV6: i32 = 41;

// IPV6 socket options
pub const IPV6_V6ONLY: i32 = 26;

// ── Unified address type ─────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum SockAddr {
    Unbound,
    V4   { ip: u32,                port: u16 },
    V6   { ip: ipv6::Addr6,        port: u16, flowinfo: u32, scope_id: u32 },
    Unix { path: String },
}

impl SockAddr {
    pub fn port(&self) -> u16 {
        match self { SockAddr::V4 { port, .. } | SockAddr::V6 { port, .. } => *port, _ => 0 }
    }
    pub fn is_unbound(&self) -> bool { matches!(self, SockAddr::Unbound) }
}

// ── Unix socket pipe-pair ────────────────────────────────────────────────────

struct UnixPipe {
    buf:    VecDeque<u8>,
    closed: bool,
}

struct UnixConn {
    rx: alloc::sync::Arc<Mutex<UnixPipe>>,
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
    fn write(&self, data: &[u8]) { self.tx.lock().buf.extend(data.iter().copied()); }
    fn read(&self, len: usize) -> Vec<u8> {
        let mut p = self.rx.lock();
        let n = len.min(p.buf.len());
        p.buf.drain(..n).collect()
    }
    fn is_readable(&self) -> bool {
        let p = self.rx.lock();
        !p.buf.is_empty() || p.closed
    }
    fn close_tx(&self) { self.tx.lock().closed = true; }
}

// ── Unix listening socket ─────────────────────────────────────────────────────

struct PendingUnix { server_conn: UnixConn }

struct UnixListener {
    backlog:     VecDeque<PendingUnix>,
    max_backlog: usize,
}

// ── Socket state ─────────────────────────────────────────────────────────────

pub enum SocketState {
    Udp4      { local_port: u16, rx_queue: VecDeque<UdpDatagram4> },
    Udp6      { local_port: u16, rx_queue: VecDeque<UdpDatagram6> },
    TcpActive { conn_idx: usize },
    TcpListen { listen_idx: usize },
    UnixConn(UnixConn),
    UnixListen { path: String },
    Unbound,
}

pub struct UdpDatagram4 {
    pub src_ip:   u32,
    pub src_port: u16,
    pub data:     Vec<u8>,
}

pub struct UdpDatagram6 {
    pub src_ip:   ipv6::Addr6,
    pub src_port: u16,
    pub data:     Vec<u8>,
}

pub struct Socket {
    pub domain:      i32,
    pub kind:        i32,
    pub proto:       i32,
    pub state:       SocketState,
    pub local:       SockAddr,
    pub peer:        SockAddr,
    pub nonblocking: bool,
    pub v6only:      bool,   // IPV6_V6ONLY — don't accept mapped IPv4
}

impl Socket {
    fn new(domain: i32, kind: i32, proto: i32) -> Self {
        Socket {
            domain, kind, proto,
            state:       SocketState::Unbound,
            local:       SockAddr::Unbound,
            peer:        SockAddr::Unbound,
            nonblocking: false,
            v6only:      false,
        }
    }
    // Compatibility shims used in legacy code paths.
    pub fn local_port(&self) -> u16  { self.local.port() }
    pub fn peer_ip4(&self) -> u32    { if let SockAddr::V4 { ip, .. } = self.peer { ip } else { 0 } }
    pub fn peer_port(&self) -> u16   { self.peer.port() }
}

// ── Global tables ─────────────────────────────────────────────────────────────

/// Combined socket table (AF_INET, AF_INET6, AF_UNIX all share one table).
pub static SOCKETS: Mutex<Vec<Option<Socket>>> = Mutex::new(Vec::new());
/// Back-compat alias used by legacy udp demux code.
pub use SOCKETS as UDP_SOCKETS;

static UNIX_LISTENERS: Mutex<BTreeMap<String, UnixListener>> = Mutex::new(BTreeMap::new());

static EPHEMERAL: Mutex<u16> = Mutex::new(49152);
fn next_ephemeral() -> u16 {
    let mut e = EPHEMERAL.lock();
    let p = *e;
    *e = if p >= 65534 { 49152 } else { p + 1 };
    p
}

// ── sockaddr readers ──────────────────────────────────────────────────────────

/// Read a `sockaddr_in` (16 bytes) from userspace.  Returns (port, ip).
fn read_sockaddr_in(va: usize) -> Option<(u16, u32)> {
    let mut buf = [0u8; 16];
    crate::uaccess::copy_from_user(va, &mut buf).ok()?;
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let ip   = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    Some((port, ip))
}

/// Read a `sockaddr_in6` (28 bytes) from userspace.
/// Layout: sin6_family(2) + sin6_port(2) + sin6_flowinfo(4) + sin6_addr(16) + sin6_scope_id(4)
fn read_sockaddr_in6(va: usize) -> Option<(u16, ipv6::Addr6, u32, u32)> {
    let mut buf = [0u8; 28];
    crate::uaccess::copy_from_user(va, &mut buf).ok()?;
    let port      = u16::from_be_bytes([buf[2], buf[3]]);
    let flowinfo  = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let ip: ipv6::Addr6 = buf[8..24].try_into().ok()?;
    let scope_id  = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
    Some((port, ip, flowinfo, scope_id))
}

/// Write a `sockaddr_in` to userspace.
fn write_sockaddr_in(va: usize, ip: u32, port: u16) {
    let mut addr = [0u8; 16];
    addr[1] = AF_INET as u8;
    addr[2] = (port >> 8) as u8;
    addr[3] = port as u8;
    addr[4..8].copy_from_slice(&ip.to_be_bytes());
    let _ = crate::uaccess::copy_to_user(va, &addr);
}

/// Write a `sockaddr_in6` to userspace.
fn write_sockaddr_in6(va: usize, ip: &ipv6::Addr6, port: u16, flowinfo: u32, scope_id: u32) {
    let mut buf = [0u8; 28];
    buf[1] = AF_INET6 as u8;
    buf[2] = (port >> 8) as u8;
    buf[3] = port as u8;
    buf[4..8].copy_from_slice(&flowinfo.to_be_bytes());
    buf[8..24].copy_from_slice(ip);
    buf[24..28].copy_from_slice(&scope_id.to_be_bytes());
    let _ = crate::uaccess::copy_to_user(va, &buf);
}

// ── UDP demultiplexers ────────────────────────────────────────────────────────

/// Route an incoming IPv4 UDP datagram.
pub fn demux_udp(src_ip: u32, src_port: u16, dst_port: u16, data: &[u8]) {
    if dst_port == crate::net::dhcp::DHCP_CLIENT_PORT {
        crate::net::dhcp::receive(src_ip, data);
        return;
    }
    if src_port == crate::net::dns::DNS_PORT && udp::is_ephemeral(dst_port) {
        crate::net::dns::receive(src_ip, data);
        return;
    }
    let mut table = SOCKETS.lock();
    for slot in table.iter_mut() {
        if let Some(Socket { state: SocketState::Udp4 { local_port, ref mut rx_queue }, .. }) = slot {
            if *local_port == dst_port {
                rx_queue.push_back(UdpDatagram4 { src_ip, src_port, data: data.to_vec() });
                return;
            }
        }
    }
}

/// Route an incoming IPv6 UDP datagram.
pub fn demux_udp6(src_ip: &ipv6::Addr6, src_port: u16, dst_port: u16, data: &[u8]) {
    let mut table = SOCKETS.lock();
    for slot in table.iter_mut() {
        if let Some(Socket { state: SocketState::Udp6 { local_port, ref mut rx_queue }, .. }) = slot {
            if *local_port == dst_port {
                rx_queue.push_back(UdpDatagram6 {
                    src_ip: *src_ip,
                    src_port,
                    data: data.to_vec(),
                });
                return;
            }
        }
    }
}

// ── Slot allocator ────────────────────────────────────────────────────────────

fn alloc_slot(table: &mut Vec<Option<Socket>>, s: Socket) -> usize {
    if let Some(i) = table.iter().position(|x| x.is_none()) {
        table[i] = Some(s); i
    } else {
        table.push(Some(s)); table.len() - 1
    }
}

// ── sys_socket ────────────────────────────────────────────────────────────────

pub fn sys_socket(domain: i32, kind: i32, proto: i32) -> isize {
    match domain {
        d if d == AF_INET || d == AF_INET6 || d == AF_UNIX => {}
        _ => return -97, // EAFNOSUPPORT
    }
    match kind & 0xF {
        k if k == SOCK_STREAM || k == SOCK_DGRAM => {}
        _ => return -22, // EINVAL
    }
    let mut sock = Socket::new(domain, kind & 0xF, proto);
    sock.nonblocking = (kind & 0x800) != 0; // SOCK_NONBLOCK
    let mut table = SOCKETS.lock();
    alloc_slot(&mut table, sock) as isize
}

// ── sys_bind ──────────────────────────────────────────────────────────────────

pub fn sys_bind(sock_idx: usize, addr_va: usize, addrlen: u32) -> isize {
    let mut hdr = [0u8; 2];
    if crate::uaccess::copy_from_user(addr_va, &mut hdr).is_err() { return -14; }
    let family = u16::from_ne_bytes(hdr) as i32;

    let mut table = SOCKETS.lock();
    let sock = match table.get_mut(sock_idx).and_then(|s| s.as_mut()) {
        Some(s) => s, None => return -9,
    };

    match family {
        f if f == AF_UNIX => {
            let mut sun = [0u8; 110];
            let _ = crate::uaccess::copy_from_user(addr_va, &mut sun);
            let path_bytes = &sun[2..];
            let nul = path_bytes.iter().position(|&b| b == 0).unwrap_or(108);
            let path = match core::str::from_utf8(&path_bytes[..nul]) {
                Ok(p) => p, Err(_) => return -22,
            };
            let mut listeners = UNIX_LISTENERS.lock();
            listeners.entry(path.into()).or_insert_with(|| UnixListener {
                backlog: VecDeque::new(), max_backlog: 128,
            });
            sock.state = SocketState::UnixListen { path: path.into() };
            sock.local = SockAddr::Unix { path: path.into() };
            0
        }
        f if f == AF_INET => {
            let (port, ip) = match read_sockaddr_in(addr_va) {
                Some(v) => v, None => return -14,
            };
            sock.local = SockAddr::V4 { ip, port };
            if sock.kind == SOCK_DGRAM {
                sock.state = SocketState::Udp4 { local_port: port, rx_queue: VecDeque::new() };
                crate::net::udp::register_port(port, sock_idx);
            }
            0
        }
        f if f == AF_INET6 => {
            let (port, ip, flowinfo, scope_id) = match read_sockaddr_in6(addr_va) {
                Some(v) => v, None => return -14,
            };
            sock.local = SockAddr::V6 { ip, port, flowinfo, scope_id };
            if sock.kind == SOCK_DGRAM {
                sock.state = SocketState::Udp6 { local_port: port, rx_queue: VecDeque::new() };
            }
            0
        }
        _ => -22,
    }
}

// ── sys_listen ────────────────────────────────────────────────────────────────

pub fn sys_listen(sock_idx: usize, backlog: i32) -> isize {
    let table = SOCKETS.lock();
    let sock = match table.get(sock_idx).and_then(|s| s.as_ref()) {
        Some(s) => s, None => return -9,
    };
    if let SocketState::UnixListen { ref path } = sock.state {
        let path = path.clone();
        drop(table);
        let mut listeners = UNIX_LISTENERS.lock();
        if let Some(l) = listeners.get_mut(path.as_str()) {
            l.max_backlog = backlog.max(1) as usize;
        }
        return 0;
    }
    if (sock.domain == AF_INET || sock.domain == AF_INET6) && sock.kind == SOCK_STREAM {
        let port = sock.local.port();
        drop(table);
        let idx = crate::net::tcp::listen(port);
        let mut t2 = SOCKETS.lock();
        if let Some(Some(s)) = t2.get_mut(sock_idx) {
            s.state = SocketState::TcpListen { listen_idx: idx };
        }
        return 0;
    }
    0
}

// ── sys_accept ────────────────────────────────────────────────────────────────

pub fn sys_accept(sock_idx: usize, addr_va: usize, addrlen_va: usize) -> isize {
    // AF_UNIX
    {
        let table = SOCKETS.lock();
        if let Some(Some(sock)) = table.get(sock_idx) {
            if let SocketState::UnixListen { ref path } = sock.state {
                let path = path.clone();
                drop(table);
                loop {
                    let conn = {
                        let mut listeners = UNIX_LISTENERS.lock();
                        listeners.get_mut(path.as_str())
                            .and_then(|l| l.backlog.pop_front())
                            .map(|p| p.server_conn)
                    };
                    if let Some(server_conn) = conn {
                        let new_sock = Socket {
                            domain: AF_UNIX, kind: SOCK_STREAM, proto: 0,
                            state: SocketState::UnixConn(server_conn),
                            local: SockAddr::Unbound, peer: SockAddr::Unbound,
                            nonblocking: false, v6only: false,
                        };
                        let new_idx = alloc_slot(&mut SOCKETS.lock(), new_sock);
                        if addr_va != 0 {
                            let _ = crate::uaccess::copy_to_user(addr_va, &[AF_UNIX as u8, 0u8]);
                            if addrlen_va != 0 {
                                let _ = crate::uaccess::copy_to_user(addrlen_va, &2u32.to_ne_bytes());
                            }
                        }
                        return new_idx as isize;
                    }
                    crate::proc::scheduler::yield_now();
                    if SOCKETS.lock().get(sock_idx).and_then(|s| s.as_ref())
                        .map(|s| s.nonblocking).unwrap_or(false) { return -11; }
                }
            }
        }
    }

    // AF_INET TCP
    let listen_idx = {
        let table = SOCKETS.lock();
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
                local: SockAddr::Unbound,
                peer:  SockAddr::V4 { ip: peer_ip, port: peer_port },
                nonblocking: false, v6only: false,
            };
            let new_idx = alloc_slot(&mut SOCKETS.lock(), new_sock);
            if addr_va != 0 {
                write_sockaddr_in(addr_va, peer_ip, peer_port);
                if addrlen_va != 0 {
                    let _ = crate::uaccess::copy_to_user(addrlen_va, &16u32.to_ne_bytes());
                }
            }
            return new_idx as isize;
        }
        crate::proc::scheduler::yield_now();
        if SOCKETS.lock().get(sock_idx).and_then(|s| s.as_ref())
            .map(|s| s.nonblocking).unwrap_or(false) { return -11; }
    }
}

// ── sys_connect ───────────────────────────────────────────────────────────────

pub fn sys_connect(sock_idx: usize, addr_va: usize, _addrlen: u32) -> isize {
    let mut hdr = [0u8; 2];
    if crate::uaccess::copy_from_user(addr_va, &mut hdr).is_err() { return -14; }
    let family = u16::from_ne_bytes(hdr) as i32;

    match family {
        f if f == AF_UNIX => {
            let mut sun = [0u8; 110];
            let _ = crate::uaccess::copy_from_user(addr_va, &mut sun);
            let path_bytes = &sun[2..];
            let nul = path_bytes.iter().position(|&b| b == 0).unwrap_or(108);
            let path = match core::str::from_utf8(&path_bytes[..nul]) {
                Ok(p) => p, Err(_) => return -22,
            };
            let (conn_a, conn_b) = UnixConn::new_pair();
            {
                let mut listeners = UNIX_LISTENERS.lock();
                let l = match listeners.get_mut(path) { Some(l) => l, None => return -111 };
                if l.backlog.len() >= l.max_backlog { return -111; }
                l.backlog.push_back(PendingUnix { server_conn: conn_a });
            }
            let mut table = SOCKETS.lock();
            if let Some(Some(sock)) = table.get_mut(sock_idx) {
                sock.state = SocketState::UnixConn(conn_b);
                sock.peer  = SockAddr::Unix { path: path.into() };
                return 0;
            }
            -9
        }
        f if f == AF_INET => {
            let (port, dst_ip) = match read_sockaddr_in(addr_va) {
                Some(v) => v, None => return -14,
            };
            let kind = SOCKETS.lock().get(sock_idx).and_then(|s| s.as_ref()).map(|s| s.kind).unwrap_or(-1);
            if kind == SOCK_STREAM {
                let src_port = next_ephemeral();
                let conn_idx = match crate::net::tcp::connect(dst_ip, port, src_port) {
                    Ok(i) => i, Err(e) => return e,
                };
                let mut table = SOCKETS.lock();
                if let Some(Some(sock)) = table.get_mut(sock_idx) {
                    sock.state = SocketState::TcpActive { conn_idx };
                    sock.local = SockAddr::V4 { ip: ip::our_ip(), port: src_port };
                    sock.peer  = SockAddr::V4 { ip: dst_ip, port };
                }
                return 0;
            }
            if kind == SOCK_DGRAM {
                let mut table = SOCKETS.lock();
                if let Some(Some(sock)) = table.get_mut(sock_idx) {
                    sock.peer = SockAddr::V4 { ip: dst_ip, port };
                    if sock.local.is_unbound() {
                        let lp = next_ephemeral();
                        sock.local = SockAddr::V4 { ip: ip::our_ip(), port: lp };
                        sock.state = SocketState::Udp4 { local_port: lp, rx_queue: VecDeque::new() };
                        crate::net::udp::register_port(lp, sock_idx);
                    }
                }
                return 0;
            }
            -22
        }
        f if f == AF_INET6 => {
            let (port, dst_ip, flowinfo, scope_id) = match read_sockaddr_in6(addr_va) {
                Some(v) => v, None => return -14,
            };
            let kind = SOCKETS.lock().get(sock_idx).and_then(|s| s.as_ref()).map(|s| s.kind).unwrap_or(-1);
            if kind == SOCK_STREAM {
                // TCP over IPv6 — stub until tcp6 module is added.
                return -38; // ENOSYS
            }
            if kind == SOCK_DGRAM {
                let mut table = SOCKETS.lock();
                if let Some(Some(sock)) = table.get_mut(sock_idx) {
                    sock.peer = SockAddr::V6 { ip: dst_ip, port, flowinfo, scope_id };
                    if sock.local.is_unbound() {
                        let lp = next_ephemeral();
                        sock.local = SockAddr::V6 { ip: ipv6::our_ip6(), port: lp, flowinfo: 0, scope_id: 0 };
                        sock.state = SocketState::Udp6 { local_port: lp, rx_queue: VecDeque::new() };
                    }
                }
                return 0;
            }
            -22
        }
        _ => -22,
    }
}

// ── sys_sendto ────────────────────────────────────────────────────────────────

pub fn sys_send(sock_idx: usize, buf_va: usize, len: usize, flags: i32) -> isize {
    sys_sendto(sock_idx, buf_va, len, flags, 0, 0)
}

pub fn sys_sendto(sock_idx: usize, buf_va: usize, len: usize, _flags: i32,
                  dest_addr: usize, addrlen: u32) -> isize {
    if len == 0 { return 0; }
    if !crate::uaccess::validate_user_ptr(buf_va, len) { return -14; }
    let mut kbuf = alloc::vec![0u8; len];
    if crate::uaccess::copy_from_user(buf_va, &mut kbuf).is_err() { return -14; }

    let table = SOCKETS.lock();
    let sock = match table.get(sock_idx).and_then(|s| s.as_ref()) {
        Some(s) => s, None => return -9,
    };

    match &sock.state {
        SocketState::UnixConn(conn) => { conn.write(&kbuf); len as isize }

        SocketState::TcpActive { conn_idx } => {
            let idx = *conn_idx;
            drop(table);
            crate::net::tcp::send(idx, &kbuf)
        }

        SocketState::Udp4 { local_port, .. } => {
            let lp = *local_port;
            let (dst_ip, dst_port) = if dest_addr != 0 && addrlen >= 8 {
                drop(table);
                match read_sockaddr_in(dest_addr) {
                    Some((p, ip)) => (ip, p),
                    None          => return -14,
                }
            } else {
                let peer = sock.peer.clone();
                drop(table);
                match peer { SockAddr::V4 { ip, port } => (ip, port), _ => return -107 }
            };
            if dst_ip == 0 || dst_port == 0 { return -107; }
            udp::send(lp, dst_ip, dst_port, &kbuf);
            len as isize
        }

        SocketState::Udp6 { local_port, .. } => {
            let lp = *local_port;
            let (dst_ip, dst_port) = if dest_addr != 0 && addrlen >= 8 {
                drop(table);
                match read_sockaddr_in6(dest_addr) {
                    Some((p, ip, _, _)) => (ip, p),
                    None => return -14,
                }
            } else {
                let peer = sock.peer.clone();
                drop(table);
                match peer { SockAddr::V6 { ip, port, .. } => (ip, port), _ => return -107 }
            };
            if dst_port == 0 { return -107; }
            udp::send6(lp, &dst_ip, dst_port, &kbuf);
            len as isize
        }

        _ => -107, // ENOTCONN
    }
}

// ── sys_recvfrom ──────────────────────────────────────────────────────────────

pub fn sys_recv(sock_idx: usize, buf_va: usize, len: usize, flags: i32) -> isize {
    sys_recvfrom(sock_idx, buf_va, len, flags, 0, 0)
}

pub fn sys_recvfrom(sock_idx: usize, buf_va: usize, len: usize, _flags: i32,
                    src_addr: usize, addrlen_va: usize) -> isize {
    if len == 0 { return 0; }
    if !crate::uaccess::validate_user_ptr(buf_va, len) { return -14; }

    loop {
        enum RecvData {
            Bytes(Vec<u8>),
            Udp4(Vec<u8>, u32, u16),
            Udp6(Vec<u8>, ipv6::Addr6, u16),
        }

        let result: RecvData = {
            let table = SOCKETS.lock();
            let sock = match table.get(sock_idx).and_then(|s| s.as_ref()) {
                Some(s) => s, None => return -9,
            };
            match &sock.state {
                SocketState::UnixConn(conn) => {
                    let d = conn.read(len);
                    if d.is_empty() {
                        if conn.rx.lock().closed { return 0; }
                        if sock.nonblocking { return -11; }
                        drop(table);
                        crate::proc::scheduler::yield_now();
                        continue;
                    }
                    RecvData::Bytes(d)
                }
                SocketState::TcpActive { conn_idx } => {
                    let idx = *conn_idx;
                    let nb  = sock.nonblocking;
                    drop(table);
                    let mut kbuf = alloc::vec![0u8; len];
                    let n = crate::net::tcp::recv(idx, &mut kbuf);
                    if n == 0 {
                        if nb { return -11; }
                        crate::proc::scheduler::yield_now();
                        continue;
                    }
                    if n < 0 { return n; }
                    kbuf.truncate(n as usize);
                    let r = crate::uaccess::copy_to_user(buf_va, &kbuf);
                    return if r.is_err() { -14 } else { n };
                }
                SocketState::Udp4 { .. } => {
                    let nb = sock.nonblocking;
                    drop(table);
                    let dg = {
                        let mut t2 = SOCKETS.lock();
                        if let Some(Some(Socket { state: SocketState::Udp4 { ref mut rx_queue, .. }, .. })) = t2.get_mut(sock_idx) {
                            rx_queue.pop_front()
                        } else { None }
                    };
                    match dg {
                        Some(d) => RecvData::Udp4(d.data, d.src_ip, d.src_port),
                        None => {
                            if nb { return -11; }
                            crate::proc::scheduler::yield_now();
                            continue;
                        }
                    }
                }
                SocketState::Udp6 { .. } => {
                    let nb = sock.nonblocking;
                    drop(table);
                    let dg = {
                        let mut t2 = SOCKETS.lock();
                        if let Some(Some(Socket { state: SocketState::Udp6 { ref mut rx_queue, .. }, .. })) = t2.get_mut(sock_idx) {
                            rx_queue.pop_front()
                        } else { None }
                    };
                    match dg {
                        Some(d) => RecvData::Udp6(d.data, d.src_ip, d.src_port),
                        None => {
                            if nb { return -11; }
                            crate::proc::scheduler::yield_now();
                            continue;
                        }
                    }
                }
                _ => return -107,
            }
        };

        return match result {
            RecvData::Bytes(data) => {
                let n = data.len().min(len);
                if crate::uaccess::copy_to_user(buf_va, &data[..n]).is_err() { -14 } else { n as isize }
            }
            RecvData::Udp4(data, from_ip, from_port) => {
                let n = data.len().min(len);
                if crate::uaccess::copy_to_user(buf_va, &data[..n]).is_err() { return -14; }
                if src_addr != 0 {
                    write_sockaddr_in(src_addr, from_ip, from_port);
                    if addrlen_va != 0 {
                        let _ = crate::uaccess::copy_to_user(addrlen_va, &16u32.to_ne_bytes());
                    }
                }
                n as isize
            }
            RecvData::Udp6(data, from_ip, from_port) => {
                let n = data.len().min(len);
                if crate::uaccess::copy_to_user(buf_va, &data[..n]).is_err() { return -14; }
                if src_addr != 0 {
                    write_sockaddr_in6(src_addr, &from_ip, from_port, 0, 0);
                    if addrlen_va != 0 {
                        let _ = crate::uaccess::copy_to_user(addrlen_va, &28u32.to_ne_bytes());
                    }
                }
                n as isize
            }
        };
    }
}

// ── sys_getsockname / sys_getpeername ─────────────────────────────────────────

pub fn sys_getsockname(sock_idx: usize, addr_va: usize, _addrlen_va: usize) -> isize {
    let table = SOCKETS.lock();
    let sock = match table.get(sock_idx).and_then(|s| s.as_ref()) { Some(s) => s, None => return -9 };
    match &sock.local {
        SockAddr::V4 { ip, port }                => { write_sockaddr_in(addr_va, *ip, *port); 0 }
        SockAddr::V6 { ip, port, flowinfo, scope_id } => { write_sockaddr_in6(addr_va, ip, *port, *flowinfo, *scope_id); 0 }
        SockAddr::Unix { .. }                    => { let _ = crate::uaccess::copy_to_user(addr_va, &[AF_UNIX as u8, 0u8]); 0 }
        SockAddr::Unbound                        => 0,
    }
}

pub fn sys_getpeername(sock_idx: usize, addr_va: usize, _addrlen_va: usize) -> isize {
    let table = SOCKETS.lock();
    let sock = match table.get(sock_idx).and_then(|s| s.as_ref()) { Some(s) => s, None => return -9 };
    match &sock.peer {
        SockAddr::V4 { ip, port }                => { write_sockaddr_in(addr_va, *ip, *port); 0 }
        SockAddr::V6 { ip, port, flowinfo, scope_id } => { write_sockaddr_in6(addr_va, ip, *port, *flowinfo, *scope_id); 0 }
        _ => 0,
    }
}

// ── sys_setsockopt ────────────────────────────────────────────────────────────

pub fn sys_setsockopt(sock_idx: usize, level: i32, opt: i32,
                      optval_va: usize, optlen: u32) -> isize {
    let mut table = SOCKETS.lock();
    let sock = match table.get_mut(sock_idx).and_then(|s| s.as_mut()) { Some(s) => s, None => return -9 };
    match (level, opt) {
        (_, 0x8004) if optlen >= 4 => {
            let mut v = [0u8; 4];
            if crate::uaccess::copy_from_user(optval_va, &mut v).is_ok() {
                sock.nonblocking = u32::from_ne_bytes(v) != 0;
            }
        }
        (l, o) if l == IPPROTO_IPV6 && o == IPV6_V6ONLY => {
            if optlen >= 4 {
                let mut v = [0u8; 4];
                if crate::uaccess::copy_from_user(optval_va, &mut v).is_ok() {
                    sock.v6only = u32::from_ne_bytes(v) != 0;
                }
            }
        }
        _ => {}
    }
    0
}

pub fn sys_getsockopt(_sock_idx: usize, _level: i32, _opt: i32,
                      _optval_va: usize, _optlen_va: usize) -> isize { 0 }

// ── sys_close_socket ─────────────────────────────────────────────────────────

pub fn sys_close_socket(sock_idx: usize) {
    let mut table = SOCKETS.lock();
    if let Some(slot) = table.get_mut(sock_idx) {
        if let Some(Socket { state: SocketState::UnixConn(ref conn), .. }) = *slot {
            conn.close_tx();
        }
        *slot = None;
    }
}

// ── Socket FD bridge helpers ──────────────────────────────────────────────────

pub fn is_socket_fd(fd: usize) -> bool {
    let t = SOCKETS.lock();
    fd < t.len() && t[fd].is_some()
}

pub fn socket_read(fd: usize, buf: &mut [u8]) -> isize {
    sys_recv(fd, buf.as_mut_ptr() as usize, buf.len(), 0)
}

pub fn socket_write(fd: usize, buf: &[u8]) -> isize {
    sys_send(fd, buf.as_ptr() as usize, buf.len(), 0)
}

pub fn socket_poll(fd: usize, events: u32) -> Option<u32> {
    let table = SOCKETS.lock();
    let sock = table.get(fd)?.as_ref()?;
    let (readable, writable) = match &sock.state {
        SocketState::UnixConn(conn)           => (conn.is_readable(), true),
        SocketState::UnixListen { path }      => {
            let l = UNIX_LISTENERS.lock();
            (l.get(path.as_str()).map(|x| !x.backlog.is_empty()).unwrap_or(false), false)
        }
        SocketState::Udp4 { rx_queue, .. }    => (!rx_queue.is_empty(), true),
        SocketState::Udp6 { rx_queue, .. }    => (!rx_queue.is_empty(), true),
        SocketState::TcpActive { conn_idx }   => (crate::net::tcp::rx_available(*conn_idx), true),
        SocketState::TcpListen { .. }         => (false, false),
        SocketState::Unbound                  => (false, true),
    };
    use crate::fs::poll::{POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};
    let mut r = 0u32;
    if readable && events & POLLIN  != 0 { r |= POLLIN  | POLLRDNORM; }
    if writable && events & POLLOUT != 0 { r |= POLLOUT | POLLWRNORM; }
    Some(r)
}

// ── sys_shutdown ─────────────────────────────────────────────────────────────

pub fn sys_shutdown(sock_idx: usize, how: i32) -> isize {
    let mut table = SOCKETS.lock();
    let sock = match table.get_mut(sock_idx).and_then(|s| s.as_mut()) { Some(s) => s, None => return -9 };
    match &sock.state {
        SocketState::UnixConn(conn) => { if how == 1 || how == 2 { conn.close_tx(); } }
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

// ── sys_socketpair ────────────────────────────────────────────────────────────

pub fn sys_socketpair(domain: i32, kind: i32, _proto: i32, sv_va: usize) -> isize {
    if domain != AF_UNIX         { return -97; }
    if kind & 0xF != SOCK_STREAM { return -22; }
    if sv_va == 0                { return -14; }
    let (conn_a, conn_b) = UnixConn::new_pair();
    let make_sock = |conn: UnixConn| -> Socket {
        Socket {
            domain: AF_UNIX, kind: SOCK_STREAM, proto: 0,
            state: SocketState::UnixConn(conn),
            local: SockAddr::Unbound, peer: SockAddr::Unbound,
            nonblocking: (kind & 0x800) != 0, v6only: false,
        }
    };
    let mut table = SOCKETS.lock();
    let fd0 = alloc_slot(&mut table, make_sock(conn_a));
    let fd1 = alloc_slot(&mut table, make_sock(conn_b));
    drop(table);
    if kind & 0x80000 != 0 {
        crate::fs::fcntl::set_cloexec(fd0, true);
        crate::fs::fcntl::set_cloexec(fd1, true);
    }
    let pair = [fd0 as i32, fd1 as i32];
    let bytes: [u8; 8] = unsafe { core::mem::transmute(pair) };
    if crate::uaccess::copy_to_user(sv_va, &bytes).is_err() { return -14; }
    0
}

// ── sys_sendmsg / sys_recvmsg ─────────────────────────────────────────────────

#[repr(C)]
struct UserIovec { base: usize, len: usize }

fn gather_iovec(iov_va: usize, iovcnt: usize) -> Option<Vec<u8>> {
    let iov_size = core::mem::size_of::<UserIovec>();
    let mut out = Vec::new();
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

fn scatter_iovec(iov_va: usize, iovcnt: usize, data: &[u8]) -> usize {
    let iov_size = core::mem::size_of::<UserIovec>();
    let mut written = 0usize;
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

pub fn sys_sendmsg(sock_idx: usize, msg_va: usize, flags: i32) -> isize {
    if msg_va == 0 { return -14; }
    let mut raw = [0u8; core::mem::size_of::<UserMsghdr>()];
    if crate::uaccess::copy_from_user(msg_va, &mut raw).is_err() { return -14; }
    let hdr: UserMsghdr = unsafe { core::mem::transmute(raw) };
    let data = match gather_iovec(hdr.msg_iov, hdr.msg_iovlen) {
        Some(d) => d, None => return -14,
    };
    sys_sendto(sock_idx, data.as_ptr() as usize, data.len(), flags, hdr.msg_name, hdr.msg_namelen)
}

pub fn sys_recvmsg(sock_idx: usize, msg_va: usize, flags: i32) -> isize {
    if msg_va == 0 { return -14; }
    let mut raw = [0u8; core::mem::size_of::<UserMsghdr>()];
    if crate::uaccess::copy_from_user(msg_va, &mut raw).is_err() { return -14; }
    let hdr: UserMsghdr = unsafe { core::mem::transmute(raw) };
  