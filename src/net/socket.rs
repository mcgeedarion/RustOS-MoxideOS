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

// SOL_SOCKET level
pub const SOL_SOCKET:   i32 = 1;
pub const SO_REUSEADDR: i32 = 2;

// IPPROTO_TCP level
pub const TCP_NODELAY: i32 = 1;


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
        let a_to_b = alloc::sync::Arc::new(Mut