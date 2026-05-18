extern crate alloc;
use alloc::string::String;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use spin::Mutex;
use super::buffer::{UnixConn, UnixListener};

pub const AF_INET:  u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_UNIX:  u16 = 1;

pub const SOCK_STREAM: u16 = 1;
pub const SOCK_DGRAM:  u16 = 2;
pub const SOCK_RAW:    u16 = 3;

pub const SOL_SOCKET:   u32 = 1;
pub const SO_REUSEADDR: u32 = 2;
pub const SO_KEEPALIVE: u32 = 9;
pub const SO_ERROR:     u32 = 4;

pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;

pub const MSG_PEEK:    u32 = 2;
pub const MSG_DONTWAIT:u32 = 64;

pub const SHUT_RD:   u32 = 0;
pub const SHUT_WR:   u32 = 1;
pub const SHUT_RDWR: u32 = 2;

pub const MAX_SOCKETS: usize = 4096;

#[derive(Clone, Debug)]
pub enum SockAddr {
    V4 { ip: u32, port: u16 },
    V6 { ip: [u8; 16], port: u16, flowinfo: u32, scope_id: u32 },
    Unix(String),
}

#[derive(Clone, Debug, PartialEq)]
pub enum SocketState {
    Unbound,
    Bound,
    Listening,
    Connecting,
    Connected,
    Closed,
}

pub struct Socket {
    pub domain:   u16,
    pub kind:     u16,
    pub protocol: u32,
    pub state:    SocketState,
    pub local:    Option<SockAddr>,
    pub peer:     Option<SockAddr>,
    /// TCP stream id (from crate::net::tcp)
    pub tcp_id:   Option<u64>,
    /// UDP receive queue
    pub udp_rx:   VecDeque<(u32, u16, alloc::vec::Vec<u8>)>,
    pub nonblock: bool,
    pub reuse_addr: bool,
    pub keepalive:  bool,
    /// For AF_UNIX connected sockets
    pub unix_conn:  Option<Arc<UnixConn>>,
    /// For AF_UNIX listening sockets
    pub unix_listener: Option<Arc<Mutex<UnixListener>>>,
    pub so_error:   i32,
}