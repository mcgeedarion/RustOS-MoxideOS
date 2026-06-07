//! BSD socket layer — submodule tree.
//!
//! See individual submodules for details.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub mod address;
pub mod buffer;
pub mod core;
pub mod poll;
pub mod syscalls;
pub mod tcp;
pub mod traits;
pub mod types;
pub mod udp;
pub mod unix;

/// Re-export the UDP demux entry point at the socket-module path so
/// callers can write `crate::net::socket::demux_udp(…)` without going
/// through `udp::`.
pub use udp::demux_udp;

pub use types::{
    SockAddr, Socket, SocketState, AF_INET, AF_INET6, AF_UNIX, IPPROTO_TCP, IPPROTO_UDP,
    MAX_SOCKETS, MSG_DONTWAIT, MSG_PEEK, SHUT_RD, SHUT_RDWR, SHUT_WR, SOCK_DGRAM, SOCK_RAW,
    SOCK_STREAM, SOL_SOCKET, SO_ERROR, SO_KEEPALIVE, SO_REUSEADDR,
};

pub use address::{
    next_ephemeral, read_sockaddr_in, read_sockaddr_in6, write_sockaddr_in, write_sockaddr_in6,
};
pub use core::{
    alloc_slot, sys_accept, sys_bind, sys_connect, sys_getpeername, sys_getsockname, sys_listen,
    sys_socket, SOCKETS,
};
pub use poll::{is_socket_fd, socket_poll, socket_read, socket_write};
pub use syscalls::{
    socket_close, socket_dup, sys_close_socket, sys_recvmsg, sys_sendmsg, sys_socketpair,
};
pub use traits::{sys_getsockopt, sys_setsockopt, sys_shutdown};
