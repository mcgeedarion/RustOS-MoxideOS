//! BSD socket layer — submodule tree.
//!
//! See individual submodules for details.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub mod types;
pub mod address;
pub mod buffer;
pub mod core;
pub mod traits;
pub mod poll;
pub mod syscalls;
pub mod tcp;
pub mod udp;
pub mod unix;

/// Re-export the UDP demux entry point at the socket-module path so
/// callers can write `crate::net::socket::demux_udp(…)` without going
/// through `udp::`.
pub use udp::demux_udp;

pub use types::{Socket, SockAddr, SocketState, AF_INET, AF_INET6, AF_UNIX,
                SOCK_STREAM, SOCK_DGRAM, SOCK_RAW,
                SOL_SOCKET, SO_REUSEADDR, SO_KEEPALIVE, SO_ERROR,
                IPPROTO_TCP, IPPROTO_UDP, MSG_PEEK, MSG_DONTWAIT,
                SHUT_RD, SHUT_WR, SHUT_RDWR, MAX_SOCKETS};

pub use core::{sys_socket, sys_bind, sys_listen, sys_accept, sys_connect,
               sys_getsockname, sys_getpeername, alloc_slot, SOCKETS};
pub use traits::{sys_setsockopt, sys_getsockopt, sys_shutdown};
pub use poll::{socket_poll, socket_read, socket_write, is_socket_fd};
pub use syscalls::{sys_sendmsg, sys_recvmsg, sys_socketpair, socket_close};
pub use address::{read_sockaddr_in, read_sockaddr_in6,
                  write_sockaddr_in, write_sockaddr_in6, next_ephemeral};