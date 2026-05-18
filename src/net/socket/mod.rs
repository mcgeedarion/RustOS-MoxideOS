//! BSD socket layer: socket(), bind(), listen(), accept(), connect(),
//! send(), recv(), sendto(), recvfrom(), socketpair(), shutdown().

extern crate alloc;

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

pub use types::{SockAddr, Socket, SocketState, AF_INET, AF_INET6, AF_UNIX,
               SOCK_STREAM, SOCK_DGRAM, SOCK_RAW,
               SHUT_RD, SHUT_WR, SHUT_RDWR};
pub use self::core::{sys_socket, sys_bind, sys_listen, sys_accept,
                     sys_accept4, sys_connect, alloc_slot};
pub use traits::{sys_setsockopt, sys_getsockopt, sys_shutdown,
                  sys_getpeername, sys_getsockname};
pub use poll::{socket_poll, socket_read, socket_write, is_socket_fd};
pub use syscalls::{sys_sendmsg, sys_recvmsg, sys_socketpair, sys_close_socket};

use alloc::sync::Arc;
use spin::Mutex;

pub static SOCKETS: Mutex<alloc::vec::Vec<Option<Arc<Mutex<Socket>>>>> =
    Mutex::new(alloc::vec![]);

pub fn alloc_slot(s: Socket) -> Option<usize> {
    let arc = Arc::new(Mutex::new(s));
    let mut socks = SOCKETS.lock();
    for (i, slot) in socks.iter_mut().enumerate() {
        if slot.is_none() { *slot = Some(arc); return Some(i); }
    }
    let idx = socks.len();
    socks.push(Some(arc));
    Some(idx)
}
