//! TCP listen/accept path.
use super::super::core::SOCKETS;
use super::super::types::{SockAddr, SocketState, AF_INET, SOCK_STREAM};
use crate::net::tcp;

pub fn tcp_listen(fd: usize, port: u16) {
    tcp::listen(fd, port);
    let mut sockets = SOCKETS.lock();
    if let Some(Some(s)) = sockets.get_mut(fd) {
        s.state = SocketState::Listening;
    }
}
