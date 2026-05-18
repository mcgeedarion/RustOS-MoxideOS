//! TCP listen/accept path.
use crate::net::tcp;
use super::super::types::{SockAddr, SocketState, AF_INET, SOCK_STREAM};
use super::super::core::SOCKETS;

pub fn tcp_listen(fd: usize, port: u16) {
    tcp::listen(fd, port);
    let mut sockets = SOCKETS.lock();
    if let Some(Some(s)) = sockets.get_mut(fd) {
        s.state = SocketState::Listening;
    }
}