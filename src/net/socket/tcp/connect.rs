//! TCP connect path.
use super::super::address::next_ephemeral;
use super::super::core::SOCKETS;
use super::super::types::{SockAddr, SocketState, AF_INET};
use crate::net::{ip, tcp};

pub fn tcp_connect(fd: usize, peer: SockAddr) -> isize {
    let (local_ip, peer_ip, peer_port) = match &peer {
        SockAddr::V4 { ip, port } => (0u32, *ip, *port),
        _ => return -22,
    };
    let local_port = next_ephemeral();
    let id = tcp::connect(local_ip, local_port, peer_ip, peer_port);
    let mut sockets = SOCKETS.lock();
    if let Some(Some(sock)) = sockets.get_mut(fd) {
        sock.tcp_id = Some(id);
        sock.local = Some(SockAddr::V4 {
            ip: local_ip,
            port: local_port,
        });
        sock.peer = Some(peer);
        sock.state = SocketState::Connected;
    }
    0
}
