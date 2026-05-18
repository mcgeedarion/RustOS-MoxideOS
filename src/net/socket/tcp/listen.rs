use super::state::TcpState;
use crate::net::socket::types::Socket;

pub fn tcp_listen(s: &mut Socket, backlog: usize) -> isize {
    s.state = TcpState::Listen;
    s.backlog = backlog;
    0
}

pub fn tcp_accept(s: &mut Socket) -> Option<Socket> {
    s.accept_queue.pop_front()
}
