use super::state::TcpState;
use crate::net::socket::types::Socket;

pub fn tcp_connect(s: &mut Socket, dst_ip: u32, dst_port: u16) -> isize {
    s.state     = TcpState::SynSent;
    s.remote_ip = dst_ip;
    s.remote_port = dst_port;
    crate::net::tcp::send_syn(s);
    0
}
