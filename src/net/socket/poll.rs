use super::SOCKETS;

pub fn is_socket_fd(fd: usize) -> bool {
    SOCKETS.lock().get(fd).map(|s| s.is_some()).unwrap_or(false)
}

pub fn socket_poll(fd: usize, events: u32) -> u32 {
    let socks = SOCKETS.lock();
    let sock  = match socks.get(fd).and_then(|s| s.as_ref()) {
        Some(s) => s.lock(), None => return 0,
    };
    let mut revents = 0u32;
    if events & 0x01 != 0 && sock.rx_buf.len() > 0 { revents |= 0x01; } // POLLIN
    if events & 0x04 != 0 { revents |= 0x04; } // POLLOUT
    revents
}

pub fn socket_read(fd: usize, buf: &mut [u8]) -> isize {
    let mut socks = SOCKETS.lock();
    let sock = match socks.get_mut(fd).and_then(|s| s.as_mut()) {
        Some(s) => s, None => return -9,
    };
    let mut s = sock.lock();
    let n = s.rx_buf.len().min(buf.len());
    buf[..n].copy_from_slice(&s.rx_buf[..n]);
    s.rx_buf.drain(..n);
    n as isize
}

pub fn socket_write(fd: usize, buf: &[u8]) -> isize {
    let socks = SOCKETS.lock();
    let sock  = match socks.get(fd).and_then(|s| s.as_ref()) {
        Some(s) => s, None => return -9,
    };
    let s = sock.lock();
    crate::net::send_raw(&s, buf);
    buf.len() as isize
}
