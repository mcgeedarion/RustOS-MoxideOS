extern crate alloc;
use crate::uaccess::{copy_from_user, copy_to_user};

pub fn read_sockaddr_in4(uptr: usize) -> Option<(u16, u32)> {
    let mut buf = [0u8; 8];
    if copy_from_user(uptr, &mut buf) < 8 { return None; }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let ip   = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    Some((port, ip))
}

pub fn write_sockaddr_in4(uptr: usize, port: u16, ip: u32) {
    let mut buf = [0u8; 16];
    buf[0] = 2; // AF_INET
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&ip.to_be_bytes());
    copy_to_user(uptr, &buf);
}

pub fn read_sockaddr_in6(uptr: usize) -> Option<(u16, [u8; 16])> {
    let mut buf = [0u8; 28];
    if copy_from_user(uptr, &mut buf) < 28 { return None; }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&buf[8..24]);
    Some((port, addr))
}

pub fn write_sockaddr_in6(uptr: usize, port: u16, addr: &[u8; 16]) {
    let mut buf = [0u8; 28];
    buf[0] = 10; // AF_INET6
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[8..24].copy_from_slice(addr);
    copy_to_user(uptr, &buf);
}
