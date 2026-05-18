use crate::net::ipv6;
use crate::uaccess::{copy_from_user, copy_to_user};

pub static EPHEMERAL: spin::Mutex<u16> = spin::Mutex::new(49152);

pub fn next_ephemeral() -> u16 {
    let mut e = EPHEMERAL.lock();
    let p = *e;
    *e = if p >= 60999 { 49152 } else { p + 1 };
    p
}

pub fn read_sockaddr_in(va: usize) -> Option<(u16, u32)> {
    let mut buf = [0u8; 8];
    copy_from_user(va, &mut buf);
    if u16::from_be_bytes([buf[0], buf[1]]) != 2 { return None; }
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let ip   = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    Some((port, ip))
}

pub fn read_sockaddr_in6(va: usize) -> Option<(u16, ipv6::Addr6, u32, u32)> {
    let mut buf = [0u8; 28];
    copy_from_user(va, &mut buf);
    if u16::from_be_bytes([buf[0], buf[1]]) != 10 { return None; }
    let port     = u16::from_be_bytes([buf[2], buf[3]]);
    let flowinfo = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&buf[8..24]);
    let scope_id = u32::from_be_bytes([buf[24], buf[25], buf[26], buf[27]]);
    Some((port, addr, flowinfo, scope_id))
}

pub fn write_sockaddr_in(va: usize, ip: u32, port: u16) {
    if va == 0 { return; }
    let mut buf = [0u8; 16];
    buf[0..2].copy_from_slice(&2u16.to_be_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&ip.to_be_bytes());
    copy_to_user(va, &buf);
}

pub fn write_sockaddr_in6(va: usize, ip: &ipv6::Addr6, port: u16, flowinfo: u32, scope_id: u32) {
    if va == 0 { return; }
    let mut buf = [0u8; 28];
    buf[0..2].copy_from_slice(&10u16.to_be_bytes());
    buf[2..4].copy_from_slice(&port.to_be_bytes());
    buf[4..8].copy_from_slice(&flowinfo.to_be_bytes());
    buf[8..24].copy_from_slice(ip);
    buf[24..28].copy_from_slice(&scope_id.to_be_bytes());
    copy_to_user(va, &buf);
}