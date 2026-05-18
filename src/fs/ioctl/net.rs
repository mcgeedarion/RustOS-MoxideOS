extern crate alloc;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};
use super::consts::*;

fn read_ifname(ifreq_va: usize) -> Option<alloc::string::String> {
    let mut buf = [0u8; super::consts::IFNAMSIZ];
    copy_from_user(ifreq_va, &mut buf);
    let end = buf.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
    alloc::str::from_utf8(&buf[..end]).ok().map(|s| alloc::string::String::from(s))
}

pub fn sioc_ioctl(cmd: u64, arg: usize) -> isize {
    match cmd {
        SIOCGIFNAME   => -38,
        SIOCGIFFLAGS  => {
            let name = read_ifname(arg);
            let flags: u16 = if name.as_deref() == Some("lo") { 0x49 } else { 0x1003 };
            copy_to_user(arg + IFNAMSIZ, &flags.to_ne_bytes());
            0
        }
        SIOCSIFFLAGS  => 0,
        SIOCGIFADDR   => {
            let ip = crate::net::ip::local_ip();
            let sa_family: u16 = 2;
            copy_to_user(arg + IFNAMSIZ,     &sa_family.to_ne_bytes());
            copy_to_user(arg + IFNAMSIZ + 4, &ip.to_be_bytes());
            0
        }
        SIOCSIFADDR   => 0,
        SIOCGIFMTU    => { let mtu: u32 = 1500; copy_to_user(arg + IFNAMSIZ + 16, &mtu.to_ne_bytes()); 0 }
        SIOCSIFMTU    => 0,
        SIOCGIFHWADDR => {
            let mac = crate::net::ip::local_mac();
            let af: u16 = 1;
            copy_to_user(arg + IFNAMSIZ,     &af.to_ne_bytes());
            copy_to_user(arg + IFNAMSIZ + 2, &mac);
            0
        }
        SIOCGIFINDEX  => { let idx: u32 = 1; copy_to_user(arg + IFNAMSIZ + 16, &idx.to_ne_bytes()); 0 }
        SIOCGIFCONF   => -38,
        _             => -38,
    }
}
