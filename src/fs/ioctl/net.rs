//! Network interface ioctl handlers (SIOC*).
use super::consts::*;
use crate::uaccess::{copy_from_user, copy_to_user, copy_to_user_value};

pub fn sioc_ioctl(req: usize, arg: usize) -> isize {
    match req {
        SIOCGIFNAME => {
            // arg is ifreq: first 16 bytes = ifr_name, next bytes = ifr_ifindex
            let mut ifr = [0u8; 40];
            copy_from_user(arg, &mut ifr);
            let idx = u32::from_ne_bytes(ifr[16..20].try_into().unwrap_or([0; 4]));
            let name: &[u8] = if idx == 1 { b"eth0\0" } else { b"lo\0" };
            ifr[..name.len()].copy_from_slice(name);
            crate::uaccess::copy_to_user_value(arg, &ifr);
            0
        },
        SIOCGIFFLAGS => {
            let mut ifr = [0u8; 40];
            copy_from_user(arg, &mut ifr);
            // IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST
            let flags: u16 = 0x1043;
            ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
            crate::uaccess::copy_to_user_value(arg, &ifr);
            0
        },
        SIOCSIFFLAGS => 0,
        SIOCGIFADDR => {
            let mut ifr = [0u8; 40];
            copy_from_user(arg, &mut ifr);
            // sockaddr_in at ifr_addr (offset 16): family=AF_INET, port=0, addr=our IP
            ifr[16..18].copy_from_slice(&2u16.to_ne_bytes());
            ifr[18..20].copy_from_slice(&0u16.to_ne_bytes());
            let our_ip = crate::net::ip::get_ip();
            ifr[20..24].copy_from_slice(&our_ip.to_be_bytes());
            crate::uaccess::copy_to_user_value(arg, &ifr);
            0
        },
        SIOCSIFADDR => 0,
        SIOCGIFNETMASK => {
            let mut ifr = [0u8; 40];
            ifr[16..18].copy_from_slice(&2u16.to_ne_bytes());
            let mask: u32 = 0xFFFFFF00; // /24
            ifr[20..24].copy_from_slice(&mask.to_be_bytes());
            crate::uaccess::copy_to_user_value(arg, &ifr);
            0
        },
        SIOCSIFNETMASK => 0,
        SIOCGIFHWADDR => {
            let mut ifr = [0u8; 40];
            let mac = crate::net::ip::get_mac();
            ifr[16..22].copy_from_slice(&mac);
            crate::uaccess::copy_to_user_value(arg, &ifr);
            0
        },
        SIOCGIFMTU => {
            let mut ifr = [0u8; 40];
            let mtu: u32 = 1500;
            ifr[16..20].copy_from_slice(&mtu.to_ne_bytes());
            crate::uaccess::copy_to_user_value(arg, &ifr);
            0
        },
        SIOCSIFMTU => 0,
        SIOCGIFINDEX => {
            let mut ifr = [0u8; 40];
            let idx: u32 = 1;
            ifr[16..20].copy_from_slice(&idx.to_ne_bytes());
            crate::uaccess::copy_to_user_value(arg, &ifr);
            0
        },
        SIOCGIFCONF => {
            // ifconf: ifc_len(i32) + ifc_buf ptr
            let mut ifc = [0u8; 16];
            copy_from_user(arg, &mut ifc);
            let buf_va = usize::from_ne_bytes(ifc[8..16].try_into().unwrap_or([0; 8]));
            // Write one ifreq for eth0
            if buf_va != 0 {
                let mut ifr = [0u8; 40];
                ifr[..5].copy_from_slice(b"eth0\0");
                ifr[16..18].copy_from_slice(&2u16.to_ne_bytes());
                let ip = crate::net::ip::get_ip();
                ifr[20..24].copy_from_slice(&ip.to_be_bytes());
                crate::uaccess::copy_to_user_value(buf_va, &ifr);
            }
            let count: i32 = 40;
            ifc[..4].copy_from_slice(&count.to_ne_bytes());
            crate::uaccess::copy_to_user_value(arg, &ifc);
            0
        },
        SIOCADDRT | SIOCDELRT => 0,
        SIOCGARP | SIOCSARP | SIOCDARP => 0,
        SIOCETHTOOL => 0,
        _ => -25,
    }
}

pub fn read_ifname(arg: usize) -> [u8; 16] {
    let mut buf = [0u8; 16];
    copy_from_user(arg, &mut buf);
    buf
}
