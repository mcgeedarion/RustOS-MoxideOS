//! Network subsystem.
//!
//! Layer hierarchy:
//!   eth     — Ethernet II framing, ARP
//!   ip      — IPv4 (fragmentation, options, routing)
//!   ipv6    — IPv6 (extension headers, fragment reassembly, SLAAC routing)
//!   icmp    — ICMPv4 echo request/reply + unreachable + time-exceeded
//!   icmpv6  — ICMPv6 (RFC 4443) + NDP (RFC 4861): NS/NA/RS/RA/Redirect
//!   udp     — UDP datagrams (IPv4 + IPv6)
//!   tcp     — TCP (RFC 793/7323): 3-way handshake, data transfer, FIN/RST
//! teardown   socket  — BSD socket layer: AF_INET / AF_INET6 / AF_UNIX
//!   dhcp    — DHCP client (RFC 2131): DORA handshake, lease management
//!   dns     — DNS stub resolver (RFC 1035): A / AAAA queries with cache

extern crate alloc;

use alloc::{string::String, vec::Vec};
use spin::Mutex;

pub mod arp;
pub mod dhcp;
pub mod dns;
pub mod eth;
pub mod icmp;
pub mod icmpv6;
pub mod ip;
pub mod ipv6;
pub mod socket;
pub mod tcp;
pub mod udp;

struct NetHandle {
    data: Vec<u8>,
    offset: usize,
    writable: bool,
}

static NET_HANDLES: Mutex<Vec<Option<NetHandle>>> = Mutex::new(Vec::new());

fn alloc_handle(handle: NetHandle) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
    let mut handles = NET_HANDLES.lock();

    for (idx, slot) in handles.iter_mut().enumerate() {
        if slot.is_none() {
            *slot = Some(handle);
            return Ok(scheme_api::SchemeFileId((idx + 1) as u64));
        }
    }

    handles.push(Some(handle));
    Ok(scheme_api::SchemeFileId(handles.len() as u64))
}

fn fid_index(fid: scheme_api::SchemeFileId) -> Result<usize, scheme_api::SchemeError> {
    fid.0
        .checked_sub(1)
        .map(|v| v as usize)
        .ok_or(scheme_api::SchemeError::InvalidArg)
}

fn fmt_ipv4(ip: u32, out: &mut String) {
    use core::fmt::Write;

    let b = ip.to_be_bytes();
    let _ = write!(out, "{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
}

fn parse_ipv4(s: &str) -> Result<u32, scheme_api::SchemeError> {
    let mut out = 0u32;
    let mut count = 0usize;

    for part in s.trim().split('.') {
        if count >= 4 || part.is_empty() {
            return Err(scheme_api::SchemeError::InvalidArg);
        }

        let octet: u8 = part
            .parse()
            .map_err(|_| scheme_api::SchemeError::InvalidArg)?;
        out = (out << 8) | octet as u32;
        count += 1;
    }

    if count != 4 {
        return Err(scheme_api::SchemeError::InvalidArg);
    }

    Ok(out)
}

fn status_bytes() -> Vec<u8> {
    use core::fmt::Write;

    let mut out = String::new();

    out.push_str("ip=");
    fmt_ipv4(ip::our_ip(), &mut out);
    out.push('\n');

    out.push_str("mac=");
    let mac = ip::get_mac();
    let _ = write!(
        out,
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    out.into_bytes()
}

fn apply_config(data: &[u8]) -> Result<(), scheme_api::SchemeError> {
    let text = core::str::from_utf8(data).map_err(|_| scheme_api::SchemeError::InvalidArg)?;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .ok_or(scheme_api::SchemeError::InvalidArg)?;

        match key.trim() {
            "ip" | "addr" | "address" => ip::set_ip(parse_ipv4(value)?),
            "gw" | "gateway" => ip::set_gw(parse_ipv4(value)?),
            "mask" | "netmask" => ip::set_mask(parse_ipv4(value)?),
            _ => return Err(scheme_api::SchemeError::InvalidArg),
        }
    }

    Ok(())
}

/// Network control scheme adapter.
///
/// Supported paths:
/// - `net:` / `net:status` / `net:ifconfig` — read a text snapshot.
/// - `net:config` — write `key=value` lines: `ip=`, `gw=`, `mask=`.
pub struct NetScheme;

impl NetScheme {
    pub const fn new() -> Self {
        Self
    }
}

impl crate::fs::scheme_table::Scheme for NetScheme {
    fn open(
        &self,
        path: &str,
        flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        let path = path.trim_matches('/');
        let writable = flags.contains(scheme_api::OpenFlags::WRITE);

        match path {
            "" | "status" | "ifconfig" => alloc_handle(NetHandle {
                data: status_bytes(),
                offset: 0,
                writable: false,
            }),
            "config" | "ctl" | "control" => alloc_handle(NetHandle {
                data: Vec::new(),
                offset: 0,
                writable,
            }),
            _ => Err(scheme_api::SchemeError::NotFound),
        }
    }

    fn read(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &mut [u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let idx = fid_index(fid)?;
        let mut handles = NET_HANDLES.lock();
        let Some(Some(handle)) = handles.get_mut(idx) else {
            return Err(scheme_api::SchemeError::InvalidArg);
        };

        let n = buf
            .len()
            .min(handle.data.len().saturating_sub(handle.offset));
        if n > 0 {
            buf[..n].copy_from_slice(&handle.data[handle.offset..handle.offset + n]);
            handle.offset += n;
        }
        Ok(n)
    }

    fn write(
        &self,
        fid: scheme_api::SchemeFileId,
        buf: &[u8],
    ) -> Result<usize, scheme_api::SchemeError> {
        let idx = fid_index(fid)?;
        let mut handles = NET_HANDLES.lock();
        let Some(Some(handle)) = handles.get_mut(idx) else {
            return Err(scheme_api::SchemeError::InvalidArg);
        };
        if !handle.writable {
            return Err(scheme_api::SchemeError::PermissionDenied);
        }

        apply_config(buf)?;
        handle.data.clear();
        handle.data.extend_from_slice(buf);
        handle.offset = handle.data.len();
        Ok(buf.len())
    }

    fn close(&self, fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        let idx = fid_index(fid)?;
        let mut handles = NET_HANDLES.lock();
        if let Some(slot) = handles.get_mut(idx) {
            *slot = None;
            Ok(())
        } else {
            Err(scheme_api::SchemeError::InvalidArg)
        }
    }
}
