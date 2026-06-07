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

/// Placeholder network control scheme adapter.
pub struct NetScheme;

impl NetScheme {
    pub const fn new() -> Self {
        Self
    }
}

impl crate::fs::scheme_table::Scheme for NetScheme {
    fn open(
        &self,
        _path: &str,
        _flags: scheme_api::OpenFlags,
    ) -> Result<scheme_api::SchemeFileId, scheme_api::SchemeError> {
        Err(scheme_api::SchemeError::NoSuchScheme)
    }

    fn close(&self, _fid: scheme_api::SchemeFileId) -> Result<(), scheme_api::SchemeError> {
        Ok(())
    }
}
