//! Network subsystem.
//!
//! Layer hierarchy:
//!   eth     — Ethernet II framing, ARP
//!   ip      — IPv4 (fragmentation, options, routing)
//!   ipv6    — IPv6 (extension headers, fragment reassembly, SLAAC routing)
//!   icmp    — ICMPv4 echo request/reply + unreachable + time-exceeded
//!   icmpv6  — ICMPv6 (RFC 4443) + NDP (RFC 4861): NS/NA/RS/RA/Redirect
//!   udp     — UDP datagrams (IPv4 + IPv6)
//!   tcp     — TCP (RFC 793/7323): 3-way handshake, data transfer, FIN/RST teardown
//!   socket  — BSD socket layer: AF_INET / AF_INET6 / AF_UNIX
//!   dhcp    — DHCP client (RFC 2131): DORA handshake, lease management
//!   dns     — DNS stub resolver (RFC 1035): A / AAAA queries with cache

pub mod eth;
pub mod arp;
pub mod ip;
pub mod ipv6;
pub mod icmp;
pub mod icmpv6;
pub mod udp;
pub mod tcp;
pub mod socket;
pub mod dhcp;
pub mod dns;
