//! Network subsystem.
//!
//! Layer hierarchy:
//!   eth    — Ethernet II framing, ARP
//!   ip     — IPv4 (fragmentation, routing table)
//!   icmp   — ICMP echo request/reply + unreachable
//!   udp    — UDP datagrams
//!   tcp    — TCP (RFC 793/7323): 3-way handshake, data transfer, FIN/RST teardown
//!   socket — BSD socket layer (AF_INET SOCK_STREAM / SOCK_DGRAM)
//!   dhcp   — DHCP client (RFC 2131): DORA handshake, lease management
//!   dns    — DNS stub resolver (RFC 1035): A / AAAA queries with cache

pub mod eth;
pub mod arp;
pub mod ip;
pub mod icmp;
pub mod udp;
pub mod tcp;
pub mod socket;
pub mod dhcp;
pub mod dns;
