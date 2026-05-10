//! IPv4 logic lives in `crate::net::ip`.
//!
//! This stub is kept so that any leftover `use crate::net::ipv4` paths
//! compile cleanly; it simply re-exports the public surface of `ip`.

pub use crate::net::ip::{
    our_ip, set_ip, set_gw, set_mask,
    checksum, send, receive,
    PROTO_ICMP, PROTO_TCP, PROTO_UDP, IP_HDR_MIN,
};
