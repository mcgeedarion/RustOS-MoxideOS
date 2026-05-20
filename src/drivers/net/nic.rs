//! Common NIC abstractions shared by network drivers.
//!
//! This module provides a tiny, allocation-free façade over the concrete
//! drivers (`e1000e`, `virtio_net`, `virtio_net_mmio`).  The rest of the
//! network stack can send/receive Ethernet frames via these helpers without
//! caring which device backed the link.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MacAddr(pub [u8; 6]);

#[derive(Clone, Copy, Debug, Default)]
pub struct NicStats {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes:   u64,
    pub tx_bytes:   u64,
}

/// Returns true if any supported NIC driver is initialised.
pub fn is_initialised() -> bool {
    crate::drivers::net::e1000e::is_initialised()
        || crate::drivers::net::virtio_net::is_initialised()
        || crate::drivers::net::virtio_net_mmio::is_initialised()
}

/// Returns the MAC address of the first initialised NIC.
pub fn mac() -> Option<MacAddr> {
    crate::drivers::net::e1000e::mac()
        .or_else(crate::drivers::net::virtio_net::mac)
        .or_else(crate::drivers::net::virtio_net_mmio::mac)
}

/// Returns statistics for the first initialised NIC.
pub fn stats() -> Option<NicStats> {
    crate::drivers::net::e1000e::stats()
        .or_else(crate::drivers::net::virtio_net::stats)
        .or_else(crate::drivers::net::virtio_net_mmio::stats)
}

/// Send one raw Ethernet frame.
pub fn send(frame: &[u8]) -> Result<(), &'static str> {
    if crate::drivers::net::e1000e::is_initialised() {
        return crate::drivers::net::e1000e::send(frame);
    }
    if crate::drivers::net::virtio_net::is_initialised() {
        return crate::drivers::net::virtio_net::send(frame);
    }
    if crate::drivers::net::virtio_net_mmio::is_initialised() {
        return crate::drivers::net::virtio_net_mmio::send(frame);
    }
    Err("no NIC initialised")
}

/// Receive one raw Ethernet frame into `out`, returning the frame length.
pub fn recv(out: &mut [u8]) -> Option<usize> {
    if crate::drivers::net::e1000e::is_initialised() {
        return crate::drivers::net::e1000e::recv(out);
    }
    if crate::drivers::net::virtio_net::is_initialised() {
        return crate::drivers::net::virtio_net::recv(out);
    }
    if crate::drivers::net::virtio_net_mmio::is_initialised() {
        return crate::drivers::net::virtio_net_mmio::recv(out);
    }
    None
}
