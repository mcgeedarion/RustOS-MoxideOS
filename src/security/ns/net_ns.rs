//! Network namespace.
//!
//! Each `NetNs` owns an independent set of virtual network interfaces and
//! a routing table.  The loopback interface is created automatically in every
//! new namespace.
//!
//! ## Linux syscall / sysfs surface modelled
//!
//!   clone(CLONE_NEWNET) / unshare(CLONE_NEWNET)
//!   /proc/net/dev          — enumerate via `iface_list()`
//!   /proc/net/route        — enumerate via `route_list()`
//!   /proc/net/if_inet6     — IPv6 addresses
//!   ioctl SIOCGIFINDEX     — look up interface by name
//!   ioctl SIOCSIFFLAGS     — set IFF_UP / IFF_PROMISC

extern crate alloc;
use crate::security::ns::alloc_ns_id;
use alloc::{string::String, vec::Vec};
use spin::Mutex;

// ─── IFF flags (match Linux UAPI) ────────────────────────────────────────────
pub mod iff {
    pub const UP: u32 = 1;
    pub const BROADCAST: u32 = 2;
    pub const LOOPBACK: u32 = 8;
    pub const RUNNING: u32 = 64;
    pub const PROMISC: u32 = 256;
    pub const MULTICAST: u32 = 0x1000;
}

/// One virtual network interface.
#[derive(Clone, Debug)]
pub struct NetIface {
    /// Interface name ("lo", "eth0", "veth0", …)
    pub name: String,
    /// Kernel-internal index (1-based, unique per ns).
    pub ifindex: u32,
    /// IFF_* flags.
    pub flags: u32,
    /// MAC address (6 bytes; all-zero for loopback).
    pub mac: [u8; 6],
    /// Assigned IPv4 addresses (addr, prefix_len).
    pub ipv4: Vec<(u32, u8)>,
    /// Assigned IPv6 addresses (addr[16], prefix_len).
    pub ipv6: Vec<([u8; 16], u8)>,
    /// MTU in bytes.
    pub mtu: u32,
    /// Rx/Tx byte counters.
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl NetIface {
    fn loopback() -> Self {
        NetIface {
            name: String::from("lo"),
            ifindex: 1,
            flags: iff::UP | iff::LOOPBACK | iff::RUNNING,
            mac: [0u8; 6],
            ipv4: alloc::vec![(0x7F00_0001u32, 8)], // 127.0.0.1/8
            ipv6: alloc::vec![([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128)], // ::1/128
            mtu: 65536,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }
}

/// An IPv4 route entry.
#[derive(Clone, Debug)]
pub struct Route4 {
    pub dst: u32,
    pub mask: u32,
    pub gateway: u32,
    pub ifindex: u32,
    pub metric: u32,
    pub flags: u32,
}

pub struct NetNs {
    pub id: u64,
    ifaces: Mutex<Vec<NetIface>>,
    routes4: Mutex<Vec<Route4>>,
    next_ifindex: Mutex<u32>,
}

impl NetNs {
    /// Initial network namespace with lo + default routes.
    pub fn new_init() -> Self {
        let ns = NetNs {
            id: alloc_ns_id(),
            ifaces: Mutex::new(alloc::vec![NetIface::loopback()]),
            routes4: Mutex::new(alloc::vec![Route4 {
                dst: 0x7F00_0000,
                mask: 0xFF00_0000,
                gateway: 0,
                ifindex: 1,
                metric: 0,
                flags: 1
            },]),
            next_ifindex: Mutex::new(2),
        };
        ns
    }

    /// New empty namespace with only loopback.
    pub fn new_empty() -> Self {
        NetNs {
            id: alloc_ns_id(),
            ifaces: Mutex::new(alloc::vec![NetIface::loopback()]),
            routes4: Mutex::new(Vec::new()),
            next_ifindex: Mutex::new(2),
        }
    }

    fn alloc_ifindex(&self) -> u32 {
        let mut n = self.next_ifindex.lock();
        let v = *n;
        *n += 1;
        v
    }

    /// Add a new virtual interface to this namespace.
    pub fn add_iface(&self, mut iface: NetIface) {
        iface.ifindex = self.alloc_ifindex();
        self.ifaces.lock().push(iface);
    }

    /// Remove an interface by index.
    pub fn remove_iface(&self, ifindex: u32) -> Result<(), isize> {
        let mut list = self.ifaces.lock();
        let pos = list
            .iter()
            .position(|i| i.ifindex == ifindex)
            .ok_or(-19isize)?;
        list.remove(pos);
        Ok(())
    }

    /// Look up interface by name (SIOCGIFINDEX).
    pub fn ifindex_by_name(&self, name: &str) -> Option<u32> {
        self.ifaces
            .lock()
            .iter()
            .find(|i| i.name == name)
            .map(|i| i.ifindex)
    }

    /// Set interface flags (SIOCSIFFLAGS).
    pub fn set_flags(&self, ifindex: u32, flags: u32) -> Result<(), isize> {
        let mut list = self.ifaces.lock();
        let iface = list
            .iter_mut()
            .find(|i| i.ifindex == ifindex)
            .ok_or(-19isize)?;
        iface.flags = flags;
        Ok(())
    }

    /// Assign an IPv4 address to an interface.
    pub fn add_addr4(&self, ifindex: u32, addr: u32, prefix: u8) -> Result<(), isize> {
        let mut list = self.ifaces.lock();
        let iface = list
            .iter_mut()
            .find(|i| i.ifindex == ifindex)
            .ok_or(-19isize)?;
        iface.ipv4.push((addr, prefix));
        Ok(())
    }

    /// Add a unicast IPv4 route.
    pub fn add_route4(&self, route: Route4) {
        self.routes4.lock().push(route);
    }

    /// Longest-prefix match for IPv4 destination.
    pub fn route_lookup4(&self, dst: u32) -> Option<Route4> {
        let routes = self.routes4.lock();
        routes
            .iter()
            .filter(|r| dst & r.mask == r.dst & r.mask)
            .max_by_key(|r| r.mask.count_ones())
            .cloned()
    }

    /// Snapshot of all interfaces (/proc/net/dev).
    pub fn iface_list(&self) -> Vec<NetIface> {
        self.ifaces.lock().clone()
    }

    /// Snapshot of all IPv4 routes (/proc/net/route).
    pub fn route_list(&self) -> Vec<Route4> {
        self.routes4.lock().clone()
    }

    /// Bump Rx byte counter for an interface.
    pub fn rx_account(&self, ifindex: u32, bytes: u64) {
        if let Some(i) = self.ifaces.lock().iter_mut().find(|i| i.ifindex == ifindex) {
            i.rx_bytes = i.rx_bytes.saturating_add(bytes);
        }
    }

    /// Bump Tx byte counter.
    pub fn tx_account(&self, ifindex: u32, bytes: u64) {
        if let Some(i) = self.ifaces.lock().iter_mut().find(|i| i.ifindex == ifindex) {
            i.tx_bytes = i.tx_bytes.saturating_add(bytes);
        }
    }
}
