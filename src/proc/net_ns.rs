//! Network namespace — per-NsId interface registry and socket isolation.
//!
//! ## What this implements
//! * Each net-ns starts with a synthetic loopback entry (lo, 127.0.0.1/8, ::1).
//! * `unshare(CLONE_NEWNET)` creates a fresh net-ns via `create_net_ns()`.
//! * Physical/virtual interfaces are registered into a specific net-ns by the
//!   network stack via `net_ns_add_iface()`.  They are removed on interface
//!   teardown or when moving between namespaces.
//! * `check_socket_ns(sock_ns, current_ns)` enforces isolation: a socket
//!   created in ns A cannot be used by a process in ns B.
//!
//! ## Integration points
//! * `net::socket::sys_socket()` should call `current_net_ns()` and store
//!   the result in the socket object.
//! * Every socket syscall (send/recv/connect/bind/…) should call
//!   `check_socket_ns(sock.net_ns, current_net_ns())` and return `-EACCES`
//!   on mismatch.
//! * procfs renders `/proc/net/dev` per net-ns via `list_ifaces(ns)`.

extern crate alloc;
use crate::proc::namespace::{NsId, INIT_NS};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::Mutex;

// ─── Interface descriptor ─────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct NetIface {
    /// Interface name ("lo", "eth0", "veth0", …)
    pub name: String,
    /// IPv4 address in network byte order (0 = none assigned)
    pub ipv4: u32,
    /// IPv4 prefix length (e.g. 8 for 127.0.0.1/8)
    pub prefix4: u8,
    /// Whether the interface is up
    pub up: bool,
    /// Loopback flag
    pub loopback: bool,
}

impl NetIface {
    fn loopback() -> Self {
        NetIface {
            name: "lo".to_string(),
            ipv4: 0x7f00_0001u32.to_be(), // 127.0.0.1 in network byte order
            prefix4: 8,
            up: true,
            loopback: true,
        }
    }
}

// ─── Per-ns interface table ──────────────────────────────────────────────────

struct NetNs {
    ifaces: Vec<NetIface>,
}

impl NetNs {
    fn new_with_loopback() -> Self {
        NetNs {
            ifaces: alloc::vec![NetIface::loopback()],
        }
    }

    fn add(&mut self, iface: NetIface) {
        // Replace if same name exists
        if let Some(pos) = self.ifaces.iter().position(|i| i.name == iface.name) {
            self.ifaces[pos] = iface;
        } else {
            self.ifaces.push(iface);
        }
    }

    fn remove(&mut self, name: &str) {
        self.ifaces.retain(|i| i.name != name);
    }

    fn list(&self) -> Vec<NetIface> {
        self.ifaces.clone()
    }
}

// ─── Global registry ────────────────────────────────────────────────────────

struct NetNsTable {
    entries: BTreeMap<NsId, NetNs>,
}

impl NetNsTable {
    const fn new() -> Self {
        NetNsTable {
            entries: BTreeMap::new(),
        }
    }

    fn ensure(&mut self, ns: NsId) {
        self.entries
            .entry(ns)
            .or_insert_with(NetNs::new_with_loopback);
    }

    fn get_mut(&mut self, ns: NsId) -> &mut NetNs {
        self.entries
            .entry(ns)
            .or_insert_with(NetNs::new_with_loopback)
    }

    fn get(&self, ns: NsId) -> Option<&NetNs> {
        self.entries.get(&ns)
    }
}

static NET_NS_TABLE: Mutex<NetNsTable> = Mutex::new(NetNsTable::new());

// ─── Public API ──────────────────────────────────────────────────────────────

/// Initialise the INIT_NS net-ns with the loopback interface.
/// Called from kernel init after network subsystem is ready.
pub fn init_net_ns() {
    NET_NS_TABLE.lock().ensure(INIT_NS);
}

/// Create a new (empty except for loopback) net-ns for `ns_id`.
/// Called by `unshare(CLONE_NEWNET)` in namespace.rs.
pub fn create_net_ns(ns_id: NsId) {
    let mut tbl = NET_NS_TABLE.lock();
    tbl.entries.insert(ns_id, NetNs::new_with_loopback());
}

/// Destroy a private net-ns when the last process holding it exits.
///
/// Removes the entry from `NET_NS_TABLE`, freeing all registered interfaces.
/// No-op for `INIT_NS` — the boot namespace is never freed.
/// Called from `exit::ns_exit` after confirming no other live process shares
/// the namespace.
pub fn destroy_net_ns(ns_id: NsId) {
    if ns_id == INIT_NS {
        return;
    }
    NET_NS_TABLE.lock().entries.remove(&ns_id);
}

/// Return the current process's net namespace id.
pub fn current_net_ns() -> NsId {
    let pid = crate::proc::scheduler::current_pid();
    crate::proc::scheduler::with_proc(pid, |p| p.ns.net).unwrap_or(INIT_NS)
}

/// Add or replace a network interface in a net-ns.
pub fn net_ns_add_iface(ns: NsId, iface: NetIface) {
    NET_NS_TABLE.lock().get_mut(ns).add(iface);
}

/// Remove a network interface from a net-ns by name.
pub fn net_ns_remove_iface(ns: NsId, name: &str) {
    NET_NS_TABLE.lock().get_mut(ns).remove(name);
}

/// List all interfaces in a net-ns (for /proc/net/dev and ioctl SIOCGIFCONF).
pub fn net_ns_list_ifaces(ns: NsId) -> Vec<NetIface> {
    let tbl = NET_NS_TABLE.lock();
    match tbl.get(ns) {
        Some(n) => n.list(),
        None => alloc::vec![NetIface::loopback()],
    }
}

/// Enforce socket-level namespace isolation.
///
/// Call this at the top of every socket syscall handler with the ns-id
/// stored in the socket object and the calling process's current net-ns.
///
/// Returns `Ok(())` if access is allowed, `Err(-13)` (EACCES) otherwise.
///
/// Exception: sockets in INIT_NS are reachable from any ns to allow
/// kernel-internal sockets (e.g. netlink) to work without changes.
pub fn check_socket_ns(socket_ns: NsId, caller_ns: NsId) -> Result<(), isize> {
    if socket_ns == INIT_NS || socket_ns == caller_ns {
        Ok(())
    } else {
        Err(-13) // EACCES
    }
}

/// Move a named interface from `src_ns` to `dst_ns`.  Used by `ip link set
/// <dev> netns <pid>` emulation.  Returns `Err(-19)` (ENODEV) if not found.
pub fn move_iface(src_ns: NsId, dst_ns: NsId, name: &str) -> Result<(), isize> {
    let mut tbl = NET_NS_TABLE.lock();
    // find and clone the iface from src
    let iface = {
        let src = tbl
            .entries
            .entry(src_ns)
            .or_insert_with(NetNs::new_with_loopback);
        match src.ifaces.iter().find(|i| i.name == name) {
            Some(i) => i.clone(),
            None => return Err(-19), // ENODEV
        }
    };
    // remove from src (loopback is protected)
    if !iface.loopback {
        tbl.entries
            .entry(src_ns)
            .or_insert_with(NetNs::new_with_loopback)
            .remove(name);
    }
    // add to dst
    tbl.entries
        .entry(dst_ns)
        .or_insert_with(NetNs::new_with_loopback)
        .add(iface);
    Ok(())
}
