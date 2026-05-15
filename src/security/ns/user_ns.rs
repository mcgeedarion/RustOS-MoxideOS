//! User namespace — UID/GID mapping + per-ns capability grants.
//!
//! Each `UserNs` holds a set of up to 5 UID map entries and 5 GID map
//! entries (matching Linux's /proc/self/uid_map format).  Capability
//! checks route through `UserNs::has_cap()` which honours the ns-local
//! capability set.
//!
//! ## Linux syscall semantics modelled
//!
//!   clone(CLONE_NEWUSER)
//!   /proc/self/uid_map  — write to establish mapping
//!   /proc/self/gid_map  — write to establish mapping
//!   /proc/self/setgroups — "deny" locks out setgroups(2) inside the ns
//!   capget(2) / capset(2) routed through the ns

extern crate alloc;
use crate::security::capset::CapSet;
use crate::security::ns::alloc_ns_id;
use alloc::{sync::Arc, vec::Vec};
use spin::Mutex;

/// One uid_map / gid_map entry: ns_id → host_id for a range of `count` IDs.
#[derive(Clone, Copy, Debug, Default)]
pub struct IdMapEntry {
    pub ns_start: u32,
    pub host_start: u32,
    pub count: u32,
}

/// Maximum entries per map (Linux also allows 5 for unprivileged users).
const MAX_MAP_ENTRIES: usize = 5;

pub struct UserNs {
    pub id: u64,
    /// Parent user namespace, None for the initial ns.
    pub parent: Option<Arc<UserNs>>,
    uid_map: Mutex<Vec<IdMapEntry>>,
    gid_map: Mutex<Vec<IdMapEntry>>,
    /// When true, setgroups(2) is denied inside this ns.
    setgroups_deny: Mutex<bool>,
    /// Capabilities granted to processes that are "root" inside this ns.
    ns_caps: Mutex<CapSet>,
    /// UID of the process that created this namespace (owner).
    pub owner_uid: u32,
    /// True if the uid_map has been written (locked after first write).
    uid_mapped: Mutex<bool>,
    gid_mapped: Mutex<bool>,
}

impl UserNs {
    pub fn new_init() -> Self {
        let mut caps = CapSet::default();
        // Initial ns: all capabilities permitted and effective for uid 0.
        caps.permitted = u64::MAX;
        caps.effective = u64::MAX;
        caps.inheritable = 0;
        UserNs {
            id: alloc_ns_id(),
            parent: None,
            uid_map: Mutex::new(alloc::vec![IdMapEntry {
                ns_start: 0,
                host_start: 0,
                count: u32::MAX
            }]),
            gid_map: Mutex::new(alloc::vec![IdMapEntry {
                ns_start: 0,
                host_start: 0,
                count: u32::MAX
            }]),
            setgroups_deny: Mutex::new(false),
            ns_caps: Mutex::new(caps),
            owner_uid: 0,
            uid_mapped: Mutex::new(true),
            gid_mapped: Mutex::new(true),
        }
    }

    pub fn new_child(parent: &Arc<UserNs>) -> Self {
        UserNs {
            id: alloc_ns_id(),
            parent: Some(parent.clone()),
            uid_map: Mutex::new(Vec::new()),
            gid_map: Mutex::new(Vec::new()),
            setgroups_deny: Mutex::new(false),
            ns_caps: Mutex::new(CapSet::default()),
            owner_uid: 0, // caller sets this
            uid_mapped: Mutex::new(false),
            gid_mapped: Mutex::new(false),
        }
    }

    // ── uid_map write (/proc/self/uid_map) ──────────────────────────────────

    /// Write the uid_map.  Only allowed once, before any threads have been
    /// created in the namespace.
    pub fn write_uid_map(&self, entries: Vec<IdMapEntry>) -> Result<(), isize> {
        let mut mapped = self.uid_mapped.lock();
        if *mapped {
            return Err(-1);
        } // EPERM: already written
        if entries.len() > MAX_MAP_ENTRIES {
            return Err(-22);
        }
        *self.uid_map.lock() = entries;
        *mapped = true;
        Ok(())
    }

    pub fn write_gid_map(&self, entries: Vec<IdMapEntry>) -> Result<(), isize> {
        let mut mapped = self.gid_mapped.lock();
        if *mapped {
            return Err(-1);
        }
        if entries.len() > MAX_MAP_ENTRIES {
            return Err(-22);
        }
        *self.gid_map.lock() = entries;
        *mapped = true;
        Ok(())
    }

    pub fn deny_setgroups(&self) {
        *self.setgroups_deny.lock() = true;
    }
    pub fn setgroups_denied(&self) -> bool {
        *self.setgroups_deny.lock()
    }

    // ── ID translation ──────────────────────────────────────────────────────

    /// Translate a namespace-local UID to the host UID.
    pub fn ns_uid_to_host(&self, ns_uid: u32) -> Option<u32> {
        Self::translate(&self.uid_map.lock(), ns_uid)
    }

    /// Translate a host UID to the namespace-local UID.
    pub fn host_uid_to_ns(&self, host_uid: u32) -> Option<u32> {
        Self::translate_rev(&self.uid_map.lock(), host_uid)
    }

    fn translate(map: &[IdMapEntry], id: u32) -> Option<u32> {
        for e in map {
            if id >= e.ns_start && id < e.ns_start + e.count {
                return Some(e.host_start + (id - e.ns_start));
            }
        }
        None
    }
    fn translate_rev(map: &[IdMapEntry], id: u32) -> Option<u32> {
        for e in map {
            if id >= e.host_start && id < e.host_start + e.count {
                return Some(e.ns_start + (id - e.host_start));
            }
        }
        None
    }

    // ── Capability check ────────────────────────────────────────────────────

    /// Check if processes inside this UserNs have a capability.
    /// `cap_bit` is the Linux capability index (0-63).
    pub fn has_cap(&self, cap_bit: u8) -> bool {
        let caps = self.ns_caps.lock();
        caps.effective & (1u64 << cap_bit) != 0
    }

    pub fn caps(&self) -> CapSet {
        self.ns_caps.lock().clone()
    }
    pub fn set_caps(&self, caps: CapSet) {
        *self.ns_caps.lock() = caps;
    }

    // ── /proc output helpers ────────────────────────────────────────────────

    pub fn uid_map_snapshot(&self) -> Vec<IdMapEntry> {
        self.uid_map.lock().clone()
    }
    pub fn gid_map_snapshot(&self) -> Vec<IdMapEntry> {
        self.gid_map.lock().clone()
    }
}
