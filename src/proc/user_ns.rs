//! User-namespace UID/GID mapping.
//!
//! ## Mapping format (mirrors Linux `/proc/<pid>/uid_map`)
//!
//! Each entry is a triple `(ns_first, host_first, count)` meaning:
//!
//!     ns_uid ∈ [ns_first, ns_first+count)  →  host_uid = host_first + (ns_uid - ns_first)
//!
//! At most `MAX_ID_MAP_ENTRIES` (5) triples per map, matching the Linux limit.
//! Entries must not overlap; writing the map is a one-shot, irreversible
//! operation (the file becomes read-only once written, same as Linux).
//!
//! ## Global tables
//!
//! `USER_NS_TABLE` maps `NsId → UserNsData`.  INIT_NS is pre-populated
//! with a single identity mapping covering the full 32-bit UID range.
//!
//! ## ID translation
//!
//! * `ns_to_host_uid(ns_id, ns_uid)` — convert a UID seen inside `ns_id`
//!   to the host UID stored in the PCB.
//! * `host_to_ns_uid(ns_id, host_uid)` — reverse mapping (for getuid(2)
//!   inside a container).
//!
//! Both return `u32::MAX` (overflow UID, -1 on Linux) when no mapping exists.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::Mutex;

use crate::proc::namespace::{NsId, INIT_NS, alloc_ns_id};

/// Maximum number of extents per uid_map or gid_map.  Linux allows 5.
pub const MAX_ID_MAP_ENTRIES: usize = 5;

/// Sentinel value returned when no mapping covers a given ID.
pub const NO_MAP: u32 = u32::MAX;

/// One extent of a uid_map or gid_map.
#[derive(Clone, Copy, Debug)]
pub struct IdMapEntry {
    /// First UID/GID in the child namespace.
    pub ns_first:   u32,
    /// Corresponding first UID/GID on the host side.
    pub host_first: u32,
    /// Number of IDs in this extent.
    pub count:      u32,
}

impl IdMapEntry {
    /// Translate a namespace-side ID to the host side.  Returns `None` if
    /// `ns_id` does not fall within this extent.
    pub fn ns_to_host(&self, ns_id: u32) -> Option<u32> {
        if ns_id >= self.ns_first && ns_id - self.ns_first < self.count {
            Some(self.host_first + (ns_id - self.ns_first))
        } else {
            None
        }
    }

    /// Translate a host-side ID to the namespace side.
    pub fn host_to_ns(&self, host_id: u32) -> Option<u32> {
        if host_id >= self.host_first && host_id - self.host_first < self.count {
            Some(self.ns_first + (host_id - self.host_first))
        } else {
            None
        }
    }
}

/// Mapping state for one user namespace.
#[derive(Clone, Debug)]
pub struct UserNsData {
    /// UID map extents (up to MAX_ID_MAP_ENTRIES).
    pub uid_map: Vec<IdMapEntry>,
    /// GID map extents.
    pub gid_map: Vec<IdMapEntry>,
    /// True once uid_map has been written (one-shot).
    pub uid_map_written: bool,
    /// True once gid_map has been written (one-shot).
    pub gid_map_written: bool,
    /// Parent user namespace ID (INIT_NS for the root).
    pub parent: NsId,
}

impl UserNsData {
    /// Identity map covering the full 32-bit UID space.  Used for INIT_NS.
    fn identity() -> Self {
        let entry = IdMapEntry { ns_first: 0, host_first: 0, count: u32::MAX };
        UserNsData {
            uid_map: alloc::vec![entry],
            gid_map: alloc::vec![entry],
            uid_map_written: true,
            gid_map_written: true,
            parent: INIT_NS,
        }
    }

    /// Empty (unmapped) state for a freshly-created user namespace.
    fn empty(parent: NsId) -> Self {
        UserNsData {
            uid_map: Vec::new(),
            gid_map: Vec::new(),
            uid_map_written: false,
            gid_map_written: false,
            parent,
        }
    }
}

struct UserNsTable {
    entries: BTreeMap<NsId, UserNsData>,
}

impl UserNsTable {
    const fn new() -> Self { UserNsTable { entries: BTreeMap::new() } }
}

static USER_NS_TABLE: Mutex<UserNsTable> = Mutex::new(UserNsTable::new());

/// Seed INIT_NS with an identity mapping.  Called once from kernel init.
pub fn init_user_ns() {
    USER_NS_TABLE.lock()
        .entries
        .entry(INIT_NS)
        .or_insert_with(UserNsData::identity);
}

/// Allocate a new child user namespace under `parent`.
/// Called by `unshare(CLONE_NEWUSER)` and `clone(CLONE_NEWUSER)`.
/// The new namespace starts with empty (unmapped) uid/gid maps.
pub fn create_user_ns(parent: NsId) -> NsId {
    let new_id = alloc_ns_id();
    USER_NS_TABLE.lock().entries.insert(new_id, UserNsData::empty(parent));
    new_id
}

/// Destroy a user namespace when it is no longer referenced.
/// No-op for INIT_NS.
pub fn drop_user_ns(ns: NsId) {
    if ns == INIT_NS { return; }
    USER_NS_TABLE.lock().entries.remove(&ns);
}

/// Translate a namespace-local UID to the host UID.
/// Returns `NO_MAP` if no mapping covers `ns_uid`.
pub fn ns_to_host_uid(ns_id: NsId, ns_uid: u32) -> u32 {
    let tbl = USER_NS_TABLE.lock();
    if let Some(data) = tbl.entries.get(&ns_id) {
        for e in &data.uid_map {
            if let Some(h) = e.ns_to_host(ns_uid) { return h; }
        }
    }
    NO_MAP
}

/// Translate a host UID to the namespace-local UID.
/// Returns `NO_MAP` if not mapped.
pub fn host_to_ns_uid(ns_id: NsId, host_uid: u32) -> u32 {
    let tbl = USER_NS_TABLE.lock();
    if let Some(data) = tbl.entries.get(&ns_id) {
        for e in &data.uid_map {
            if let Some(n) = e.host_to_ns(host_uid) { return n; }
        }
    }
    NO_MAP
}

/// Translate a namespace-local GID to the host GID.
pub fn ns_to_host_gid(ns_id: NsId, ns_gid: u32) -> u32 {
    let tbl = USER_NS_TABLE.lock();
    if let Some(data) = tbl.entries.get(&ns_id) {
        for e in &data.gid_map {
            if let Some(h) = e.ns_to_host(ns_gid) { return h; }
        }
    }
    NO_MAP
}

/// Translate a host GID to the namespace-local GID.
pub fn host_to_ns_gid(ns_id: NsId, host_gid: u32) -> u32 {
    let tbl = USER_NS_TABLE.lock();
    if let Some(data) = tbl.entries.get(&ns_id) {
        for e in &data.gid_map {
            if let Some(n) = e.host_to_ns(host_gid) { return n; }
        }
    }
    NO_MAP
}

/// Errors returned by `write_uid_map` / `write_gid_map`.
#[derive(Debug, PartialEq)]
pub enum MapWriteError {
    /// Namespace not found.
    NoSuchNs,
    /// Map has already been written (one-shot).
    AlreadyWritten,
    /// Too many entries (> MAX_ID_MAP_ENTRIES).
    TooManyEntries,
    /// Entries overlap within the namespace side.
    NsSideOverlap,
    /// Entries overlap on the host side.
    HostSideOverlap,
    /// An entry count of 0 is illegal.
    ZeroCount,
    /// The host IDs claimed are not available to the writing process.
    PermissionDenied,
}

/// Validate and install `entries` as the uid_map for `ns_id`.
///
/// `writer_host_uid` is the host UID of the process writing the map
/// (read from `/proc/<pid>/uid_map`).  For unprivileged mappers, every
/// `host_first` must equal `writer_host_uid` and count must be 1 — this
/// matches the Linux single-UID-map restriction for non-root writers.
/// A `writer_host_uid` of 0 (root) bypasses this check.
pub fn write_uid_map(
    ns_id: NsId,
    entries: &[IdMapEntry],
    writer_host_uid: u32,
) -> Result<(), MapWriteError> {
    write_map(ns_id, entries, writer_host_uid, MapKind::Uid)
}

/// Validate and install `entries` as the gid_map for `ns_id`.
pub fn write_gid_map(
    ns_id: NsId,
    entries: &[IdMapEntry],
    writer_host_uid: u32,
) -> Result<(), MapWriteError> {
    write_map(ns_id, entries, writer_host_uid, MapKind::Gid)
}

#[derive(Clone, Copy)]
enum MapKind { Uid, Gid }

fn write_map(
    ns_id: NsId,
    entries: &[IdMapEntry],
    writer_host_uid: u32,
    kind: MapKind,
) -> Result<(), MapWriteError> {
    if entries.len() > MAX_ID_MAP_ENTRIES { return Err(MapWriteError::TooManyEntries); }

    // Validate individual entries.
    for e in entries {
        if e.count == 0 { return Err(MapWriteError::ZeroCount); }
        // Overflow check: ns_first + count must not wrap u32.
        if e.ns_first.checked_add(e.count).is_none() { return Err(MapWriteError::ZeroCount); }
        if e.host_first.checked_add(e.count).is_none() { return Err(MapWriteError::ZeroCount); }
        // Unprivileged writers may only map their own single UID.
        if writer_host_uid != 0 {
            if e.host_first != writer_host_uid || e.count != 1 {
                return Err(MapWriteError::PermissionDenied);
            }
        }
    }

    // Check for overlapping extents (O(n²) — n ≤ 5, so fine).
    for i in 0..entries.len() {
        for j in (i + 1)..entries.len() {
            let a = &entries[i];
            let b = &entries[j];
            // Namespace-side overlap.
            let a_ns_end = a.ns_first + a.count;
            let b_ns_end = b.ns_first + b.count;
            if a.ns_first < b_ns_end && b.ns_first < a_ns_end {
                return Err(MapWriteError::NsSideOverlap);
            }
            // Host-side overlap.
            let a_h_end = a.host_first + a.count;
            let b_h_end = b.host_first + b.count;
            if a.host_first < b_h_end && b.host_first < a_h_end {
                return Err(MapWriteError::HostSideOverlap);
            }
        }
    }

    let mut tbl = USER_NS_TABLE.lock();
    let data = tbl.entries.get_mut(&ns_id).ok_or(MapWriteError::NoSuchNs)?;

    match kind {
        MapKind::Uid => {
            if data.uid_map_written { return Err(MapWriteError::AlreadyWritten); }
            data.uid_map = entries.to_vec();
            data.uid_map_written = true;
        }
        MapKind::Gid => {
            if data.gid_map_written { return Err(MapWriteError::AlreadyWritten); }
            data.gid_map = entries.to_vec();
            data.gid_map_written = true;
        }
    }
    Ok(())
}

/// Render the uid_map for `ns_id` as a Linux-formatted string.
/// Each line: "<ns_first>\t<host_first>\t<count>\n"
/// Returns an empty string if the namespace does not exist or is unmapped.
pub fn format_uid_map(ns_id: NsId) -> alloc::string::String {
    format_map(ns_id, MapKind::Uid)
}

/// Render the gid_map for `ns_id`.
pub fn format_gid_map(ns_id: NsId) -> alloc::string::String {
    format_map(ns_id, MapKind::Gid)
}

fn format_map(ns_id: NsId, kind: MapKind) -> alloc::string::String {
    use alloc::string::ToString;
    let tbl = USER_NS_TABLE.lock();
    let data = match tbl.entries.get(&ns_id) {
        Some(d) => d,
        None    => return alloc::string::String::new(),
    };
    let entries = match kind {
        MapKind::Uid => &data.uid_map,
        MapKind::Gid => &data.gid_map,
    };
    let mut out = alloc::string::String::new();
    for e in entries {
        out.push_str(&alloc::format!(
            "{}\t{}\t{}\n",
            e.ns_first, e.host_first, e.count
        ));
    }
    out
}

/// Parse a Linux uid_map / gid_map write payload.
///
/// The payload is a sequence of whitespace-separated triples:
///   `<ns_first> <host_first> <count>`
/// Multiple triples may appear, separated by newlines.
/// Returns `Err` with an appropriate `MapWriteError` on parse failure.
pub fn parse_id_map(text: &str) -> Result<Vec<IdMapEntry>, MapWriteError> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let mut parts = line.split_whitespace();
        let ns_first   = parts.next().and_then(|s| s.parse::<u32>().ok());
        let host_first = parts.next().and_then(|s| s.parse::<u32>().ok());
        let count      = parts.next().and_then(|s| s.parse::<u32>().ok());
        match (ns_first, host_first, count) {
            (Some(n), Some(h), Some(c)) => entries.push(IdMapEntry {
                ns_first: n, host_first: h, count: c,
            }),
            _ => return Err(MapWriteError::ZeroCount), // reuse as parse error
        }
        if entries.len() > MAX_ID_MAP_ENTRIES {
            return Err(MapWriteError::TooManyEntries);
        }
    }
    Ok(entries)
}

/// Handle a write to `/proc/<pid>/uid_map` or `/proc/<pid>/gid_map`.
///
/// `writer_pid` is the process doing the write (its host UID is used for
/// privilege checks).  Returns 0 on success, negative errno on error.
pub fn procfs_write_id_map(
    target_pid: usize,
    kind: &str,          // "uid_map" or "gid_map"
    buf: &[u8],
    writer_pid: usize,
) -> isize {
    let text = match core::str::from_utf8(buf) {
        Ok(s)  => s,
        Err(_) => return -22, // EINVAL
    };
    let entries = match parse_id_map(text) {
        Ok(v)  => v,
        Err(_) => return -22,
    };
    // Look up the target process's user namespace.
    let ns_id = match crate::proc::scheduler::with_proc(target_pid, |p| p.ns.user) {
        Some(id) => id,
        None     => return -3, // ESRCH
    };
    // Writer's host UID (privilege check).
    let writer_uid = crate::proc::scheduler::with_proc(writer_pid, |p| p.uid)
        .unwrap_or(0);
    let result = match kind {
        "uid_map" => write_uid_map(ns_id, &entries, writer_uid),
        "gid_map" => write_gid_map(ns_id, &entries, writer_uid),
        _         => return -22,
    };
    match result {
        Ok(())                              => 0,
        Err(MapWriteError::AlreadyWritten)  => -16, // EBUSY
        Err(MapWriteError::PermissionDenied) => -1, // EPERM
        Err(_)                              => -22, // EINVAL
    }
}
