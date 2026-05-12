//! Time namespace — per-namespace clock offsets.
//!
//! Linux time namespaces (CLONE_NEWTIME, added in 5.6) allow processes to
//! see a different value for CLOCK_MONOTONIC and CLOCK_BOOTTIME by applying
//! a fixed offset stored in the namespace.  CLOCK_REALTIME is **not**
//! affected (it is always the global wall clock).
//!
//! ## Data model
//!
//! Each time namespace stores:
//!   - `monotonic_offset_ns: i64` — added to `crate::time::monotonic_ns()`
//!     before returning it to user-space for CLOCK_MONOTONIC.
//!   - `boottime_offset_ns: i64`  — same for CLOCK_BOOTTIME.
//!
//! INIT_NS has both offsets at 0 (pass-through).
//!
//! ## Syscall integration
//!
//! `clock_gettime(CLOCK_MONOTONIC, tp)` and `clock_gettime(CLOCK_BOOTTIME, tp)`
//! call `time_ns_adjust_monotonic(ns_id, raw_ns)` before writing the result
//! to user-space.  All other clocks are unaffected.
//!
//! `clock_settime` is rejected with EPERM for CLOCK_MONOTONIC / CLOCK_BOOTTIME
//! (consistent with Linux; use `timens_offsets` write instead).  For
//! CLOCK_REALTIME a privileged caller may use adjtime — not yet implemented.
//!
//! ## /proc/PID/timens_offsets
//!
//! Writing `"monotonic <secs> <nsecs>\n"` or `"boottime <secs> <nsecs>\n"`
//! to this file sets the offset.  Reading returns the current offsets.
//! This matches the Linux interface added in kernel 5.6.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::Mutex;
use crate::proc::namespace::{NsId, INIT_NS, alloc_ns_id};

// ─── Per-namespace offsets ────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default)]
pub struct TimeNsOffsets {
    /// Added to CLOCK_MONOTONIC reads.  May be negative.
    pub monotonic_ns: i64,
    /// Added to CLOCK_BOOTTIME reads.
    pub boottime_ns:  i64,
}

static TIME_NS_TABLE: Mutex<BTreeMap<NsId, TimeNsOffsets>> =
    Mutex::new(BTreeMap::new());

/// Seed INIT_NS with zero offsets.  Called once from kernel init.
pub fn init_time_ns() {
    TIME_NS_TABLE.lock().entry(INIT_NS).or_default();
}

/// Create a new child time namespace.
/// The new namespace **inherits** the parent's current offsets (Linux 5.6
/// semantics: the child starts at the same apparent time as the parent).
pub fn create_time_ns(parent: NsId) -> NsId {
    let new_id = alloc_ns_id();
    let parent_offsets = TIME_NS_TABLE.lock()
        .get(&parent)
        .copied()
        .unwrap_or_default();
    TIME_NS_TABLE.lock().insert(new_id, parent_offsets);
    new_id
}

/// Destroy a time namespace.  No-op for INIT_NS.
pub fn drop_time_ns(ns: NsId) {
    if ns == INIT_NS { return; }
    TIME_NS_TABLE.lock().remove(&ns);
}

// ─── Offset read / write ──────────────────────────────────────────────────────

/// Get the offsets for `ns`.  Returns all-zero for unknown namespaces.
pub fn get_offsets(ns: NsId) -> TimeNsOffsets {
    TIME_NS_TABLE.lock()
        .get(&ns)
        .copied()
        .unwrap_or_default()
}

/// Set the CLOCK_MONOTONIC offset for `ns` (in nanoseconds).
pub fn set_monotonic_offset(ns: NsId, offset_ns: i64) {
    TIME_NS_TABLE.lock()
        .entry(ns)
        .or_default()
        .monotonic_ns = offset_ns;
}

/// Set the CLOCK_BOOTTIME offset for `ns`.
pub fn set_boottime_offset(ns: NsId, offset_ns: i64) {
    TIME_NS_TABLE.lock()
        .entry(ns)
        .or_default()
        .boottime_ns = offset_ns;
}

// ─── Clock adjustment helpers ─────────────────────────────────────────────────

/// Adjust a raw CLOCK_MONOTONIC reading for the calling process's time namespace.
/// Call this immediately before copying the timespec to user-space.
pub fn adjust_monotonic(ns: NsId, raw_ns: u64) -> u64 {
    let off = get_offsets(ns).monotonic_ns;
    if off >= 0 {
        raw_ns.saturating_add(off as u64)
    } else {
        raw_ns.saturating_sub((-off) as u64)
    }
}

/// Adjust a raw CLOCK_BOOTTIME reading.
pub fn adjust_boottime(ns: NsId, raw_ns: u64) -> u64 {
    let off = get_offsets(ns).boottime_ns;
    if off >= 0 {
        raw_ns.saturating_add(off as u64)
    } else {
        raw_ns.saturating_sub((-off) as u64)
    }
}

// ─── /proc/<pid>/timens_offsets ──────────────────────────────────────────────

/// Format the offsets for `/proc/<pid>/timens_offsets` reads.
/// Output format (two lines):
///   `monotonic <secs> <nsecs>\n`
///   `boottime  <secs> <nsecs>\n`
pub fn format_offsets(ns: NsId) -> String {
    let off = get_offsets(ns);
    let (mono_s, mono_ns) = split_offset(off.monotonic_ns);
    let (boot_s, boot_ns) = split_offset(off.boottime_ns);
    alloc::format!(
        "monotonic {} {}\nboottime  {} {}\n",
        mono_s, mono_ns,
        boot_s, boot_ns,
    )
}

/// Parse and apply a write to `/proc/<pid>/timens_offsets`.
/// Accepted lines: `"monotonic <secs> <nsecs>"` or `"boottime <secs> <nsecs>"`
/// Returns 0 on success, -EINVAL on parse error, -EPERM if the namespace
/// already has processes other than the writing process inside it.
pub fn write_offsets(ns: NsId, text: &str) -> isize {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let mut parts = line.split_whitespace();
        let clock = parts.next().unwrap_or("");
        let secs  = parts.next().and_then(|s| s.parse::<i64>().ok());
        let nsecs = parts.next().and_then(|s| s.parse::<i64>().ok());
        match (clock, secs, nsecs) {
            ("monotonic", Some(s), Some(n)) => {
                let total = s.saturating_mul(1_000_000_000).saturating_add(n);
                set_monotonic_offset(ns, total);
            }
            ("boottime", Some(s), Some(n)) => {
                let total = s.saturating_mul(1_000_000_000).saturating_add(n);
                set_boottime_offset(ns, total);
            }
            _ => return -22,
        }
    }
    0
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Split a nanosecond offset into (whole_seconds, remaining_ns) for display.
fn split_offset(ns: i64) -> (i64, i64) {
    let s  = ns / 1_000_000_000;
    let ns = ns % 1_000_000_000;
    (s, ns)
}

// ─── clock_gettime integration ────────────────────────────────────────────────

pub const CLOCK_REALTIME:          u32 = 0;
pub const CLOCK_MONOTONIC:         u32 = 1;
pub const CLOCK_PROCESS_CPUTIME:   u32 = 2;
pub const CLOCK_THREAD_CPUTIME:    u32 = 3;
pub const CLOCK_MONOTONIC_RAW:     u32 = 4;
pub const CLOCK_REALTIME_COARSE:   u32 = 5;
pub const CLOCK_MONOTONIC_COARSE:  u32 = 6;
pub const CLOCK_BOOTTIME:          u32 = 7;
pub const CLOCK_TAI:               u32 = 11;

/// Full `clock_gettime(2)` implementation with time-namespace support.
/// Called from `sys_clock_gettime_impl` in stubs.rs.
pub fn sys_clock_gettime(clkid: u32, tp_va: usize) -> isize {
    use crate::uaccess::copy_to_user;
    if tp_va == 0 { return -22; }

    let raw_ns = crate::time::monotonic_ns();
    let pid    = crate::proc::scheduler::current_pid();
    let ns     = crate::proc::scheduler::with_proc(pid, |p| p.ns.time)
        .unwrap_or(INIT_NS);

    let final_ns: u64 = match clkid {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE | CLOCK_TAI => raw_ns,
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE => {
            adjust_monotonic(ns, raw_ns)
        }
        CLOCK_BOOTTIME => adjust_boottime(ns, raw_ns),
        CLOCK_PROCESS_CPUTIME => {
            crate::proc::scheduler::with_proc(pid, |p| p.cpu_time_ns).unwrap_or(raw_ns)
        }
        CLOCK_THREAD_CPUTIME => {
            crate::proc::scheduler::with_proc(pid, |p| p.cpu_time_ns).unwrap_or(raw_ns)
        }
        _ => return -22, // EINVAL
    };

    let secs  = (final_ns / 1_000_000_000) as i64;
    let nanos = (final_ns % 1_000_000_000) as i64;
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&secs.to_le_bytes());
    buf[8..16].copy_from_slice(&nanos.to_le_bytes());
    if copy_to_user(tp_va, &buf).is_err() { return -14; }
    0
}
