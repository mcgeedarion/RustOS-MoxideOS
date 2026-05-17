//! /sys pseudo-filesystem (sysfs).
//!
//! ## Directories / files implemented
//!
//!   /sys/kernel/hostname          → kernel hostname string
//!   /sys/kernel/ostype            → "Linux"
//!   /sys/kernel/osrelease         → "6.1.0-rustos"
//!   /sys/kernel/version           → build version string
//!   /sys/kernel/pid_max           → max PID value
//!   /sys/kernel/threads-max       → max threads value
//!   /sys/kernel/dmesg_restrict     → "0"
//!   /sys/kernel/perf_event_paranoid → "1"
//!   /sys/kernel/randomize_va_space → "2" (ASLR on)
//!
//!   /sys/devices/system/cpu/online → cpu mask string e.g. "0-3"
//!   /sys/devices/system/cpu/possible → cpu mask string
//!   /sys/devices/system/cpu/present  → cpu mask string
//!
//!   /sys/bus/pci/devices/         → directory (empty listing)
//!
//!   /sys/class/net/lo/operstate   → "unknown"
//!   /sys/class/net/lo/mtu         → "65536"
//!   /sys/class/net/eth0/operstate → "up"
//!   /sys/class/net/eth0/mtu       → "1500"
//!
//!   /sys/block/                   → directory (empty listing)
//!   /sys/power/state              → "freeze standby mem disk"
//!   /sys/power/wakeup_count       → "0"
//!
//! ## Integration
//!   sys_open("/sys/…")  → sysfs_open()  → returns a synthetic fd (>= SYSFS_FD_BASE)
//!   sys_read(fd, …)     → sysfs_read()  (dispatched from io_syscalls.rs)
//!   sys_close(fd)       → sysfs_close() (dispatched from io_syscalls.rs)
//!   getdents(fd)        → sysfs_list_dir() (returns Vec<DirEntry>)
//!
//!   All reads are synthesised on-the-fly; there is no backing storage.

extern crate alloc;
use alloc::{string::String, vec::Vec};
use spin::Mutex;

// ─── Synthetic fd table ─────────────────────────────────────────────────────

pub const SYSFS_FD_BASE: usize = 0x7000_0000;

struct SysEntry {
    content: Vec<u8>,
    /// true when the fd was opened on a directory (getdents path)
    is_dir:  bool,
    /// canonical path stored so getdents can enumerate children
    path:    String,
}

static TABLE: Mutex<alloc::collections::BTreeMap<usize, SysEntry>> =
    Mutex::new(alloc::collections::BTreeMap::new());
static COUNTER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Returns true if `fdno` is a sysfs synthetic fd.
pub fn is_sysfs_fd(fdno: usize) -> bool {
    fdno >= SYSFS_FD_BASE && TABLE.lock().contains_key(&fdno)
}

/// Called by sys_open() when the path starts with "/sys/".
/// Returns a synthetic fd on success, or -ENOENT (-2).
pub fn sysfs_open(path: &str) -> isize {
    let (content, is_dir) = match generate(path) {
        Some(pair) => pair,
        None       => return -2,
    };
    let id   = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let fdno = SYSFS_FD_BASE + id;
    TABLE.lock().insert(fdno, SysEntry {
        content,
        is_dir,
        path: alloc::format!("{}", path),
    });
    fdno as isize
}

/// Read bytes from a sysfs fd starting at `offset`.
pub fn sysfs_read(fdno: usize, buf: &mut [u8], offset: usize) -> isize {
    let chunk: Vec<u8> = {
        let tbl = TABLE.lock();
        match tbl.get(&fdno) {
            None => return -9, // EBADF
            Some(e) => {
                if e.is_dir || offset >= e.content.len() { return 0; }
                let avail = &e.content[offset..];
                let n = avail.len().min(buf.len());
                avail[..n].to_vec()
            }
        }
    };
    let n = chunk.len();
    buf[..n].copy_from_slice(&chunk);
    n as isize
}

pub fn sysfs_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}

// ─── getdents support ───────────────────────────────────────────────────────

pub struct DirEntry {
    pub name:   String,
    pub is_dir: bool,
}

/// Return immediate children of `path` if it is a known sysfs directory,
/// or None if the path is not a directory in sysfs.
pub fn sysfs_list_dir(path: &str) -> Option<Vec<DirEntry>> {
    let entries = static_children(path)?;
    Some(entries)
}

// ─── Content / directory generator ─────────────────────────────────────────

/// Returns (content_bytes, is_dir).  None → ENOENT.
fn generate(path: &str) -> Option<(Vec<u8>, bool)> {
    // ── /sys root ───────────────────────────────────────────────────────────
    if path == "/sys" || path == "/sys/" {
        return Some((Vec::new(), true));
    }

    // ── /sys/kernel/* ───────────────────────────────────────────────────────
    if path == "/sys/kernel" {
        return Some((Vec::new(), true));
    }
    if path == "/sys/kernel/hostname" {
        return Some((b"rustos\n".to_vec(), false));
    }
    if path == "/sys/kernel/ostype" {
        return Some((b"Linux\n".to_vec(), false));
    }
    if path == "/sys/kernel/osrelease" {
        return Some((b"6.1.0-rustos\n".to_vec(), false));
    }
    if path == "/sys/kernel/version" {
        let s = alloc::format!("#1 SMP RustOS {}\n", "2023-01-01");
        return Some((s.into_bytes(), false));
    }
    if path == "/sys/kernel/pid_max" {
        return Some((b"32768\n".to_vec(), false));
    }
    if path == "/sys/kernel/threads-max" {
        return Some((b"32768\n".to_vec(), false));
    }
    if path == "/sys/kernel/dmesg_restrict" {
        return Some((b"0\n".to_vec(), false));
    }
    if path == "/sys/kernel/perf_event_paranoid" {
        return Some((b"1\n".to_vec(), false));
    }
    if path == "/sys/kernel/randomize_va_space" {
        return Some((b"2\n".to_vec(), false));
    }

    // ── /sys/devices/system/cpu/* ────────────────────────────────────────────
    if path == "/sys/devices"
        || path == "/sys/devices/system"
        || path == "/sys/devices/system/cpu" {
        return Some((Vec::new(), true));
    }
    if path == "/sys/devices/system/cpu/online"
        || path == "/sys/devices/system/cpu/possible"
        || path == "/sys/devices/system/cpu/present" {
        let cpus = cpu_count();
        let mask = if cpus <= 1 {
            alloc::format!("0\n")
        } else {
            alloc::format!("0-{}\n", cpus - 1)
        };
        return Some((mask.into_bytes(), false));
    }

    // ── /sys/bus/pci* ───────────────────────────────────────────────────────
    if path == "/sys/bus"
        || path == "/sys/bus/pci"
        || path == "/sys/bus/pci/devices" {
        return Some((Vec::new(), true));
    }

    // ── /sys/class/net/* ────────────────────────────────────────────────────
    if path == "/sys/class"
        || path == "/sys/class/net"
        || path == "/sys/class/net/lo"
        || path == "/sys/class/net/eth0" {
        return Some((Vec::new(), true));
    }
    if path == "/sys/class/net/lo/operstate" {
        return Some((b"unknown\n".to_vec(), false));
    }
    if path == "/sys/class/net/lo/mtu" {
        return Some((b"65536\n".to_vec(), false));
    }
    if path == "/sys/class/net/eth0/operstate" {
        return Some((b"up\n".to_vec(), false));
    }
    if path == "/sys/class/net/eth0/mtu" {
        return Some((b"1500\n".to_vec(), false));
    }

    // ── /sys/block ──────────────────────────────────────────────────────────
    if path == "/sys/block" {
        return Some((Vec::new(), true));
    }

    // ── /sys/power/* ────────────────────────────────────────────────────────
    if path == "/sys/power" {
        return Some((Vec::new(), true));
    }
    if path == "/sys/power/state" {
        return Some((b"freeze standby mem disk\n".to_vec(), false));
    }
    if path == "/sys/power/wakeup_count" {
        return Some((b"0\n".to_vec(), false));
    }

    None
}

/// Return the names of the immediate children of a sysfs directory.
/// Returns None when the path is not a known directory.
fn static_children(path: &str) -> Option<Vec<DirEntry>> {
    let dir = |n: &str| DirEntry { name: alloc::format!("{}", n), is_dir: true  };
    let fil = |n: &str| DirEntry { name: alloc::format!("{}", n), is_dir: false };

    let entries: Vec<DirEntry> = match path {
        "/sys" | "/sys/" => vec![
            dir("kernel"), dir("devices"), dir("bus"),
            dir("class"),  dir("block"),   dir("power"),
        ],
        "/sys/kernel" => vec![
            fil("hostname"), fil("ostype"), fil("osrelease"),
            fil("version"),  fil("pid_max"),fil("threads-max"),
            fil("dmesg_restrict"), fil("perf_event_paranoid"),
            fil("randomize_va_space"),
        ],
        "/sys/devices"                 => vec![dir("system")],
        "/sys/devices/system"          => vec![dir("cpu")],
        "/sys/devices/system/cpu"      => vec![
            fil("online"), fil("possible"), fil("present"),
        ],
        "/sys/bus"                     => vec![dir("pci")],
        "/sys/bus/pci"                 => vec![dir("devices")],
        "/sys/bus/pci/devices"         => vec![],
        "/sys/class"                   => vec![dir("net")],
        "/sys/class/net"               => vec![dir("lo"), dir("eth0")],
        "/sys/class/net/lo"            => vec![fil("operstate"), fil("mtu")],
        "/sys/class/net/eth0"          => vec![fil("operstate"), fil("mtu")],
        "/sys/block"                   => vec![],
        "/sys/power"                   => vec![fil("state"), fil("wakeup_count")],
        _ => return None,
    };
    Some(entries)
}

// ─── Helper: CPU count from ACPI or fallback 1 ──────────────────────────────

fn cpu_count() -> usize {
    let mut n = 0usize;
    crate::firmware::acpi::with_cpus(|_| { n += 1; });
    if n == 0 { 1 } else { n }
}
