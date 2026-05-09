//! procfs — synthetic /proc filesystem.
//!
//! ## Paths handled
//!   /proc/self/exe     → readlink target = path of current executable
//!   /proc/<pid>/exe    → same for any pid
//!   /proc/self/fd/N    → symlink to the open file behind fd N
//!   /proc/self/fd/     → directory listing of open fds (getdents)
//!   /proc/self/maps    → VMA map in Linux /proc/maps format
//!   /proc/<pid>/maps   → same for any pid
//!   /proc/self/status  → minimal status fields
//!   /proc/self/stat    → minimal stat line (for getrusage etc.)
//!   /proc/<pid>/limits → per-process resource limits (ulimit -a format)
//!   /proc/uptime       → uptime in seconds
//!   /proc/meminfo      → basic memory figures
//!   /proc/cpuinfo      → single-CPU stub
//!
//! ## readlink support
//!   readlink("/proc/self/exe")  → exe path string (no NUL)
//!   readlink("/proc/self/fd/N") → path behind fd N
//!   readlink("/proc/self")      → "/proc/<pid>"
//!   procfs_readlink(path, buf, bufsz) is the entry point; called from
//!   stat_syscalls::sys_readlink and sys_readlinkat.
//!
//! ## Synthetic fd support
//!   Used by close_range to enumerate synthetic procfs fds without
//!   allocating real VFS fds.

extern crate alloc;
use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Returns true if `fdno` is a procfs synthetic fd.
pub fn is_procfs_fd(fdno: usize) -> bool {
    PROCFS_FDS.lock().contains_key(&fdno)
}

use spin::Mutex;
use alloc::collections::BTreeMap;

#[derive(Clone)]
struct ProcFd {
    content: Vec<u8>,
    offset:  usize,
}

static PROCFS_FDS: Mutex<BTreeMap<usize, ProcFd>> = Mutex::new(BTreeMap::new());

/// Read bytes from a procfs fd, starting at `offset`.
pub fn procfs_read(fdno: usize, buf: &mut [u8], offset: usize) -> isize {
    let guard = PROCFS_FDS.lock();
    let pfd = match guard.get(&fdno) {
        Some(p) => p,
        None    => return -9,
    };
    let start = offset.min(pfd.content.len());
    let avail = &pfd.content[start..];
    let n = avail.len().min(buf.len());
    buf[..n].copy_from_slice(&avail[..n]);
    n as isize
}

pub fn procfs_close(fdno: usize) {
    PROCFS_FDS.lock().remove(&fdno);
}

/// Enumerate all open procfs synthetic fds. Used by close_range.
pub fn procfs_fds() -> Vec<usize> {
    PROCFS_FDS.lock().keys().cloned().collect()
}

// ─── readlink support ────────────────────────────────────────────────────────

pub fn procfs_readlink(path: &str, buf: &mut [u8]) -> isize {
    let pid = crate::proc::scheduler::current_pid();

    if path == "/proc/self" {
        let s = format!("/proc/{}", pid);
        return copy_link(s.as_bytes(), buf);
    }

    let norm: Cow<str> = if path.starts_with("/proc/self/") {
        Cow::Owned(path.replacen("/proc/self", &format!("/proc/{}", pid), 1))
    } else {
        Cow::Borrowed(path)
    };
    let p = norm.as_ref();

    if let Some((epid, "")) = strip_pid_prefix(p, "/exe") {
        let exe = crate::proc::scheduler::exe_path_of(epid)
            .unwrap_or_else(|| String::from("/init"));
        return copy_link(exe.as_bytes(), buf);
    }

    if let Some((_spid, fdpart)) = strip_pid_prefix(p, "/fd/") {
        if let Ok(fdno) = fdpart.parse::<usize>() {
            let target = crate::fs::vfs::fd_get_debug_name(fdno)
                .or_else(|| crate::fs::vfs::fd_to_path(fdno))
                .unwrap_or_else(|| format!("socket:[{}]", fdno));
            return copy_link(target.as_bytes(), buf);
        }
    }

    -2 // ENOENT
}

fn copy_link(src: &[u8], buf: &mut [u8]) -> isize {
    let n = src.len().min(buf.len());
    buf[..n].copy_from_slice(&src[..n]);
    n as isize
}

// ─── Content generators ──────────────────────────────────────────────────────

fn generate(path: &str) -> Option<Vec<u8>> {
    let pid = crate::proc::scheduler::current_pid();
    let norm: Cow<str> = if path.contains("/proc/self") {
        Cow::Owned(path.replacen("/proc/self", &format!("/proc/{}", pid), 1))
    } else {
        Cow::Borrowed(path)
    };
    let p = norm.as_ref();

    if let Some((mpid, "")) = strip_pid_prefix(p, "/maps") {
        return Some(gen_maps(mpid).into_bytes());
    }
    if let Some((lpid, "")) = strip_pid_prefix(p, "/limits") {
        return Some(gen_limits(lpid).into_bytes());
    }
    if let Some((_, "")) = strip_pid_prefix(p, "/status") {
        return Some(gen_status(pid).into_bytes());
    }
    if let Some((_, "")) = strip_pid_prefix(p, "/stat") {
        return Some(gen_stat(pid).into_bytes());
    }
    if p == "/proc/uptime" {
        let ns = crate::time::monotonic_ns();
        let secs = ns / 1_000_000_000;
        let frac = (ns % 1_000_000_000) / 10_000_000;
        return Some(format!("{}.{:02} 0.00\n", secs, frac).into_bytes());
    }
    if p == "/proc/meminfo" {
        let total = crate::mm::pmm::total_pages() as u64 * 4;
        let free  = crate::mm::pmm::free_pages()  as u64 * 4;
        return Some(format!(
            "MemTotal:  {:8} kB\nMemFree:   {:8} kB\nMemAvailable: {:8} kB\n",
            total, free, free
        ).into_bytes());
    }
    if p == "/proc/cpuinfo" {
        return Some(b"processor\t: 0\nmodel name\t: rustos virtual CPU\n".to_vec());
    }
    if p == "/proc/self/cmdline" || p.ends_with("/cmdline") {
        let exe = crate::proc::scheduler::exe_path_of(pid)
            .unwrap_or_else(|| String::from("/init"));
        let mut v = exe.into_bytes();
        v.push(0);
        return Some(v);
    }
    if let Some((_spid, fdpart)) = strip_pid_prefix(p, "/fd/") {
        if let Ok(fdno) = fdpart.parse::<usize>() {
            if let Some(name) = crate::fs::vfs::fd_get_debug_name(fdno) {
                return Some(name.into_bytes());
            }
            if let Some(path) = crate::fs::vfs::fd_to_path(fdno) {
                return Some(path.into_bytes());
            }
        }
    }
    if let Some((_spid, "")) = strip_pid_prefix(p, "/fd") {
        return Some(gen_fd_dir(pid));
    }
    if p == "/proc/filesystems" {
        return Some(b"nodev\ttmpfs\next4\nvfat\n".to_vec());
    }
    if p == "/proc/mounts" || p == "/proc/self/mounts" || p.ends_with("/mounts") {
        return Some(b"tmpfs /dev/shm tmpfs rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n".to_vec());
    }
    None
}

// ─── /proc/<pid>/limits generator ────────────────────────────────────────────
//
// Produces the same tabular format as Linux's /proc/<pid>/limits:
//
//   Limit                     Soft Limit           Hard Limit           Units
//   Max cpu time              unlimited            unlimited            seconds
//   Max file size             unlimited            unlimited            bytes
//   ...
//
// "unlimited" is printed whenever the value equals RLIM_INFINITY (u64::MAX).

const RLIM_INFINITY: u64 = u64::MAX;

fn fmt_limit(v: u64) -> alloc::string::String {
    if v == RLIM_INFINITY {
        alloc::string::String::from("unlimited")
    } else {
        format!("{}", v)
    }
}

fn gen_limits(pid: usize) -> String {
    use crate::proc::rlimit::*;

    // Snapshot the rlimit table for the target pid.
    let get = |res: usize| -> (u64, u64) {
        crate::proc::rlimit::getrlimit_for(pid, res)
    };

    let header = format!(
        "{:<26}{:<21}{:<21}{}\n",
        "Limit", "Soft Limit", "Hard Limit", "Units"
    );

    // (name, resource_index, units_string)
    let rows: &[(&str, usize, &str)] = &[
        ("Max cpu time",          RLIMIT_CPU,      "seconds"),
        ("Max file size",         RLIMIT_FSIZE,    "bytes"),
        ("Max data size",         RLIMIT_DATA,     "bytes"),
        ("Max stack size",        RLIMIT_STACK,    "bytes"),
        ("Max core file size",    RLIMIT_CORE,     "bytes"),
        ("Max resident set",      RLIMIT_RSS,      "bytes"),
        ("Max processes",         RLIMIT_NPROC,    "processes"),
        ("Max open files",        RLIMIT_NOFILE,   "files"),
        ("Max locked memory",     RLIMIT_MEMLOCK,  "bytes"),
        ("Max address space",     RLIMIT_AS,       "bytes"),
        ("Max file locks",        RLIMIT_LOCKS,    "locks"),
        ("Max pending signals",   RLIMIT_SIGPENDING, "signals"),
        ("Max msgqueue size",     RLIMIT_MSGQUEUE, "bytes"),
        ("Max nice priority",     RLIMIT_NICE,     ""),
        ("Max realtime priority", RLIMIT_RTPRIO,   ""),
        ("Max realtime timeout",  RLIMIT_RTTIME,   "us"),
    ];

    let mut out = header;
    for &(name, res, units) in rows {
        let (soft, hard) = get(res);
        out.push_str(&format!(
            "{:<26}{:<21}{:<21}{}\n",
            name,
            fmt_limit(soft),
            fmt_limit(hard),
            units
        ));
    }
    out
}

// ─── /proc stat/status generators ───────────────────────────────────────────

fn gen_status(pid: usize) -> String {
    format!(
        "Name:\trustos\nState:\tR (running)\nPid:\t{}\nPPid:\t1\nVmRSS:\t4096 kB\n",
        pid
    )
}

fn gen_stat(pid: usize) -> String {
    format!("{} (rustos) R 1 {} {} 0 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0\n",
        pid, pid, pid)
}

// ─── /proc/<pid>/maps generator ──────────────────────────────────────────────

fn gen_maps(pid: usize) -> String {
    let mut out = String::new();
    let vmas = crate::proc::scheduler::with_proc(pid, |p| p.vmas.clone())
        .unwrap_or_default();
    for vma in &vmas {
        let r = if vma.prot & 1 != 0 { 'r' } else { '-' };
        let w = if vma.prot & 2 != 0 { 'w' } else { '-' };
        let x = if vma.prot & 4 != 0 { 'x' } else { '-' };
        let s = match vma.kind {
            crate::mm::mmap::VmaKind::Anonymous      => 'p',
            crate::mm::mmap::VmaKind::FileBacked(..) => 'p',
            crate::mm::mmap::VmaKind::Fixed          => 'p',
            crate::mm::mmap::VmaKind::PhysMap(..)    => 'p',
        };
        let label = match &vma.kind {
            crate::mm::mmap::VmaKind::FileBacked(fd, _) =>
                crate::fs::vfs::fd_to_path(*fd).unwrap_or_default(),
            _ => String::new(),
        };
        out.push_str(&format!(
            "{:016x}-{:016x} {}{}{}{} {:08x} 00:00 0\t{}\n",
            vma.start, vma.end, r, w, x, s, vma.file_offset, label
        ));
    }
    out
}

// ─── /proc/<pid>/fd/<N> ──────────────────────────────────────────────────────

fn gen_fd_dir(pid: usize) -> Vec<u8> {
    let _ = pid;
    let mut out = Vec::new();
    for fdno in 0usize..256 {
        if crate::fs::vfs::fd_to_path(fdno).is_some() {
            out.extend_from_slice(format!("{} ", fdno).as_bytes());
        }
    }
    out
}

// ─── open helper ─────────────────────────────────────────────────────────────

pub fn procfs_open(path: &str) -> Option<usize> {
    let content = generate(path)?;
    let fdno = next_procfs_fd();
    PROCFS_FDS.lock().insert(fdno, ProcFd { content, offset: 0 });
    Some(fdno)
}

fn next_procfs_fd() -> usize {
    let guard = PROCFS_FDS.lock();
    for candidate in 256..512 {
        if !guard.contains_key(&candidate) {
            return candidate;
        }
    }
    256
}

// ─── strip_pid_prefix helper ─────────────────────────────────────────────────

fn strip_pid_prefix<'a>(path: &'a str, suffix: &str) -> Option<(usize, &'a str)> {
    let after_proc = path.strip_prefix("/proc/")?;
    let slash = after_proc.find('/').unwrap_or(after_proc.len());
    let pid_str = &after_proc[..slash];
    let pid: usize = pid_str.parse().ok()?;
    let rest = &after_proc[slash..];
    let tail = rest.strip_prefix(suffix)?;
    Some((pid, tail))
}
