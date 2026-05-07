//! /proc pseudo-filesystem.
//!
//! ## Entries implemented
//!   /proc/self         → symlink to /proc/<current_pid>
//!   /proc/self/exe     → readlink target = path of current executable
//!   /proc/self/maps    → VMA list in /proc/maps format
//!   /proc/self/status  → task_struct subset (Name, Pid, PPid, VmRSS…)
//!   /proc/self/fd/N    → symlink to the open file behind fd N
//!   /proc/self/fd/     → directory listing of open fds (getdents)
//!   /proc/cpuinfo      → one entry per ACPI CPU
//!   /proc/meminfo      → PMM totals
//!   /proc/version      → kernel version string
//!   /proc/<pid>/…      → same as /proc/self/… for the given pid
//!
//! ## readlink support
//!   readlink("/proc/self/exe")  → exe path string (no NUL)
//!   readlink("/proc/self/fd/N") → path behind fd N
//!   readlink("/proc/self")      → "/proc/<pid>"
//!   procfs_readlink(path, buf, bufsz) is the entry point; called from
//!   stat_syscalls::sys_readlink and sys_readlinkat.
//!
//! ## for_open_fds
//!   Used by close_range to enumerate synthetic procfs fds without
//!   exposing the internal TABLE.

extern crate alloc;
use alloc::{format, string::String, vec::Vec, borrow::Cow};
use spin::Mutex;

// ─── Synthetic fd table ──────────────────────────────────────────────────────

pub const PROCFS_FD_BASE: usize = 0x6000_0000;

struct ProcEntry {
    content: Vec<u8>,
}

static TABLE: Mutex<alloc::collections::BTreeMap<usize, ProcEntry>> =
    Mutex::new(alloc::collections::BTreeMap::new());
static COUNTER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Returns true if `fdno` is a procfs synthetic fd.
pub fn is_procfs_fd(fdno: usize) -> bool {
    fdno >= PROCFS_FD_BASE && TABLE.lock().contains_key(&fdno)
}

/// Called by vfs::open() when the path starts with "/proc/".
/// Returns a synthetic fd, or -ENOENT.
pub fn procfs_open(path: &str) -> isize {
    let content = match generate(path) {
        Some(c) => c,
        None    => return -2,
    };
    let id   = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let fdno = PROCFS_FD_BASE + id;
    TABLE.lock().insert(fdno, ProcEntry { content });
    fdno as isize
}

/// Read bytes from a procfs fd, starting at `offset`.
pub fn procfs_read(fdno: usize, buf: &mut [u8], offset: usize) -> isize {
    let chunk: Vec<u8> = {
        let tbl = TABLE.lock();
        match tbl.get(&fdno) {
            None => return -9,
            Some(e) => {
                if offset >= e.content.len() { return 0; }
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

pub fn procfs_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}

/// Enumerate all open procfs synthetic fds. Used by close_range.
pub fn for_open_fds<F: FnMut(usize)>(mut f: F) {
    let fds: Vec<usize> = TABLE.lock().keys().copied().collect();
    for fd in fds { f(fd); }
}

// ─── readlink support ────────────────────────────────────────────────────────
//
// procfs_readlink is the single entry point for all /proc readlink targets.
// It does NOT open a synthetic fd — it synthesises the link target directly
// into the caller's buffer.  This matches how Linux handles readlink on
// symlink-like /proc entries.
//
// Supported paths:
//   /proc/self            → "/proc/<current_pid>"
//   /proc/self/exe        → absolute exe path
//   /proc/self/fd/<N>     → path behind fd N
//   /proc/<pid>/exe       → exe path for pid
//   /proc/<pid>/fd/<N>    → path behind fd N of pid (cross-pid; pid ignored)

pub fn procfs_readlink(path: &str, buf: &mut [u8]) -> isize {
    let pid = crate::proc::scheduler::current_pid();

    // /proc/self → /proc/<pid>
    if path == "/proc/self" {
        let s = format!("/proc/{}", pid);
        return copy_link(s.as_bytes(), buf);
    }

    // Normalise /proc/self/… → /proc/<pid>/…
    let norm: Cow<str> = if path.starts_with("/proc/self/") {
        Cow::Owned(path.replacen("/proc/self", &format!("/proc/{}", pid), 1))
    } else {
        Cow::Borrowed(path)
    };
    let p = norm.as_ref();

    // /proc/<pid>/exe
    if let Some((epid, "")) = strip_pid_prefix(p, "/exe") {
        let exe = crate::proc::scheduler::exe_path_of(epid)
            .unwrap_or_else(|| String::from("/init"));
        return copy_link(exe.as_bytes(), buf);
    }

    // /proc/<pid>/fd/<N>
    if let Some((_spid, fdpart)) = strip_pid_prefix(p, "/fd/") {
        if let Ok(fdno) = fdpart.parse::<usize>() {
            let target = crate::fs::vfs::fd_to_path(fdno)
                .unwrap_or_else(|| format!("socket:[{}]", fdno));
            return copy_link(target.as_bytes(), buf);
        }
    }

    -2 // ENOENT
}

/// Copy up to `buf.len()` bytes of `src` into `buf`; return bytes copied.
/// Never writes a NUL terminator (readlink does not NUL-terminate).
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
    if let Some((spid, "")) = strip_pid_prefix(p, "/status") {
        return Some(gen_status(spid).into_bytes());
    }
    // /proc/<pid>/exe — readable as a file returns the path as plain text.
    // readlink uses procfs_readlink() instead.
    if let Some((epid, "")) = strip_pid_prefix(p, "/exe") {
        return Some(gen_exe(epid).into_bytes());
    }
    // /proc/<pid>/fd/<N> — readable content = symlink target.
    if let Some((_spid, fdpart)) = strip_pid_prefix(p, "/fd/") {
        let fdno: usize = fdpart.parse().ok()?;
        return Some(gen_fd_link(fdno).into_bytes());
    }
    // /proc/<pid>/fd/ — directory listing of open fd numbers.
    if let Some((_spid, "")) = strip_pid_prefix(p, "/fd") {
        return Some(gen_fd_dir().into_bytes());
    }
    if p == "/proc/cpuinfo"  { return Some(gen_cpuinfo().into_bytes()); }
    if p == "/proc/meminfo"  { return Some(gen_meminfo().into_bytes()); }
    if p == "/proc/version"  { return Some(gen_version().into_bytes()); }
    if p == format!("/proc/{}", pid).as_str() {
        return Some(b"maps\nstatus\nexe\nfd\n".to_vec());
    }
    None
}

/// Returns (pid, suffix_after_prefix) if path matches "/proc/<pid><suffix>".
fn strip_pid_prefix<'a>(path: &'a str, suffix: &str) -> Option<(usize, &'a str)> {
    let after = path.strip_prefix("/proc/")?;
    let slash  = after.find('/')?;
    let pid: usize = after[..slash].parse().ok()?;
    let rest = &after[slash..];
    if suffix.is_empty() {
        return Some((pid, rest));
    }
    if rest == suffix {
        Some((pid, ""))
    } else if rest.starts_with(suffix) {
        Some((pid, &rest[suffix.len()..]))
    } else {
        None
    }
}

// ─── /proc/<pid>/maps ────────────────────────────────────────────────────────

fn gen_maps(pid: usize) -> String {
    let mut out = String::new();
    crate::mm::mmap::with_vmas(pid as u32, |vma| {
        let r = if vma.prot & 1 != 0 { 'r' } else { '-' };
        let w = if vma.prot & 2 != 0 { 'w' } else { '-' };
        let x = if vma.prot & 4 != 0 { 'x' } else { '-' };
        let s = if vma.flags & 1 != 0 { 's' } else { 'p' };
        let perms = format!("{}{}{}{}", r, w, x, s);
        out.push_str(&format!(
            "{:016x}-{:016x} {} {:08x} 00:00 0\n",
            vma.start, vma.end, perms, vma.file_offset,
        ));
    });
    out
}

// ─── /proc/<pid>/status ──────────────────────────────────────────────────────

fn gen_status(pid: usize) -> String {
    let ppid  = crate::proc::scheduler::ppid_of(pid);
    let vm_kb = crate::mm::mmap::vma_total_kb(pid as u32);
    format!(
        "Name:\trustos-proc\n\
         Pid:\t{}\n\
         PPid:\t{}\n\
         State:\tR (running)\n\
         VmRSS:\t{} kB\n\
         VmSize:\t{} kB\n\
         Threads:\t1\n",
        pid, ppid, vm_kb, vm_kb,
    )
}

// ─── /proc/<pid>/exe ─────────────────────────────────────────────────────────

fn gen_exe(pid: usize) -> String {
    crate::proc::scheduler::exe_path_of(pid)
        .unwrap_or_else(|| String::from("/init"))
}

// ─── /proc/<pid>/fd/<N> ──────────────────────────────────────────────────────

fn gen_fd_link(fdno: usize) -> String {
    crate::fs::vfs::fd_to_path(fdno)
        .unwrap_or_else(|| format!("socket:[{}]", fdno))
}

// ─── /proc/<pid>/fd/ (directory listing) ─────────────────────────────────────
//
// Returns newline-separated fd numbers for all open fds.  This is the
// content musl's closefrom() fallback reads when close_range is unavailable.

fn gen_fd_dir() -> String {
    let mut out = String::new();
    crate::fs::vfs::for_open_fds(|fd| {
        out.push_str(&format!("{}", fd));
        out.push('\n');
    });
    out
}

// ─── /proc/cpuinfo ───────────────────────────────────────────────────────────

fn gen_cpuinfo() -> String {
    let mut out = String::new();
    let mut idx = 0usize;
    crate::acpi::with_cpus(|cpu| {
        out.push_str(&format!(
            "processor\t: {}\n\
             vendor_id\t: RustOS\n\
             cpu MHz\t: 1000.000\n\
             model name\t: RustOS Virtual CPU\n\
             apicid\t: {}\n\n",
            idx, cpu.apic_id,
        ));
        idx += 1;
    });
    if idx == 0 {
        out.push_str(
            "processor\t: 0\nvendor_id\t: RustOS\n\
             cpu MHz\t: 1000.000\nmodel name\t: RustOS Virtual CPU\n\n"
        );
    }
    out
}

// ─── /proc/meminfo ───────────────────────────────────────────────────────────

fn gen_meminfo() -> String {
    let total_kb = crate::mm::pmm::total_pages() * 4;
    let free_kb  = crate::mm::pmm::free_pages()  * 4;
    format!(
        "MemTotal:\t{} kB\n\
         MemFree:\t{} kB\n\
         MemAvailable:\t{} kB\n\
         Buffers:\t0 kB\n\
         Cached:\t0 kB\n\
         SwapTotal:\t0 kB\n\
         SwapFree:\t0 kB\n",
        total_kb, free_kb, free_kb,
    )
}

// ─── /proc/version ───────────────────────────────────────────────────────────

fn gen_version() -> String {
    format!("Linux version 6.1.0-rustos (rustc) #1 SMP {}\n",
            "Sun Jan  1 00:00:00 UTC 2023")
}
