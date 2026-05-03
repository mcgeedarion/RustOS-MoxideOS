//! /proc pseudo-filesystem.
//!
//! ## Entries implemented
//!   /proc/self         → symlink to /proc/<current_pid>
//!   /proc/self/exe     → path of current executable
//!   /proc/self/maps    → VMA list in /proc/maps format
//!   /proc/self/status  → task_struct subset (Name, Pid, PPid, VmRSS…)
//!   /proc/self/fd/N    → symlink to the open file behind fd N
//!   /proc/cpuinfo      → one entry per ACPI CPU
//!   /proc/meminfo      → PMM totals
//!   /proc/version      → kernel version string
//!   /proc/<pid>/…      → same as /proc/self/… for the given pid
//!
//! ## Integration
//!   All reads are synthesised on-the-fly; there is no backing storage.
//!   open("/proc/…") in vfs.rs calls procfs_open() which returns a
//!   synthetic fd whose content is generated at read() time.
//!   The fd is stored in a small table here alongside its generator fn.

extern crate alloc;
use alloc::{format, string::String, vec::Vec};
use spin::Mutex;

// ─── Synthetic fd table ───────────────────────────────────────────────────────

pub const PROCFS_FD_BASE: usize = 0x6000_0000;

struct ProcEntry {
    content: Vec<u8>,
}

static TABLE: Mutex<alloc::collections::BTreeMap<usize, ProcEntry>> =
    Mutex::new(alloc::collections::BTreeMap::new());
static COUNTER: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Returns true if `fdno` is a procfs fd.
pub fn is_procfs_fd(fdno: usize) -> bool {
    fdno >= PROCFS_FD_BASE && TABLE.lock().contains_key(&fdno)
}

/// Called by vfs::open() when the path starts with "/proc/".
/// Returns a synthetic fd, or -ENOENT.
pub fn procfs_open(path: &str) -> isize {
    let content = match generate(path) {
        Some(c) => c,
        None    => return -2, // ENOENT
    };
    let id   = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let fdno = PROCFS_FD_BASE + id;
    TABLE.lock().insert(fdno, ProcEntry { content });
    fdno as isize
}

/// Read bytes from a procfs fd, starting at `offset`.
pub fn procfs_read(fdno: usize, buf: &mut [u8], offset: usize) -> isize {
    let tbl = TABLE.lock();
    match tbl.get(&fdno) {
        None => -9,
        Some(e) => {
            if offset >= e.content.len() { return 0; }
            let avail = &e.content[offset..];
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            n as isize
        }
    }
}

pub fn procfs_close(fdno: usize) {
    TABLE.lock().remove(&fdno);
}

// ─── Content generators ───────────────────────────────────────────────────────

fn generate(path: &str) -> Option<Vec<u8>> {
    // Normalise /proc/self → /proc/<current_pid>
    let pid = crate::proc::scheduler::current_pid();
    let norm = path.replacen("/proc/self", &format!("/proc/{}", pid), 1);
    let p = norm.as_str();

    // /proc/<pid>/maps
    if let Some(rest) = strip_pid_prefix(p, "/maps") {
        return Some(gen_maps(rest.0).into_bytes());
    }
    // /proc/<pid>/status
    if let Some(rest) = strip_pid_prefix(p, "/status") {
        return Some(gen_status(rest.0).into_bytes());
    }
    // /proc/<pid>/exe
    if let Some(rest) = strip_pid_prefix(p, "/exe") {
        return Some(gen_exe(rest.0).into_bytes());
    }
    // /proc/<pid>/fd/<N>
    if let Some((spid, fdpart)) = strip_pid_prefix(p, "/fd/") {
        let fdno: usize = fdpart.parse().ok()?;
        return Some(gen_fd_link(spid, fdno).into_bytes());
    }
    // /proc/cpuinfo
    if p == "/proc/cpuinfo" {
        return Some(gen_cpuinfo().into_bytes());
    }
    // /proc/meminfo
    if p == "/proc/meminfo" {
        return Some(gen_meminfo().into_bytes());
    }
    // /proc/version
    if p == "/proc/version" {
        return Some(gen_version().into_bytes());
    }
    // /proc/self → directory listing stub
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
    if rest.starts_with(suffix) {
        Some((pid, &rest[suffix.len()..]))
    } else {
        None
    }
}

// ─── /proc/<pid>/maps ─────────────────────────────────────────────────────────

fn gen_maps(pid: usize) -> String {
    let mut out = String::new();
    crate::mm::mmap::with_vmas(pid as u32, |vma| {
        // Format: start-end perms offset dev ino pathname
        let perms = format!(
            "{}{}{p}",
            if vma.prot & 1 != 0 { 'r' } else { '-' },
            if vma.prot & 2 != 0 { 'w' } else { '-' },
            if vma.prot & 4 != 0 { 'x' } else { '-' },
            p = if vma.flags & 1 != 0 { 's' } else { 'p' },
        );
        out.push_str(&format!(
            "{:016x}-{:016x} {} {:08x} 00:00 0\n",
            vma.start, vma.end, perms, vma.file_offset,
        ));
    });
    out
}

// ─── /proc/<pid>/status ───────────────────────────────────────────────────────

fn gen_status(pid: usize) -> String {
    let ppid = crate::proc::scheduler::ppid_of(pid);
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

// ─── /proc/<pid>/exe ──────────────────────────────────────────────────────────

fn gen_exe(pid: usize) -> String {
    crate::proc::scheduler::exe_path_of(pid)
        .unwrap_or_else(|| String::from("/init"))
}

// ─── /proc/<pid>/fd/<N> ───────────────────────────────────────────────────────

fn gen_fd_link(pid: usize, fdno: usize) -> String {
    crate::fs::vfs::fd_to_path(fdno)
        .unwrap_or_else(|| format!("socket:[{}]", fdno))
}

// ─── /proc/cpuinfo ────────────────────────────────────────────────────────────

fn gen_cpuinfo() -> String {
    let mut out = String::new();
    let mut idx = 0usize;
    crate::acpi::with_cpus(|cpu| {
        out.push_str(&format!(
            "processor\t: {}\n\
             vendor_id\t: RustOS\n\
             cpu MHz\t: 1000.000\n\
             model name\t: RustOS Virtual CPU\n\
             apicid\t: {}\n\
             \n",
            idx, cpu.apic_id,
        ));
        idx += 1;
    });
    if idx == 0 {
        out.push_str("processor\t: 0\nvendor_id\t: RustOS\ncpu MHz\t: 1000.000\nmodel name\t: RustOS Virtual CPU\n\n");
    }
    out
}

// ─── /proc/meminfo ────────────────────────────────────────────────────────────

fn gen_meminfo() -> String {
    let total_kb = crate::mm::pmm::total_pages() * 4;
    let free_kb  = crate::mm::pmm::free_pages()  * 4;
    let used_kb  = total_kb - free_kb;
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

// ─── /proc/version ────────────────────────────────────────────────────────────

fn gen_version() -> String {
    format!("Linux version 6.1.0-rustos (rustc) #1 SMP {}\n",
            "Sun Jan  1 00:00:00 UTC 2023")
}
