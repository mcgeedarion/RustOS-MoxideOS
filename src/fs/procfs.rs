//! procfs — synthetic /proc filesystem.
//!
//! ## Paths handled
//!   /proc/self/exe     → readlink target = path of current executable
//!   /proc/<pid>/exe    → same for any pid
//!   /proc/self/fd/N    → symlink to the open file behind fd N
//!   /proc/self/fd/     → directory listing of open fds (getdents)
//!   /proc/self/maps    → VMA map in Linux /proc/maps format
//!   /proc/<pid>/maps   → same for any pid
//!   /proc/self/status  → minimal status fields (incl. RtCpuTime)
//!   /proc/<pid>/stat   → full 52-field stat line (Linux 3.5+ format)
//!   /proc/<pid>/limits → per-process resource limits (ulimit -a format)
//!   /proc/uptime       → uptime in seconds
//!   /proc/meminfo      → basic memory figures
//!   /proc/cpuinfo      → single-CPU stub
//!   /proc/slabinfo     → slab allocator cache statistics
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
    if let Some((spid, "")) = strip_pid_prefix(p, "/status") {
        return Some(gen_status(spid).into_bytes());
    }
    if let Some((stpid, "")) = strip_pid_prefix(p, "/stat") {
        return Some(gen_stat(stpid).into_bytes());
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
        // Pull slab usage from the slab allocator.
        let slab  = crate::mm::slab::slab_stats();
        let slab_kb = (slab.total_slabs * 4) as u64; // each slab = 1 page = 4 KiB
        return Some(format!(
            "MemTotal:      {:8} kB\n\
             MemFree:       {:8} kB\n\
             MemAvailable:  {:8} kB\n\
             Slab:          {:8} kB\n\
             SReclaimable:  {:8} kB\n\
             SUnreclaim:    {:8} kB\n",
            total, free, free,
            slab_kb,
            slab_kb, // all slabs are reclaimable via slab_shrink()
            0u64,
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
    // ── /proc/slabinfo ────────────────────────────────────────────────────────
    //
    // Format matches Linux 2.6+ /proc/slabinfo v2.1:
    //
    //   slabinfo - version: 2.1
    //   # name          <active_objs> <num_objs> <objsize> <objperslab> \
    //         <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> \
    //         : slabdata <active_slabs> <num_slabs> <sharedavail>
    //
    // tunables / sharedavail are 0 (no per-CPU magazines yet).
    if p == "/proc/slabinfo" {
        return Some(gen_slabinfo().into_bytes());
    }
    None
}

// ─── /proc/slabinfo generator ─────────────────────────────────────────────────

fn gen_slabinfo() -> String {
    use crate::mm::slab::slab_stats;

    let stats = slab_stats();
    let mut out = String::from(
        "slabinfo - version: 2.1\n\
         # name                  <active_objs> <num_objs> <objsize> \
<objperslab> <pagesperslab> \
: tunables <limit> <batchcount> <sharedfactor> \
: slabdata <active_slabs> <num_slabs> <sharedavail>\n"
    );

    for cs in &stats.per_cache {
        if cs.obj_size == 0 { continue; }
        // slots_per_page = (4096 - hdr_offset(obj_size)) / obj_size
        // Re-derive here to avoid pulling slab internals into procfs.
        let hdr_raw   = 40usize; // size_of::<SlabHdr>() — kept in sync with slab.rs
        let hdr_off   = (hdr_raw + cs.obj_size - 1) & !(cs.obj_size - 1);
        let obj_per_slab = (4096 - hdr_off) / cs.obj_size;

        let total_objs    = cs.total_slabs * obj_per_slab;
        let active_slabs  = cs.partial_slabs + cs.full_slabs;

        out.push_str(&format!(
            "{:<22} {:6} {:6} {:6} {:6} {:6} : tunables      0      0      0 \
: slabdata {:6} {:6}      0\n",
            format!("kmalloc-{}", cs.obj_size),
            cs.active_objs,
            total_objs,
            cs.obj_size,
            obj_per_slab,
            1,              // pages_per_slab is always 1
            active_slabs,
            cs.total_slabs,
        ));
    }
    out
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

// ─── /proc/<pid>/status generator ────────────────────────────────────────────

fn gen_status(pid: usize) -> String {
    use crate::proc::scheduler::with_proc;
    use crate::proc::process::State;

    // Snapshot the fields we need from the PCB.
    let (state_ch, ppid, vsize_kb, comm, rt_cpu_time_us) =
        with_proc(pid, |p| {
            let ch = match p.state {
                State::Running | State::Ready => 'R',
                State::Blocked               => 'S',
                State::Zombie                => 'Z',
            };
            let vsize: u64 = p.vmas.iter().map(|v| (v.end - v.start) as u64).sum();
            let comm = exe_basename(&p.exe_path);
            (ch, p.ppid, vsize / 1024, comm, p.rt_cpu_time_us)
        })
        .unwrap_or_else(|| ('R', 1, 0, String::from("rustos"), 0));

    format!(
        "Name:\t{}\nState:\t{} \nPid:\t{}\nPPid:\t{}\nVmSize:\t{} kB\nVmRSS:\t{} kB\nRtCpuTime:\t{} us\n",
        comm, state_ch, pid, ppid, vsize_kb, vsize_kb, rt_cpu_time_us
    )
}

// ─── /proc/<pid>/stat generator ──────────────────────────────────────────────
//
// Produces the full 52-field Linux /proc/<pid>/stat line as specified in
// `proc(5)` (kernel 3.5+).  Fields are space-separated; the line is newline
// terminated.
//
// Fields sourced from live PCB / scheduler state
// ───────────────────────────────────────────────
//  (1)  pid
//  (2)  comm            basename of exe_path, truncated to 15 chars, wrapped in parens
//  (3)  state           R/S/D/Z mapped from proc::State
//  (4)  ppid
//  (5)  pgrp            = pid  (no process groups implemented yet)
//  (6)  session         = pid  (no sessions implemented yet)
//  (7)  tty_nr          = 0    (no controlling terminal)
//  (8)  tpgid           = -1
//  (9)  flags           = 0
// (10)  minflt          = 0    (minor fault counting not yet wired)
// (11)  cminflt         = 0
// (12)  majflt          = 0    (major fault counting not yet wired)
// (13)  cmajflt         = 0
// (14)  utime           cpu_time_ns converted to jiffies (USER_HZ = 100)
// (15)  stime           = 0    (no kernel/user time split yet — all in utime)
// (16)  cutime          = 0
// (17)  cstime          = 0
// (18)  priority        99 - rt_priority for RT tasks; -(nice+2) for CFS (Linux convention)
// (19)  nice            sched.nice cast to i64
// (20)  num_threads     = 1    (per-tgid thread count not yet aggregated)
// (21)  itrealvalue     = 0    (no interval timer)
// (22)  starttime       = 0    (no per-process birth timestamp yet)
// (23)  vsize           sum of VMA byte ranges (bytes)
// (24)  rss             vsize / PAGE_SIZE (proxy; no physical RSS tracking yet)
// (25)  rsslim          RLIMIT_RSS soft limit (bytes)
// (26)  startcode       lowest VMA start address
// (27)  endcode         highest VMA end address
// (28)  startstack      = 0    (stack VA not yet tracked separately)
// (29)  kstkesp         = 0
// (30)  kstkeip         p.pc  (last saved user PC)
// (31)  signal          = 0    (pending signal bitmask not yet exposed)
// (32)  blocked         = 0
// (33)  sigignore        = 0
// (34)  sigcatch        = 0
// (35)  wchan           = 0
// (36)  nswap           = 0
// (37)  cnswap          = 0
// (38)  exit_signal     p.exit_signal (clone() signo sent to parent on death)
// (39)  processor       sched.last_cpu
// (40)  rt_priority     sched.rt_priority
// (41)  policy          sched.policy as u32  (0=NORMAL 1=FIFO 2=RR 6=DEADLINE)
// (42)  delayacct_blkio_ticks — overloaded: rt_cpu_time_us (microseconds of
//       continuous RT CPU time since last voluntary block; 0 for non-RT tasks)
// (43)  guest_time      = 0
// (44)  cguest_time     = 0
// (45)  start_data      brk_base (first data page)
// (46)  end_data        brk     (current program break)
// (47)  start_brk       brk_base
// (48)  arg_start       = 0
// (49)  arg_end         = 0
// (50)  env_start       = 0
// (51)  env_end         = 0
// (52)  exit_code       p.exit_code as i64

/// Jiffies per second (USER_HZ).
const USER_HZ: u64 = 100;

fn gen_stat(pid: usize) -> String {
    use crate::proc::scheduler::with_proc;
    use crate::proc::process::State;
    use crate::proc::rlimit::RLIMIT_RSS;
    use crate::proc::rlimit::getrlimit_for;

    // ── Snapshot from PCB ─────────────────────────────────────────────────
    let snap = with_proc(pid, |p| {
        // (3) state char
        let state_ch = match p.state {
            State::Running | State::Ready => 'R',
            State::Blocked               => 'S',
            State::Zombie                => 'Z',
        };

        // (2) comm: basename of exe, max 15 chars
        let comm = exe_basename(&p.exe_path);
        let comm = if comm.len() > 15 { comm[..15].to_string() } else { comm };

        // (14) utime in jiffies
        let utime = p.cpu_time_ns * USER_HZ / 1_000_000_000;

        // (18) priority — mirrors the Linux sign convention:
        //   RT:  priority = 99 - rt_priority  (range 0..99, lower = higher prio)
        //   CFS: priority = -(nice + 2)         (matches `ps` output: -20..19 → 22..-1)
        let priority: i64 = {
            use crate::proc::scheduler::SchedPolicy;
            match p.sched.policy {
                SchedPolicy::Fifo | SchedPolicy::Rr =>
                    (99i64).saturating_sub(p.sched.rt_priority as i64),
                _ =>
                    -((p.sched.nice as i64) + 2),
            }
        };

        // (23/24) vsize and rss (proxy)
        let vsize: u64 = p.vmas.iter().map(|v| (v.end - v.start) as u64).sum();
        let rss: u64   = vsize / 4096;

        // (26/27) code segment range
        let start_code: u64 = p.vmas.first().map(|v| v.start as u64).unwrap_or(0);
        let end_code:   u64 = p.vmas.last().map(|v| v.end   as u64).unwrap_or(0);

        (
            state_ch,
            comm,
            p.ppid,
            utime,
            priority,
            p.sched.nice as i64,
            vsize,
            rss,
            start_code,
            end_code,
            p.pc as u64,
            p.exit_signal as i64,
            p.sched.last_cpu as u64,
            p.sched.rt_priority as u64,
            p.sched.policy as u32,
            p.brk_base as u64,
            p.brk      as u64,
            p.exit_code as i64,
            // (42) rt_cpu_time_us — live RT budget accumulator
            p.rt_cpu_time_us,
        )
    });

    // ── Assemble the line ─────────────────────────────────────────────────
    let (
        state_ch, comm, ppid, utime, priority, nice,
        vsize, rss, start_code, end_code,
        kstkeip, exit_signal, processor, rt_priority, policy,
        start_data, end_data, exit_code,
        rt_cpu_time_us,
    ) = match snap {
        Some(s) => s,
        None    => return format!("{} (?) Z 1 {} {} 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", pid, pid, pid),
    };

    // RLIMIT_RSS soft limit
    let (rsslim, _) = getrlimit_for(pid, RLIMIT_RSS);

    format!(
        // fields 1-13
        "{pid} ({comm}) {state} {ppid} {pgrp} {session} 0 -1 0 0 0 0 0 \
         // fields 14-22
         {utime} 0 0 0 {priority} {nice} 1 0 0 \
         // fields 23-37
         {vsize} {rss} {rsslim} {start_code} {end_code} 0 0 {kstkeip} 0 0 0 0 0 \
         // fields 38-52
         {exit_signal} {processor} {rt_priority} {policy} {rt_cpu_time_us} 0 0 {start_data} {end_data} {start_data} 0 0 0 0 {exit_code}\n",
        pid        = pid,
        comm       = comm,
        state      = state_ch,
        ppid       = ppid,
        pgrp       = pid,
        session    = pid,
        utime      = utime,
        priority   = priority,
        nice       = nice,
        vsize      = vsize,
        rss        = rss,
        rsslim     = rsslim,
        start_code = start_code,
        end_code   = end_code,
        kstkeip    = kstkeip,
        exit_signal = exit_signal,
        processor  = processor,
        rt_priority = rt_priority,
        policy     = policy,
        rt_cpu_time_us = rt_cpu_time_us,
        start_data = start_data,
        end_data   = end_data,
        exit_code  = exit_code,
    )
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Extract the basename of the exe path (or "rustos" as a fallback).
fn exe_basename(exe_path: &Option<String>) -> String {
    exe_path.as_deref()
        .and_then(|p| p.rsplit('/').next())
        .map(|s| s.to_string())
        .unwrap_or_else(|| String::from("rustos"))
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
        // All non-shared VMA kinds are 'p' (private copy-on-write).
        // MAP_SHARED is not yet tracked at the VmaKind level, so every
        // entry is 'p' for now — identical to Linux for anonymous/file-
        // private maps, and consistent with our COW implementation.
        let s = 'p';
        let label = match &vma.kind {
            crate::mm::mmap::VmaKind::FileBacked(fd, _) =>
                crate::fs::vfs::fd_to_path(*fd).unwrap_or_default(),
            crate::mm::mmap::VmaKind::Heap    => String::from("[heap]"),
            crate::mm::mmap::VmaKind::Stack   => String::from("[stack]"),
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
