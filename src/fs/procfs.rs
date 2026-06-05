//! procfs — synthetic /proc filesystem.
//!
//! ## Paths handled
//!   /proc/self/exe          → readlink target = path of current executable
//!   /proc/<pid>/exe         → same for any pid
//!   /proc/self/fd/N         → symlink to the open file behind fd N
//!   /proc/self/fd/          → directory listing of open fds (getdents)
//!   /proc/self/maps         → VMA map in Linux /proc/maps format
//!   /proc/<pid>/maps        → same for any pid
//!   /proc/self/status       → minimal status fields (incl. RtCpuTime)
//!   /proc/<pid>/stat        → full 52-field stat line (Linux 3.5+ format)
//!   /proc/<pid>/limits      → per-process resource limits (ulimit -a format)
//!   /proc/uptime            → uptime in seconds
//!   /proc/meminfo           → basic memory figures
//!   /proc/cpuinfo           → per-CPU info (one block per logical CPU)
//!   /proc/perf_core_count   → count of online Performance-class cores
//!   /proc/slabinfo          → slab allocator cache statistics
//!   /proc/schemes           → one registered scheme name per line (Redox-style)
//!
//! ## Debug fds  (/proc/<pid>/mem|regs|ctl)
//!   Delegated to proc_debug.rs — see that file for details.
//!
//! ## Namespace inodes  (/proc/<pid>/ns/)
//!   /proc/<pid>/ns/         → directory listing of 7 ns names
//!   /proc/<pid>/ns/<name>   → synthetic symlink
//!
//! ## readlink support
//!   readlink("/proc/self/exe")    → exe path string (no NUL)
//!   readlink("/proc/self/fd/N")   → path behind fd N
//!   readlink("/proc/self")        → "/proc/<pid>"
//!   readlink("/proc/<pid>/ns/X")  → "X:[<ns_id>]"

extern crate alloc;
use alloc::borrow::Cow;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use spin::Mutex;
use alloc::collections::BTreeMap;

/// The 7 canonical namespace names in /proc/<pid>/ns/.
pub const NS_NAMES: &[&str] = &["mnt", "pid", "net", "uts", "ipc", "user", "time"];

/// Returns true if `fdno` is a procfs synthetic (text-content) fd.
pub fn is_procfs_fd(fdno: usize) -> bool {
    PROCFS_FDS.lock().contains_key(&fdno)
}

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

/// True if `path` is a /proc/<pid>/ns or /proc/<pid>/ns/<name> path.
pub fn procfs_is_ns_path(path: &str) -> bool {
    let pid = crate::proc::scheduler::current_pid();
    let norm = norm_self(path, pid);
    let p = norm.as_ref();
    if let Some((_, rest)) = strip_pid_prefix(p, "/ns") {
        return rest.is_empty() || rest.starts_with('/');
    }
    false
}

/// Synthetic stat for a /proc/<pid>/ns/<name> inode.
pub fn procfs_ns_stat(path: &str) -> Option<(u64, u32)> {
    let pid = crate::proc::scheduler::current_pid();
    let norm = norm_self(path, pid);
    let p = norm.as_ref();
    let (tpid, rest) = strip_pid_prefix(p, "/ns")?;
    let name = rest.trim_start_matches('/');
    if name.is_empty() {
        return Some((tpid as u64 * 1000 + 7, 0o040555));
    }
    if !NS_NAMES.contains(&name) { return None; }
    let ns_id = crate::proc::namespace::ns_id_of(tpid, name)?;
    Some((ns_id, 0o120444))
}

pub fn procfs_readlink(path: &str, buf: &mut [u8]) -> isize {
    let pid = crate::proc::scheduler::current_pid();

    if path == "/proc/self" {
        let s = format!("/proc/{}", pid);
        return copy_link(s.as_bytes(), buf);
    }

    let norm = norm_self(path, pid);
    let p = norm.as_ref();

    if let Some((tpid, rest)) = strip_pid_prefix(p, "/ns/") {
        let name = rest.trim_end_matches('/');
        if NS_NAMES.contains(&name) {
            if let Some(ns_id) = crate::proc::namespace::ns_id_of(tpid, name) {
                let target = crate::proc::namespace::ns_symlink(name, ns_id);
                return copy_link(target.as_bytes(), buf);
            }
            return -3;
        }
        return -2;
    }

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

fn gen_cpuinfo() -> Vec<u8> {
    let total = crate::smp::num_cpus();
    let mut out = String::new();
    for i in 0..total {
        if let Some(info) = crate::smp::cpu_info(i) {
            let core_type = match info.core_type {
                crate::smp::CoreType::Performance => "performance",
                crate::smp::CoreType::Efficiency  => "efficiency",
            };
            out.push_str(&format!(
                "processor\t: {}\nhw_id\t\t: {}\nnode\t\t: {}\ncore_type\t: {}\nonline\t\t: {}\n\n",
                info.cpu_id, info.hw_id, info.node, core_type, info.online,
            ));
        }
    }
    if out.is_empty() {
        out.push_str("processor\t: 0\nmodel name\t: rustos virtual CPU\ncore_type\t: performance\n");
    }
    out.into_bytes()
}

fn generate(path: &str) -> Option<Vec<u8>> {
    let pid = crate::proc::scheduler::current_pid();
    let norm = norm_self(path, pid);
    let p = norm.as_ref();

    if let Some((_tpid, "")) = strip_pid_prefix(p, "/ns") {
        let mut out = String::new();
        for name in NS_NAMES { out.push_str(name); out.push('\n'); }
        return Some(out.into_bytes());
    }

    if let Some((tpid, rest)) = strip_pid_prefix(p, "/ns/") {
        let name = rest.trim_end_matches('/');
        if NS_NAMES.contains(&name) {
            if let Some(ns_id) = crate::proc::namespace::ns_id_of(tpid, name) {
                let target = crate::proc::namespace::ns_symlink(name, ns_id);
                return Some(target.into_bytes());
            }
        }
        return None;
    }

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
        let slab  = crate::mm::slab::slab_stats();
        let slab_kb = (slab.total_slabs * 4) as u64;
        return Some(format!(
            "MemTotal:      {:8} kB\n\
             MemFree:       {:8} kB\n\
             MemAvailable:  {:8} kB\n\
             Slab:          {:8} kB\n\
             SReclaimable:  {:8} kB\n\
             SUnreclaim:    {:8} kB\n",
            total, free, free, slab_kb, slab_kb, 0u64,
        ).into_bytes());
    }
    if p == "/proc/cpuinfo" {
        return Some(gen_cpuinfo());
    }
    if p == "/proc/perf_core_count" {
        let count = crate::smp::perf_core_count();
        return Some(format!("{count}\n").into_bytes());
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
            if let Some(path2) = crate::fs::vfs::fd_to_path(fdno) {
                return Some(path2.into_bytes());
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
    if p == "/proc/slabinfo" {
        return Some(gen_slabinfo().into_bytes());
    }
    // Redox-inspired: expose all currently-registered scheme names so that
    // userspace service managers can poll this file to discover which drivers
    // are live.  Format: one bare scheme name per line (no colon suffix),
    // alphabetically sorted (BTreeMap order from SchemeTable::list).
    // Example contents after blk + net + tcp drivers register:
    //   blk
    //   file
    //   net
    //   tcp
    //   tty
    if p == "/proc/schemes" {
        let names = crate::fs::scheme_table::SCHEME_TABLE.list();
        let mut out = String::new();
        for name in &names {
            out.push_str(name);
            out.push('\n');
        }
        return Some(out.into_bytes());
    }
    None
}

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
        let hdr_raw      = 40usize;
        let hdr_off      = (hdr_raw + cs.obj_size - 1) & !(cs.obj_size - 1);
        let obj_per_slab = (4096 - hdr_off) / cs.obj_size;
        let total_objs   = cs.total_slabs * obj_per_slab;
        let active_slabs = cs.partial_slabs + cs.full_slabs;
        out.push_str(&format!(
            "{:<22} {:6} {:6} {:6} {:6} {:6} : tunables      0      0      0 \
: slabdata {:6} {:6}      0\n",
            format!("kmalloc-{}", cs.obj_size),
            cs.active_objs, total_objs, cs.obj_size, obj_per_slab, 1,
            active_slabs, cs.total_slabs,
        ));
    }
    out
}

const RLIM_INFINITY: u64 = u64::MAX;

fn fmt_limit(v: u64) -> alloc::string::String {
    if v == RLIM_INFINITY { alloc::string::String::from("unlimited") }
    else { format!("{}", v) }
}

fn gen_limits(pid: usize) -> String {
    use crate::proc::rlimit::*;
    let get = |res: usize| -> (u64, u64) { crate::proc::rlimit::getrlimit_for(pid, res) };
    let header = format!("{:<26}{:<21}{:<21}{}\n", "Limit", "Soft Limit", "Hard Limit", "Units");
    let rows: &[(&str, usize, &str)] = &[
        ("Max cpu time",          RLIMIT_CPU,       "seconds"),
        ("Max file size",         RLIMIT_FSIZE,     "bytes"),
        ("Max data size",         RLIMIT_DATA,      "bytes"),
        ("Max stack size",        RLIMIT_STACK,     "bytes"),
        ("Max core file size",    RLIMIT_CORE,      "bytes"),
        ("Max resident set",      RLIMIT_RSS,       "bytes"),
        ("Max processes",         RLIMIT_NPROC,     "processes"),
        ("Max open files",        RLIMIT_NOFILE,    "files"),
        ("Max locked memory",     RLIMIT_MEMLOCK,   "bytes"),
        ("Max address space",     RLIMIT_AS,        "bytes"),
        ("Max file locks",        RLIMIT_LOCKS,     "locks"),
        ("Max pending signals",   RLIMIT_SIGPENDING,"signals"),
        ("Max msgqueue size",     RLIMIT_MSGQUEUE,  "bytes"),
        ("Max nice priority",     RLIMIT_NICE,      ""),
        ("Max realtime priority", RLIMIT_RTPRIO,    ""),
        ("Max realtime timeout",  RLIMIT_RTTIME,    "us"),
    ];
    let mut out = header;
    for &(name, res, units) in rows {
        let (soft, hard) = get(res);
        out.push_str(&format!("{:<26}{:<21}{:<21}{}\n", name, fmt_limit(soft), fmt_limit(hard), units));
    }
    out
}

fn gen_status(pid: usize) -> String {
    use crate::proc::scheduler::with_proc;
    use crate::proc::process::State;
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

const USER_HZ: u64 = 100;

fn gen_stat(pid: usize) -> String {
    use crate::proc::scheduler::with_proc;
    use crate::proc::process::State;
    use crate::proc::rlimit::RLIMIT_RSS;
    use crate::proc::rlimit::getrlimit_for;

    let snap = with_proc(pid, |p| {
        let state_ch = match p.state {
            State::Running | State::Ready => 'R',
            State::Blocked               => 'S',
            State::Zombie                => 'Z',
        };
        let comm = exe_basename(&p.exe_path);
        let comm = if comm.len() > 15 { comm[..15].to_string() } else { comm };
        let utime = p.cpu_time_ns * USER_HZ / 1_000_000_000;
        let priority: i64 = {
            use crate::proc::scheduler::SchedPolicy;
            match p.sched.policy {
                SchedPolicy::Fifo | SchedPolicy::Rr =>
                    (99i64).saturating_sub(p.sched.rt_priority as i64),
                _ => -((p.sched.nice as i64) + 2),
            }
        };
        let vsize: u64 = p.vmas.iter().map(|v| (v.end - v.start) as u64).sum();
        let rss: u64   = vsize / 4096;
        let start_code: u64 = p.vmas.first().map(|v| v.start as u64).unwrap_or(0);
        let end_code:   u64 = p.vmas.last().map(|v| v.end   as u64).unwrap_or(0);
        (state_ch, comm, p.ppid, utime, priority, p.sched.nice as i64,
         vsize, rss, start_code, end_code, p.pc as u64,
         p.exit_signal as i64, p.sched.last_cpu as u64,
         p.sched.rt_priority as u64, p.sched.policy as u32,
         p.brk_base as u64, p.brk as u64, p.exit_code as i64,
         p.rt_cpu_time_us)
    });
    let (state_ch, comm, ppid, utime, priority, nice, vsize, rss,
         start_code, end_code, kstkeip, exit_signal, processor,
         rt_priority, policy, start_data, end_data, exit_code,
         rt_cpu_time_us) = match snap {
        Some(s) => s,
        None    => return format!(
            "{} (?) Z 1 {} {} 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0 0 \
             0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", pid, pid, pid),
    };
    let (rsslim, _) = getrlimit_for(pid, RLIMIT_RSS);
    format!(
        "{pid} ({comm}) {state} {ppid} {pgrp} {session} 0 -1 0 0 0 0 0 \
         {utime} 0 0 0 {priority} {nice} 1 0 0 \
         {vsize} {rss} {rsslim} {start_code} {end_code} 0 0 {kstkeip} 0 0 0 0 0 \
         {exit_signal} {processor} {rt_priority} {policy} {rt_cpu_time_us} 0 0 \
         {start_data} {end_data} {start_data} 0 0 0 0 {exit_code}\n",
        pid=pid, comm=comm, state=state_ch, ppid=ppid, pgrp=pid, session=pid,
        utime=utime, priority=priority, nice=nice,
        vsize=vsize, rss=rss, rsslim=rsslim,
        start_code=start_code, end_code=end_code, kstkeip=kstkeip,
        exit_signal=exit_signal, processor=processor,
        rt_priority=rt_priority, policy=policy,
        rt_cpu_time_us=rt_cpu_time_us,
        start_data=start_data, end_data=end_data, exit_code=exit_code,
    )
}

fn exe_basename(exe_path: &Option<String>) -> String {
    exe_path.as_deref()
        .and_then(|p| p.rsplit('/').next())
        .map(|s| s.to_string())
        .unwrap_or_else(|| String::from("rustos"))
}

fn gen_maps(pid: usize) -> String {
    let mut out = String::new();
    let vmas = crate::proc::scheduler::with_proc(pid, |p| p.vmas.clone())
        .unwrap_or_default();
    for vma in &vmas {
        let r = if vma.prot & 1 != 0 { 'r' } else { '-' };
        let w = if vma.prot & 2 != 0 { 'w' } else { '-' };
        let x = if vma.prot & 4 != 0 { 'x' } else { '-' };
        let label = match &vma.kind {
            crate::mm::mmap::VmaKind::FileBacked(fd, _) =>
                crate::fs::vfs::fd_to_path(*fd).unwrap_or_default(),
            crate::mm::mmap::VmaKind::Heap  => String::from("[heap]"),
            crate::mm::mmap::VmaKind::Stack => String::from("[stack]"),
            _ => String::new(),
        };
        out.push_str(&format!(
            "{:016x}-{:016x} {}{}{}p {:08x} 00:00 0\t{}\n",
            vma.start, vma.end, r, w, x, vma.file_offset, label
        ));
    }
    out
}

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

/// Open a procfs path and return a synthetic fd number, or a negative errno.
pub fn procfs_open(path: &str, _flags: u32) -> isize {
    let cur_pid = crate::proc::scheduler::current_pid();

    // Delegate /proc/<pid>/mem|regs|ctl to proc_debug
    if is_debug_path(path) {
        return crate::fs::proc_debug::proc_debug_open(cur_pid, path);
    }

    let norm = norm_self(path, cur_pid);
    let p = norm.as_ref();
    if let Some((tpid, rest)) = strip_pid_prefix(p, "/ns/") {
        let name = rest.trim_end_matches('/');
        if NS_NAMES.contains(&name) {
            let ns_fd = crate::proc::namespace::ns_fd_open(tpid, name);
            if ns_fd < 0 { return ns_fd; }
            if let Some(ns_id) = crate::proc::namespace::ns_id_of(tpid, name) {
                let content = crate::proc::namespace::ns_symlink(name, ns_id)
                    .into_bytes();
                PROCFS_FDS.lock().insert(ns_fd as usize, ProcFd { content, offset: 0 });
            }
            return ns_fd;
        }
        return -2;
    }
    match generate(path) {
        Some(content) => {
            let fdno = next_procfs_fd();
            PROCFS_FDS.lock().insert(fdno, ProcFd { content, offset: 0 });
            fdno as isize
        }
        None => -2,
    }
}

fn is_debug_path(path: &str) -> bool {
    // Quickly check if the leaf is mem/regs/ctl under /proc/<N>/
    let p = if path.starts_with("/proc/self/") {
        // norm_self not needed for this check
        let leaf = path.trim_start_matches("/proc/self/");
        matches!(leaf, "mem" | "regs" | "ctl")
    } else {
        // /proc/<digits>/<leaf>
        if let Some(after) = path.strip_prefix("/proc/") {
            if let Some(slash) = after.find('/') {
                let maybe_pid = &after[..slash];
                let leaf = &after[slash+1..];
                maybe_pid.bytes().all(|b| b.is_ascii_digit())
                    && matches!(leaf, "mem" | "regs" | "ctl")
            } else { false }
        } else { false }
    };
    p
}

fn next_procfs_fd() -> usize {
    let guard = PROCFS_FDS.lock();
    for candidate in 256..512 {
        if !guard.contains_key(&candidate) { return candidate; }
    }
    256
}

fn norm_self(path: &str, pid: usize) -> Cow<'static, str> {
    if path.starts_with("/proc/self") {
        Cow::Owned(path.replacen("/proc/self", &format!("/proc/{}", pid), 1))
    } else {
        Cow::Owned(path.to_string())
    }
}

fn strip_pid_prefix<'a>(path: &'a str, suffix: &str) -> Option<(usize, &'a str)> {
    let after_proc = path.strip_prefix("/proc/")?;
    let slash = after_proc.find('/').unwrap_or(after_proc.len());
    let pid_str = &after_proc[..slash];
    let pid: usize = pid_str.parse().ok()?;
    let rest = &after_proc[slash..];
    let tail = rest.strip_prefix(suffix)?;
    Some((pid, tail))
}
