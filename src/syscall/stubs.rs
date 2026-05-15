// Implementations for syscalls that are either trivial, return constant
// data, or are safely no-ops for a single-user root kernel.
//
// Included from syscall/mod.rs via `include!("stubs.rs")`.

use crate::uaccess::{copy_to_user, copy_from_user, validate_user_ptr};
use crate::sync::SpinMutex;
extern crate alloc;
use alloc::collections::BTreeMap;

// ── NR 39  getpid ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_getpid_impl()  -> isize { crate::proc::scheduler::current_pid()  as isize }
fn sys_getppid_impl() -> isize { crate::proc::scheduler::current_ppid() as isize }
fn sys_gettid_impl()  -> isize { crate::proc::scheduler::current_tid()  as isize }

// ── NR 102/104/107/108  getuid/getgid/geteuid/getegid ──────────────────────────────────────────────
fn sys_getuid_impl()  -> isize { 0 }
fn sys_getgid_impl()  -> isize { 0 }
fn sys_geteuid_impl() -> isize { 0 }
fn sys_getegid_impl() -> isize { 0 }

// ── NR 63  uname ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_uname_impl(buf: usize) -> isize {
    if buf == 0 || !validate_user_ptr(buf, 390) { return -14; }

    // Resolve the UTS namespace for the calling process so that
    // nodename and domainname reflect the values set by sethostname(2)
    // and setdomainname(2) rather than hardcoded boot-time strings.
    let pid        = crate::proc::scheduler::current_pid();
    let ns         = crate::proc::scheduler::with_proc(pid, |p| p.ns.uts)
                         .unwrap_or(crate::proc::namespace::INIT_NS);
    let nodename   = crate::proc::namespace::uts_hostname(ns);
    let domainname = crate::proc::namespace::uts_domainname(ns);

    // struct utsname has 6 fields, each 65 bytes (64 chars + NUL).
    let mut dst = [0u8; 390];
    let fields: &[&[u8]] = &[
        b"Linux",                  // sysname   — report Linux for compat
        nodename.as_bytes(),       // nodename  — live from UTS ns
        b"6.1.0-rustos",           // release
        b"#1 SMP",                 // version
        b"x86_64",                 // machine
        domainname.as_bytes(),     // domainname — live from UTS ns
    ];
    for (i, field) in fields.iter().enumerate() {
        let off = i * 65;
        let len = field.len().min(64);
        dst[off..off + len].copy_from_slice(&field[..len]);
        // NUL terminator is already 0 (zeroed array).
    }
    if copy_to_user(buf, &dst).is_err() { return -14; }
    0
}

// ── NR 96  gettimeofday ─────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_gettimeofday_impl(tv_va: usize, tz_va: usize) -> isize {
    crate::proc::time_ns::sys_gettimeofday(tv_va, tz_va)
}

// ── NR 99  sysinfo ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_sysinfo_impl(info_va: usize) -> isize {
    crate::mm::sysinfo::sys_sysinfo(info_va)
}

// ── NR 100  times(buf) ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_times_impl(buf_va: usize) -> isize {
    // struct tms { tms_utime, tms_stime, tms_cutime, tms_cstime } — 4 × i64 = 32 bytes.
    // Clock tick = HZ = 100.  Convert ns → ticks: ns / 10_000_000.
    const NS_PER_TICK: u64 = 10_000_000;
    let pid = crate::proc::scheduler::current_pid() as usize;
    let (utime_ns, stime_ns) = crate::proc::scheduler::with_proc(pid, |p| {
        (p.utime_ns, p.stime_ns)
    }).unwrap_or((0, 0));
    let tms_utime  = (utime_ns / NS_PER_TICK) as i64;
    let tms_stime  = (stime_ns / NS_PER_TICK) as i64;
    if buf_va != 0 {
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&tms_utime.to_le_bytes());
        buf[8..16].copy_from_slice(&tms_stime.to_le_bytes());
        // cutime / cstime — child accounting not yet tracked; zero.
        if copy_to_user(buf_va, &buf).is_err() { return -14; }
    }
    // Return value: total elapsed real ticks since boot (monotonic).
    let mono_ns = crate::time::clock::monotonic_ns();
    (mono_ns / NS_PER_TICK) as isize
}

// ── NR 110  getppid ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
// Already defined above as sys_getppid_impl(); listed here for cross-reference.

// ── NR 135  personality(persona) ────────────────────────────────────────────────────────────────────────────────────────────
fn sys_personality_impl(persona: u32) -> isize {
    let pid = crate::proc::scheduler::current_pid() as usize;
    const GET_PERSONA: u32 = 0xffff_ffff;
    if persona == GET_PERSONA {
        // Query: return current personality without changing it.
        return crate::proc::scheduler::with_proc(pid, |p| p.personality)
            .unwrap_or(0) as isize;
    }
    // Only accept PER_LINUX (0) and PER_LINUX32 (0x08) — anything else is EINVAL.
    const PER_LINUX:   u32 = 0x0000_0000;
    const PER_LINUX32: u32 = 0x0000_0008;
    if persona != PER_LINUX && persona != PER_LINUX32 {
        return -22; // EINVAL
    }
    let old = crate::proc::scheduler::with_proc_mut(pid, |p, _| {
        let prev = p.personality;
        p.personality = persona;
        prev
    }).unwrap_or(0);
    old as isize
}

// ── NR 137  statfs / NR 138  fstatfs ─────────────────────────────────────────────────────────────────────────────────────
fn sys_statfs_impl(path_va: usize, buf_va: usize) -> isize {
    crate::fs::statfs::sys_statfs(path_va, buf_va)
}
fn sys_fstatfs_impl(fd: usize, buf_va: usize) -> isize {
    crate::fs::statfs::sys_fstatfs(fd, buf_va)
}

// ── NR 160  sethostname / NR 161  getdomainname (via NR 163) ─────────────────────────────────────────────
fn sys_sethostname_impl(name_va: usize, len: usize) -> isize {
    crate::proc::namespace::sys_sethostname(name_va, len)
}
fn sys_setdomainname_impl(name_va: usize, len: usize) -> isize {
    crate::proc::namespace::sys_setdomainname(name_va, len)
}

// ── NR 185  prctl ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const PR_SET_NAME:        i32 = 15;
const PR_GET_NAME:        i32 = 16;
const PR_SET_DUMPABLE:    i32 = 4;
const PR_GET_DUMPABLE:    i32 = 3;
const PR_SET_SECCOMP:     i32 = 22;
const PR_SET_PDEATHSIG:   i32 = 1;
const PR_SET_NO_NEW_PRIVS: i32 = 38;

static PROC_NAME: SpinMutex<BTreeMap<usize, [u8; 16]>> = SpinMutex::new(BTreeMap::new());

pub fn proc_name_clear(pid: usize) { PROC_NAME.lock().remove(&pid); }

fn sys_prctl_impl(op: i32, a2: usize, _a3: usize, _a4: usize, _a5: usize) -> isize {
    let pid = crate::proc::scheduler::current_pid();
    match op {
        PR_SET_NAME => {
            let mut name = [0u8; 16];
            if copy_from_user(&mut name[..15], a2).is_err() { return -14; }
            PROC_NAME.lock().insert(pid, name);
            0
        }
        PR_GET_NAME => {
            let name = PROC_NAME.lock().get(&pid).copied().unwrap_or([0u8; 16]);
            if copy_to_user(a2, &name).is_err() { return -14; }
            0
        }
        PR_SET_DUMPABLE | PR_GET_DUMPABLE     => 1,
        PR_SET_SECCOMP                         => -22,
        PR_SET_PDEATHSIG | PR_SET_NO_NEW_PRIVS => 0,
        _                                      => 0,
    }
}

// ── NR 201  time ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_time_impl(t_va: usize) -> isize {
    let mono_ns = crate::time::read_monotonic_ns();
    let offset  = crate::time::realtime_offset_ns();
    let real_ns = (mono_ns as i64).wrapping_add(offset) as u64;
    let secs    = (real_ns / 1_000_000_000) as i64;
    if t_va != 0 {
        if copy_to_user(t_va, &secs.to_le_bytes()).is_err() { return -14; }
    }
    secs as isize
}

// ── NR 203/204  sched_setaffinity / sched_getaffinity ────────────────────────────────────────────────────────────────────────────────────
fn sys_sched_setaffinity_impl(pid: usize, sz: usize, mask: usize) -> isize {
    crate::syscall::sched::sys_sched_setaffinity(pid, sz, mask)
}
fn sys_sched_getaffinity_impl(pid: usize, sz: usize, mask: usize) -> isize {
    crate::syscall::sched::sys_sched_getaffinity(pid, sz, mask)
}
fn sys_sched_setattr_impl(pid: usize, attr_uptr: usize, flags: u32) -> isize {
    crate::syscall::sched::sys_sched_setattr(pid, attr_uptr, flags)
}
fn sys_sched_getattr_impl(pid: usize, size: u32, flags: u32, attr_uptr: u32) -> isize {
    crate::syscall::sched::sys_sched_getattr(pid, attr_uptr as usize, size, flags)
}

// ── NR 228/229  clock_gettime / clock_settime ────────────────────────────────────────────────────────────────────────────────────────────
fn sys_clock_gettime_impl(clkid: u32, tp_va: usize) -> isize {
    crate::proc::time_ns::sys_clock_gettime(clkid, tp_va)
}

// NR 229: was unconditionally -1 (EPERM).
// Now: CLOCK_REALTIME sets the wall-clock offset; all others return EINVAL.
fn sys_clock_settime_impl(clkid: u32, tp_va: usize) -> isize {
    crate::proc::time_ns::sys_clock_settime(clkid, tp_va)
}

// ── NR 230  clock_getres ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_clock_getres_impl(_clkid: u32, res_va: usize) -> isize {
    // All our clocks have 1ns resolution.
    if res_va != 0 {
        let ts: [u8; 16] = {
            let mut b = [0u8; 16];
            // tv_sec = 0, tv_nsec = 1
            b[8..16].copy_from_slice(&1i64.to_le_bytes());
            b
        };
        if copy_to_user(res_va, &ts).is_err() { return -14; }
    }
    0
}

// ── NR 231  exit_group ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_exit_group_impl(code: i32) -> isize {
    crate::proc::exit::sys_exit(code as usize);
    unreachable!()
}

// ── NR 234  tgkill ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_tgkill_impl(tgid: usize, tid: usize, sig: i32) -> isize {
    crate::proc::signal::sys_tgkill(tgid, tid, sig)
}

// ── NR 269  faccessat ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_faccessat_impl(dirfd: i32, path_va: usize, mode: u32, flags: u32) -> isize {
    crate::fs::access::sys_faccessat(dirfd, path_va, mode, flags)
}

// ── NR 285  fallocate ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_fallocate_impl(fd: usize, mode: u32, offset: i64, len: i64) -> isize {
    crate::fs::fallocate::sys_fallocate(fd, mode, offset, len)
}

// ── NR 288  accept4 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_accept4_impl(sockfd: usize, addr_va: usize, addrlen_va: usize, flags: u32) -> isize {
    crate::net::socket::sys_accept4(sockfd, addr_va, addrlen_va, flags)
}

// ── NR 291  epoll_create1 ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
fn sys_epoll_create1_impl(flags: u32) -> isize {
    crate::fs::epoll::sys_epoll_create1(flags)
}

// ── NR 293/295/296  sendmsg/recvmsg/sendmmsg ─────────────────────────────────────────────────────────────────────────────
fn sys_sendmsg_impl(sockfd: usize, msg_va: usize, flags: u32) -> isize {
    crate::net::socket::sys_sendmsg(sockfd, msg_va, flags)
}
fn sys_recvmsg_impl(sockfd: usize, msg_va: usize, flags: u32) -> isize {
    crate::net::socket::sys_recvmsg(sockfd, msg_va, flags)
}
fn sys_sendmmsg_impl(sockfd: usize, msgvec_va: usize, vlen: u32, flags: u32) -> isize {
    crate::net::socket::sys_sendmmsg(sockfd, msgvec_va, vlen, flags)
}
