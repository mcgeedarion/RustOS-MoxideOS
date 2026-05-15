// Full POSIX syscall surface for rustos.
//
// Included from syscall/mod.rs via `include!("posix_full.rs")`.
// Every function here returns a value that can be placed directly in the
// syscall dispatch match arm.  All user-space pointer accesses go through
// `copy_from_user` / `copy_to_user` so that a bad pointer yields EFAULT
// (-14) rather than a kernel fault.

#![allow(unused_variables, dead_code)]
extern crate alloc;
use alloc::string::String;
use crate::uaccess::{copy_from_user, copy_to_user};
use crate::proc::exec::read_cstr_safe;

// ─── Process / session / uid-gid ────────────────────────────────────────────

/// NR 37  alarm(seconds)
/// Arms a one-shot ITIMER_REAL via itimer::sys_alarm; returns remaining
/// seconds of any previously armed alarm (POSIX-correct).
pub(super) fn sys_alarm_impl(seconds: u32) -> isize {
    crate::proc::itimer::sys_alarm(seconds) as isize
}

/// NR 34  pause()  — yield until a signal is delivered.
pub(super) fn sys_pause_impl() -> isize {
    crate::proc::scheduler::schedule();
    -4 // EINTR
}

/// NR 111  getpgrp()
pub(super) fn sys_getpgrp_impl() -> isize {
    crate::proc::scheduler::current_pid() as isize
}

/// NR 112  setsid()
pub(super) fn sys_setsid_impl() -> isize {
    crate::proc::scheduler::current_pid() as isize
}

/// NR 122  setreuid / NR 123 setregid — single-user root, always succeed.
pub(super) fn sys_setreuid_impl(_ruid: u32, _euid: u32) -> isize { 0 }
pub(super) fn sys_setregid_impl(_rgid: u32, _egid: u32) -> isize { 0 }

/// NR 124  getgroups(size, list_va)
pub(super) fn sys_getgroups_impl(size: i32, list_va: usize) -> isize {
    if size == 0 { return 1; }
    if size < 1  { return -22; }
    let gid: u32 = 0;
    if copy_to_user(list_va, &gid.to_le_bytes()).is_err() { return -14; }
    1
}

/// NR 125  setgroups — accept unconditionally.
pub(super) fn sys_setgroups_impl(_size: i32, _list_va: usize) -> isize { 0 }

/// NR 126  setresuid / NR 129 setresgid
pub(super) fn sys_setresuid_impl(_ruid: u32, _euid: u32, _suid: u32) -> isize { 0 }
pub(super) fn sys_setresgid_impl(_rgid: u32, _egid: u32, _sgid: u32) -> isize { 0 }

/// NR 147  getsid(pid)
pub(super) fn sys_getsid_impl(_pid: u32) -> isize {
    crate::proc::scheduler::current_pid() as isize
}

/// NR 183 / NR 309  getcpu(cpu_va, node_va, _tcache)
pub(super) fn sys_getcpu_impl(cpu_va: usize, node_va: usize, _tcache: usize) -> isize {
    let zero = 0u32;
    if cpu_va  != 0 { if copy_to_user(cpu_va,  &zero.to_le_bytes()).is_err() { return -14; } }
    if node_va != 0 { if copy_to_user(node_va, &zero.to_le_bytes()).is_err() { return -14; } }
    0
}

// ─── Interval timers ────────────────────────────────────────────────────────

/// NR 36  getitimer(which, val_va)
/// Only ITIMER_REAL (which=0) is fully implemented.  Other timers return
/// zero itimerval (ITIMER_VIRTUAL and ITIMER_PROF are not tracked).
pub(super) fn sys_getitimer_impl(which: i32, val_va: usize) -> isize {
    if val_va == 0 { return -14; }
    let (val_us, interval_us) = match which {
        0 => crate::proc::itimer::sys_getitimer_real(),
        _ => (0, 0),  // VIRTUAL / PROF: not tracked
    };
    // itimerval: { it_interval.tv_sec(8), it_interval.tv_usec(8),
    //              it_value.tv_sec(8),    it_value.tv_usec(8) }
    let mut buf = [0u8; 32];
    let iv_sec  = (interval_us / 1_000_000) as i64;
    let iv_usec = (interval_us % 1_000_000) as i64;
    let vl_sec  = (val_us      / 1_000_000) as i64;
    let vl_usec = (val_us      % 1_000_000) as i64;
    buf[0..8].copy_from_slice(&iv_sec.to_le_bytes());
    buf[8..16].copy_from_slice(&iv_usec.to_le_bytes());
    buf[16..24].copy_from_slice(&vl_sec.to_le_bytes());
    buf[24..32].copy_from_slice(&vl_usec.to_le_bytes());
    if copy_to_user(val_va, &buf).is_err() { return -14; }
    0
}

/// NR 38  setitimer(which, new_va, old_va)
/// ITIMER_REAL arms the real-time interval timer and delivers SIGALRM
/// when it fires.  ITIMER_VIRTUAL and ITIMER_PROF are accepted but not
/// tracked (virtual/prof CPU time accounting is not yet implemented).
pub(super) fn sys_setitimer_impl(which: i32, new_va: usize, old_va: usize) -> isize {
    // Read new itimerval from user space.
    let mut buf = [0u8; 32];
    if new_va != 0 {
        if copy_from_user(&mut buf, new_va).is_err() { return -14; }
    }
    let iv_sec  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let iv_usec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    let vl_sec  = i64::from_le_bytes(buf[16..24].try_into().unwrap());
    let vl_usec = i64::from_le_bytes(buf[24..32].try_into().unwrap());
    if iv_sec < 0 || iv_usec < 0 || vl_sec < 0 || vl_usec < 0 { return -22; }

    let new_val_us      = (vl_sec as u64) * 1_000_000 + (vl_usec as u64);
    let new_interval_us = (iv_sec as u64) * 1_000_000 + (iv_usec as u64);

    let (old_val_us, old_interval_us) = match which {
        0 => crate::proc::itimer::sys_setitimer_real(
                Some(new_val_us), Some(new_interval_us)
             ),
        1 | 2 => (0, 0), // VIRTUAL/PROF not tracked; return zero old-value
        _ => return -22,
    };

    if old_va != 0 {
        let mut old_buf = [0u8; 32];
        let oi_sec  = (old_interval_us / 1_000_000) as i64;
        let oi_usec = (old_interval_us % 1_000_000) as i64;
        let ov_sec  = (old_val_us      / 1_000_000) as i64;
        let ov_usec = (old_val_us      % 1_000_000) as i64;
        old_buf[0..8].copy_from_slice(&oi_sec.to_le_bytes());
        old_buf[8..16].copy_from_slice(&oi_usec.to_le_bytes());
        old_buf[16..24].copy_from_slice(&ov_sec.to_le_bytes());
        old_buf[24..32].copy_from_slice(&ov_usec.to_le_bytes());
        if copy_to_user(old_va, &old_buf).is_err() { return -14; }
    }
    0
}

// ─── POSIX per-process timers ────────────────────────────────────────────────
//
// timer_create stores the timer in the itimer module's POSIX_TIMERS table.
// timer_settime arms it; the tick() path in itimer.rs delivers the signal.
// timer_getoverrun reads the real overrun counter from the same table.

use spin::Mutex as SpinMutex;
use alloc::collections::BTreeMap;

static TIMER_ID_CTR: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(1);

/// NR 222  timer_create(clockid, sevp_va, timerid_va)
pub(super) fn sys_timer_create_impl(clockid: u32, sevp_va: usize, timerid_va: usize) -> isize {
    let id = TIMER_ID_CTR.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut sigev_signo: u32 = 14; // SIGALRM default
    if sevp_va != 0 {
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, sevp_va).is_err() { return -14; }
        // sigevent layout: sigev_value(8) sigev_signo(4) sigev_notify(4)
        sigev_signo = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        // sigev_notify == SIGEV_NONE (1) => don't wire up signal delivery
        let sigev_notify = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        if sigev_notify == 1 { sigev_signo = 0; }
    }
    let tgid = crate::proc::thread::tgid_of(
        crate::proc::scheduler::current_pid()
    );
    let tgid = if tgid != 0 { tgid } else { crate::proc::scheduler::current_pid() };
    // Pre-register in itimer's POSIX_TIMERS table (disarmed).
    crate::proc::itimer::arm_posix_timer(tgid, id, sigev_signo, 0, 0);
    if copy_to_user(timerid_va, &id.to_le_bytes()).is_err() { return -14; }
    0
}

/// NR 223  timer_settime(timerid, flags, new_va, old_va)
///
/// Populates `old_va` with the timer's current remaining time and interval
/// by reading the live state from `POSIX_TIMERS` before arming the new value.
pub(super) fn sys_timer_settime_impl(timerid: u32, flags: i32,
                                      new_va: usize, old_va: usize) -> isize {
    let mut new_buf = [0u8; 32];
    if copy_from_user(&mut new_buf, new_va).is_err() { return -14; }

    let int_sec  = i64::from_le_bytes(new_buf[0..8].try_into().unwrap());
    let int_ns   = i64::from_le_bytes(new_buf[8..16].try_into().unwrap());
    let val_sec  = i64::from_le_bytes(new_buf[16..24].try_into().unwrap());
    let val_ns   = i64::from_le_bytes(new_buf[24..32].try_into().unwrap());

    let interval_ns = (int_sec as u64) * 1_000_000_000 + (int_ns as u64);
    let value_ns    = (val_sec as u64) * 1_000_000_000 + (val_ns  as u64);

    let tgid = crate::proc::thread::tgid_of(
        crate::proc::scheduler::current_pid()
    );
    let tgid = if tgid != 0 { tgid } else { crate::proc::scheduler::current_pid() };

    // Populate old_va with the *current* timer state before we replace it.
    if old_va != 0 {
        let (old_val_ns, old_int_ns) =
            crate::proc::itimer::get_posix_timer_state(tgid, timerid);
        let mut old_buf = [0u8; 32];
        let ois = (old_int_ns / 1_000_000_000) as i64;
        let oin = (old_int_ns % 1_000_000_000) as i64;
        let ovs = (old_val_ns / 1_000_000_000) as i64;
        let ovn = (old_val_ns % 1_000_000_000) as i64;
        old_buf[0..8].copy_from_slice(&ois.to_le_bytes());
        old_buf[8..16].copy_from_slice(&oin.to_le_bytes());
        old_buf[16..24].copy_from_slice(&ovs.to_le_bytes());
        old_buf[24..32].copy_from_slice(&ovn.to_le_bytes());
        if copy_to_user(old_va, &old_buf).is_err() { return -14; }
    }

    const TIMER_ABSTIME: i32 = 1;
    let now_ns = crate::time::monotonic_ns();
    let expire_ns = if flags & TIMER_ABSTIME != 0 {
        value_ns
    } else {
        now_ns.saturating_add(value_ns)
    };

    if value_ns == 0 {
        crate::proc::itimer::disarm_posix_timer(tgid, timerid);
    } else {
        // arm_posix_timer expects a relative duration; subtract now.
        let rel_ns = expire_ns.saturating_sub(now_ns);
        crate::proc::itimer::arm_posix_timer(tgid, timerid, 0, rel_ns, interval_ns);
    }
    0
}

/// NR 224  timer_gettime(timerid, curr_va)
pub(super) fn sys_timer_gettime_impl(timerid: u32, curr_va: usize) -> isize {
    let now_ns = crate::time::monotonic_ns();
    // Read from the itimer POSIX table.
    let tgid = crate::proc::thread::tgid_of(
        crate::proc::scheduler::current_pid()
    );
    let tgid = if tgid != 0 { tgid } else { crate::proc::scheduler::current_pid() };
    let timer = crate::proc::itimer::POSIX_TIMERS.lock();
    if let Some(t) = timer.get(&(tgid, timerid)) {
        let rem = if t.deadline_ns > now_ns { t.deadline_ns - now_ns } else { 0 };
        let mut buf = [0u8; 32];
        let iv_sec = (t.interval_ns / 1_000_000_000) as i64;
        let iv_ns  = (t.interval_ns % 1_000_000_000) as i64;
        buf[0..8].copy_from_slice(&iv_sec.to_le_bytes());
        buf[8..16].copy_from_slice(&iv_ns.to_le_bytes());
        let rv_sec = (rem / 1_000_000_000) as i64;
        let rv_ns  = (rem % 1_000_000_000) as i64;
        buf[16..24].copy_from_slice(&rv_sec.to_le_bytes());
        buf[24..32].copy_from_slice(&rv_ns.to_le_bytes());
        if copy_to_user(curr_va, &buf).is_err() { return -14; }
        0
    } else {
        -22
    }
}

/// NR 225  timer_getoverrun(timerid) — returns real overrun count from itimer table.
pub(super) fn sys_timer_getoverrun_impl(timerid: u32) -> isize {
    let tgid = crate::proc::thread::tgid_of(
        crate::proc::scheduler::current_pid()
    );
    let tgid = if tgid != 0 { tgid } else { crate::proc::scheduler::current_pid() };
    crate::proc::itimer::get_overrun(tgid, timerid) as isize
}

/// NR 226  timer_delete(timerid)
pub(super) fn sys_timer_delete_impl(timerid: u32) -> isize {
    let tgid = crate::proc::thread::tgid_of(
        crate::proc::scheduler::current_pid()
    );
    let tgid = if tgid != 0 { tgid } else { crate::proc::scheduler::current_pid() };
    crate::proc::itimer::disarm_posix_timer(tgid, timerid);
    0
}

/// NR 227  clock_settime — update the kernel wall-clock offset so
/// subsequent CLOCK_REALTIME reads reflect the user-supplied value.
pub(super) fn sys_clock_settime_impl(clkid: u32, tp_va: usize) -> isize {
    const CLOCK_REALTIME: u32 = 0;
    if clkid != CLOCK_REALTIME { return -1; } // only REALTIME is settable
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, tp_va).is_err() { return -14; }
    let new_sec  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let new_nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    let new_ns   = (new_sec as u64) * 1_000_000_000 + (new_nsec as u64);
    let mono_ns  = crate::time::monotonic_ns();
    // Store the offset: wall_ns = mono_ns + WALL_OFFSET
    WALL_OFFSET.store(
        new_ns.wrapping_sub(mono_ns) as i64,
        core::sync::atomic::Ordering::Relaxed,
    );
    0
}

/// NR 229  clock_nanosleep — delegate to regular nanosleep implementation.
pub(super) fn sys_clock_nanosleep_impl(_clkid: u32, _flags: i32,
                                        rqtp_va: usize, rmtp_va: usize) -> isize {
    crate::proc::nanosleep::sys_nanosleep(rqtp_va, rmtp_va)
}

// ─── Wall-clock offset (settimeofday / clock_settime) ───────────────────────
//
// We use a single signed i64 storing the offset in nanoseconds between
// the monotonic clock and UNIX epoch time:
//     wall_ns = monotonic_ns() + WALL_OFFSET
// Initialised to zero, which gives epoch 0 (1970-01-01) at boot —
// acceptable for a single-user kernel; settimeofday/clock_settime correct it.

static WALL_OFFSET: core::sync::atomic::AtomicI64 =
    core::sync::atomic::AtomicI64::new(0);

/// Returns current wall-clock time as (seconds, nanoseconds) since epoch.
pub fn wall_clock_now() -> (i64, i64) {
    let mono  = crate::time::monotonic_ns() as i64;
    let off   = WALL_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
    let total = mono.wrapping_add(off);
    (total / 1_000_000_000, total % 1_000_000_000)
}

// ─── Signal extras ───────────────────────────────────────────────────────────

/// NR 15  rt_sigreturn — signal frame is already unwound by the delivery trampoline.
pub(super) fn sys_rt_sigreturn_impl() -> isize { 0 }

// ─── Timestamp syscalls ─────────────────────────────────────────────────────
//
// Previously these were no-ops that discarded the caller's timestamp.
// Now they parse the user-supplied time and forward it to the VFS layer
// so that inode mtime/atime fields are actually updated.
//
// The VFS `set_times` helper takes (path, atime_ns: Option<u64>,
// mtime_ns: Option<u64>) where None means "use current time".

/// Parse a `struct timeval` (tv_sec: i64, tv_usec: i64) at `va`.
/// Returns the value as nanoseconds, or None on EFAULT.
fn parse_timeval(va: usize) -> Option<u64> {
    let mut buf = [0u8; 16];
    copy_from_user(&mut buf, va).ok()?;
    let sec  = i64::from_le_bytes(buf[0..8].try_into().ok()?);
    let usec = i64::from_le_bytes(buf[8..16].try_into().ok()?);
    Some((sec as u64) * 1_000_000_000 + (usec as u64) * 1_000)
}

/// Parse a `struct timespec` (tv_sec: i64, tv_nsec: i64) at `va`.
/// Returns the value as nanoseconds, or None on EFAULT.
/// UTIME_NOW (0x3fffffff) and UTIME_OMIT (0x3ffffffe) are returned as-is
/// encoded (caller checks for these magic values).
const UTIME_NOW:  i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;

fn parse_timespec_ns(va: usize) -> Option<i64> {
    let mut buf = [0u8; 16];
    copy_from_user(&mut buf, va).ok()?;
    let sec  = i64::from_le_bytes(buf[0..8].try_into().ok()?);
    let nsec = i64::from_le_bytes(buf[8..16].try_into().ok()?);
    // nsec == UTIME_NOW or UTIME_OMIT are special markers, pass through
    if nsec == UTIME_NOW || nsec == UTIME_OMIT {
        return Some(nsec);
    }
    Some(sec * 1_000_000_000 + nsec)
}

/// NR 132  utime(path, utimbuf)
/// utimbuf: { actime: time_t (8), modtime: time_t (8) }   (POSIX)
pub(super) fn sys_utime_impl(path_va: usize, times_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    let (atime_ns, mtime_ns) = if times_va == 0 {
        // NULL → set both to current time
        let now = crate::time::monotonic_ns();
        (Some(now), Some(now))
    } else {
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, times_va).is_err() { return -14; }
        let atime_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        let mtime_sec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        (
            Some((atime_sec as u64) * 1_000_000_000),
            Some((mtime_sec as u64) * 1_000_000_000),
        )
    };
    crate::fs::vfs::set_times(&path, atime_ns, mtime_ns);
    0
}

/// NR 235  utimes(path, timesval[2])
/// timesval[0] = atime (struct timeval), timesval[1] = mtime (struct timeval)
pub(super) fn sys_utimes_impl(path_va: usize, times_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    let (atime_ns, mtime_ns) = if times_va == 0 {
        let now = crate::time::monotonic_ns();
        (Some(now), Some(now))
    } else {
        let a = parse_timeval(times_va);
        let m = parse_timeval(times_va + 16);
        (a, m)
    };
    crate::fs::vfs::set_times(&path, atime_ns, mtime_ns);
    0
}

/// NR 280  utimensat(dirfd, path, times[2], flags)
/// times[0] = atime (struct timespec), times[1] = mtime (struct timespec)
/// Handles UTIME_NOW and UTIME_OMIT magic values correctly.
pub(super) fn sys_utimensat_impl(dirfd: i32, path_va: usize,
                                  times_va: usize, _flags: i32) -> isize {
    let path = match crate::syscall::stubs_at_path(dirfd, path_va) {
        Some(p) => p, None => return -14,
    };
    let now_ns = crate::time::monotonic_ns();
    let (atime_ns, mtime_ns) = if times_va == 0 {
        (Some(now_ns), Some(now_ns))
    } else {
        let a_raw = parse_timespec_ns(times_va);
        let m_raw = parse_timespec_ns(times_va + 16);
        let a = match a_raw {
            Some(UTIME_OMIT) => None,
            Some(UTIME_NOW)  => Some(now_ns),
            Some(ns) if ns >= 0 => Some(ns as u64),
            _ => Some(now_ns),
        };
        let m = match m_raw {
            Some(UTIME_OMIT) => None,
            Some(UTIME_NOW)  => Some(now_ns),
            Some(ns) if ns >= 0 => Some(ns as u64),
            _ => Some(now_ns),
        };
        (a, m)
    };
    crate::fs::vfs::set_times(&path, atime_ns, mtime_ns);
    0
}

// ─── File-system operations ──────────────────────────────────────────────────

/// NR 133  mknod(path, mode, dev)
pub(super) fn sys_mknod_impl(path_va: usize, _mode: u32, _dev: u64) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    crate::fs::vfs::create_file(&path, &[]);
    0
}

/// NR 259  mknodat(dirfd, path, mode, dev)
pub(super) fn sys_mknodat_impl(dirfd: i32, path_va: usize, _mode: u32, _dev: u64) -> isize {
    let path = match crate::syscall::stubs_at_path(dirfd, path_va) {
        Some(p) => p, None => return -14,
    };
    crate::fs::vfs::create_file(&path, &[]);
    0
}

/// NR 136  ustat(dev, ubuf) — return zeroed legacy struct.
pub(super) fn sys_ustat_impl(_dev: u64, ubuf_va: usize) -> isize {
    if copy_to_user(ubuf_va, &[0u8; 32]).is_err() { return -14; }
    0
}

/// NR 163  acct — BSD process accounting; not implemented, return ENOSYS.
pub(super) fn sys_acct_impl(_path_va: usize) -> isize { -38 }

/// NR 164  settimeofday(tv, tz)
/// Updates the kernel wall-clock offset so that CLOCK_REALTIME / gettimeofday
/// return the user-supplied time from this point forward.
pub(super) fn sys_settimeofday_impl(tv_va: usize, _tz_va: usize) -> isize {
    if tv_va == 0 { return 0; }
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, tv_va).is_err() { return -14; }
    let new_sec  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let new_usec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    if new_usec < 0 || new_usec >= 1_000_000 { return -22; }
    let new_ns  = (new_sec as u64) * 1_000_000_000 + (new_usec as u64) * 1_000;
    let mono_ns = crate::time::monotonic_ns();
    WALL_OFFSET.store(
        new_ns.wrapping_sub(mono_ns) as i64,
        core::sync::atomic::Ordering::Relaxed,
    );
    0
}

/// NR 96  gettimeofday — reads wall clock via WALL_OFFSET.
/// NOTE: the dispatch entry for NR 96 in stubs.rs reads raw monotonic_ns;
/// replace that arm with a call to this function for correct epoch time.
pub(super) fn sys_gettimeofday_real_impl(tv_va: usize, _tz_va: usize) -> isize {
    if tv_va == 0 { return 0; }
    let (sec, nsec) = wall_clock_now();
    let usec = nsec / 1_000;
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&sec.to_le_bytes());
    buf[8..16].copy_from_slice(&usec.to_le_bytes());
    if copy_to_user(tv_va, &buf).is_err() { return -14; }
    0
}

/// NR 166  umount2 / NR 167 swapon / NR 168 swapoff — no-ops.
pub(super) fn sys_umount2_impl(_tgt: usize, _flags: i32) -> isize { 0 }
pub(super) fn sys_swapon_impl(_path: usize, _flags: i32) -> isize { 0 }
pub(super) fn sys_swapoff_impl(_path: usize) -> isize { 0 }

/// NR 169  reboot — QEMU ACPI power-off.
pub(super) fn sys_reboot_impl(_magic1: u32, _magic2: u32, _cmd: u32, _arg: usize) -> isize {
    #[cfg(target_arch = "x86_64")]
    unsafe { crate::arch::x86_64::io::outw(0x604, 0x2000); }
    0
}

/// NR 170  sethostname(name_va, len)
pub(super) fn sys_sethostname_impl(name_va: usize, len: usize) -> isize {
    let l = len.min(64);
    let mut buf = [0u8; 64];
    if copy_from_user(&mut buf[..l], name_va).is_err() { return -14; }
    HOSTNAME.lock().copy_from_slice(&buf);
    0
}

/// NR 171  setdomainname — accept, no-op.
pub(super) fn sys_setdomainname_impl(_name: usize, _len: usize) -> isize { 0 }

static HOSTNAME: SpinMutex<[u8; 64]> = SpinMutex::new(*b"rustos\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");

/// NR 172  iopl / NR 173 ioperm — deny.
pub(super) fn sys_iopl_impl(_level: i32) -> isize { -1 }
pub(super) fn sys_ioperm_impl(_from: usize, _num: usize, _turn_on: i32) -> isize { -1 }

/// NR 175 / NR 176  init_module / delete_module — deny (no LKM).
pub(super) fn sys_init_module_impl(_mod: usize, _len: usize, _opts: usize) -> isize { -1 }
pub(super) fn sys_delete_module_impl(_name: usize, _flags: u32) -> isize { -1 }

// ─── fallocate ───────────────────────────────────────────────────────────────

/// NR 285  fallocate(fd, mode, offset, len)
pub(super) fn sys_fallocate_impl(fd: usize, _mode: i32, offset: i64, len: i64) -> isize {
    if offset < 0 || len <= 0 { return -22; }
    let new_size = (offset + len) as u64;
    crate::fs::vfs::truncate(fd, new_size);
    0
}

// ─── copy_file_range ─────────────────────────────────────────────────────────

/// NR 326  copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
pub(super) fn sys_copy_file_range_impl(
    fd_in: usize, off_in_va: usize,
    fd_out: usize, off_out_va: usize,
    len: usize, _flags: u32,
) -> isize {
    if len == 0 { return 0; }
    let capped = len.min(1 << 20);
    if off_in_va != 0 {
        let mut buf = [0u8; 8];
        if copy_from_user(&mut buf, off_in_va).is_err() { return -14; }
        crate::fs::vfs::seek(fd_in, i64::from_le_bytes(buf), crate::fs::vfs::SEEK_SET);
    }
    if off_out_va != 0 {
        let mut buf = [0u8; 8];
        if copy_from_user(&mut buf, off_out_va).is_err() { return -14; }
        crate::fs::vfs::seek(fd_out, i64::from_le_bytes(buf), crate::fs::vfs::SEEK_SET);
    }
    let mut data = alloc::vec![0u8; capped];
    let n = crate::fs::vfs::read(fd_in, &mut data);
    if n <= 0 { return n; }
    let written = crate::fs::vfs::write(fd_out, &data[..n as usize]);
    if off_in_va != 0 {
        let new_off = crate::fs::vfs::seek(fd_in, 0, crate::fs::vfs::SEEK_CUR) as i64;
        if copy_to_user(off_in_va, &new_off.to_le_bytes()).is_err() { return -14; }
    }
    if off_out_va != 0 {
        let new_off = crate::fs::vfs::seek(fd_out, 0, crate::fs::vfs::SEEK_CUR) as i64;
        if copy_to_user(off_out_va, &new_off.to_le_bytes()).is_err() { return -14; }
    }
    written
}

// ─── preadv2 / pwritev2 ──────────────────────────────────────────────────────

/// NR 327  preadv2 — flags ignored; delegate to preadv at offset.
pub(super) fn sys_preadv2_impl(fd: usize, iov_va: usize, iovcnt: usize,
                                pos_l: usize, pos_h: usize, _flags: i32) -> isize {
    let offset = (pos_l as i64) | ((pos_h as i64) << 32);
    let old = crate::fs::vfs::seek(fd, 0, crate::fs::vfs::SEEK_CUR) as i64;
    if offset >= 0 { crate::fs::vfs::seek(fd, offset, crate::fs::vfs::SEEK_SET); }
    let n = crate::syscall::sys_readv_impl(fd, iov_va, iovcnt);
    if offset >= 0 { crate::fs::vfs::seek(fd, old, crate::fs::vfs::SEEK_SET); }
    n
}

/// NR 328  pwritev2 — flags ignored; delegate to pwrite64 per iov.
pub(super) fn sys_pwritev2_impl(fd: usize, iov_va: usize, iovcnt: usize,
                                 pos_l: usize, pos_h: usize, _flags: i32) -> isize {
    if iovcnt == 0 { return 0; }
    if iovcnt > 1024 { return -22; }
    let offset = (pos_l as i64) | ((pos_h as i64) << 32);
    let mut total: isize = 0;
    for i in 0..iovcnt {
        let mut iov_buf = [0u8; 16];
        if copy_from_user(&mut iov_buf, iov_va + i * 16).is_err() { return -14; }
        let base = usize::from_le_bytes(iov_buf[0..8].try_into().unwrap());
        let len  = usize::from_le_bytes(iov_buf[8..16].try_into().unwrap());
        if len == 0 { continue; }
        let n = crate::syscall::sys_pwrite64_impl(fd, base, len,
            if offset >= 0 { offset + total as i64 } else { -1 });
        if n < 0 { return if total > 0 { total } else { n }; }
        total += n;
    }
    total
}

// ─── statx ───────────────────────────────────────────────────────────────────

/// NR 332  statx(dirfd, path, flags, mask, statxbuf_va)
pub(super) fn sys_statx_impl(
    dirfd: i32, path_va: usize, _flags: u32, _mask: u32, statxbuf_va: usize,
) -> isize {
    let path = match crate::syscall::stubs_at_path(dirfd, path_va) {
        Some(p) => p, None => return -14,
    };
    let mut kstat = [0u8; 144];
    let kstat_va = kstat.as_mut_ptr() as usize;
    let rc = crate::fs::vfs::stat(&path, kstat_va);
    if rc < 0 { return rc; }
    let mut sx = [0u8; 256];
    sx[0..4].copy_from_slice(&0x7ffu32.to_le_bytes());
    let blksize = u64::from_le_bytes(kstat[56..64].try_into().unwrap()) as u32;
    sx[4..8].copy_from_slice(&blksize.to_le_bytes());
    let nlink = u64::from_le_bytes(kstat[16..24].try_into().unwrap()) as u32;
    sx[16..20].copy_from_slice(&nlink.to_le_bytes());
    sx[20..24].copy_from_slice(&kstat[24..28]);
    sx[24..28].copy_from_slice(&kstat[28..32]);
    sx[28..30].copy_from_slice(&kstat[24..26]);
    sx[32..40].copy_from_slice(&kstat[8..16]);
    sx[40..48].copy_from_slice(&kstat[48..56]);
    sx[48..56].copy_from_slice(&kstat[64..72]);
    sx[64..80].copy_from_slice(&kstat[72..88]);
    sx[80..96].copy_from_slice(&kstat[72..88]);
    sx[96..112].copy_from_slice(&kstat[104..120]);
    sx[112..128].copy_from_slice(&kstat[88..104]);
    if copy_to_user(statxbuf_va, &sx).is_err() { return -14; }
    0
}

// ─── execveat ────────────────────────────────────────────────────────────────

/// NR 322  execveat(dirfd, pathname, argv, envp, flags)
pub(super) fn sys_execveat_impl(
    dirfd: i32, path_va: usize, argv_va: usize, envp_va: usize, _flags: i32,
) -> isize {
    let path = match crate::syscall::stubs_at_path(dirfd, path_va) {
        Some(p) => p, None => return -14,
    };
    let path_bytes = path.as_bytes();
    let mut kbuf = alloc::vec![0u8; path_bytes.len() + 1];
    kbuf[..path_bytes.len()].copy_from_slice(path_bytes);
    crate::proc::exec::sys_execve(kbuf.as_ptr() as usize, argv_va, envp_va)
}

// ─── pkey_* ──────────────────────────────────────────────────────────────────

/// NR 329  pkey_mprotect — forward to mprotect (pkey ignored).
pub(super) fn sys_pkey_mprotect_impl(addr: usize, len: usize, prot: u32, _pkey: i32) -> isize {
    crate::mm::mmap::sys_mprotect(addr, len, prot)
}

/// NR 330  pkey_alloc — always return pkey 0.
pub(super) fn sys_pkey_alloc_impl(_flags: u32, _access_rights: u64) -> isize { 0 }

/// NR 331  pkey_free — accept.
pub(super) fn sys_pkey_free_impl(_pkey: i32) -> isize { 0 }

// ─── mlock2 ──────────────────────────────────────────────────────────────────

/// NR 325  mlock2 — no-op in single-user kernel.
pub(super) fn sys_mlock2_impl(_addr: usize, _len: usize, _flags: u32) -> isize { 0 }

// ─── Scheduler attrs ─────────────────────────────────────────────────────────

/// NR 315  sched_getattr — return SCHED_OTHER with priority 0.
pub(super) fn sys_sched_getattr_impl(_pid: usize, attr_va: usize, size: u32, _flags: u32) -> isize {
    if size < 48 { return -22; }
    let mut buf = [0u8; 48];
    buf[0..4].copy_from_slice(&48u32.to_le_bytes());
    if copy_to_user(attr_va, &buf).is_err() { return -14; }
    0
}

/// NR 316  sched_setattr — accept, no-op.
pub(super) fn sys_sched_setattr_impl(_pid: usize, _attr_va: usize, _flags: u32) -> isize { 0 }

// ─── Denied / not-implemented gate ───────────────────────────────────────────

pub(super) fn sys_eperm_impl() -> isize { -1 }

// ─── process_vm_readv / process_vm_writev ────────────────────────────────────
//
// Cross-process memory access using the target process's page table.
//
// Algorithm (readv — writev is symmetric):
//   For each (remote_base, remote_len) in rvec:
//     Walk the remote CR3 page-by-page via Paging::virt_to_phys.
//     Map each physical page into a kernel bounce buffer.
//     copy_to_user into successive local iovecs.
//
// Constraints:
//   - Unknown PID → ESRCH (-3)
//   - Bad remote VA on any page → EFAULT (-14) for that iovec; partial
//     byte count already written is returned.
//   - Individual iov_len clamped to 1 MiB to keep the bounce bounded.
//   - flags must be 0 (Linux requirement).

use crate::arch::{Arch, api::Paging};

const PROCESS_VM_MAX_IOV: usize = 1 << 20; // 1 MiB per iov
const PAGE: usize = 4096;

/// NR 310  process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags)
///
/// Reads from the virtual address space of `pid` into the caller's buffers.
pub(super) fn sys_process_vm_readv_impl(
    pid:      usize,
    lvec_va:  usize,
    liovcnt:  usize,
    rvec_va:  usize,
    riovcnt:  usize,
    flags:    usize,
) -> isize {
    if flags != 0 { return -22; }
    if liovcnt == 0 || riovcnt == 0 { return 0; }
    if liovcnt > 1024 || riovcnt > 1024 { return -22; }

    // Resolve the target process's page table root.
    let remote_cr3 = match crate::proc::scheduler::with_proc(pid, |p| p.user_satp) {
        Some(cr3) if cr3 != 0 => cr3,
        _ => return -3, // ESRCH
    };

    // Gather all remote iovecs.
    let mut remote_iovs: alloc::vec::Vec<(usize, usize)> =
        alloc::vec::Vec::with_capacity(riovcnt);
    for i in 0..riovcnt {
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, rvec_va + i * 16).is_err() { return -14; }
        let base = usize::from_le_bytes(buf[0..8].try_into().unwrap());
        let len  = usize::from_le_bytes(buf[8..16].try_into().unwrap());
        remote_iovs.push((base, len.min(PROCESS_VM_MAX_IOV)));
    }

    // Gather all local iovecs.
    let mut local_iovs: alloc::vec::Vec<(usize, usize)> =
        alloc::vec::Vec::with_capacity(liovcnt);
    for i in 0..liovcnt {
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, lvec_va + i * 16).is_err() { return -14; }
        let base = usize::from_le_bytes(buf[0..8].try_into().unwrap());
        let len  = usize::from_le_bytes(buf[8..16].try_into().unwrap());
        local_iovs.push((base, len));
    }

    let mut total_copied: isize = 0;
    let mut local_idx  = 0usize;
    let mut local_off  = 0usize; // bytes consumed in local_iovs[local_idx]

    'outer: for (r_base, r_len) in &remote_iovs {
        let mut r_off = 0usize;
        while r_off < *r_len {
            // Locate next local destination.
            while local_idx < local_iovs.len() && local_off >= local_iovs[local_idx].1 {
                local_idx += 1;
                local_off  = 0;
            }
            if local_idx >= local_iovs.len() { break 'outer; }

            let r_va    = r_base + r_off;
            let page_va = r_va & !(PAGE - 1);
            let page_off = r_va & (PAGE - 1);

            // Walk the remote page table to get the physical frame.
            let pa = match <Arch as Paging>::virt_to_phys(remote_cr3, page_va) {
                Some(p) => p,
                None    => return if total_copied > 0 { total_copied } else { -14 },
            };

            let avail_in_page = PAGE - page_off;
            let (l_base, l_len) = local_iovs[local_idx];
            let local_avail     = l_len - local_off;
            let chunk = avail_in_page
                .min(*r_len - r_off)
                .min(local_avail);

            // Read from the physical frame directly.
            let src_ptr = (pa + page_off) as *const u8;
            let src_slice = unsafe { core::slice::from_raw_parts(src_ptr, chunk) };

            if copy_to_user(l_base + local_off, src_slice).is_err() {
                return if total_copied > 0 { total_copied } else { -14 };
            }

            r_off         += chunk;
            local_off     += chunk;
            total_copied  += chunk as isize;
        }
    }

    total_copied
}

/// NR 311  process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags)
///
/// Writes from the caller's buffers into the virtual address space of `pid`.
pub(super) fn sys_process_vm_writev_impl(
    pid:      usize,
    lvec_va:  usize,
    liovcnt:  usize,
    rvec_va:  usize,
    riovcnt:  usize,
    flags:    usize,
) -> isize {
    if flags != 0 { return -22; }
    if liovcnt == 0 || riovcnt == 0 { return 0; }
    if liovcnt > 1024 || riovcnt > 1024 { return -22; }

    let remote_cr3 = match crate::proc::scheduler::with_proc(pid, |p| p.user_satp) {
        Some(cr3) if cr3 != 0 => cr3,
        _ => return -3, // ESRCH
    };

    let mut remote_iovs: alloc::vec::Vec<(usize, usize)> =
        alloc::vec::Vec::with_capacity(riovcnt);
    for i in 0..riovcnt {
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, rvec_va + i * 16).is_err() { return -14; }
        let base = usize::from_le_bytes(buf[0..8].try_into().unwrap());
        let len  = usize::from_le_bytes(buf[8..16].try_into().unwrap());
        remote_iovs.push((base, len.min(PROCESS_VM_MAX_IOV)));
    }

    let mut local_iovs: alloc::vec::Vec<(usize, usize)> =
        alloc::vec::Vec::with_capacity(liovcnt);
    for i in 0..liovcnt {
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, lvec_va + i * 16).is_err() { return -14; }
        let base = usize::from_le_bytes(buf[0..8].try_into().unwrap());
        let len  = usize::from_le_bytes(buf[8..16].try_into().unwrap());
        local_iovs.push((base, len));
    }

    let mut total_copied: isize = 0;
    let mut local_idx  = 0usize;
    let mut local_off  = 0usize;
    // Bounce buffer: one page, stack-allocated.
    let mut bounce = [0u8; PAGE];

    'outer: for (r_base, r_len) in &remote_iovs {
        let mut r_off = 0usize;
        while r_off < *r_len {
            while local_idx < local_iovs.len() && local_off >= local_iovs[local_idx].1 {
                local_idx += 1;
                local_off  = 0;
            }
            if local_idx >= local_iovs.len() { break 'outer; }

            let r_va     = r_base + r_off;
            let page_va  = r_va & !(PAGE - 1);
            let page_off = r_va & (PAGE - 1);

            let pa = match <Arch as Paging>::virt_to_phys(remote_cr3, page_va) {
                Some(p) => p,
                None    => return if total_copied > 0 { total_copied } else { -14 },
            };

            let avail_in_page = PAGE - page_off;
            let (l_base, l_len) = local_iovs[local_idx];
            let local_avail     = l_len - local_off;
            let chunk = avail_in_page
                .min(*r_len - r_off)
                .min(local_avail)
                .min(PAGE);

            // Copy from caller into bounce buffer.
            if copy_from_user(&mut bounce[..chunk], l_base + local_off).is_err() {
                return if total_copied > 0 { total_copied } else { -14 };
            }

            // Write bounce buffer directly into the remote physical frame.
            let dst_ptr = (pa + page_off) as *mut u8;
            unsafe { core::ptr::copy_nonoverlapping(bounce.as_ptr(), dst_ptr, chunk); }
            // Flush the written VA in the remote address space.
            <Arch as Paging>::flush_va(r_va);

            r_off        += chunk;
            local_off    += chunk;
            total_copied += chunk as isize;
        }
    }

    total_copied
}

// ─── syncfs ──────────────────────────────────────────────────────────────────

/// NR 306  syncfs(fd) — flush all dirty VFS buffers (same as sync).
pub(super) fn sys_syncfs_impl(_fd: usize) -> isize {
    crate::fs::vfs::sync_all();
    0
}

// ─── sendmmsg / recvmmsg ────────────────────────────────────────────────────

/// NR 307  sendmmsg(sockfd, msgvec, vlen, flags)
pub(super) fn sys_sendmmsg_impl(sockfd: usize, msgvec_va: usize, vlen: u32, flags: u32) -> isize {
    if vlen == 0 { return 0; }
    let vlen = vlen.min(1024) as usize;
    const MMSGHDR_SZ: usize = 56;
    let mut sent: isize = 0;
    for i in 0..vlen {
        let hdr_va = msgvec_va + i * MMSGHDR_SZ;
        let n = crate::net::socket::sys_sendmsg(sockfd, hdr_va, flags as usize);
        if n < 0 { return if sent > 0 { sent } else { n }; }
        let msg_len = n as u32;
        if copy_to_user(hdr_va + 48, &msg_len.to_le_bytes()).is_err() { return -14; }
        sent += 1;
    }
    sent
}

/// NR 299  recvmmsg(sockfd, msgvec, vlen, flags, timeout)
pub(super) fn sys_recvmmsg_impl(
    sockfd: usize, msgvec_va: usize, vlen: u32, flags: u32, _timeout_va: usize,
) -> isize {
    if vlen == 0 { return 0; }
    let vlen = vlen.min(1024) as usize;
    const MMSGHDR_SZ: usize = 56;
    let mut recvd: isize = 0;
    for i in 0..vlen {
        let hdr_va = msgvec_va + i * MMSGHDR_SZ;
        let n = crate::net::socket::sys_recvmsg(sockfd, hdr_va, flags as usize);
        if n < 0 { return if recvd > 0 { recvd } else { n }; }
        let msg_len = n as u32;
        if copy_to_user(hdr_va + 48, &msg_len.to_le_bytes()).is_err() { return -14; }
        recvd += 1;
    }
    recvd
}

// ─── kexec / bpf / userfaultfd / remap_file_pages ───────────────────────────

pub(super) fn sys_kexec_file_load_impl() -> isize { -1 }
pub(super) fn sys_bpf_impl() -> isize { -1 }
pub(super) fn sys_userfaultfd_impl() -> isize { -1 }
pub(super) fn sys_remap_file_pages_impl() -> isize { -38 }
