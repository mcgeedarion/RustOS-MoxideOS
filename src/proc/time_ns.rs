//! Time-namespace-aware clock_gettime / clock_settime / settimeofday.
//!
//! Clock IDs handled:
//!   0  CLOCK_REALTIME           – wall clock, offset by realtime_offset_ns
//!   1  CLOCK_MONOTONIC          – time since boot, ns-timens offset applied
//!   2  CLOCK_PROCESS_CPUTIME_ID – cpu_time_ns from current process entry
//!   3  CLOCK_THREAD_CPUTIME_ID  – same as process for now
//!   4  CLOCK_MONOTONIC_RAW      – raw monotonic, no offset
//!   5  CLOCK_REALTIME_COARSE    – same as REALTIME (no coarse hw here)
//!   6  CLOCK_MONOTONIC_COARSE   – same as MONOTONIC
//!   7  CLOCK_BOOTTIME           – alias for MONOTONIC
//!   8  CLOCK_REALTIME_ALARM     – alias for REALTIME
//!   9  CLOCK_BOOTTIME_ALARM     – alias for MONOTONIC

extern crate alloc;
use crate::uaccess::{copy_from_user, copy_to_user};

// Nanosecond special values from <time.h>.
const UTIME_NOW: i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;

/// Read a `struct timespec { i64 tv_sec; i64 tv_nsec; }` from userspace.
#[inline]
fn read_timespec(va: usize) -> Option<(i64, i64)> {
    if va == 0 {
        return None;
    }
    let mut buf = [0u8; 16];
    copy_from_user(&mut buf, va).ok()?;
    let sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    Some((sec, nsec))
}

/// Write a `struct timespec` to userspace.
#[inline]
fn write_timespec(va: usize, sec: i64, nsec: i64) -> isize {
    if va == 0 {
        return 0;
    }
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&sec.to_le_bytes());
    buf[8..16].copy_from_slice(&nsec.to_le_bytes());
    if copy_to_user(va, &buf).is_err() {
        -14
    } else {
        0
    }
}

/// Return the monotonic ns adjusted for the current process's time namespace.
fn mono_ns_for_current() -> u64 {
    let raw = crate::time::read_monotonic_ns();
    let pid = crate::proc::scheduler::current_pid();
    // Fetch the timens monotonic offset if one has been set.
    let tns_off = crate::proc::scheduler::with_proc(pid, |p| p.timens_mono_off).unwrap_or(0i64);
    (raw as i64).wrapping_add(tns_off) as u64
}

/// Read cpu_time_ns for a pid; returns 0 if the process is not found.
fn cpu_ns(pid: usize) -> u64 {
    crate::proc::scheduler::with_proc(pid, |p| p.cpu_time_ns).unwrap_or(0)
}

pub fn sys_clock_gettime(clkid: u32, tp_va: usize) -> isize {
    if tp_va == 0 {
        return -14;
    }

    let ns: u64 = match clkid {
        // CLOCK_REALTIME / CLOCK_REALTIME_COARSE / CLOCK_REALTIME_ALARM
        0 | 5 | 8 => {
            let mono = crate::time::read_monotonic_ns();
            let off = crate::time::realtime_offset_ns();
            (mono as i64).wrapping_add(off) as u64
        },

        // CLOCK_MONOTONIC / CLOCK_MONOTONIC_COARSE / CLOCK_BOOTTIME /
        // CLOCK_BOOTTIME_ALARM
        1 | 6 | 7 | 9 => mono_ns_for_current(),

        // CLOCK_MONOTONIC_RAW
        4 => crate::time::read_monotonic_ns(),

        // CLOCK_PROCESS_CPUTIME_ID
        2 => {
            let pid = crate::proc::scheduler::current_pid();
            cpu_ns(pid)
        },

        // CLOCK_THREAD_CPUTIME_ID
        // We track cpu_time_ns per-task, so this is the same value.
        // When per-thread split accounting lands, update here.
        3 => {
            let tid = crate::proc::scheduler::current_pid();
            cpu_ns(tid)
        },

        _ => return -22, // EINVAL
    };

    let sec = (ns / 1_000_000_000) as i64;
    let nsec = (ns % 1_000_000_000) as i64;
    write_timespec(tp_va, sec, nsec)
}

pub fn sys_clock_settime(clkid: u32, tp_va: usize) -> isize {
    match clkid {
        // CLOCK_REALTIME only – other clocks cannot be set.
        0 => {
            let (sec, nsec) = match read_timespec(tp_va) {
                Some(v) => v,
                None => return -14,
            };
            if nsec < 0 || nsec >= 1_000_000_000 {
                return -22;
            }
            let new_real_ns = sec as u64 * 1_000_000_000 + nsec as u64;
            let mono_ns = crate::time::read_monotonic_ns();
            let offset = new_real_ns as i64 - mono_ns as i64;
            crate::time::set_realtime_offset_ns(offset);
            0
        },
        // CPU clocks, monotonic clocks: EINVAL per POSIX.
        _ => -22,
    }
}

/// settimeofday(tv: *const timeval, tz: *const timezone)
///
/// Sets CLOCK_REALTIME by computing offset = new_real_ns - mono_ns.
/// The timezone argument is accepted but ignored (Linux behaviour).
pub fn sys_settimeofday(tv_va: usize, _tz_va: usize) -> isize {
    if tv_va == 0 {
        return 0;
    }
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, tv_va).is_err() {
        return -14;
    }
    let sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let usec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    if usec < 0 || usec >= 1_000_000 {
        return -22;
    }
    let new_real_ns = sec as u64 * 1_000_000_000 + usec as u64 * 1_000;
    let mono_ns = crate::time::read_monotonic_ns();
    let offset = new_real_ns as i64 - mono_ns as i64;
    crate::time::set_realtime_offset_ns(offset);
    0
}

/// Return current realtime in nanoseconds.
fn now_real_ns() -> u64 {
    let mono = crate::time::read_monotonic_ns();
    let off = crate::time::realtime_offset_ns();
    (mono as i64).wrapping_add(off) as u64
}

/// utime(path, times: *const utimbuf)  [NR 132]
///
/// struct utimbuf { time_t actime; time_t modtime; } -- both are i64 seconds.
pub fn sys_utime(path_va: usize, times_va: usize) -> isize {
    if path_va == 0 {
        return -14;
    }
    let mut path_buf = [0u8; 4096];
    if copy_from_user(&mut path_buf, path_va).is_err() {
        return -14;
    }
    let end = path_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_buf.len());
    let path = match core::str::from_utf8(&path_buf[..end]) {
        Ok(s) => s,
        Err(_) => return -14,
    };

    let (atime_ns, mtime_ns) = if times_va == 0 {
        let now = now_real_ns();
        (now, now)
    } else {
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, times_va).is_err() {
            return -14;
        }
        let actime = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        let modtime = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        (
            actime as u64 * 1_000_000_000,
            modtime as u64 * 1_000_000_000,
        )
    };

    match crate::fs::vfs_ops::utimens(path, atime_ns, mtime_ns) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// utimes(path, times: *const [timeval; 2])  [NR 235]
///
/// struct timeval { i64 tv_sec; i64 tv_usec; }
pub fn sys_utimes(path_va: usize, times_va: usize) -> isize {
    if path_va == 0 {
        return -14;
    }
    let mut path_buf = [0u8; 4096];
    if copy_from_user(&mut path_buf, path_va).is_err() {
        return -14;
    }
    let end = path_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(path_buf.len());
    let path = match core::str::from_utf8(&path_buf[..end]) {
        Ok(s) => s,
        Err(_) => return -14,
    };

    let (atime_ns, mtime_ns) = if times_va == 0 {
        let now = now_real_ns();
        (now, now)
    } else {
        let mut buf = [0u8; 32];
        if copy_from_user(&mut buf, times_va).is_err() {
            return -14;
        }
        let a_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        let a_usec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        let m_sec = i64::from_le_bytes(buf[16..24].try_into().unwrap());
        let m_usec = i64::from_le_bytes(buf[24..32].try_into().unwrap());
        (
            a_sec as u64 * 1_000_000_000 + a_usec as u64 * 1_000,
            m_sec as u64 * 1_000_000_000 + m_usec as u64 * 1_000,
        )
    };

    match crate::fs::vfs_ops::utimens(path, atime_ns, mtime_ns) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// utimensat(dirfd, path, times: *const [timespec; 2], flags)  [NR 280]
///
/// UTIME_NOW (0x3fffffff) and UTIME_OMIT (0x3ffffffe) are honoured.
/// AT_FDCWD and absolute paths are handled; relative paths resolve via
/// dirfd's path.
pub fn sys_utimensat(dirfd: i32, path_va: usize, times_va: usize, _flags: u32) -> isize {
    // Build the full path string.
    let path: alloc::string::String = if path_va == 0 {
        // path_va==0 with AT_EMPTY_PATH applies to dirfd itself.
        match crate::fs::vfs::fd_path(dirfd as usize) {
            Some(p) => p,
            None => return -9, // EBADF
        }
    } else {
        let mut path_buf = [0u8; 4096];
        if copy_from_user(&mut path_buf, path_va).is_err() {
            return -14;
        }
        let end = path_buf
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_buf.len());
        let s = match core::str::from_utf8(&path_buf[..end]) {
            Ok(s) => s,
            Err(_) => return -14,
        };
        if s.starts_with('/') {
            alloc::string::String::from(s)
        } else {
            const AT_FDCWD: i32 = -100;
            let dir = if dirfd == AT_FDCWD {
                let pid = crate::proc::scheduler::current_pid();
                crate::proc::cwd::get_cwd(pid)
            } else {
                crate::fs::vfs::fd_path(dirfd as usize)
                    .unwrap_or_else(|| alloc::string::String::from("/"))
            };
            alloc::format!("{}/{}", dir.trim_end_matches('/'), s)
        }
    };

    let now = now_real_ns();

    let (atime_ns, mtime_ns) = if times_va == 0 {
        (now, now)
    } else {
        let mut buf = [0u8; 32];
        if copy_from_user(&mut buf, times_va).is_err() {
            return -14;
        }
        let a_sec = i64::from_le_bytes(buf[0..8].try_into().unwrap());
        let a_nsec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
        let m_sec = i64::from_le_bytes(buf[16..24].try_into().unwrap());
        let m_nsec = i64::from_le_bytes(buf[24..32].try_into().unwrap());

        let resolve_ts = |sec: i64, nsec: i64| -> Option<u64> {
            if nsec == UTIME_NOW {
                return Some(now);
            }
            if nsec == UTIME_OMIT {
                return None;
            }
            Some(sec as u64 * 1_000_000_000 + nsec as u64)
        };

        let a = resolve_ts(a_sec, a_nsec);
        let m = resolve_ts(m_sec, m_nsec);

        // If both are OMIT, nothing to do.
        if a.is_none() && m.is_none() {
            return 0;
        }

        // For OMIT fields, read the existing inode timestamp to preserve it.
        let (existing_atime, existing_mtime) =
            crate::fs::vfs_ops::get_times(&path).unwrap_or((now, now));

        (a.unwrap_or(existing_atime), m.unwrap_or(existing_mtime))
    };

    match crate::fs::vfs_ops::utimens(&path, atime_ns, mtime_ns) {
        Ok(()) => 0,
        Err(e) => e,
    }
}
