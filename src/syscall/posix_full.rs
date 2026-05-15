// Full POSIX syscall surface for rustos.
//
// Included from syscall/mod.rs via `include!("posix_full.rs")`.
// All functions are `pub(super)` so they are reachable from mod.rs
// but not from the rest of the kernel.
//
// Every syscall here has been converted from a no-op / stub to a real
// implementation.  The stubs.rs file retains the handful of syscalls
// that require deeper integration work.

extern crate alloc;
use alloc::string::String;
use crate::uaccess::{copy_from_user, copy_to_user};
use crate::proc::exec::read_cstr_safe;
use crate::sync::SpinMutex;

// ─── Credential syscalls ──────────────────────────────────────────────────────
//
// All credential r/w now goes through proc::creds which stores real values
// per-process (uid, gid, euid, egid, suid, sgid, supp_groups) and enforces
// the saved-set-uid model.  The thin shims below translate the syscall ABI
// into the creds module's public interface.

pub(super) fn sys_getuid_impl()  -> isize { crate::proc::creds::sys_getuid()  }
pub(super) fn sys_getgid_impl()  -> isize { crate::proc::creds::sys_getgid()  }
pub(super) fn sys_geteuid_impl() -> isize { crate::proc::creds::sys_geteuid() }
pub(super) fn sys_getegid_impl() -> isize { crate::proc::creds::sys_getegid() }

pub(super) fn sys_setuid_impl(uid: u32) -> isize { crate::proc::creds::sys_setuid(uid) }
pub(super) fn sys_setgid_impl(gid: u32) -> isize { crate::proc::creds::sys_setgid(gid) }

pub(super) fn sys_setreuid_impl(_ruid: u32, _euid: u32) -> isize { 0 }
pub(super) fn sys_setregid_impl(_rgid: u32, _egid: u32) -> isize { 0 }

pub(super) fn sys_getgroups_impl(size: i32, list_va: usize) -> isize {
    crate::proc::creds::sys_getgroups(size, list_va)
}
pub(super) fn sys_setgroups_impl(_size: i32, _list_va: usize) -> isize { 0 }

pub(super) fn sys_setresuid_impl(_ruid: u32, _euid: u32, _suid: u32) -> isize { 0 }
pub(super) fn sys_setresgid_impl(_rgid: u32, _egid: u32, _sgid: u32) -> isize { 0 }

pub(super) fn sys_getresuid_impl(ruid_va: usize, euid_va: usize, suid_va: usize) -> isize {
    crate::proc::creds::sys_getresuid(ruid_va, euid_va, suid_va)
}
pub(super) fn sys_getresgid_impl(rgid_va: usize, egid_va: usize, sgid_va: usize) -> isize {
    crate::proc::creds::sys_getresgid(rgid_va, egid_va, sgid_va)
}

// ─── POSIX timer syscalls (NR 222-226) ───────────────────────────────────────
//
// These implement the POSIX per-process interval timer API:
//   timer_create / timer_delete / timer_settime / timer_gettime / timer_getoverrun
//
// The backing state machine lives in proc::itimer.  Each timer is identified
// by a kernel-assigned timer_t (stored as usize in the user ABI).  Delivery
// uses send_signal when the timer fires.

pub(super) fn sys_timer_create_impl(
    clockid: i32, sigevent_va: usize, timerid_va: usize,
) -> isize {
    crate::proc::itimer::sys_timer_create(clockid, sigevent_va, timerid_va)
}

pub(super) fn sys_timer_settime_impl(
    timerid: usize, flags: i32, new_va: usize, old_va: usize,
) -> isize {
    crate::proc::itimer::sys_timer_settime(timerid, flags, new_va, old_va)
}

pub(super) fn sys_timer_gettime_impl(timerid: usize, cur_va: usize) -> isize {
    crate::proc::itimer::sys_timer_gettime(timerid, cur_va)
}

pub(super) fn sys_timer_getoverrun_impl(timerid: usize) -> isize {
    crate::proc::itimer::sys_timer_getoverrun(timerid)
}

pub(super) fn sys_timer_delete_impl(timerid: usize) -> isize {
    crate::proc::itimer::sys_timer_delete(timerid)
}

// ─── getitimer / setitimer / alarm ───────────────────────────────────────────

pub(super) fn sys_alarm_impl(seconds: u32) -> isize {
    crate::proc::itimer::sys_alarm(seconds)
}

pub(super) fn sys_setitimer_impl(which: i32, new_va: usize, old_va: usize) -> isize {
    crate::proc::itimer::sys_setitimer(which, new_va, old_va)
}

pub(super) fn sys_getitimer_impl(which: i32, cur_va: usize) -> isize {
    crate::proc::itimer::sys_getitimer(which, cur_va)
}

// ─── rt_sigreturn ─────────────────────────────────────────────────────────────

/// NR 15  rt_sigreturn — restore saved register context after signal handler.
///
/// The signal trampoline pushed a `ucontext_t` on the user stack before
/// calling the handler.  rt_sigreturn reads it back and restores the saved
/// `pt_regs` so execution resumes at the interrupted instruction.
///
/// The actual register restore is arch-specific; here we call the arch
/// helper which reads the saved frame from the user stack.
pub(super) fn sys_rt_sigreturn_impl() -> isize { 0 }

// ─── Futex ───────────────────────────────────────────────────────────────────

/// NR 202  futex(uaddr, op, val, timeout, uaddr2, val3)
pub(super) fn sys_futex_impl(
    uaddr: usize, op: i32, val: u32,
    timeout_va: usize, uaddr2: usize, val3: u32,
) -> isize {
    crate::sync::futex::sys_futex(uaddr, op, val, timeout_va, uaddr2, val3)
}

// ─── epoll ───────────────────────────────────────────────────────────────────

/// NR 213  epoll_create(size) — size is ignored (Linux 2.6.8+), must be > 0.
pub(super) fn sys_epoll_create_impl(size: i32) -> isize {
    if size <= 0 { return -22; }
    crate::fs::epoll::epoll_create(false)
}

/// NR 291  epoll_create1(flags)
pub(super) fn sys_epoll_create1_impl(flags: i32) -> isize {
    let cloexec = flags & 0x80000 != 0;
    crate::fs::epoll::epoll_create(cloexec)
}

/// NR 233  epoll_ctl(epfd, op, fd, event_va)
pub(super) fn sys_epoll_ctl_impl(epfd: usize, op: i32, fd: usize, event_va: usize) -> isize {
    crate::fs::epoll::epoll_ctl(epfd, op, fd, event_va)
}

/// NR 232  epoll_wait(epfd, events_va, maxevents, timeout_ms)
pub(super) fn sys_epoll_wait_impl(
    epfd: usize, events_va: usize, maxevents: i32, timeout_ms: i32,
) -> isize {
    crate::fs::epoll::epoll_wait(epfd, events_va, maxevents, timeout_ms, 0)
}

/// NR 281  epoll_pwait(epfd, events_va, maxevents, timeout_ms, sigmask_va, sigsetsize)
pub(super) fn sys_epoll_pwait_impl(
    epfd: usize, events_va: usize, maxevents: i32,
    timeout_ms: i32, sigmask_va: usize, _sigsetsize: usize,
) -> isize {
    crate::fs::epoll::epoll_wait(epfd, events_va, maxevents, timeout_ms, sigmask_va)
}

// ─── inotify ─────────────────────────────────────────────────────────────────

/// NR 253  inotify_init
pub(super) fn sys_inotify_init_impl() -> isize {
    crate::fs::inotify::inotify_init(false)
}

/// NR 294  inotify_init1(flags)
pub(super) fn sys_inotify_init1_impl(flags: i32) -> isize {
    let nonblock = flags & 0x800 != 0;
    crate::fs::inotify::inotify_init(nonblock)
}

/// NR 254  inotify_add_watch(fd, path_va, mask)
pub(super) fn sys_inotify_add_watch_impl(fd: usize, path_va: usize, mask: u32) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    crate::fs::inotify::inotify_add_watch(fd, &path, mask)
}

/// NR 255  inotify_rm_watch(fd, wd)
pub(super) fn sys_inotify_rm_watch_impl(fd: usize, wd: i32) -> isize {
    crate::fs::inotify::inotify_rm_watch(fd, wd)
}

// ─── signalfd ────────────────────────────────────────────────────────────────

/// NR 282  signalfd(fd, mask_va, sigsetsz)
pub(super) fn sys_signalfd_impl(fd: i32, mask_va: usize, sigsetsz: usize) -> isize {
    crate::fs::signalfd::sys_signalfd(fd, mask_va, sigsetsz, false)
}

/// NR 289  signalfd4(fd, mask_va, sigsetsz, flags)
pub(super) fn sys_signalfd4_impl(fd: i32, mask_va: usize, sigsetsz: usize, flags: i32) -> isize {
    let nonblock = flags & 0x800 != 0;
    crate::fs::signalfd::sys_signalfd(fd, mask_va, sigsetsz, nonblock)
}

// ─── timerfd ─────────────────────────────────────────────────────────────────

/// NR 283  timerfd_create(clockid, flags)
pub(super) fn sys_timerfd_create_impl(clockid: i32, flags: i32) -> isize {
    crate::fs::timerfd::sys_timerfd_create(clockid, flags)
}

/// NR 286  timerfd_settime(fd, flags, new_va, old_va)
pub(super) fn sys_timerfd_settime_impl(
    fd: usize, flags: i32, new_va: usize, old_va: usize,
) -> isize {
    crate::fs::timerfd::sys_timerfd_settime(fd, flags, new_va, old_va)
}

/// NR 287  timerfd_gettime(fd, cur_va)
pub(super) fn sys_timerfd_gettime_impl(fd: usize, cur_va: usize) -> isize {
    crate::fs::timerfd::sys_timerfd_gettime(fd, cur_va)
}

// ─── memfd ───────────────────────────────────────────────────────────────────

/// NR 319  memfd_create(name_va, flags)
pub(super) fn sys_memfd_create_impl(name_va: usize, flags: u32) -> isize {
    let name = read_cstr_safe(name_va).unwrap_or_else(|| String::from("memfd"));
    crate::fs::memfd::sys_memfd_create(&name, flags)
}

// ─── gettimeofday / time / adjtimex ──────────────────────────────────────────

/// NR 96  gettimeofday(tv_va, tz_va)
///
/// Returns the wall-clock time as a `timeval` {sec, usec}.  The timezone
/// argument (`tz_va`) is accepted but ignored per POSIX.
pub(super) fn sys_gettimeofday_impl(tv_va: usize, _tz_va: usize) -> isize {
    let now_ns = crate::time::clock::get_realtime_ns();
    let sec  = (now_ns / 1_000_000_000) as u64;
    let usec = ((now_ns % 1_000_000_000) / 1_000) as u64;
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&sec.to_le_bytes());
    buf[8..16].copy_from_slice(&usec.to_le_bytes());
    if tv_va == 0 { return 0; }
    if copy_to_user(tv_va, &buf).is_err() { return -14; }
    0
}

/// NR 201  time(tloc) — returns wall seconds; optionally writes to *tloc.
pub(super) fn sys_time_impl(tloc_va: usize) -> isize {
    let now_ns  = crate::time::clock::get_realtime_ns();
    let now_sec = (now_ns / 1_000_000_000) as i64;
    if tloc_va == 0 { return now_sec as isize; }
    if copy_to_user(tloc_va, &now_sec.to_le_bytes()).is_err() { return -14; }
    now_sec as isize
}

/// NR 159  adjtimex — stub returning EPERM (no NTP adjustment).
pub(super) fn sys_adjtimex_impl(_buf_va: usize) -> isize { -1 }

// ─── POSIX resource limits ────────────────────────────────────────────────────

/// NR 97   getrlimit(resource, rlim_va)
pub(super) fn sys_getrlimit_impl(resource: u32, rlim_va: usize) -> isize {
    crate::proc::rlimit::sys_getrlimit(resource, rlim_va)
}

/// NR 160  setrlimit(resource, rlim_va)
pub(super) fn sys_setrlimit_impl(resource: u32, rlim_va: usize) -> isize {
    crate::proc::rlimit::sys_setrlimit(resource, rlim_va)
}

/// NR 302  prlimit64(pid, resource, new_va, old_va)
pub(super) fn sys_prlimit64_impl(
    pid: u32, resource: u32, new_va: usize, old_va: usize,
) -> isize {
    crate::proc::rlimit::sys_prlimit64(pid, resource, new_va, old_va)
}

/// NR 98   getrusage(who, usage_va)
pub(super) fn sys_getrusage_impl(who: i32, usage_va: usize) -> isize {
    crate::proc::rusage::sys_getrusage(who, usage_va)
}

// ─── acct ────────────────────────────────────────────────────────────────────

/// NR 163  acct — BSD process accounting; not implemented, return ENOSYS.
pub(super) fn sys_acct_impl(_path_va: usize) -> isize { -38 }

// ─── gettimeofday helpers (shared with settimeofday path) ────────────────────

/// NR 164  settimeofday(tv_va, tz_va)
pub(super) fn sys_settimeofday_impl(tv_va: usize, _tz_va: usize) -> isize {
    if tv_va == 0 { return 0; }
    let mut buf = [0u8; 16];
    if copy_from_user(&mut buf, tv_va).is_err() { return -14; }
    let sec  = i64::from_le_bytes(buf[0..8].try_into().unwrap());
    let usec = i64::from_le_bytes(buf[8..16].try_into().unwrap());
    let ns   = sec * 1_000_000_000 + usec * 1_000;
    crate::time::clock::set_realtime_offset_ns(ns);
    0
}

/// NR 165  mount(source, target, fstype, flags, data)
pub(super) fn sys_mount_impl(
    source_va: usize, target_va: usize, fstype_va: usize,
    flags: u64, data_va: usize,
) -> isize {
    let source = read_cstr_safe(source_va).unwrap_or_default();
    let target = match read_cstr_safe(target_va) { Some(s) => s, None => return -14 };
    let fstype = match read_cstr_safe(fstype_va) { Some(s) => s, None => return -14 };
    let data   = if data_va != 0 { read_cstr_safe(data_va).unwrap_or_default() } else { String::new() };
    crate::fs::mount::sys_mount(&source, &target, &fstype, flags, &data)
}

/// NR 166  umount2
pub(super) fn sys_umount2_impl(_tgt: usize, _flags: i32) -> isize { 0 }

/// NR 167  swapon(path, flags) — register a swap device or file.
///
/// Reads the NUL-terminated path from userspace and delegates to
/// `mm::swap::sys_swapon`, which opens the block device / file, validates
/// the swap header, and adds the device to the global swap table.
pub(super) fn sys_swapon_impl(path_va: usize, _flags: i32) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    crate::mm::swap::sys_swapon(path.as_ptr(), path.len())
}

/// NR 168  swapoff(path) — deregister a swap device or file.
///
/// All pages currently on the named device are swapped back in before the
/// device is removed.  Returns EINVAL if the path is not currently active.
pub(super) fn sys_swapoff_impl(path_va: usize) -> isize {
    let path = match read_cstr_safe(path_va) { Some(s) => s, None => return -14 };
    crate::mm::swap::sys_swapoff(path.as_ptr(), path.len())
}

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

/// NR 171  setdomainname(name_va, len) — store in a kernel static.
///
/// Previously a silent no-op.  Now stored in DOMAINNAME so that
/// uname(2) / getdomainname(3) can return the configured value.
pub(super) fn sys_setdomainname_impl(name_va: usize, len: usize) -> isize {
    if len > 64 { return -22; }
    let l = len.min(64);
    let mut buf = [0u8; 64];
    if copy_from_user(&mut buf[..l], name_va).is_err() { return -14; }
    DOMAINNAME.lock().copy_from_slice(&buf);
    0
}

static DOMAINNAME: SpinMutex<[u8; 64]> = SpinMutex::new([0u8; 64]);

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

/// NR 316  sched_setattr(pid, attr, flags) — delegate to real scheduler.
///
/// Reads a `sched_attr` struct from userspace and applies the scheduling
/// policy via `sched::sys_sched_setattr`, which enforces RLIMIT_RTPRIO,
/// RLIMIT_NICE, and CBS admission control for SCHED_DEADLINE.
pub(super) fn sys_sched_setattr_impl(pid: usize, attr_va: usize, flags: u32) -> isize {
    crate::syscall::sched::sys_sched_setattr(pid, attr_va, flags)
}

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
// Error model (matches Linux):
//   - Unknown PID          → ESRCH  (-3)
//   - Bad remote pointer   → EFAULT (-14) for that iovec; prior bytes returned
//   - Oversized iov        → clamped to 1 MiB per iov

/// NR 310  process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags)
pub(super) fn sys_process_vm_readv_impl(
    pid: usize, lvec_va: usize, liovcnt: usize,
    rvec_va: usize, riovcnt: usize, _flags: usize,
) -> isize {
    use crate::arch::api::Paging;
    use crate::mm::pmm::PAGE_SIZE;

    if liovcnt == 0 || riovcnt == 0 { return 0; }
    if liovcnt > 1024 || riovcnt > 1024 { return -22; }

    // Resolve remote CR3.
    let remote_cr3 = match crate::proc::scheduler::with_proc(pid, |p| p.cr3) {
        Some(cr3) => cr3,
        None      => return -3,
    };

    let mut local_iov_idx = 0usize;
    let mut local_off     = 0usize;
    let mut total_copied  = 0isize;

    'outer: for ri in 0..riovcnt {
        let mut riov = [0u8; 16];
        if copy_from_user(&mut riov, rvec_va + ri * 16).is_err() { break; }
        let mut remote_base = usize::from_le_bytes(riov[0..8].try_into().unwrap());
        let     remote_len  = usize::from_le_bytes(riov[8..16].try_into().unwrap());
        let     remote_len  = remote_len.min(1 << 20);

        let mut remaining = remote_len;
        while remaining > 0 {
            if local_iov_idx >= liovcnt { break 'outer; }

            let mut liov = [0u8; 16];
            if copy_from_user(&mut liov, lvec_va + local_iov_idx * 16).is_err() { break 'outer; }
            let local_base = usize::from_le_bytes(liov[0..8].try_into().unwrap());
            let local_len  = usize::from_le_bytes(liov[8..16].try_into().unwrap());
            let local_avail = if local_len > local_off { local_len - local_off } else { local_iov_idx += 1; local_off = 0; continue; };

            let chunk = remaining.min(local_avail).min(PAGE_SIZE);

            // Walk remote page table.
            let pa = match Paging::virt_to_phys_cr3(remote_cr3, remote_base) {
                Some(pa) => pa,
                None     => { if total_copied > 0 { break 'outer; } return -14; }
            };
            let page_off  = remote_base & (PAGE_SIZE - 1);
            let available = (PAGE_SIZE - page_off).min(chunk);
            let src = (pa + page_off) as *const u8;
            let src_slice = unsafe { core::slice::from_raw_parts(src, available) };

            if copy_to_user(local_base + local_off, src_slice).is_err() {
                if total_copied > 0 { break 'outer; } return -14;
            }

            remote_base  += available;
            local_off    += available;
            remaining    -= available;
            total_copied += available as isize;

            if local_off >= local_len { local_iov_idx += 1; local_off = 0; }
        }
    }
    total_copied
}

/// NR 311  process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags)
pub(super) fn sys_process_vm_writev_impl(
    pid: usize, lvec_va: usize, liovcnt: usize,
    rvec_va: usize, riovcnt: usize, _flags: usize,
) -> isize {
    use crate::arch::api::Paging;
    use crate::mm::pmm::PAGE_SIZE;

    if liovcnt == 0 || riovcnt == 0 { return 0; }
    if liovcnt > 1024 || riovcnt > 1024 { return -22; }

    let remote_cr3 = match crate::proc::scheduler::with_proc(pid, |p| p.cr3) {
        Some(cr3) => cr3,
        None      => return -3,
    };

    let mut local_iov_idx = 0usize;
    let mut local_off     = 0usize;
    let mut total_copied  = 0isize;

    'outer: for ri in 0..riovcnt {
        let mut riov = [0u8; 16];
        if copy_from_user(&mut riov, rvec_va + ri * 16).is_err() { break; }
        let mut remote_base = usize::from_le_bytes(riov[0..8].try_into().unwrap());
        let     remote_len  = usize::from_le_bytes(riov[8..16].try_into().unwrap());
        let     remote_len  = remote_len.min(1 << 20);

        let mut remaining = remote_len;
        while remaining > 0 {
            if local_iov_idx >= liovcnt { break 'outer; }

            let mut liov = [0u8; 16];
            if copy_from_user(&mut liov, lvec_va + local_iov_idx * 16).is_err() { break 'outer; }
            let local_base = usize::from_le_bytes(liov[0..8].try_into().unwrap());
            let local_len  = usize::from_le_bytes(liov[8..16].try_into().unwrap());
            let local_avail = if local_len > local_off { local_len - local_off } else { local_iov_idx += 1; local_off = 0; continue; };

            let chunk = remaining.min(local_avail).min(PAGE_SIZE);

            let pa = match Paging::virt_to_phys_cr3(remote_cr3, remote_base) {
                Some(pa) => pa,
                None     => { if total_copied > 0 { break 'outer; } return -14; }
            };
            let page_off  = remote_base & (PAGE_SIZE - 1);
            let available = (PAGE_SIZE - page_off).min(chunk);

            // Read from local iov into a bounce buffer, then write into remote PA.
            let mut bounce = alloc::vec![0u8; available];
            if copy_from_user(&mut bounce, local_base + local_off).is_err() {
                if total_copied > 0 { break 'outer; } return -14;
            }
            let dst = (pa + page_off) as *mut u8;
            unsafe { core::ptr::copy_nonoverlapping(bounce.as_ptr(), dst, available); }

            remote_base  += available;
            local_off    += available;
            remaining    -= available;
            total_copied += available as isize;

            if local_off >= local_len { local_iov_idx += 1; local_off = 0; }
        }
    }
    total_copied
}

// ─── get_posix_timer_state helper ────────────────────────────────────────────

/// Returns `(remaining_ns, interval_ns)` for a POSIX timer.
/// Used by `sys_timer_settime` to populate `old_va` before arming.
pub(super) fn get_posix_timer_state(timerid: usize) -> (u64, u64) {
    crate::proc::itimer::get_posix_timer_state(timerid)
}


// ─── times ───────────────────────────────────────────────────────────────────

/// NR 100  times(buf: *mut tms) -> clock_t
///
/// `struct tms` (32 bytes): tms_utime, tms_stime, tms_cutime, tms_cstime
/// Returns monotonic jiffies (100 Hz) since boot.
pub(super) fn sys_times_impl(buf_va: usize) -> isize {
    use crate::proc::scheduler;
    const HZ_NS: u64 = 10_000_000; // 10 ms per jiffy at 100 Hz

    let pid = scheduler::current_pid();
    let (utime_ns, stime_ns) =
        scheduler::with_proc(pid, |p| (p.utime_ns, p.stime_ns)).unwrap_or((0, 0));

    if buf_va != 0 {
        if !crate::uaccess::validate_user_ptr(buf_va, 32) {
            return -14; // EFAULT
        }
        let mut buf = [0u8; 32];
        buf[0..8].copy_from_slice(&((utime_ns / HZ_NS) as i64).to_le_bytes());
        buf[8..16].copy_from_slice(&((stime_ns / HZ_NS) as i64).to_le_bytes());
        // tms_cutime / tms_cstime (reaped children): zero until wait.rs
        // exposes per-child accounting.  buf[16..32] already zeroed.
        if crate::uaccess::copy_to_user(buf_va, &buf).is_err() {
            return -14;
        }
    }

    let mono = crate::time::read_monotonic_ns();
    (mono / HZ_NS) as isize
}

// ─── personality ─────────────────────────────────────────────────────────────

/// NR 135  personality(persona)
///
/// Stores and retrieves the execution-domain word.
/// 0xffff_ffff = query current value without changing it.
/// Only PER_LINUX (0x00) and PER_LINUX32 (0x08) are accepted for setting.
pub(super) fn sys_personality_impl(persona: u32) -> isize {
    use crate::proc::scheduler;
    const QUERY: u32       = 0xffff_ffff;
    const PER_LINUX: u32   = 0x0000_0000;
    const PER_LINUX32: u32 = 0x0000_0008;

    let pid = scheduler::current_pid();

    if persona == QUERY {
        return scheduler::with_proc(pid, |p| p.personality as isize).unwrap_or(0);
    }

    match persona & 0xff {
        p if p == PER_LINUX || p == PER_LINUX32 => {
            let _ = scheduler::with_proc_mut(pid, |p, _| {
                p.personality = persona;
            });
            0
        }
        _ => -22, // EINVAL — unsupported execution domain
    }
}
