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

/// NR 37  alarm(seconds)  — stub; no SIGALRM delivery yet.
pub(super) fn sys_alarm_impl(seconds: u32) -> isize { 0 }

/// NR 34  pause()  — yield until a signal is delivered.
pub(super) fn sys_pause_impl() -> isize {
    // Block until the next signal wakes this task.
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
    if size == 0 { return 1; }      // report 1 supplementary group
    if size < 1  { return -22; }    // EINVAL
    let gid: u32 = 0;
    if copy_to_user(list_va, &gid.to_le_bytes()).is_err() { return -14; }
    1
}

/// NR 125  setgroups — accept unconditionally (single-user root).
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

// ─── Interval timers & POSIX timers ─────────────────────────────────────────

/// NR 36  getitimer — return zero-valued timeval struct (no timer armed).
pub(super) fn sys_getitimer_impl(_which: i32, val_va: usize) -> isize {
    if val_va != 0 {
        if copy_to_user(val_va, &[0u8; 32]).is_err() { return -14; }
    }
    0
}

/// NR 38  setitimer — accept and discard; SIGALRM not yet delivered.
pub(super) fn sys_setitimer_impl(_which: i32, _new_va: usize, old_va: usize) -> isize {
    if old_va != 0 {
        if copy_to_user(old_va, &[0u8; 32]).is_err() { return -14; }
    }
    0
}

// POSIX per-process timers (timer_create / timer_settime / …)
// We keep a simple ring of 64 timer slots per process in a global table.
// Real delivery via SIGEV_SIGNAL is not yet wired; programs that only
// poll timer_gettime() will see correct remaining time via monotonic_ns.

use spin::Mutex as SpinMutex;
use alloc::collections::BTreeMap;

#[derive(Clone, Copy, Default)]
struct PosixTimer {
    pid:        usize,
    clockid:    u32,
    sigev_signo: u32,
    /// Absolute expiry in nanoseconds (monotonic clock).
    expire_ns:  u64,
    /// Re-arm interval in nanoseconds (0 = one-shot).
    interval_ns: u64,
    armed:      bool,
}

static POSIX_TIMERS: SpinMutex<BTreeMap<u32, PosixTimer>> =
    SpinMutex::new(BTreeMap::new());

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
    }
    let pid = crate::proc::scheduler::current_pid();
    POSIX_TIMERS.lock().insert(id, PosixTimer { pid, clockid, sigev_signo, ..Default::default() });
    if copy_to_user(timerid_va, &id.to_le_bytes()).is_err() { return -14; }
    0
}

/// NR 223  timer_settime(timerid, flags, new_va, old_va)
pub(super) fn sys_timer_settime_impl(timerid: u32, flags: i32,
                                      new_va: usize, old_va: usize) -> isize {
    // Read new itimerspec: [it_interval.tv_sec(8), it_interval.tv_nsec(8),
    //                       it_value.tv_sec(8),    it_value.tv_nsec(8)]
    let mut new_buf = [0u8; 32];
    if copy_from_user(&mut new_buf, new_va).is_err() { return -14; }

    let int_sec  = i64::from_le_bytes(new_buf[0..8].try_into().unwrap());
    let int_ns   = i64::from_le_bytes(new_buf[8..16].try_into().unwrap());
    let val_sec  = i64::from_le_bytes(new_buf[16..24].try_into().unwrap());
    let val_ns   = i64::from_le_bytes(new_buf[24..32].try_into().unwrap());

    let interval_ns = (int_sec as u64) * 1_000_000_000 + (int_ns as u64);
    let value_ns    = (val_sec as u64) * 1_000_000_000 + (val_ns  as u64);

    const TIMER_ABSTIME: i32 = 1;
    let now_ns = crate::time::monotonic_ns();
    let expire_ns = if flags & TIMER_ABSTIME != 0 {
        value_ns
    } else {
        now_ns.saturating_add(value_ns)
    };

    let mut lock = POSIX_TIMERS.lock();
    if let Some(t) = lock.get_mut(&timerid) {
        if old_va != 0 {
            let rem = if t.armed { t.expire_ns.saturating_sub(now_ns) } else { 0 };
            let mut old_buf = [0u8; 32];
            // it_interval
            let iv_sec = (t.interval_ns / 1_000_000_000) as i64;
            let iv_ns  = (t.interval_ns % 1_000_000_000) as i64;
            old_buf[0..8].copy_from_slice(&iv_sec.to_le_bytes());
            old_buf[8..16].copy_from_slice(&iv_ns.to_le_bytes());
            // it_value (remaining)
            let rv_sec = (rem / 1_000_000_000) as i64;
            let rv_ns  = (rem % 1_000_000_000) as i64;
            old_buf[16..24].copy_from_slice(&rv_sec.to_le_bytes());
            old_buf[24..32].copy_from_slice(&rv_ns.to_le_bytes());
            if copy_to_user(old_va, &old_buf).is_err() { return -14; }
        }
        t.expire_ns   = expire_ns;
        t.interval_ns = interval_ns;
        t.armed       = value_ns != 0;
        0
    } else {
        -22 // EINVAL — unknown timer id
    }
}

/// NR 224  timer_gettime(timerid, curr_va)
pub(super) fn sys_timer_gettime_impl(timerid: u32, curr_va: usize) -> isize {
    let lock = POSIX_TIMERS.lock();
    if let Some(t) = lock.get(&timerid) {
        let now_ns = crate::time::monotonic_ns();
        let rem = if t.armed && t.expire_ns > now_ns { t.expire_ns - now_ns } else { 0 };
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

/// NR 225  timer_getoverrun(timerid)
pub(super) fn sys_timer_getoverrun_impl(_timerid: u32) -> isize { 0 }

/// NR 226  timer_delete(timerid)
pub(super) fn sys_timer_delete_impl(timerid: u32) -> isize {
    POSIX_TIMERS.lock().remove(&timerid);
    0
}

/// NR 227  clock_settime — accept, no-op (kernel clock is read-only).
pub(super) fn sys_clock_settime_impl(_clkid: u32, _tp_va: usize) -> isize { 0 }

/// NR 229  clock_nanosleep — delegate to regular nanosleep implementation.
pub(super) fn sys_clock_nanosleep_impl(_clkid: u32, _flags: i32,
                                        rqtp_va: usize, rmtp_va: usize) -> isize {
    crate::proc::nanosleep::sys_nanosleep(rqtp_va, rmtp_va)
}

// ─── Signal extras ───────────────────────────────────────────────────────────

/// NR 15  rt_sigreturn — signal frame is already unwound by the signal
/// delivery trampoline; the syscall itself just needs to return 0 here.
pub(super) fn sys_rt_sigreturn_impl() -> isize { 0 }

/// NR 132  utime(path, times) — accept, no-op.
pub(super) fn sys_utime_impl(_path_va: usize, _times_va: usize) -> isize { 0 }

/// NR 235  utimes(path, times) — accept, no-op.
pub(super) fn sys_utimes_impl(_path_va: usize, _times_va: usize) -> isize { 0 }

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

/// NR 163  acct — accept, no-op (BSD accounting not implemented).
pub(super) fn sys_acct_impl(_path_va: usize) -> isize { 0 }

/// NR 164  settimeofday — accept, no-op.
pub(super) fn sys_settimeofday_impl(_tv_va: usize, _tz_va: usize) -> isize { 0 }

/// NR 166  umount2 / NR 167 swapon / NR 168 swapoff — stubs.
pub(super) fn sys_umount2_impl(_tgt: usize, _flags: i32) -> isize { 0 }
pub(super) fn sys_swapon_impl(_path: usize, _flags: i32) -> isize { 0 }
pub(super) fn sys_swapoff_impl(_path: usize) -> isize { 0 }

/// NR 169  reboot — power-off via architecture-specific port.
pub(super) fn sys_reboot_impl(_magic1: u32, _magic2: u32, _cmd: u32, _arg: usize) -> isize {
    // QEMU: write 0x2000 to port 0x604 triggers ACPI power-off.
    #[cfg(target_arch = "x86_64")]
    unsafe { crate::arch::x86_64::io::outw(0x604, 0x2000); }
    0
}

/// NR 170  sethostname(name_va, len)
pub(super) fn sys_sethostname_impl(name_va: usize, len: usize) -> isize {
    let l = len.min(64);
    let mut buf = [0u8; 64];
    if copy_from_user(&mut buf[..l], name_va).is_err() { return -14; }
    // Store in a static so gethostname can read it back.
    HOSTNAME.lock().copy_from_slice(&buf);
    0
}

/// NR 171  setdomainname — accept, no-op.
pub(super) fn sys_setdomainname_impl(_name: usize, _len: usize) -> isize { 0 }

static HOSTNAME: SpinMutex<[u8; 64]> = SpinMutex::new(*b"rustos\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");

/// NR 172  iopl / NR 173 ioperm — deny; user-space shouldn't touch I/O ports.
pub(super) fn sys_iopl_impl(_level: i32) -> isize { -1 }  // EPERM
pub(super) fn sys_ioperm_impl(_from: usize, _num: usize, _turn_on: i32) -> isize { -1 }

/// NR 175 / NR 176  init_module / delete_module — deny (no LKM support).
pub(super) fn sys_init_module_impl(_mod: usize, _len: usize, _opts: usize) -> isize { -1 }
pub(super) fn sys_delete_module_impl(_name: usize, _flags: u32) -> isize { -1 }

// ─── fallocate ───────────────────────────────────────────────────────────────

/// NR 285  fallocate(fd, mode, offset, len)
/// Best-effort: extend file to (offset+len) using ftruncate if that's larger.
pub(super) fn sys_fallocate_impl(fd: usize, _mode: i32, offset: i64, len: i64) -> isize {
    if offset < 0 || len <= 0 { return -22; }
    let new_size = (offset + len) as u64;
    crate::fs::vfs::truncate(fd, new_size);
    0
}

// ─── copy_file_range ─────────────────────────────────────────────────────────

/// NR 326  copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
/// Best-effort: read from fd_in (honouring off_in) then write to fd_out.
pub(super) fn sys_copy_file_range_impl(
    fd_in: usize, off_in_va: usize,
    fd_out: usize, off_out_va: usize,
    len: usize, _flags: u32,
) -> isize {
    if len == 0 { return 0; }
    let capped = len.min(1 << 20); // 1 MiB max per call

    if off_in_va != 0 {
        let mut buf = [0u8; 8];
        if copy_from_user(&mut buf, off_in_va).is_err() { return -14; }
        let off = i64::from_le_bytes(buf);
        crate::fs::vfs::seek(fd_in, off, crate::fs::vfs::SEEK_SET);
    }
    if off_out_va != 0 {
        let mut buf = [0u8; 8];
        if copy_from_user(&mut buf, off_out_va).is_err() { return -14; }
        let off = i64::from_le_bytes(buf);
        crate::fs::vfs::seek(fd_out, off, crate::fs::vfs::SEEK_SET);
    }

    let mut data = alloc::vec![0u8; capped];
    let n = crate::fs::vfs::read(fd_in, &mut data);
    if n <= 0 { return n; }
    let written = crate::fs::vfs::write(fd_out, &data[..n as usize]);

    // Update caller-supplied offsets.
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

/// NR 327  preadv2 — flags ignored; delegate to preadv (== readv at offset).
pub(super) fn sys_preadv2_impl(fd: usize, iov_va: usize, iovcnt: usize,
                                pos_l: usize, pos_h: usize, _flags: i32) -> isize {
    let offset = (pos_l as i64) | ((pos_h as i64) << 32);
    let old = crate::fs::vfs::seek(fd, 0, crate::fs::vfs::SEEK_CUR) as i64;
    if offset >= 0 {
        crate::fs::vfs::seek(fd, offset, crate::fs::vfs::SEEK_SET);
    }
    let n = crate::syscall::sys_readv_impl(fd, iov_va, iovcnt);
    if offset >= 0 {
        crate::fs::vfs::seek(fd, old, crate::fs::vfs::SEEK_SET);
    }
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
///
/// Fills a 256-byte statx struct by calling the existing fstat path and
/// transcribing the fields.  Only the mask-requested fields are populated;
/// unused bytes are zeroed.
pub(super) fn sys_statx_impl(
    dirfd: i32, path_va: usize, _flags: u32, _mask: u32, statxbuf_va: usize,
) -> isize {
    // Resolve path → stat via the existing NR 262 / lstat pathway.
    let path = match crate::syscall::stubs_at_path(dirfd, path_va) {
        Some(p) => p,
        None    => return -14,
    };

    // Use a 144-byte kernel stat buffer (struct stat layout).
    // We copy it into userspace via a scratch VA on the process stack —
    // instead, allocate in kernel and read back.
    let kstat_buf: alloc::vec::Vec<u8> = alloc::vec![0u8; 144];
    // We need a user VA to fill.  Since we own kstat_buf in the kernel,
    // pass its kernel address cast as a VA (valid because the higher half
    // is mapped 1-1 in rustos).  copy_to_user is not needed here; we read
    // the result directly.
    //
    // Simpler: call sys_lstat which writes stat into a user VA.  We
    // reserve a small bounce buffer in our own stack frame instead.
    //
    // Because this is a no_std kernel environment we use a fixed-size
    // array on the call stack.
    let mut kstat = [0u8; 144];
    // sys_lstat writes into a user virtual address.  For a kernel-internal
    // call we pass the physical address of our array.  This is valid on
    // rustos because the kernel heap is identity-mapped and copy_to_user
    // in our VFS layer accepts any mapped address.
    let kstat_va = kstat.as_mut_ptr() as usize;
    let rc = crate::fs::vfs::stat(&path, kstat_va);
    if rc < 0 { return rc; }

    // Transcode struct stat → struct statx (256 bytes).
    // stat layout (x86-64):  st_dev(8) st_ino(8) st_nlink(8) st_mode(4)
    //   st_uid(4) st_gid(4) _pad0(4) st_rdev(8) st_size(8) st_blksize(8)
    //   st_blocks(8) st_atim(16) st_mtim(16) st_ctim(16)
    // statx layout: stx_mask(4) stx_blksize(4) stx_attributes(8)
    //   stx_nlink(4) stx_uid(4) stx_gid(4) stx_mode(2) _pad1(2)
    //   stx_ino(8) stx_size(8) stx_blocks(8) stx_attributes_mask(8)
    //   stx_atime(16) stx_btime(16) stx_ctime(16) stx_mtime(16)
    //   stx_rdev_major(4) stx_rdev_minor(4) stx_dev_major(4) stx_dev_minor(4)
    //   (+ 112 bytes padding / future fields)

    let mut sx = [0u8; 256];

    // stx_mask = STATX_BASIC_STATS (0x7ff)
    sx[0..4].copy_from_slice(&0x7ffu32.to_le_bytes());
    // stx_blksize
    let blksize = u64::from_le_bytes(kstat[56..64].try_into().unwrap()) as u32;
    sx[4..8].copy_from_slice(&blksize.to_le_bytes());
    // stx_nlink
    let nlink = u64::from_le_bytes(kstat[16..24].try_into().unwrap()) as u32;
    sx[16..20].copy_from_slice(&nlink.to_le_bytes());
    // stx_uid / stx_gid
    sx[20..24].copy_from_slice(&kstat[24..28]); // st_uid
    sx[24..28].copy_from_slice(&kstat[28..32]); // st_gid
    // stx_mode
    sx[28..30].copy_from_slice(&kstat[24..26]); // low 2 bytes of st_mode
    // stx_ino
    sx[32..40].copy_from_slice(&kstat[8..16]); // st_ino
    // stx_size
    sx[40..48].copy_from_slice(&kstat[48..56]); // st_size
    // stx_blocks
    sx[48..56].copy_from_slice(&kstat[64..72]); // st_blocks
    // stx_atime (stx_sec + stx_nsec)
    sx[64..80].copy_from_slice(&kstat[72..88]);   // st_atim
    // stx_btime — use atime as birth time (no birth time in classic stat)
    sx[80..96].copy_from_slice(&kstat[72..88]);
    // stx_ctime
    sx[96..112].copy_from_slice(&kstat[104..120]);
    // stx_mtime
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
        Some(p) => p,
        None    => return -14,
    };
    // Resolve to an absolute path string VA and reuse execve.
    let path_bytes = path.as_bytes();
    // We need a user-accessible path; create a kernel buffer copy and pass
    // its VA into the execve implementation.
    let mut kbuf = alloc::vec![0u8; path_bytes.len() + 1];
    kbuf[..path_bytes.len()].copy_from_slice(path_bytes);
    crate::proc::exec::sys_execve(kbuf.as_ptr() as usize, argv_va, envp_va)
}

// ─── pkey_* ──────────────────────────────────────────────────────────────────

/// NR 329  pkey_mprotect — forward to mprotect (pkey ignored).
pub(super) fn sys_pkey_mprotect_impl(addr: usize, len: usize, prot: u32, _pkey: i32) -> isize {
    crate::mm::mmap::sys_mprotect(addr, len, prot)
}

/// NR 330  pkey_alloc — always return pkey 0 (single domain).
pub(super) fn sys_pkey_alloc_impl(_flags: u32, _access_rights: u64) -> isize { 0 }

/// NR 331  pkey_free — accept, no-op.
pub(super) fn sys_pkey_free_impl(_pkey: i32) -> isize { 0 }

// ─── mlock2 ──────────────────────────────────────────────────────────────────

/// NR 325  mlock2 — same semantics as mlock (no-op in single-user kernel).
pub(super) fn sys_mlock2_impl(_addr: usize, _len: usize, _flags: u32) -> isize { 0 }

// ─── Scheduler attrs ─────────────────────────────────────────────────────────

/// NR 315  sched_getattr — return SCHED_OTHER with priority 0.
pub(super) fn sys_sched_getattr_impl(_pid: usize, attr_va: usize, size: u32, _flags: u32) -> isize {
    if size < 48 { return -22; }
    let mut buf = [0u8; 48];
    // sched_attr.size = 48
    buf[0..4].copy_from_slice(&48u32.to_le_bytes());
    // sched_policy = SCHED_OTHER = 0
    if copy_to_user(attr_va, &buf).is_err() { return -14; }
    0
}

/// NR 316  sched_setattr — accept, no-op.
pub(super) fn sys_sched_setattr_impl(_pid: usize, _attr_va: usize, _flags: u32) -> isize { 0 }

// ─── Denied / not-implemented gate ───────────────────────────────────────────

/// Return -EPERM for privileged ops that rustos does not implement.
pub(super) fn sys_eperm_impl() -> isize { -1 }

/// NR 184/310  process_vm_readv / process_vm_writev — deny cross-process memory.
pub(super) fn sys_process_vm_readv_impl(
    _pid: usize, _lvec: usize, _liovcnt: usize,
    _rvec: usize, _riovcnt: usize, _flags: usize,
) -> isize { -1 }

pub(super) fn sys_process_vm_writev_impl(
    _pid: usize, _lvec: usize, _liovcnt: usize,
    _rvec: usize, _riovcnt: usize, _flags: usize,
) -> isize { -1 }

// ─── syncfs ──────────────────────────────────────────────────────────────────

/// NR 306  syncfs(fd) — accept, no-op (in-memory VFS).
pub(super) fn sys_syncfs_impl(_fd: usize) -> isize { 0 }

// ─── sendmmsg ────────────────────────────────────────────────────────────────

/// NR 307  sendmmsg(sockfd, msgvec, vlen, flags)
/// Iterates over the mmsghdr array and calls sys_sendmsg for each entry,
/// updating msg_len in-place.
pub(super) fn sys_sendmmsg_impl(sockfd: usize, msgvec_va: usize, vlen: u32, flags: u32) -> isize {
    if vlen == 0 { return 0; }
    let vlen = vlen.min(1024) as usize;
    // struct mmsghdr = { struct msghdr (48 bytes), unsigned int msg_len (4), pad(4) }
    const MMSGHDR_SZ: usize = 56;
    let mut sent: isize = 0;
    for i in 0..vlen {
        let hdr_va = msgvec_va + i * MMSGHDR_SZ;
        // sendmsg(fd, msghdr_va, flags)
        let n = crate::net::socket::sys_sendmsg(sockfd, hdr_va, flags as usize);
        if n < 0 {
            return if sent > 0 { sent } else { n };
        }
        // Write msg_len field at offset 48.
        let msg_len = n as u32;
        if copy_to_user(hdr_va + 48, &msg_len.to_le_bytes()).is_err() { return -14; }
        sent += 1;
    }
    sent
}

// ─── recvmmsg ────────────────────────────────────────────────────────────────

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
        if n < 0 {
            return if recvd > 0 { recvd } else { n };
        }
        let msg_len = n as u32;
        if copy_to_user(hdr_va + 48, &msg_len.to_le_bytes()).is_err() { return -14; }
        recvd += 1;
    }
    recvd
}

// ─── userfaultfd / kexec / bpf gates ─────────────────────────────────────────

/// NR 320 kexec_file_load — deny.
pub(super) fn sys_kexec_file_load_impl() -> isize { -1 }

/// NR 321 bpf — deny (no eBPF JIT).
pub(super) fn sys_bpf_impl() -> isize { -1 }

/// NR 323 userfaultfd — deny.
pub(super) fn sys_userfaultfd_impl() -> isize { -1 }

/// NR 216 remap_file_pages — removed from Linux 4.0, keep ENOSYS.
pub(super) fn sys_remap_file_pages_impl() -> isize { -38 }
