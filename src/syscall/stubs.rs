//! Syscall stub implementations — included into `src/syscall/mod.rs` via
//! `include!("stubs.rs")`.
//!
//! ## Conventions
//!
//! - Every function defined here is `fn` (not `pub fn`): they live in
//!   the same crate scope as `mod.rs` and don't need re-export.
//! - Functions are organised by subsystem in the same order as the
//!   `match nr { … }` arms in `mod.rs`.
//! - Real implementations delegate to the appropriate kernel subsystem;
//!   unimplemented-but-safe syscalls return 0 (no-op success); privileged
//!   or dangerous syscalls that would require root return -1 (EPERM) or
//!   the appropriate errno.
//! - Errno codes used:
//!     -1  EPERM   — operation not permitted
//!     -9  EBADF   — bad file descriptor
//!    -11  EAGAIN  — resource temporarily unavailable
//!    -12  ENOMEM  — out of memory
//!    -14  EFAULT  — bad address
//!    -19  ENODEV  — no such device
//!    -22  EINVAL  — invalid argument
//!    -25  ENOTTY  — inappropriate ioctl
//!    -38  ENOSYS  — function not implemented
//!    -40  ELOOP   — too many levels of symbolic links

#![allow(unused_variables, unused_imports, dead_code)]
extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr};

// ── helpers ───────────────────────────────────────────────────────────────────

#[inline(always)]
fn cpid() -> usize { crate::proc::scheduler::current_pid() as usize }

/// Read a NUL-terminated path string from user space.
#[inline]
fn read_path(va: usize) -> Option<String> {
    crate::proc::exec::read_cstr_safe(va)
}

/// Resolve a (dirfd, path_va) pair to an absolute path.
#[inline]
fn at_path(dirfd: i32, path_va: usize) -> Option<String> {
    crate::syscall::stubs_at_path(dirfd, path_va)
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Process / signals ────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 56  clone(flags, stack, ptid, ctid, tls)
///
/// Delegates to the thread / process clone implementation.  The kernel
/// clone module handles CLONE_THREAD, CLONE_VM, CLONE_FS, CLONE_FILES,
/// and CLONE_SIGHAND.  Flags that are silently ignored (CLONE_SYSVSEM,
/// CLONE_SETTLS, etc.) are documented in proc/clone.rs.
fn sys_clone_impl(flags: usize, stack: usize, ptid: usize, ctid: usize, tls: usize) -> isize {
    crate::proc::clone::sys_clone(flags, stack, ptid, ctid, tls)
}

/// NR 58  vfork()
///
/// Implemented as a regular fork: vfork's guarantee that the child runs
/// before the parent resumes is not enforced in our cooperative scheduler,
/// but the fork itself is correct.
fn sys_vfork_impl() -> isize {
    crate::proc::fork_syscall::sys_fork()
}

/// NR 62  kill(pid, sig)
fn sys_kill_impl(pid: isize, sig: u32) -> isize {
    if sig == 0 {
        // Existence check — always succeed for now.
        return 0;
    }
    crate::proc::signal::send_signal(pid as usize, sig);
    0
}

/// NR 34  pause()
///
/// Suspends the calling process until a signal is delivered.  We block
/// the current task and return -EINTR when it is woken.
fn sys_pause_impl() -> isize {
    crate::proc::scheduler::block_current();
    -4 // EINTR
}

/// NR 112  setsid()
fn sys_setsid_impl() -> isize {
    let pid = cpid();
    crate::proc::scheduler::with_proc_mut(pid, |p| {
        p.session_id = pid as u32;
        p.pgid       = pid as u32;
    });
    pid as isize
}

/// NR 111  getpgrp()
fn sys_getpgrp_impl() -> isize {
    let pid = cpid();
    crate::proc::scheduler::with_proc(pid, |p| p.pgid)
        .unwrap_or(pid as u32) as isize
}

/// NR 147  getsid(pid)
fn sys_getsid_impl(pid: u32) -> isize {
    let target = if pid == 0 { cpid() } else { pid as usize };
    crate::proc::scheduler::with_proc(target, |p| p.session_id)
        .unwrap_or(target as u32) as isize
}

/// NR 247  waitid(idtype, id, infop, options, rusage)
fn sys_waitid_impl(idtype: i32, id: usize, infop: usize, options: u32) -> isize {
    // Re-use waitpid: translate idtype/id to a pid_t.
    //   P_ALL  (0) → wait for any child (pid = -1)
    //   P_PID  (1) → wait for specific pid
    //   P_PGID (2) → wait for process group (pid = -pgid)
    let pid: isize = match idtype {
        0 => -1,
        1 => id as isize,
        2 => -(id as isize),
        _ => return -22,
    };
    // We don't populate siginfo_t; the waiter just wants the child state.
    let ret = crate::proc::wait::sys_waitpid(pid, 0, options);
    if ret < 0 { return ret; }
    // Zero out infop (siginfo_t) if provided.
    if infop != 0 && validate_user_ptr(infop, 128) {
        let zeroes = [0u8; 128];
        let _ = copy_to_user(infop, &zeroes);
    }
    0
}

/// NR 131  sigaltstack(ss, old_ss)
fn sys_sigaltstack_impl(ss: usize, old_ss: usize) -> isize {
    // We don't support alternate signal stacks; return success silently.
    // Populate old_ss with an "SS_DISABLE" record so callers that read it
    // know there is no alternate stack configured.
    if old_ss != 0 && validate_user_ptr(old_ss, 24) {
        // struct stack_t: ss_sp (ptr), ss_flags (i32), ss_size (usize)
        // SS_DISABLE = 4
        let mut buf = [0u8; 24];
        buf[8..12].copy_from_slice(&4i32.to_ne_bytes()); // ss_flags = SS_DISABLE
        let _ = copy_to_user(old_ss, &buf);
    }
    0
}

/// NR 101  ptrace(request, pid, addr, data)
fn sys_ptrace_impl(request: i32, pid: i32, addr: usize, data: usize) -> isize {
    crate::proc::ptrace::sys_ptrace(request, pid, addr, data)
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Credentials / UIDs / GIDs ────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
//
// These are implemented in posix_full.rs.  Only stub-forwarding wrappers that
// weren't already present are listed here.

// ─────────────────────────────────────────────────────────────────────────────
// ── Scheduling ───────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 24  sched_yield()
fn sys_sched_yield_impl() -> isize {
    crate::proc::scheduler::schedule();
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Time / clocks ────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 227  clock_settime(clockid, tp)
///
/// Ignored: we don't support adjusting the wall clock.  Return 0 so musl's
/// time-zone code doesn't fail.
fn sys_clock_settime_impl(clockid: u32, tp: usize) -> isize {
    0
}

/// NR 116  clock_getres(clockid, res)
///
/// Report 1 ms resolution for all clocks (conservative; real HW has ~1 ns).
fn sys_clock_getres_impl(clockid: u32, res: usize) -> isize {
    if res == 0 { return 0; }
    if !validate_user_ptr(res, 16) { return -14; }
    // struct timespec { tv_sec: i64, tv_nsec: i64 }
    let mut ts = [0u8; 16];
    ts[8..16].copy_from_slice(&1_000_000i64.to_ne_bytes()); // 1 ms in nanoseconds
    if copy_to_user(res, &ts).is_err() { return -14; }
    0
}

/// NR 229  clock_nanosleep(clockid, flags, request, remain)
fn sys_clock_nanosleep_impl(clockid: u32, flags: i32, req: usize, rem: usize) -> isize {
    // Delegate to the same nanosleep implementation — clockid differences
    // are minor for our monotonic kernel clock.
    crate::proc::nanosleep::sys_nanosleep(req, rem)
}

/// NR 100  times(buf)
///
/// Fills a `struct tms` with CPU times.  We report everything as 0 ticks
/// since we don't track per-process CPU usage yet.
fn sys_times_impl(buf: usize) -> isize {
    // struct tms { utime, stime, cutime, cstime } — 4 × i64 on x86-64
    if buf != 0 && validate_user_ptr(buf, 32) {
        let zeroes = [0u8; 32];
        let _ = copy_to_user(buf, &zeroes);
    }
    // Return value: clock ticks since arbitrary point.  Use the wall time
    // in nanoseconds divided by tick duration (10 ms) as a monotonic count.
    let ns = crate::proc::nanosleep::current_ns();
    (ns / 10_000_000) as isize
}

/// NR 99   sysinfo(info)
fn sys_sysinfo_impl(info: usize) -> isize {
    if info == 0 || !validate_user_ptr(info, 112) { return -14; }
    // struct sysinfo layout (x86-64 Linux):
    //  0: uptime     i64        8 bytes
    //  8: loads[3]   u64×3     24 bytes
    // 32: totalram   u64        8 bytes
    // 40: freeram    u64        8 bytes
    // 48: sharedram  u64        8 bytes
    // 56: bufferram  u64        8 bytes
    // 64: totalswap  u64        8 bytes
    // 72: freeswap   u64        8 bytes
    // 80: procs      u16        2 bytes
    // 82: pad        u16
    // 84: pad
    // 88: totalhigh  u64        8 bytes
    // 96: freehigh   u64        8 bytes
    //100: mem_unit   u32        4 bytes
    //104: _f[20]     pad
    let mut buf = [0u8; 112];
    let uptime_s = (crate::proc::nanosleep::current_ns() / 1_000_000_000) as i64;
    buf[0..8].copy_from_slice(&uptime_s.to_ne_bytes());

    // Memory stats from the PMM.
    let (total, free) = crate::mm::pmm::total_and_free_bytes();
    buf[32..40].copy_from_slice(&(total as u64).to_ne_bytes()); // totalram
    buf[40..48].copy_from_slice(&(free  as u64).to_ne_bytes()); // freeram
    buf[56..64].copy_from_slice(&(free  as u64).to_ne_bytes()); // bufferram (approx)
    buf[100..104].copy_from_slice(&1u32.to_ne_bytes());          // mem_unit = 1 byte

    let procs = crate::proc::scheduler::proc_count() as u16;
    buf[80..82].copy_from_slice(&procs.to_ne_bytes());

    if copy_to_user(info, &buf).is_err() { return -14; }
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Randomness ───────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 318  getrandom(buf, count, flags)
///
/// Fills `count` bytes from the kernel CSPRNG.  We use the hardware RNG
/// when available (RDRAND on x86-64), falling back to a simple LCG seeded
/// from the TSC for environments where RDRAND is absent.
fn sys_getrandom_impl(buf_va: usize, count: usize, flags: u32) -> isize {
    if count == 0 { return 0; }
    if !validate_user_ptr(buf_va, count) { return -14; }

    let mut remaining = count;
    let mut offset    = 0usize;

    while remaining > 0 {
        let chunk_len = remaining.min(8);
        let rand_bytes = crate::arch::rand::get_random_bytes();
        let slice = &rand_bytes[..chunk_len];
        if copy_to_user(buf_va + offset, slice).is_err() { return -14; }
        offset    += chunk_len;
        remaining -= chunk_len;
    }

    count as isize
}

// ─────────────────────────────────────────────────────────────────────────────
// ── System information ───────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 63   uname(buf)
///
/// Fills a `struct utsname` (6 × 65-byte fields).
fn sys_uname_impl(buf: usize) -> isize {
    if buf == 0 || !validate_user_ptr(buf, 390) { return -14; }

    let fields: [&[u8]; 6] = [
        b"RustOS",             // sysname
        b"rustos-node",        // nodename
        b"6.1.0-rustos",       // release
        b"#1 SMP",             // version
        b"x86_64",             // machine
        b"rustos.local",       // domainname
    ];

    let mut dst = [0u8; 390];
    for (i, field) in fields.iter().enumerate() {
        let off = i * 65;
        let len = field.len().min(64);
        dst[off..off + len].copy_from_slice(&field[..len]);
        // NUL terminator is already 0 (zeroed).
    }
    if copy_to_user(buf, &dst).is_err() { return -14; }
    0
}

/// NR 183  getcpu(cpu, node, tcache)
fn sys_getcpu_impl(cpu_va: usize, node_va: usize, _tcache: usize) -> isize {
    // Report CPU 0, NUMA node 0.
    if cpu_va  != 0 && validate_user_ptr(cpu_va,  4) {
        let _ = copy_to_user(cpu_va,  &0u32.to_ne_bytes());
    }
    if node_va != 0 && validate_user_ptr(node_va, 4) {
        let _ = copy_to_user(node_va, &0u32.to_ne_bytes());
    }
    0
}

/// NR 103  syslog(type, buf, len)
fn sys_syslog_impl(log_type: i32, buf_va: usize, len: usize) -> isize {
    // Type 3 = SYSLOG_ACTION_READ_ALL: return 0 (no messages buffered).
    // Type 10 = SYSLOG_ACTION_SIZE_BUFFER: return kernel log buffer size.
    match log_type {
        10 => 131072, // 128 KiB typical Linux default
        _  => 0,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Process control ──────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 185  prctl(option, arg2, arg3, arg4, arg5)
fn sys_prctl_impl(option: i32, arg2: usize, arg3: usize, arg4: usize, arg5: usize) -> isize {
    match option {
        // PR_SET_NAME (15): rename thread.
        15 => {
            if arg2 != 0 && validate_user_ptr(arg2, 16) {
                let mut name = [0u8; 16];
                let _ = copy_from_user(&mut name, arg2);
                // Store in the current task's comm field.
                let pid = cpid();
                let _ = crate::proc::scheduler::with_proc_mut(pid, |p| {
                    let end = name.iter().position(|&b| b == 0).unwrap_or(16);
                    p.name = alloc::string::String::from_utf8_lossy(&name[..end]).into_owned();
                });
            }
            0
        }
        // PR_GET_NAME (16)
        16 => {
            if arg2 == 0 || !validate_user_ptr(arg2, 16) { return -14; }
            let pid = cpid();
            let name = crate::proc::scheduler::with_proc(pid, |p| p.name.clone())
                .unwrap_or_else(|| alloc::string::String::from("rustos"));
            let mut buf = [0u8; 16];
            let len = name.len().min(15);
            buf[..len].copy_from_slice(&name.as_bytes()[..len]);
            let _ = copy_to_user(arg2, &buf);
            0
        }
        // PR_SET_DUMPABLE (4) / PR_GET_DUMPABLE (3): silently succeed.
        3  => 1,
        4  => 0,
        // PR_SET_PDEATHSIG (1): silently succeed.
        1  => 0,
        // PR_SET_NO_NEW_PRIVS (38): accept, ignore.
        38 => 0,
        // PR_GET_CHILD_SUBREAPER (37) / PR_SET_CHILD_SUBREAPER (36)
        36 | 37 => 0,
        // PR_SET_SECCOMP (22): seccomp is handled by the seccomp module.
        22 => crate::security::seccomp::sys_seccomp(
            1, /* SECCOMP_SET_MODE_STRICT */ 0, 0),
        // PR_CAP_AMBIENT (47): capabilities not enforced.
        47 => 0,
        // PR_SET_MM (35): silently succeed.
        35 => 0,
        // Anything else: not implemented, but don't fault callers.
        _  => 0,
    }
}

/// NR 39   getpid() — already inlined in mod.rs; this is the impl for completeness.
/// NR 110  getppid() — also inlined; not needed here.

// ─────────────────────────────────────────────────────────────────────────────
// ── Filesystem — path operations ─────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 85   creat(path, mode)
fn sys_creat_impl(path_va: usize, mode: u32) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    match crate::fs::vfs_ops::create(&path) {
        Ok(()) => {
            match crate::fs::vfs::open(&path, 0o1 /* O_WRONLY */ | 0o100 /* O_CREAT */ | 0o1000 /* O_TRUNC */) {
                Ok(fd) => fd as isize,
                Err(e) => e,
            }
        }
        Err(e) => e,
    }
}

/// NR 86   link(oldpath, newpath)
fn sys_link_impl(old_va: usize, new_va: usize) -> isize {
    let old = match read_path(old_va) { Some(p) => p, None => return -14 };
    let new = match read_path(new_va) { Some(p) => p, None => return -14 };
    match crate::fs::vfs_ops::link(&old, &new) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 88   symlink(target, linkpath)
fn sys_symlink_impl(target_va: usize, link_va: usize) -> isize {
    let target = match read_path(target_va) { Some(p) => p, None => return -14 };
    let link   = match read_path(link_va)   { Some(p) => p, None => return -14 };
    match crate::fs::vfs_ops::symlink(&target, &link) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 89   readlink(path, buf, bufsiz)
fn sys_readlink_impl(path_va: usize, buf_va: usize, bufsiz: usize) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    if !validate_user_ptr(buf_va, bufsiz) { return -14; }
    // Delegate to procfs for /proc paths, then VFS symlink layer.
    let target = if path.starts_with("/proc") {
        match crate::fs::procfs::procfs_readlink(&path) {
            Some(t) => t,
            None    => return -2, // ENOENT
        }
    } else {
        match crate::fs::vfs_ops::readlink(&path) {
            Ok(t)  => t,
            Err(e) => return e,
        }
    };
    let bytes = target.as_bytes();
    let n = bytes.len().min(bufsiz);
    if copy_to_user(buf_va, &bytes[..n]).is_err() { return -14; }
    n as isize
}

/// NR 267  readlinkat(dirfd, path, buf, bufsiz)
fn sys_readlinkat_impl(dirfd: i32, path_va: usize, buf_va: usize, bufsiz: usize) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    if !validate_user_ptr(buf_va, bufsiz) { return -14; }
    let target = if path.starts_with("/proc") {
        match crate::fs::procfs::procfs_readlink(&path) {
            Some(t) => t,
            None    => return -2,
        }
    } else {
        match crate::fs::vfs_ops::readlink(&path) {
            Ok(t)  => t,
            Err(e) => return e,
        }
    };
    let bytes = target.as_bytes();
    let n = bytes.len().min(bufsiz);
    if copy_to_user(buf_va, &bytes[..n]).is_err() { return -14; }
    n as isize
}

/// NR 84   rmdir(path)
fn sys_rmdir_impl(path_va: usize) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    match crate::fs::vfs_ops::rmdir(&path) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 87   unlink → re-exported via stat_syscalls; kept for completeness.
/// NR 263  unlinkat(dirfd, path, flags)
fn sys_unlinkat_impl(dirfd: i32, path_va: usize, flags: u32) -> isize {
    const AT_REMOVEDIR: u32 = 0x200;
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    if flags & AT_REMOVEDIR != 0 {
        match crate::fs::vfs_ops::rmdir(&path) {
            Ok(()) => 0, Err(e) => e,
        }
    } else {
        match crate::fs::vfs_ops::unlink(&path) {
            Ok(()) => 0, Err(e) => e,
        }
    }
}

/// NR 82   rename → stat_syscalls; NR 264 renameat(olddirfd, old, newdirfd, new)
fn sys_renameat_impl(olddirfd: i32, old_va: usize, newdirfd: i32, new_va: usize) -> isize {
    let old = match at_path(olddirfd, old_va) { Some(p) => p, None => return -14 };
    let new = match at_path(newdirfd, new_va) { Some(p) => p, None => return -14 };
    match crate::fs::vfs_ops::rename(&old, &new) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 83   mkdir → stat_syscalls; NR 258 mkdirat(dirfd, path, mode)
fn sys_mkdirat_impl(dirfd: i32, path_va: usize, mode: u32) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    match crate::fs::vfs_ops::mkdir(&path) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 133  mknod(path, mode, dev)
fn sys_mknod_impl(path_va: usize, mode: u32, dev: u64) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    // Only regular files supported via mknod at this layer.
    match crate::fs::vfs_ops::create(&path) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 259  mknodat(dirfd, path, mode, dev)
fn sys_mknodat_impl(dirfd: i32, path_va: usize, mode: u32, dev: u64) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    match crate::fs::vfs_ops::create(&path) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 2    open → io_syscalls; NR 257 openat(dirfd, path, flags, mode)
fn sys_openat_impl(dirfd: i32, path_va: usize, flags: i32, mode: u32) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    let pid = crate::proc::scheduler::current_pid() as usize;
    crate::fs::process_fd::proc_fd_open(pid, &path, flags as u32, mode)
}

/// NR 81   fchdir(fd)
fn sys_fchdir_impl(fd: usize) -> isize {
    let pid = cpid();
    let bfd = crate::fs::process_fd::proc_fd_backing(pid, fd);
    if bfd < 0 { return -9; }
    let path = match crate::fs::vfs::fd_to_path(bfd as usize) {
        Some(p) => p,
        None    => return -9,
    };
    crate::fs::stat_syscalls::sys_chdir_path(&path)
}

/// NR 91   fchmod(fd, mode)  — permissions not enforced, always succeed
fn sys_fchmod_impl(fd: usize, mode: u32) -> isize { 0 }

/// NR 90   chmod(path, mode) — permissions not enforced
fn sys_chmod_impl(path_va: usize, mode: u32) -> isize { 0 }

/// NR 92   fchown(fd, uid, gid) — ownership not enforced
fn sys_fchown_impl(fd: usize, uid: u32, gid: u32) -> isize { 0 }

/// NR 94   chown(path, uid, gid) — ownership not enforced
fn sys_chown_impl(path_va: usize, uid: u32, gid: u32) -> isize { 0 }

// ─────────────────────────────────────────────────────────────────────────────
// ── Filesystem — file descriptor operations ───────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 17   pread64(fd, buf, count, offset) — via io_syscalls
/// NR 18   pwrite64(fd, buf, count, offset)
fn sys_pwrite64_impl(fd: usize, buf_va: usize, count: usize, offset: i64) -> isize {
    crate::fs::io_syscalls::sys_pwrite64(fd, buf_va, count, offset)
}

/// NR 19   readv(fd, iov, iovcnt)
fn sys_readv_impl(fd: usize, iov_va: usize, iovcnt: usize) -> isize {
    crate::fs::io_syscalls::sys_readv(fd, iov_va, iovcnt)
}

/// NR 76   truncate(path, length)
fn sys_truncate_impl(path_va: usize, length: i64) -> isize {
    if length < 0 { return -22; }
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    match crate::fs::vfs_ops::truncate(&path, length as usize) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 77   ftruncate(fd, length)
fn sys_ftruncate_impl(fd: usize, length: i64) -> isize {
    if length < 0 { return -22; }
    let pid = cpid();
    let bfd = crate::fs::process_fd::proc_fd_backing(pid, fd);
    if bfd < 0 { return -9; }
    match crate::fs::vfs_ops::truncate_fd(bfd as usize, length as usize) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 74   fsync(fd) — flush all dirty data and metadata
fn sys_fsync_impl(fd: usize) -> isize {
    let pid = cpid();
    let bfd = crate::fs::process_fd::proc_fd_backing(pid, fd);
    if bfd < 0 { return -9; }
    crate::fs::vfs::flush_fd(bfd as usize, true /* include_metadata */)
}

/// NR 75   fdatasync(fd) — flush data only (no metadata)
fn sys_fdatasync_impl(fd: usize) -> isize {
    let pid = cpid();
    let bfd = crate::fs::process_fd::proc_fd_backing(pid, fd);
    if bfd < 0 { return -9; }
    crate::fs::vfs::flush_fd(bfd as usize, false)
}

/// NR 162  sync() — flush all dirty blocks
fn sys_sync_impl() -> isize {
    crate::fs::vfs::flush_all_dirty();
    0
}

/// NR 306  syncfs(fd) — flush all dirty blocks for the filesystem containing fd
fn sys_syncfs_impl(fd: usize) -> isize {
    // For simplicity flush everything.
    crate::fs::vfs::flush_all_dirty();
    0
}

/// NR 40   sendfile(out_fd, in_fd, offset, count)
fn sys_sendfile_impl(out_fd: usize, in_fd: usize, offset_va: usize, count: usize) -> isize {
    crate::fs::io_syscalls::sys_sendfile(out_fd, in_fd, offset_va, count)
}

/// NR 307  sendmmsg(sockfd, msgvec, vlen, flags)
fn sys_sendmmsg_impl(sockfd: usize, msgvec: usize, vlen: usize, flags: usize) -> isize {
    crate::net::socket::sys_sendmmsg(sockfd, msgvec, vlen as u32, flags as u32)
}

/// NR 299  recvmmsg(sockfd, msgvec, vlen, flags, timeout)
fn sys_recvmmsg_impl(sockfd: usize, msgvec: usize, vlen: usize, flags: usize, timeout: usize) -> isize {
    crate::net::socket::sys_recvmmsg(sockfd, msgvec, vlen as u32, flags as u32, timeout)
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Filesystem — stat / fs info ──────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 137  statfs(path, buf)
fn sys_statfs_impl(path_va: usize, buf_va: usize) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    if !validate_user_ptr(buf_va, 120) { return -14; }
    match crate::fs::vfs_ops::statfs(&path) {
        Ok(ks) => {
            // Serialize KStatfs into struct statfs (120 bytes, x86-64 layout).
            let mut buf = [0u8; 120];
            buf[0..8].copy_from_slice(&(ks.f_type   as i64).to_ne_bytes());
            buf[8..16].copy_from_slice(&(ks.f_bsize  as i64).to_ne_bytes());
            buf[16..24].copy_from_slice(&(ks.f_blocks as u64).to_ne_bytes());
            buf[24..32].copy_from_slice(&(ks.f_bfree  as u64).to_ne_bytes());
            buf[32..40].copy_from_slice(&(ks.f_bavail as u64).to_ne_bytes());
            buf[40..48].copy_from_slice(&(ks.f_files  as u64).to_ne_bytes());
            buf[48..56].copy_from_slice(&(ks.f_ffree  as u64).to_ne_bytes());
            // f_fsid: two u32s — leave as 0
            buf[64..72].copy_from_slice(&(ks.f_namelen as i64).to_ne_bytes());
            buf[72..80].copy_from_slice(&(ks.f_frsize  as i64).to_ne_bytes());
            if copy_to_user(buf_va, &buf).is_err() { return -14; }
            0
        }
        Err(e) => e,
    }
}

/// NR 138  fstatfs(fd, buf)
fn sys_fstatfs_impl(fd: usize, buf_va: usize) -> isize {
    let pid = cpid();
    let bfd = crate::fs::process_fd::proc_fd_backing(pid, fd);
    if bfd < 0 { return -9; }
    let path = match crate::fs::vfs::fd_to_path(bfd as usize) {
        Some(p) => p,
        None    => String::from("/"),
    };
    sys_statfs_impl(0 /* unused */, buf_va); // we need the path, not the VA
    // Re-do with the resolved path.
    if !validate_user_ptr(buf_va, 120) { return -14; }
    match crate::fs::vfs_ops::statfs(&path) {
        Ok(ks) => {
            let mut buf = [0u8; 120];
            buf[0..8].copy_from_slice(&(ks.f_type   as i64).to_ne_bytes());
            buf[8..16].copy_from_slice(&(ks.f_bsize  as i64).to_ne_bytes());
            buf[16..24].copy_from_slice(&(ks.f_blocks as u64).to_ne_bytes());
            buf[24..32].copy_from_slice(&(ks.f_bfree  as u64).to_ne_bytes());
            buf[32..40].copy_from_slice(&(ks.f_bavail as u64).to_ne_bytes());
            buf[40..48].copy_from_slice(&(ks.f_files  as u64).to_ne_bytes());
            buf[48..56].copy_from_slice(&(ks.f_ffree  as u64).to_ne_bytes());
            buf[64..72].copy_from_slice(&(ks.f_namelen as i64).to_ne_bytes());
            buf[72..80].copy_from_slice(&(ks.f_frsize  as i64).to_ne_bytes());
            if copy_to_user(buf_va, &buf).is_err() { return -14; }
            0
        }
        Err(e) => e,
    }
}

/// NR 262  newfstatat(dirfd, path, statbuf, flags)
fn sys_newfstatat_impl(dirfd: i32, path_va: usize, statbuf: usize, flags: u32) -> isize {
    let path = match at_path(dirfd, path_va) { Some(p) => p, None => return -14 };
    const AT_EMPTY_PATH: u32  = 0x1000;
    const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

    if flags & AT_EMPTY_PATH != 0 && path.is_empty() {
        // fstat on the dirfd itself.
        return crate::fs::stat_syscalls::sys_fstat(dirfd as usize, statbuf);
    }

    let stat_path = alloc::format!(
        "{}{}",
        if path.starts_with('/') { "" } else { "" },
        path
    );

    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        crate::fs::stat_syscalls::sys_lstat_path(&stat_path, statbuf)
    } else {
        crate::fs::stat_syscalls::sys_stat_path(&stat_path, statbuf)
    }
}

/// NR 136  ustat(dev, ubuf) — deprecated, return ENOSYS
fn sys_ustat_impl(dev: u64, ubuf: usize) -> isize {
    -38 // ENOSYS
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Filesystem — timestamps ───────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 132  utime(filename, times)
fn sys_utime_impl(path_va: usize, times_va: usize) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    let (atime_ns, mtime_ns) = if times_va == 0 {
        let now = crate::proc::nanosleep::current_ns();
        (now, now)
    } else {
        if !validate_user_ptr(times_va, 16) { return -14; }
        let mut buf = [0u8; 16];
        if copy_from_user(&mut buf, times_va).is_err() { return -14; }
        let atime = i64::from_ne_bytes(buf[0..8].try_into().unwrap_or([0;8]));
        let mtime = i64::from_ne_bytes(buf[8..16].try_into().unwrap_or([0;8]));
        (atime as u64 * 1_000_000_000, mtime as u64 * 1_000_000_000)
    };
    match crate::fs::vfs_ops::utimens(&path, atime_ns, mtime_ns) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 235  utimes(path, times[2])  — struct timeval (microsecond resolution)
fn sys_utimes_impl(path_va: usize, times_va: usize) -> isize {
    let path = match read_path(path_va) { Some(p) => p, None => return -14 };
    let (atime_ns, mtime_ns) = if times_va == 0 {
        let now = crate::proc::nanosleep::current_ns();
        (now, now)
    } else {
        if !validate_user_ptr(times_va, 32) { return -14; }
        let mut buf = [0u8; 32];
        if copy_from_user(&mut buf, times_va).is_err() { return -14; }
        // struct timeval: { tv_sec: i64, tv_usec: i64 } × 2
        let asec  = i64::from_ne_bytes(buf[0..8].try_into().unwrap_or([0;8]));
        let ausec = i64::from_ne_bytes(buf[8..16].try_into().unwrap_or([0;8]));
        let msec  = i64::from_ne_bytes(buf[16..24].try_into().unwrap_or([0;8]));
        let musec = i64::from_ne_bytes(buf[24..32].try_into().unwrap_or([0;8]));
        (
            (asec as u64).saturating_mul(1_000_000_000).saturating_add(ausec as u64 * 1000),
            (msec as u64).saturating_mul(1_000_000_000).saturating_add(musec as u64 * 1000),
        )
    };
    match crate::fs::vfs_ops::utimens(&path, atime_ns, mtime_ns) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// NR 280  utimensat(dirfd, path, times[2], flags)  — struct timespec (nanosecond)
fn sys_utimensat_impl(dirfd: i32, path_va: usize, times_va: usize, flags: i32) -> isize {
    const UTIME_NOW:  i64 = 0x3FFF_FFFF;
    const UTIME_OMIT: i64 = 0x3FFF_FFFE;

    let path = if path_va == 0 {
        // AT_EMPTY_PATH: operate on the dirfd itself.
        match crate::fs::vfs::fd_to_path(dirfd as usize) {
            Some(p) => p,
            None    => return -9,
        }
    } else {
        match at_path(dirfd, path_va) { Some(p) => p, None => return -14 }
    };

    let now = crate::proc::nanosleep::current_ns();

    let (atime_ns, mtime_ns) = if times_va == 0 {
        (now, now)
    } else {
        if !validate_user_ptr(times_va, 32) { return -14; }
        let mut buf = [0u8; 32];
        if copy_from_user(&mut buf, times_va).is_err() { return -14; }
        let a_sec  = i64::from_ne_bytes(buf[0..8].try_into().unwrap_or([0;8]));
        let a_nsec = i64::from_ne_bytes(buf[8..16].try_into().unwrap_or([0;8]));
        let m_sec  = i64::from_ne_bytes(buf[16..24].try_into().unwrap_or([0;8]));
        let m_nsec = i64::from_ne_bytes(buf[24..32].try_into().unwrap_or([0;8]));
        let a = match a_nsec {
            UTIME_NOW  => now,
            UTIME_OMIT => {
                // Don't change atime: read current value.
                crate::fs::vfs_ops::get_times(&path).map(|(a, _)| a).unwrap_or(now)
            }
            _ => (a_sec as u64).saturating_mul(1_000_000_000).saturating_add(a_nsec as u64),
        };
        let m = match m_nsec {
            UTIME_NOW  => now,
            UTIME_OMIT => {
                crate::fs::vfs_ops::get_times(&path).map(|(_, m)| m).unwrap_or(now)
            }
            _ => (m_sec as u64).saturating_mul(1_000_000_000).saturating_add(m_nsec as u64),
        };
        (a, m)
    };

    match crate::fs::vfs_ops::utimens(&path, atime_ns, mtime_ns) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Filesystem — mount / swap / disk ─────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 95   umask(mask)
fn sys_umask_impl(mask: u32) -> isize {
    let pid = cpid();
    let old = crate::proc::scheduler::with_proc(pid, |p| p.umask)
        .unwrap_or(0o022);
    crate::proc::scheduler::with_proc_mut(pid, |p| p.umask = mask & 0o777);
    old as isize
}

// ─────────────────────────────────────────────────────────────────────────────
// ── Memory ───────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 25   mremap(old_addr, old_size, new_size, flags, new_addr)
fn sys_mremap_impl(old_addr: usize, old_size: usize, new_size: usize,
                   flags: usize, new_addr: usize) -> isize {
    crate::mm::mmap::sys_mremap(old_addr, old_size, new_size, flags as u32, new_addr)
}

/// NR 28   madvise(addr, length, advice)
fn sys_madvise_impl(addr: usize, length: usize, advice: i32) -> isize {
    // Most hints are performance-only and can be silently ignored.
    // MADV_DONTNEED (8): we honour this by zeroing the range (CoW semantics).
    if advice == 8 {
        crate::mm::mmap::sys_madvise_dontneed(addr, length)
    } else {
        0
    }
}

/// NR 149  mlock(addr, len)
fn sys_mlock_impl(addr: usize, len: usize) -> isize {
    // We don't support page locking, but pretend we do.
    0
}

/// NR 150  munlock(addr, len)
fn sys_munlock_impl(addr: usize, len: usize) -> isize {
    0
}

/// NR 216  remap_file_pages — deprecated; return ENOSYS
fn sys_remap_file_pages_impl() -> isize {
    -38 // ENOSYS
}

/// NR 319  memfd_create(name, flags)
fn sys_memfd_create_impl(name_va: usize, flags: u32) -> isize {
    crate::fs::memfd::sys_memfd_create(name_va, flags)
}

/// NR 317  userfaultfd(flags)
fn sys_userfaultfd_impl(flags: usize) -> isize {
    // userfaultfd is not implemented; return ENOSYS so user space can
    // fall back gracefully.
    -38
}

// ─────────────────────────────────────────────────────────────────────────────
// ── BPF / kexec / privileged ops ─────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

/// NR 321  bpf(cmd, attr, size)
fn sys_bpf_impl(cmd: usize, attr: usize, size: usize) -> isize {
    // BPF is not implemented.  Return EPERM so programs that probe for
    // BPF support know it's unavailable rather than just not a valid
    // syscall.
    -1 // EPERM
}

/// NR 320  kexec_file_load — privileged, not supported
fn sys_kexec_file_load_impl(kernel_fd: usize, initrd_fd: usize,
                             cmdline_len: usize, cmdline: usize,
                             flags: usize) -> isize {
    -1 // EPERM
}
