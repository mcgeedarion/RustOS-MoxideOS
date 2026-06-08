// POSIX-full syscall implementations — syscalls with real logic that are
// not large enough to warrant their own module. (Included by
// src/syscall/mod.rs.)

#[inline]
fn copy_bytes_to_user(dst: usize, bytes: &[u8]) -> bool {
    crate::uaccess::copy_to_user(dst, bytes.as_ptr(), bytes.len()).is_ok()
}

fn read_user_str(addr: usize, max_len: usize) -> Result<String, ()> {
    let mut buf = alloc::vec![0u8; max_len.saturating_add(1)];
    let len = crate::uaccess::strncpy_from_user(&mut buf, addr).map_err(|_| ())?;
    core::str::from_utf8(&buf[..len])
        .map(alloc::string::String::from)
        .map_err(|_| ())
}
pub(super) fn sys_getrlimit_impl(resource: u32, rlim_va: usize) -> isize {
    const RLIM_INFINITY: u64 = u64::MAX;
    // Provide sane defaults that won't break typical userspace.
    let (cur, max): (u64, u64) = match resource {
        0  /* RLIMIT_CPU     */ => (RLIM_INFINITY, RLIM_INFINITY),
        1  /* RLIMIT_FSIZE   */ => (RLIM_INFINITY, RLIM_INFINITY),
        2  /* RLIMIT_DATA    */ => (RLIM_INFINITY, RLIM_INFINITY),
        3  /* RLIMIT_STACK   */ => (8 * 1024 * 1024, RLIM_INFINITY), // 8 MiB default
        4  /* RLIMIT_CORE    */ => (0, RLIM_INFINITY),
        5  /* RLIMIT_RSS     */ => (RLIM_INFINITY, RLIM_INFINITY),
        6  /* RLIMIT_NPROC   */ => (4096, 4096),
        7  /* RLIMIT_NOFILE  */ => (1024, 4096),
        8  /* RLIMIT_MEMLOCK */ => (RLIM_INFINITY, RLIM_INFINITY),
        9  /* RLIMIT_AS      */ => (RLIM_INFINITY, RLIM_INFINITY),
        10 /* RLIMIT_LOCKS   */ => (RLIM_INFINITY, RLIM_INFINITY),
        11 /* RLIMIT_SIGPEND */ => (0, 0),
        12 /* RLIMIT_MSGQ    */ => (819200, 819200),
        13 /* RLIMIT_NICE    */ => (0, 0),
        14 /* RLIMIT_RTPRIO  */ => (0, 0),
        15 /* RLIMIT_RTTIME  */ => (RLIM_INFINITY, RLIM_INFINITY),
        _  => return -22,
    };
    // struct rlimit { rlim_t rlim_cur; rlim_t rlim_max; }  (two u64 on x86-64)
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&cur.to_le_bytes());
    buf[8..16].copy_from_slice(&max.to_le_bytes());
    if !copy_bytes_to_user(rlim_va, &buf) {
        return -14;
    }
    0
}

/// NR 160  setrlimit(resource, rlim_va) — accept silently; we don't enforce.
pub(super) fn sys_setrlimit_impl(_resource: u32, _rlim_va: usize) -> isize {
    0
}

/// NR 302  prlimit64(pid, resource, new_va, old_va)
pub(super) fn sys_prlimit64_impl(_pid: u32, resource: u32, _new_va: usize, old_va: usize) -> isize {
    if old_va != 0 {
        sys_getrlimit_impl(resource, old_va)
    } else {
        0
    }
}

/// NR 98  getrusage(who, usage_va) — return zeroed struct rusage.
pub(super) fn sys_getrusage_impl(_who: i32, usage_va: usize) -> isize {
    let buf = [0u8; 144];
    if !copy_bytes_to_user(usage_va, &buf) {
        return -14;
    }
    0
}

/// NR 99  sysinfo(info_va)
pub(super) fn sys_sysinfo_impl(info_va: usize) -> isize {
    let uptime = crate::arch::time::uptime_secs() as i64;
    let free_mem = crate::mm::pmm::free_pages() * 4096;
    let total_mem = crate::mm::pmm::total_pages() * 4096;

    let mut buf = [0u8; 112]; // sizeof(struct sysinfo)
    buf[0..8].copy_from_slice(&uptime.to_le_bytes()); // uptime
    buf[48..56].copy_from_slice(&total_mem.to_le_bytes()); // totalram
    buf[56..64].copy_from_slice(&free_mem.to_le_bytes()); // freeram
    buf[104..108].copy_from_slice(&(4096u32).to_le_bytes()); // mem_unit
    if !copy_bytes_to_user(info_va, &buf) {
        return -14;
    }
    0
}

/// NR 100  times(tbuf_va) — return zeroed struct tms + monotonic tick count.
pub(super) fn sys_times_impl(tbuf_va: usize) -> isize {
    if tbuf_va != 0 {
        let buf = [0u8; 32]; // struct tms: 4 × clock_t (8 bytes each)
        if !copy_bytes_to_user(tbuf_va, &buf) {
            return -14;
        }
    }
    crate::arch::time::monotonic_ticks() as isize
}

/// NR 63  uname(uname_va)
pub(super) fn sys_uname_impl(uname_va: usize) -> isize {
    fn write_field(dst: &mut [u8; 65], s: &str) {
        let b = s.as_bytes();
        let n = b.len().min(64);
        dst[..n].copy_from_slice(&b[..n]);
        dst[n] = 0;
    }
    let mut buf = [[0u8; 65]; 6];
    write_field(&mut buf[0], "Linux"); // sysname
    write_field(&mut buf[1], "rustos"); // nodename
    write_field(&mut buf[2], "6.1.0-rustos"); // release
    write_field(&mut buf[3], "#1 SMP"); // version
    write_field(&mut buf[4], "x86_64"); // machine
    write_field(&mut buf[5], "(none)"); // domainname
                                        // Flatten [[u8;65];6] → [u8;390] safely (no transmute).
    let mut flat = [0u8; 390];
    for (i, field) in buf.iter().enumerate() {
        flat[i * 65..(i + 1) * 65].copy_from_slice(field);
    }
    if !copy_bytes_to_user(uname_va, &flat) {
        return -14;
    }
    0
}

/// NR 157  prctl(op, a2, a3, a4, a5)
pub(super) fn sys_prctl_impl(op: i32, a2: usize, _a3: usize, _a4: usize, _a5: usize) -> isize {
    const PR_SET_NAME: i32 = 15;
    const PR_GET_NAME: i32 = 16;
    const PR_SET_DUMPABLE: i32 = 4;
    const PR_GET_DUMPABLE: i32 = 3;
    const PR_SET_PDEATHSIG: i32 = 1;
    const PR_GET_PDEATHSIG: i32 = 2;
    const PR_SET_SECCOMP: i32 = 22;
    const PR_CAP_AMBIENT: i32 = 47;
    const PR_SET_NO_NEW_PRIVS: i32 = 38;

    match op {
        PR_SET_NAME => {
            let pid = crate::proc::scheduler::current_pid();
            if let Ok(name) = read_user_str(a2, 16) {
                crate::proc::scheduler::with_proc_mut(pid, |p, _| {
                    p.name = name.clone();
                })
                .unwrap_or(());
            }
            0
        },
        PR_GET_NAME => {
            let pid = crate::proc::scheduler::current_pid();
            let name =
                crate::proc::scheduler::with_proc(pid, |p| p.name.clone()).unwrap_or_default();
            let b = name.as_bytes();
            let n = b.len().min(15);
            let mut buf = [0u8; 16];
            buf[..n].copy_from_slice(&b[..n]);
            if !copy_bytes_to_user(a2, &buf) {
                return -14;
            }
            0
        },
        PR_SET_DUMPABLE => 0,
        PR_GET_DUMPABLE => 1,
        PR_SET_PDEATHSIG => 0,
        PR_GET_PDEATHSIG => 0,
        PR_SET_SECCOMP => 0, // silently accept — no seccomp enforcement yet
        PR_CAP_AMBIENT => 0,
        PR_SET_NO_NEW_PRIVS => 0,
        _ => -22, // EINVAL
    }
}

/// NR 158  arch_prctl(code, addr)
#[cfg(target_arch = "x86_64")]
pub(super) fn sys_arch_prctl_impl(code: i32, addr: usize) -> isize {
    const ARCH_SET_FS: i32 = 0x1002;
    const ARCH_GET_FS: i32 = 0x1003;
    const ARCH_SET_GS: i32 = 0x1001;
    const ARCH_GET_GS: i32 = 0x1004;

    let pid = crate::proc::scheduler::current_pid();
    match code {
        ARCH_SET_FS => {
            crate::proc::scheduler::with_proc_mut(pid, |p, _| p.fs_base = addr).unwrap_or(());
            unsafe {
                core::arch::x86_64::__cpuid(0);
            } // serialise
            unsafe {
                crate::arch::x86_64::cpu::wrmsr(0xC0000100, addr as u64);
            } // IA32_FS_BASE
            0
        },
        ARCH_GET_FS => {
            let base = crate::proc::scheduler::with_proc(pid, |p| p.fs_base).unwrap_or(0);
            if !copy_bytes_to_user(addr, &base.to_le_bytes()) {
                return -14;
            }
            0
        },
        ARCH_SET_GS => {
            crate::proc::scheduler::with_proc_mut(pid, |p, _| p.gs_base = addr).unwrap_or(());
            unsafe {
                crate::arch::x86_64::cpu::wrmsr(0xC0000101, addr as u64);
            } // IA32_GS_BASE
            0
        },
        ARCH_GET_GS => {
            let base = crate::proc::scheduler::with_proc(pid, |p| p.gs_base).unwrap_or(0);
            if !copy_bytes_to_user(addr, &base.to_le_bytes()) {
                return -14;
            }
            0
        },
        _ => -22,
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub(super) fn sys_arch_prctl_impl(_code: i32, _addr: usize) -> isize {
    -22
}

/// NR 16  ioctl(fd, request, arg)
pub(super) fn sys_ioctl_impl(fd: usize, request: u64, arg: usize) -> isize {
    crate::fs::ioctl::sys_ioctl(fd, request, arg)
}

/// NR 172  iopl / NR 173 ioperm — deny.
pub(super) fn sys_iopl_impl(_level: i32) -> isize {
    -1
}
pub(super) fn sys_ioperm_impl(_from: usize, _num: usize, _turn_on: i32) -> isize {
    -1
}

/// NR 175  init_module — RustOS has no loadable kernel module subsystem.
pub(super) fn sys_init_module_impl(_mod: usize, _len: usize, _opts: usize) -> isize {
    -38
}

/// NR 176  delete_module — same rationale as init_module above.
pub(super) fn sys_delete_module_impl(_name: usize, _flags: u32) -> isize {
    -38
}

/// NR 285  fallocate(fd, mode, offset, len)
pub(super) fn sys_fallocate_impl(fd: usize, _mode: i32, offset: i64, len: i64) -> isize {
    if offset < 0 || len <= 0 {
        return -22;
    }
    let new_size = (offset + len) as u64;
    crate::fs::vfs::truncate(fd, new_size);
    0
}

/// NR 326  copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)
pub(super) fn sys_copy_file_range_impl(
    fd_in: usize,
    off_in_va: usize,
    fd_out: usize,
    off_out_va: usize,
    len: usize,
    _flags: u32,
) -> isize {
    crate::fs::io_syscalls::sys_copy_file_range(fd_in, off_in_va, fd_out, off_out_va, len)
}

/// NR 162  fsync(fd)
pub(super) fn sys_fsync_impl(fd: usize) -> isize {
    crate::fs::vfs::fsync(fd)
}

/// NR 163  fdatasync(fd)
pub(super) fn sys_fdatasync_impl(fd: usize) -> isize {
    crate::fs::vfs::fsync(fd) // treat as fsync
}

/// NR 306  syncfs(fd)
pub(super) fn sys_syncfs_impl(_fd: usize) -> isize {
    0
}

/// NR 162 (alt)  sync() — no-op; no write-back queue yet.
pub(super) fn sys_sync_impl() -> isize {
    0
}

/// NR 135  personality(persona) — report PER_LINUX, accept silently.
pub(super) fn sys_personality_impl(_persona: u32) -> isize {
    0
}

pub(super) fn sys_setpgid_impl(pid: usize, pgid: usize) -> isize {
    crate::proc::session::set_pgid(pid, pgid)
}
pub(super) fn sys_getpgid_impl(pid: usize) -> isize {
    crate::proc::session::get_pgid(pid)
}
pub(super) fn sys_setsid_impl() -> isize {
    crate::proc::session::setsid()
}
pub(super) fn sys_getsid_impl(pid: usize) -> isize {
    crate::proc::session::get_sid(pid)
}

pub(super) fn sys_getpriority_impl(_which: i32, _who: u32) -> isize {
    20
}
pub(super) fn sys_setpriority_impl(_which: i32, _who: u32, _prio: i32) -> isize {
    0
}
pub(super) fn sys_nice_impl(_inc: i32) -> isize {
    0
}

/// NR 125/126  capget/capset — report full capabilities (we run as root).
pub(super) fn sys_capget_impl(hdr_va: usize, data_va: usize) -> isize {
    // struct __user_cap_data_struct: two u32 effective/permitted/inheritable pairs.
    if data_va != 0 {
        let full = [0xFFu8; 24]; // all caps set in effective + permitted
        let _ = crate::uaccess::copy_to_user(data_va, full.as_ptr(), full.len());
    }
    0
}
pub(super) fn sys_capset_impl(_hdr_va: usize, _data_va: usize) -> isize {
    0
}
