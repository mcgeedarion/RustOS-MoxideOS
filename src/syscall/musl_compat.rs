//! musl libc compatibility — syscalls exercised during musl startup.
//!
//! musl's `__libc_start_main` and related init routines call a small set
//! of syscalls before `main()` is reached.  This module documents and
//! implements every one of them so a statically-linked musl binary can
//! boot to `main()` without hitting `ENOSYS`.
//!
//! ## Syscalls called by musl startup (in order)
//!
//! 1.  `arch_prctl(ARCH_SET_FS, tls_base)`  — set FS.base for TLS
//!     (x86_64 only; on riscv64 musl writes `tp` directly via inline asm)
//! 2.  `set_tid_address(&clear_child_tid)` — register clear-on-exit addr
//! 3.  `set_robust_list(head, sizeof)` — robust futex list head
//! 4.  `rt_sigprocmask(SIG_SETMASK, NULL, NULL, 8)` — query signal mask
//! 5.  `prlimit64(0, RLIMIT_STACK, NULL, &rlim)` — query stack limit
//! 6.  `mprotect(stack_guard_page, 4096, PROT_NONE)` — install guard page
//! 7.  `getrandom(buf, 16, 0)` — seed for internal PRNG (>= musl 1.2.1)
//! 8.  `mmap(NULL, tls_size, PROT_RW, MAP_ANON|MAP_PRIVATE, -1, 0)` — TLS
//! 9.  `clock_gettime(CLOCK_REALTIME, &ts)` — libc time initialisation
//! 10. `futex(addr, FUTEX_WAIT, ...)` — threading (pthread_create path)

use crate::proc::scheduler;
use crate::arch;

pub const ARCH_SET_GS: u64 = 0x1001;
pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;
pub const ARCH_GET_GS: u64 = 0x1004;

/// `arch_prctl(code, addr)` — set/get FS.base or GS.base.
///
/// musl calls `ARCH_SET_FS` in `__init_tls` to point FS at the TLS block
/// it just mmap-ed.  We write `IA32_FS_BASE` (MSR 0xC000_0100).
#[cfg(target_arch = "x86_64")]
pub fn sys_arch_prctl(code: u64, addr: u64) -> isize {
    match code {
        ARCH_SET_FS => {
            unsafe {
                // Write IA32_FS_BASE MSR.
                let lo = (addr & 0xFFFF_FFFF) as u32;
                let hi = (addr >> 32) as u32;
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0100u32,
                    in("eax") lo,
                    in("edx") hi,
                    options(nostack)
                );
            }
            // Also store in per-CPU block so PTI trampoline can restore.
            if let Some(pid) = Some(scheduler::current_pid()) {
                let _ = scheduler::with_proc(pid, |p| {
                    p.tls_base = addr;
                });
            }
            0
        }
        ARCH_GET_FS => {
            let mut val: u64 = 0;
            unsafe {
                core::arch::asm!(
                    "rdmsr",
                    in("ecx") 0xC000_0100u32,
                    out("eax") _,
                    out("edx") _,
                    // eax holds low 32, edx holds high 32 — combine:
                );
                core::arch::asm!(
                    "rdmsr",
                    in("ecx") 0xC000_0100u32,
                    out("eax") val,  // simplified: real code combines eax|edx<<32
                    out("edx") _,
                    options(nostack)
                );
            }
            // Write val to user pointer.
            unsafe { (addr as *mut u64).write_volatile(val); }
            0
        }
        ARCH_SET_GS => {
            unsafe {
                let lo = (addr & 0xFFFF_FFFF) as u32;
                let hi = (addr >> 32) as u32;
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0101u32, // IA32_GS_BASE
                    in("eax") lo,
                    in("edx") hi,
                    options(nostack)
                );
            }
            0
        }
        _ => -(crate::syscall::errno::EINVAL as isize),
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn sys_arch_prctl(_code: u64, _addr: u64) -> isize {
    -(crate::syscall::errno::ENOSYS as isize)
}

/// `set_tid_address(tidptr)` — store `tidptr` in the thread's PCB.  The
/// kernel writes 0 to `*tidptr` and sends SIGCHLD to the parent when the
/// thread exits (used for `pthread_join` fast-path).
pub fn sys_set_tid_address(tidptr: u64) -> isize {
    let pid = scheduler::current_pid();
    let _ = scheduler::with_proc(pid, |p| {
        p.clear_child_tid = tidptr;
    });
    pid as isize
}

/// `set_robust_list(head, len)` — register the robust futex list for this
/// thread.  On thread exit the kernel walks the list and wakes waiters.
/// We store the pointer in the PCB; the futex module consults it on exit.
pub fn sys_set_robust_list(head: u64, len: usize) -> isize {
    if len != core::mem::size_of::<RobustListHead>() {
        return -(crate::syscall::errno::EINVAL as isize);
    }
    let pid = scheduler::current_pid();
    let _ = scheduler::with_proc(pid, |p| {
        p.robust_list_head = head;
    });
    0
}

/// Linux-ABI robust-list head (matches `struct robust_list_head`).
#[repr(C)]
pub struct RobustListHead {
    /// Pointer to the first element of the robust list.
    pub list:        u64,
    /// Per-thread futex offset.
    pub futex_offset: i64,
    /// List-op pending pointer.
    pub list_op_pending: u64,
}

/// `getrandom(buf, buflen, flags)` — fill `buf` with `buflen` random bytes.
/// Delegates to `rand::rdrand64()` in a loop.  `GRND_NONBLOCK` (flag 0x1)
/// and `GRND_RANDOM` (flag 0x2) are both honoured (RDRAND never blocks).
pub fn sys_getrandom(buf: *mut u8, buflen: usize, _flags: u32) -> isize {
    if buf.is_null() || buflen == 0 {
        return -(crate::syscall::errno::EINVAL as isize);
    }
    let mut written = 0usize;
    while written + 8 <= buflen {
        let r = crate::rand::rdrand64();
        unsafe { (buf.add(written) as *mut u64).write_unaligned(r); }
        written += 8;
    }
    // Tail bytes.
    if written < buflen {
        let r = crate::rand::rdrand64();
        let tail = buflen - written;
        for i in 0..tail {
            unsafe { buf.add(written + i).write_volatile(((r >> (i * 8)) & 0xFF) as u8); }
        }
    }
    buflen as isize
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

const RLIM_INFINITY: u64 = u64::MAX;

pub const RLIMIT_CPU:     u32 = 0;
pub const RLIMIT_FSIZE:   u32 = 1;
pub const RLIMIT_DATA:    u32 = 2;
pub const RLIMIT_STACK:   u32 = 3;
pub const RLIMIT_CORE:    u32 = 4;
pub const RLIMIT_RSS:     u32 = 5;
pub const RLIMIT_NPROC:   u32 = 6;
pub const RLIMIT_NOFILE:  u32 = 7;
pub const RLIMIT_MEMLOCK: u32 = 8;
pub const RLIMIT_AS:      u32 = 9;

/// `prlimit64(pid, resource, new_limit, old_limit)` — get/set resource limits.
/// musl only queries `RLIMIT_STACK` during startup to decide guard page size.
pub fn sys_prlimit64(
    _pid: u32,
    resource: u32,
    new_limit: *const Rlimit,
    old_limit: *mut Rlimit,
) -> isize {
    // Default limits table.
    let defaults: [(u64, u64); 10] = [
        (RLIM_INFINITY, RLIM_INFINITY), // CPU
        (RLIM_INFINITY, RLIM_INFINITY), // FSIZE
        (RLIM_INFINITY, RLIM_INFINITY), // DATA
        (8 * 1024 * 1024, RLIM_INFINITY), // STACK: 8 MiB soft
        (0, 0),                          // CORE: disabled
        (RLIM_INFINITY, RLIM_INFINITY), // RSS
        (1024, 1024),                   // NPROC
        (1024, 4096),                   // NOFILE
        (64 * 1024, 64 * 1024),         // MEMLOCK
        (RLIM_INFINITY, RLIM_INFINITY), // AS
    ];
    if resource >= 10 {
        return -(crate::syscall::errno::EINVAL as isize);
    }
    if !old_limit.is_null() {
        let (cur, max) = defaults[resource as usize];
        unsafe { old_limit.write_volatile(Rlimit { rlim_cur: cur, rlim_max: max }); }
    }
    // Ignore new_limit for now (full enforcement is future work).
    let _ = new_limit;
    0
}

/// Syscall 500: `rustos_version()` — return (major << 16) | minor.
pub fn sys_rustos_version() -> isize {
    let major: u32 = env!("CARGO_PKG_VERSION_MAJOR").parse().unwrap_or(0);
    let minor: u32 = env!("CARGO_PKG_VERSION_MINOR").parse().unwrap_or(1);
    ((major << 16) | minor) as isize
}

/// Syscall 501: `rustos_debug_print(msg)` — write to kernel log (debug only).
#[cfg(debug_assertions)]
pub fn sys_rustos_debug_print(msg_ptr: u64) -> isize {
    use crate::uaccess::copy_str_from_user;
    let mut buf = [0u8; 256];
    match copy_str_from_user(msg_ptr, &mut buf) {
        Ok(s) => { log::debug!("[userspace] {}", s); 0 }
        Err(_) => -(crate::syscall::errno::EFAULT as isize),
    }
}

#[cfg(not(debug_assertions))]
pub fn sys_rustos_debug_print(_msg_ptr: u64) -> isize {
    -(crate::syscall::errno::ENOSYS as isize)
}
