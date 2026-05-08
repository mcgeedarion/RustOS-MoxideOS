//! Thread group (TGID) tracking, gettid, tkill, tgkill, set_tid_address.
//!
//! TGID is stored directly on `Pcb.tgid`, so there is no separate
//! global table — all lookups go through the scheduler's process list.
//!
//! A process created by fork() has tgid == pid.
//! Threads created by clone3(CLONE_THREAD) share the parent's tgid.

use crate::proc::scheduler;
use crate::uaccess::copy_to_user;

/// Register a new thread: sets Pcb.tgid for the given pid.
/// Called by sys_clone3 after enqueueing the child PCB.
pub fn register_thread(pid: usize, tgid: usize) {
    scheduler::with_proc_mut(pid, |p| p.tgid = tgid);
}

/// Remove a thread from its group (called by do_exit before zombify).
/// The PCB stays in the run list as a Zombie until waitpid reaps it.
pub fn unregister_thread(_pid: usize) {
    // tgid stays on the PCB; it is correct until the PCB is reaped.
}

/// Look up the TGID for a pid. Falls back to pid itself (main thread).
pub fn tgid_of(pid: usize) -> usize {
    scheduler::tgid_of(pid)
}

/// Collect all live thread pids that share `tgid` (including tgid itself).
/// Used by FUTEX_FLAG_TSYNC in seccomp and by tgkill validation.
pub fn threads_of(tgid: usize) -> alloc::vec::Vec<usize> {
    scheduler::with_procs_ro(|procs| {
        procs.iter()
            .filter(|p| p.tgid == tgid)
            .map(|p| p.pid)
            .collect()
    })
}

/// VMA namespace key: threads in the same group share the parent's tgid.
pub fn vma_pid(pid: usize) -> u32 { tgid_of(pid) as u32 }

/// sys_gettid() [NR 186] — returns the calling thread's TID (== Pcb.pid).
pub fn sys_gettid() -> isize {
    scheduler::current_pid() as isize
}

/// sys_tkill(tid, sig) [NR 200]
///
/// Send signal `sig` to thread `tid`.  Unlike kill(2), the target is a
/// specific thread rather than any thread in the process group.
/// NPTL uses this internally; tgkill(2) is the preferred form.
pub fn sys_tkill(tid: usize, sig: u32) -> isize {
    if sig == 0 {
        return match scheduler::with_proc(tid, |_| ()) {
            Some(_) => 0,
            None    => -3, // ESRCH
        };
    }
    if sig > 64 { return -22; } // EINVAL
    crate::proc::signal::send_signal(tid, sig as i32)
}

/// sys_tgkill(tgid, tid, sig) [NR 234]
///
/// Like tkill but validates that `tid` belongs to `tgid`.  This prevents
/// accidentally hitting a recycled TID after a thread exits.
pub fn sys_tgkill(tgid: usize, tid: usize, sig: u32) -> isize {
    if sig > 64 { return -22; } // EINVAL
    let real_tgid = scheduler::tgid_of(tid);
    if real_tgid == 0 || real_tgid != tgid { return -3; } // ESRCH
    if sig == 0 { return 0; } // probe only
    crate::proc::signal::send_signal(tid, sig as i32)
}

/// sys_set_tid_address(tidptr) [NR 218]
///
/// Stores `tidptr` as the clear_child_tid address for the calling thread.
/// On thread exit the kernel will:
///   1. Write 0 to *tidptr (the futex word pthread_join polls).
///   2. Call FUTEX_WAKE(tidptr, 1) to unblock any waiter.
///
/// Returns the calling thread's TID (same as gettid).
/// musl's __pthread_create calls this immediately after clone3 to register
/// the TID word before the thread does any real work.
pub fn sys_set_tid_address(tidptr: usize) -> isize {
    let pid = scheduler::current_pid();
    scheduler::with_proc_mut(pid, |p| {
        p.clear_child_tid_va = tidptr;
    });
    pid as isize
}

/// sys_arch_prctl(code, addr) [NR 158] — x86-64 only.
///
/// Handles ARCH_SET_FS (0x1002) and ARCH_GET_FS (0x1003) which musl uses
/// to install the TLS block pointer into FS.base.
///
/// Both the Context.fs_base and Pcb.tls_base are updated so the value
/// survives context switches.
#[cfg(target_arch = "x86_64")]
pub fn sys_arch_prctl(code: usize, addr: usize) -> isize {
    use crate::uaccess::copy_to_user;
    const ARCH_SET_GS: usize = 0x1001;
    const ARCH_SET_FS: usize = 0x1002;
    const ARCH_GET_FS: usize = 0x1003;
    const ARCH_GET_GS: usize = 0x1004;

    let pid = scheduler::current_pid();
    match code {
        ARCH_SET_FS => {
            scheduler::with_proc_mut(pid, |p| {
                p.tls_base   = addr;
                p.ctx.fs_base = addr;
            });
            // Write the new base into the hardware MSR immediately so the
            // current thread sees the new FS.base without waiting for a
            // context switch.
            unsafe {
                // wrmsr(IA32_FS_BASE = 0xC000_0100, addr)
                let lo = addr as u32;
                let hi = (addr >> 32) as u32;
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0100u32,
                    in("eax") lo,
                    in("edx") hi,
                    options(nostack, nomem),
                );
            }
            0
        }
        ARCH_GET_FS => {
            let base = scheduler::with_proc(pid, |p| p.tls_base).unwrap_or(0);
            if copy_to_user(addr, &base.to_ne_bytes()).is_err() { return -14; }
            0
        }
        ARCH_SET_GS => {
            // GS is used for kernel percpu on x86-64; deny userspace writes.
            -1 // EPERM
        }
        ARCH_GET_GS => {
            // Return 0 — we do not expose the kernel GS base.
            if copy_to_user(addr, &0usize.to_ne_bytes()).is_err() { return -14; }
            0
        }
        _ => -22, // EINVAL
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn sys_arch_prctl(_code: usize, _addr: usize) -> isize { -38 } // ENOSYS
