//! Thread group (TGID) tracking, gettid, tkill, tgkill, set_tid_address.
//!
//! ## Bug fix
//!
//! ### sys_arch_prctl: copy_to_user return type mismatch
//!   `copy_to_user` returns `bool` (true = success). `.is_err()` is not
//!   valid on `bool`. Both ARCH_GET_FS and ARCH_GET_GS arms had this.
//!   Fixed to `if !copy_to_user(...)`.

use crate::proc::scheduler;
use crate::uaccess::copy_to_user;

pub fn register_thread(pid: usize, tgid: usize) {
    scheduler::with_proc_mut(pid, |p| p.tgid = tgid);
}

pub fn unregister_thread(_pid: usize) {}

pub fn tgid_of(pid: usize) -> usize {
    scheduler::tgid_of(pid)
}

pub fn threads_of(tgid: usize) -> alloc::vec::Vec<usize> {
    scheduler::with_procs_ro(|procs| {
        procs
            .iter()
            .filter(|p| p.tgid == tgid)
            .map(|p| p.pid)
            .collect()
    })
}

pub fn vma_pid(pid: usize) -> u32 {
    tgid_of(pid) as u32
}

pub fn sys_gettid() -> isize {
    scheduler::current_pid() as isize
}

pub fn sys_tkill(tid: usize, sig: u32) -> isize {
    if sig == 0 {
        return match scheduler::with_proc(tid, |_| ()) {
            Some(_) => 0,
            None => -3,
        };
    }
    if sig > 64 {
        return -22;
    }
    crate::proc::signal::send_signal(tid, sig as i32)
}

pub fn sys_tgkill(tgid: usize, tid: usize, sig: u32) -> isize {
    if sig > 64 {
        return -22;
    }
    let real_tgid = scheduler::tgid_of(tid);
    if real_tgid == 0 || real_tgid != tgid {
        return -3;
    }
    if sig == 0 {
        return 0;
    }
    crate::proc::signal::send_signal(tid, sig as i32)
}

pub fn sys_set_tid_address(tidptr: usize) -> isize {
    let pid = scheduler::current_pid();
    scheduler::with_proc_mut(pid, |p| {
        p.clear_child_tid_va = tidptr;
    });
    pid as isize
}

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
                p.tls_base = addr;
                p.ctx.fs_base = addr;
            });
            unsafe {
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
            // FIX: copy_to_user returns bool, not Result. Was .is_err().
            if !copy_to_user(addr, &base.to_ne_bytes()) {
                return -14;
            }
            0
        }
        ARCH_SET_GS => {
            -1 // EPERM
        }
        ARCH_GET_GS => {
            // FIX: same bool vs Result mismatch.
            if !copy_to_user(addr, &0usize.to_ne_bytes()) {
                return -14;
            }
            0
        }
        _ => -22,
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn sys_arch_prctl(_code: usize, _addr: usize) -> isize {
    -38
}
