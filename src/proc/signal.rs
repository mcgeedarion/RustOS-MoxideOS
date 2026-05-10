//! Signal delivery, masking, and rt_sigreturn.
//!
//! ## Delivery model
//!
//! ### Thread-directed signals  (tgkill, tkill, raise)
//!
//!   send_signal(tid, sig) -> pushed to PENDING[tid]
//!   Delivered only to that specific thread in check_and_deliver.
//!
//! ### Group-directed signals  (kill, sigqueue, SIGCHLD to parent)
//!
//!   send_signal_group(tgid, sig) -> pushed to GROUP_PENDING[tgid]
//!   At check_and_deliver time, any thread in the group whose mask
//!   allows the signal may claim and handle it (first-come-first-served
//!   atomic removal from the group queue).
//!
//! ### Delivery order in check_and_deliver
//!
//!   1. Per-TID PENDING (thread-directed, highest priority)
//!   2. GROUP_PENDING   (group-directed, any unblocked thread)
//!
//! ## Post-S2 locking notes
//!
//!   - send_signal_group_info wakes all threads in the group.
//!   - check_and_deliver uses with_proc_mut for SIGSTOP.
//!   - sys_rt_sigsuspend / sys_rt_sigtimedwait use with_proc_mut.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::Mutex;

use crate::proc::{scheduler, process::State};
use crate::uaccess::{copy_from_user, copy_to_user, USER_SPACE_END};

// ── Signal metadata ───────────────────────────────────────────────────

#[derive(Clone, Copy, Default, Debug)]
pub struct SigInfo {
    pub sig:    u32,
    pub code:   i32,
    pub pid:    u32,
    pub uid:    u32,
    pub status: i32,
    pub addr:   usize,
    pub value:  i64,
}

const SI_KERNEL:   i32 = 128;
const CLD_EXITED:  i32 = 1;
const CLD_KILLED:  i32 = 2;
const SEGV_MAPERR: i32 = 1;
const SI_USER:     i32 = 0;

/// Signals that are ignored by default (SIGCHLD=17, SIGURG=23, SIGWINCH=28).
const SIG_IGN_DEFAULT: u64 =
    (1u64 << 17) | (1u64 << 23) | (1u64 << 28);

/// Signals that stop by default (SIGTSTP=20, SIGTTIN=21, SIGTTOU=22, SIGSTOP=19+1).
const SIG_STOP_DEFAULT: u64 =
    (1u64 << 19) | (1u64 << 20) | (1u64 << 21) | (1u64 << 22);

// ── Signal storage ───────────────────────────────────────────────────

/// Thread-directed pending signals, keyed by TID.
static PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> =
    Mutex::new(BTreeMap::new());

/// Group-directed pending signals, keyed by TGID.
static GROUP_PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> =
    Mutex::new(BTreeMap::new());

/// Per-TID signal mask.
static SIGMASK: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

// ── Alternate stack ───────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct AltStack { ss_sp: usize, ss_flags: i32, ss_size: usize }

const SS_DISABLE:    i32 = 2;
const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

static ALTSTACK: Mutex<BTreeMap<usize, AltStack>> = Mutex::new(BTreeMap::new());

// ── SA_* flags ───────────────────────────────────────────────────────────

const SA_ONSTACK:  u32 = 0x08000000;
const SA_RESTORER: u32 = 0x04000000;
const SA_NODEFER:  u32 = 0x40000000;

// ── sigprocmask how ──────────────────────────────────────────────────────

const SIG_BLOCK:   u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

// ── Process-group helpers ─────────────────────────────────────────────

/// Return the TGIDs of all process-group leaders (pid == tgid) whose
/// Pcb::pgid matches `pgid`.  Each TGID appears exactly once.
fn pids_in_pgrp(pgid: usize) -> Vec<usize> {
    scheduler::with_procs_ro(|procs| {
        procs.iter()
            .filter(|p| p.pgid == pgid && p.pid == p.tgid)
            .map(|p| p.tgid)
            .collect()
    })
}

// ── Thread-directed send API ───────────────────────────────────────────

/// Send `sig` to a specific thread (TID).  Used by tkill/tgkill/raise.
pub fn send_signal(tid: usize, sig: i32) -> isize {
    if sig <= 0 || sig > 64 { return -22; }
    send_signal_info(tid, SigInfo { sig: sig as u32, code: SI_KERNEL, ..Default::default() });
    0
}

/// Rate-limited user-originated thread-directed send.
pub fn send_signal_user(tid: usize, sig: i32) -> isize {
    if sig <= 0 || sig > 64 { return -22; }
    let bypass = sig == 9 || sig == 19;
    if !bypass {
        let queue_len = {
            let map = PENDING.lock();
            map.get(&tid).map_or(0, |q| q.len())
        };
        let (soft, _hard) = crate::proc::rlimit::getrlimit_for(
            tid, crate::proc::rlimit::RLIMIT_SIGPENDING);
        let limit = if soft == crate::proc::rlimit::RLIM_INFINITY {
            usize::MAX
        } else {
            soft as usize
        };
        if queue_len >= limit { return -11; }
    }
    let caller_pid = scheduler::current_pid();
    send_signal_info(tid, SigInfo {
        sig:  sig as u32,
        code: SI_USER,
        pid:  caller_pid as u32,
        ..Default::default()
    });
    0
}

/// Low-level: push info onto per-TID PENDING and wake that thread.
pub fn send_signal_info(tid: usize, info: SigInfo) {
    if info.sig == 0 || info.sig > 64 { return; }
    PENDING.lock().entry(tid).or_default().push_back(info);
    scheduler::wake_pid(tid);
}

// ── Group-directed send API ───────────────────────────────────────────

/// Send `sig` to the thread group identified by `tgid`.
/// Used by kill(2) and sigqueue(2).
pub fn send_signal_group(tgid: usize, sig: i32) -> isize {
    if sig <= 0 || sig > 64 { return -22; }
    send_signal_group_info(tgid, SigInfo {
        sig: sig as u32,
        code: SI_KERNEL,
        ..Default::default()
    });
    0
}

/// Low-level: push info onto GROUP_PENDING[tgid] and wake all threads
/// in the group so any unblocked one can claim it quickly.
pub fn send_signal_group_info(tgid: usize, info: SigInfo) {
    if info.sig == 0 || info.sig > 64 { return; }
    GROUP_PENDING.lock().entry(tgid).or_default().push_back(info);
    // Wake every member so the first unblocked one claims the signal.
    let members = crate::proc::thread::threads_of(tgid);
    for tid in members {
        scheduler::wake_pid(tid);
    }
}

/// SIGCHLD to a process (group leader).  Always group-directed.
pub fn send_sigchld(parent_pid: usize, child_pid: usize, exit_code: i32, killed: bool) {
    let tgid = crate::proc::thread::tgid_of(parent_pid);
    let tgid = if tgid != 0 { tgid } else { parent_pid };
    send_signal_group_info(tgid, SigInfo {
        sig:    17,
        code:   if killed { CLD_KILLED } else { CLD_EXITED },
        pid:    child_pid as u32,
        status: exit_code,
        ..Default::default()
    });
}

/// SIGSEGV is always thread-directed (fault belongs to the faulting thread).
pub fn send_sigsegv(pid: usize, fault_addr: usize) {
    send_signal_info(pid, SigInfo {
        sig: 11, code: SEGV_MAPERR, addr: fault_addr, ..Default::default()
    });
}

pub fn has_pending_signal(pid: usize) -> bool {
    if PENDING.lock().get(&pid).map_or(false, |q| !q.is_empty()) {
        return true;
    }
    // Also check group queue.
    let tgid = crate::proc::thread::tgid_of(pid);
    let tgid = if tgid != 0 { tgid } else { pid };
    let mask = get_sigmask(pid);
    GROUP_PENDING.lock().get(&tgid).map_or(false, |q| {
        q.iter().any(|s| s.sig >= 1 && s.sig <= 64 && (mask >> s.sig) & 1 == 0)
    })
}

pub fn get_sigmask(pid: usize) -> u64 {
    SIGMASK.lock().get(&pid).copied().unwrap_or(0)
}

pub fn set_sigmask(pid: usize, mask: u64) {
    SIGMASK.lock().insert(pid, mask);
}

// ── check_and_deliver ─────────────────────────────────────────────────
//
// Called at every trap return. Runs two passes:
//   Pass 1: per-TID PENDING (thread-directed)
//   Pass 2: GROUP_PENDING   (group-directed, any unblocked thread claims)
//
// Returns once a signal has been delivered to a frame, or when both
// queues are empty / fully masked.

/// Pick one deliverable SigInfo from either queue, removing it atomically.
/// Returns (info, from_group).
fn dequeue_signal(pid: usize) -> Option<(SigInfo, bool)> {
    let mask = get_sigmask(pid);

    // Pass 1: thread-directed.
    {
        let mut map = PENDING.lock();
        if let Some(queue) = map.get_mut(&pid) {
            let pos = queue.iter().position(|s| {
                s.sig >= 1 && s.sig <= 64 && (mask >> s.sig) & 1 == 0
            });
            if let Some(i) = pos {
                return Some((queue.remove(i).unwrap(), false));
            }
        }
    }

    // Pass 2: group-directed.
    let tgid = crate::proc::thread::tgid_of(pid);
    let tgid = if tgid != 0 { tgid } else { pid };
    {
        let mut map = GROUP_PENDING.lock();
        if let Some(queue) = map.get_mut(&tgid) {
            let pos = queue.iter().position(|s| {
                s.sig >= 1 && s.sig <= 64 && (mask >> s.sig) & 1 == 0
            });
            if let Some(i) = pos {
                return Some((queue.remove(i).unwrap(), true));
            }
        }
    }

    None
}

#[cfg(target_arch = "riscv64")]
pub fn check_and_deliver(frame: &mut crate::arch::riscv64::trap::TrapFrame) {
    let pid = scheduler::current_pid() as usize;

    loop {
        let (info, _from_group) = match dequeue_signal(pid) {
            Some(x) => x,
            None    => return,
        };

        let sig = info.sig as usize;

        let (handler, sa_flags, restorer) = scheduler::with_proc(pid, |p| {
            let h = p.signal_handlers.lock();
            (
                h.handlers.get(sig).copied().unwrap_or(0),
                h.flags.get(sig).copied().unwrap_or(0),
                h.restorer,
            )
        }).unwrap_or((0, 0, 0));

        match handler {
            0 => {
                if (SIG_IGN_DEFAULT >> sig) & 1 != 0 { continue; }
                if (SIG_STOP_DEFAULT >> sig) & 1 != 0 {
                    scheduler::with_proc_mut(pid, |p, pl| {
                        pl.set_state(p, State::Blocked);
                    });
                    scheduler::schedule();
                    continue;
                }
                crate::proc::exit::do_exit(pid, -(sig as i32));
                return;
            }
            1 => { continue; }
            handler_va => {
                let old_mask = get_sigmask(pid);
                if sa_flags & SA_NODEFER == 0 {
                    set_sigmask(pid, old_mask | (1u64 << sig));
                }
                push_sigframe_riscv(frame, &info, handler_va, restorer, sa_flags, old_mask);
                return;
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub fn check_and_deliver(frame: &mut crate::arch::x86_64::syscall::SyscallFrame) {
    let pid = scheduler::current_pid() as usize;

    loop {
        let (info, _from_group) = match dequeue_signal(pid) {
            Some(x) => x,
            None    => return,
        };

        let sig = info.sig as usize;

        let (handler, sa_flags, restorer) = scheduler::with_proc(pid, |p| {
            let h = p.signal_handlers.lock();
            (
                h.handlers.get(sig).copied().unwrap_or(0),
                h.flags.get(sig).copied().unwrap_or(0),
                h.restorer,
            )
        }).unwrap_or((0, 0, 0));

        match handler {
            0 => {
                if (SIG_IGN_DEFAULT >> sig) & 1 != 0 { continue; }
                if (SIG_STOP_DEFAULT >> sig) & 1 != 0 {
                    scheduler::with_proc_mut(pid, |p, pl| {
                        pl.set_state(p, State::Blocked);
                    });
                    scheduler::schedule();
                    continue;
                }
                crate::proc::exit::do_exit(pid, -(sig as i32));
                return;
            }
            1 => { continue; }
            handler_va => {
                let old_mask = get_sigmask(pid);
                if sa_flags & SA_NODEFER == 0 {
                    set_sigmask(pid, old_mask | (1u64 << sig));
                }
                push_sigframe_x86(frame, &info, handler_va, restorer, sa_flags, old_mask);
                return;
            }
        }
    }
}

// ── push_sigframe_riscv ───────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
fn push_sigframe_riscv(
    frame:      &mut crate::arch::riscv64::trap::TrapFrame,
    info:       &SigInfo,
    handler_va: usize,
    restorer:   usize,
    sa_flags:   u32,
    old_mask:   u64,
) {
    use crate::arch::riscv64::trap::TRAP_FRAME_SIZE;

    let pid = scheduler::current_pid() as usize;
    let base_sp = if sa_flags & SA_ONSTACK != 0 {
        let alt = ALTSTACK.lock().get(&pid).copied().unwrap_or(AltStack::default());
        if alt.ss_flags & SS_DISABLE == 0 && alt.ss_sp != 0 {
            if alt.ss_flags & SS_AUTODISARM != 0 { ALTSTACK.lock().remove(&pid); }
            alt.ss_sp + alt.ss_size
        } else { frame.sp }
    } else { frame.sp };

    const SIGINFO_SIZE:    usize = 80;
    const SIGMASK_SLOT:    usize = 8;
    const RESTORER_SLOT:   usize = 8;
    const TRAMPOLINE_SIZE: usize = 16;
    const FRAME_TOTAL: usize =
        TRAP_FRAME_SIZE + SIGINFO_SIZE + SIGMASK_SLOT + RESTORER_SLOT + TRAMPOLINE_SIZE;

    let new_sp           = (base_sp - FRAME_TOTAL) & !0xf;
    let saved_frame_va   = new_sp;
    let siginfo_va       = new_sp + TRAP_FRAME_SIZE;
    let sigmask_va       = new_sp + TRAP_FRAME_SIZE + SIGINFO_SIZE;
    let restorer_slot_va = new_sp + TRAP_FRAME_SIZE + SIGINFO_SIZE + SIGMASK_SLOT;
    let trampoline_va    = new_sp + TRAP_FRAME_SIZE + SIGINFO_SIZE + SIGMASK_SLOT + RESTORER_SLOT;

    unsafe {
        core::ptr::copy_nonoverlapping(
            frame as *const _ as *const u8,
            saved_frame_va as *mut u8,
            TRAP_FRAME_SIZE,
        );
    }
    unsafe {
        let si = siginfo_va as *mut u8;
        core::ptr::write_bytes(si, 0, SIGINFO_SIZE);
        (si.add(0)  as *mut i32).write(info.sig as i32);
        (si.add(8)  as *mut i32).write(info.code);
        (si.add(16) as *mut u64).write(info.addr as u64);
        (si.add(24) as *mut u32).write(info.pid);
        (si.add(28) as *mut u32).write(info.uid);
    }
    unsafe { (sigmask_va as *mut u64).write(old_mask); }

    let effective_restorer = if sa_flags & SA_RESTORER != 0 && restorer != 0 {
        unsafe { (restorer_slot_va as *mut usize).write(restorer); }
        restorer
    } else {
        unsafe {
            core::ptr::write_bytes(trampoline_va as *mut u8, 0, TRAMPOLINE_SIZE);
            (trampoline_va as *mut u32).write(0x08b00893u32);
            (trampoline_va as *mut u32).add(1).write(0x00000073u32);
            (restorer_slot_va as *mut usize).write(trampoline_va);
        }
        trampoline_va
    };

    frame.sepc = handler_va;
    frame.a0   = info.sig as usize;
    frame.a1   = siginfo_va;
    frame.a2   = 0;
    frame.sp   = new_sp;
    frame.ra   = effective_restorer;
}

// ── push_sigframe_x86 ─────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn push_sigframe_x86(
    frame:      &mut crate::arch::x86_64::syscall::SyscallFrame,
    info:       &SigInfo,
    handler_va: usize,
    restorer:   usize,
    sa_flags:   u32,
    old_mask:   u64,
) {
    let pid = scheduler::current_pid() as usize;
    let base_rsp = if sa_flags & SA_ONSTACK != 0 {
        let alt = ALTSTACK.lock().get(&pid).copied().unwrap_or(AltStack::default());
        if alt.ss_flags & SS_DISABLE == 0 && alt.ss_sp != 0 {
            if alt.ss_flags & SS_AUTODISARM != 0 { ALTSTACK.lock().remove(&pid); }
            alt.ss_sp + alt.ss_size
        } else { frame.rsp }
    } else { frame.rsp };

    const UCTX_SIZE:    usize = 320;
    const SIGINFO_SIZE: usize = 80;
    const RETADDR_SIZE: usize = 8;
    const FRAME_TOTAL:  usize = UCTX_SIZE + SIGINFO_SIZE + RETADDR_SIZE;

    let new_rsp    = (base_rsp - FRAME_TOTAL) & !0xf;
    let uctx_va    = new_rsp;
    let siginfo_va = new_rsp + UCTX_SIZE;
    let retaddr_va = new_rsp + UCTX_SIZE + SIGINFO_SIZE;

    unsafe {
        core::ptr::write_bytes(uctx_va as *mut u8, 0, UCTX_SIZE);
        let gregs = (uctx_va + 40) as *mut usize;
        gregs.add(0).write(frame.r8);     gregs.add(1).write(frame.r9);
        gregs.add(2).write(frame.r10);    gregs.add(3).write(frame.rflags);
        gregs.add(4).write(frame.r12);    gregs.add(5).write(frame.r13);
        gregs.add(6).write(frame.r14);    gregs.add(7).write(frame.r15);
        gregs.add(8).write(frame.rdi);    gregs.add(9).write(frame.rsi);
        gregs.add(10).write(frame.rbp);   gregs.add(11).write(frame.rbx);
        gregs.add(12).write(frame.rdx);   gregs.add(13).write(frame.rax);
        gregs.add(14).write(frame.rip);   gregs.add(15).write(frame.rsp);
        gregs.add(16).write(frame.rip);   gregs.add(17).write(frame.rflags);
        let sigmask_ptr = (uctx_va + 296) as *mut u64;
        sigmask_ptr.write(old_mask);
    }
    unsafe {
        let si = siginfo_va as *mut u8;
        core::ptr::write_bytes(si, 0, SIGINFO_SIZE);
        (si.add(0)  as *mut i32).write(info.sig as i32);
        (si.add(8)  as *mut i32).write(info.code);
        (si.add(16) as *mut u64).write(info.addr as u64);
        (si.add(24) as *mut u32).write(info.pid);
        (si.add(28) as *mut u32).write(info.uid);
    }
    unsafe { (retaddr_va as *mut usize).write(restorer); }

    frame.rip    = handler_va;
    frame.rdi    = info.sig as usize;
    frame.rsi    = siginfo_va;
    frame.rdx    = uctx_va;
    frame.rsp    = new_rsp;
    frame.rflags = 0x202;
}

// ── sys_rt_sigreturn ───────────────────────────────────────────────────

#[cfg(target_arch = "riscv64")]
pub fn sys_rt_sigreturn(frame: &mut crate::arch::riscv64::trap::TrapFrame) -> isize {
    use crate::arch::riscv64::trap::TRAP_FRAME_SIZE;
    let saved_va = frame.sp;
    if saved_va == 0 || saved_va >= USER_SPACE_END || saved_va & 7 != 0 { return -14; }
    unsafe {
        core::ptr::copy_nonoverlapping(
            saved_va as *const u8,
            frame as *mut _ as *mut u8,
            TRAP_FRAME_SIZE,
        );
    }
    const SIGINFO_SIZE: usize = 80;
    let sigmask_va = saved_va + TRAP_FRAME_SIZE + SIGINFO_SIZE;
    let old_mask = unsafe { core::ptr::read_unaligned(sigmask_va as *const u64) };
    let pid = scheduler::current_pid() as usize;
    set_sigmask(pid, old_mask);
    0
}

#[cfg(target_arch = "x86_64")]
pub fn sys_rt_sigreturn(frame: &mut crate::arch::x86_64::syscall::SyscallFrame) -> isize {
    let uctx_va = frame.rsp;
    if uctx_va == 0 || uctx_va >= USER_SPACE_END { return -14; }
    unsafe {
        let gregs = (uctx_va + 40) as *const usize;
        frame.r8     = gregs.add(0).read();  frame.r9     = gregs.add(1).read();
        frame.r10    = gregs.add(2).read();  frame.rflags = gregs.add(3).read();
        frame.r12    = gregs.add(4).read();  frame.r13    = gregs.add(5).read();
        frame.r14    = gregs.add(6).read();  frame.r15    = gregs.add(7).read();
        frame.rdi    = gregs.add(8).read();  frame.rsi    = gregs.add(9).read();
        frame.rbp    = gregs.add(10).read(); frame.rbx    = gregs.add(11).read();
        frame.rdx    = gregs.add(12).read(); frame.rax    = gregs.add(13).read();
        frame.rsp    = gregs.add(15).read(); frame.rip    = gregs.add(16).read();
        frame.rflags = gregs.add(17).read();
        let old_mask = core::ptr::read_unaligned((uctx_va + 296) as *const u64);
        let pid = scheduler::current_pid() as usize;
        set_sigmask(pid, old_mask);
    }
    0
}

// ── sys_rt_sigpending [NR 127] ────────────────────────────────────────────

pub fn sys_rt_sigpending(set_va: usize, sigsetsize: usize) -> isize {
    if sigsetsize != 8 { return -22; }
    if set_va == 0 || set_va >= USER_SPACE_END { return -14; }
    let pid = scheduler::current_pid() as usize;
    let mut pending_set: u64 = 0;
    {
        let map = PENDING.lock();
        if let Some(queue) = map.get(&pid) {
            for info in queue.iter() {
                if info.sig >= 1 && info.sig <= 64 {
                    pending_set |= 1u64 << info.sig;
                }
            }
        }
    }
    // Also include group-pending signals not currently blocked.
    {
        let tgid = crate::proc::thread::tgid_of(pid);
        let tgid = if tgid != 0 { tgid } else { pid };
        let map = GROUP_PENDING.lock();
        if let Some(queue) = map.get(&tgid) {
            for info in queue.iter() {
                if info.sig >= 1 && info.sig <= 64 {
                    pending_set |= 1u64 << info.sig;
                }
            }
        }
    }
    if !copy_to_user(set_va, &pending_set.to_ne_bytes()) { return -14; }
    0
}

// ── sys_rt_sigsuspend [NR 130] ───────────────────────────────────────────

pub fn sys_rt_sigsuspend(mask_va: usize, sigsetsize: usize) -> isize {
    if sigsetsize != 8 { return -22; }
    if mask_va == 0 || mask_va >= USER_SPACE_END { return -14; }
    let pid = scheduler::current_pid() as usize;
    let mut mask_bytes = [0u8; 8];
    if copy_from_user(&mut mask_bytes, mask_va).is_err() { return -14; }
    let new_mask = u64::from_ne_bytes(mask_bytes) & !((1u64 << 9) | (1u64 << 19));
    let old_mask = get_sigmask(pid);
    set_sigmask(pid, new_mask);
    loop {
        // Check both per-TID and group queues.
        let has_deliverable = {
            let tid_ok = {
                let map = PENDING.lock();
                map.get(&pid).map_or(false, |q| {
                    q.iter().any(|s| s.sig >= 1 && s.sig <= 64
                        && (new_mask >> s.sig) & 1 == 0)
                })
            };
            let grp_ok = if !tid_ok {
                let tgid = crate::proc::thread::tgid_of(pid);
                let tgid = if tgid != 0 { tgid } else { pid };
                let map = GROUP_PENDING.lock();
                map.get(&tgid).map_or(false, |q| {
                    q.iter().any(|s| s.sig >= 1 && s.sig <= 64
                        && (new_mask >> s.sig) & 1 == 0)
                })
            } else { false };
            tid_ok || grp_ok
        };
        if has_deliverable {
            set_sigmask(pid, old_mask);
            return -4; // EINTR
        }
        scheduler::with_proc_mut(pid, |p, pl| {
            pl.set_state(p, State::Blocked);
        });
        scheduler::schedule();
    }
}

// ── sys_rt_sigtimedwait [NR 128] ─────────────────────────────────────────

pub fn sys_rt_sigtimedwait(
    uset_va:    usize,
    uinfo_va:   usize,
    timeout_va: usize,
    sigsetsize: usize,
) -> isize {
    if sigsetsize != 8 { return -22; }
    if uset_va == 0 || uset_va >= USER_SPACE_END { return -14; }
    let mut set_bytes = [0u8; 8];
    if copy_from_user(&mut set_bytes, uset_va).is_err() { return -14; }
    let wait_set = u64::from_ne_bytes(set_bytes);
    if wait_set == 0 { return -22; }

    let deadline_ns: Option<u64> = if timeout_va != 0 && timeout_va < USER_SPACE_END {
        let mut ts = [0u8; 16];
        if copy_from_user(&mut ts, timeout_va).is_err() { return -14; }
        let secs  = i64::from_ne_bytes(ts[0..8].try_into().unwrap());
        let nsecs = i64::from_ne_bytes(ts[8..16].try_into().unwrap());
        if secs < 0 || nsecs < 0 || nsecs >= 1_000_000_000 { return -22; }
        let rel_ns = (secs as u64).saturating_mul(1_000_000_000)
                         .saturating_add(nsecs as u64);
        Some(crate::proc::nanosleep::now_ns().saturating_add(rel_ns))
    } else {
        None
    };

    let pid = scheduler::current_pid() as usize;
    let tgid = { let t = crate::proc::thread::tgid_of(pid); if t != 0 { t } else { pid } };

    loop {
        // Try per-TID first, then group.
        let found: Option<SigInfo> = {
            let mut map = PENDING.lock();
            if let Some(queue) = map.get_mut(&pid) {
                let pos = queue.iter().position(|s| {
                    s.sig >= 1 && s.sig <= 64 && (wait_set >> s.sig) & 1 != 0
                });
                pos.and_then(|i| queue.remove(i))
            } else { None }
        }.or_else(|| {
            let mut map = GROUP_PENDING.lock();
            if let Some(queue) = map.get_mut(&tgid) {
                let pos = queue.iter().position(|s| {
                    s.sig >= 1 && s.sig <= 64 && (wait_set >> s.sig) & 1 != 0
                });
                pos.and_then(|i| queue.remove(i))
            } else { None }
        });

        if let Some(info) = found {
            if uinfo_va != 0 && uinfo_va < USER_SPACE_END {
                let mut si = [0u8; 80];
                si[0..4].copy_from_slice(&(info.sig as i32).to_ne_bytes());
                si[4..8].copy_from_slice(&info.code.to_ne_bytes());
                match info.sig {
                    17       => si[24..28].copy_from_slice(&info.status.to_ne_bytes()),
                    11|7|8   => si[16..24].copy_from_slice(&info.addr.to_ne_bytes()),
                    _        => {}
                }
                let _ = copy_to_user(uinfo_va, &si);
            }
            return info.sig as isize;
        }
        if let Some(dl) = deadline_ns {
            if crate::proc::nanosleep::now_ns() >= dl { return -11; }
        }
        // EINTR if a non-waited unblocked signal is already pending.
        {
            let mask = get_sigmask(pid);
            let tid_intr = {
                let map = PENDING.lock();
                map.get(&pid).map_or(false, |q| {
                    q.iter().any(|s| s.sig >= 1 && s.sig <= 64
                        && (wait_set >> s.sig) & 1 == 0
                        && (mask     >> s.sig) & 1 == 0)
                })
            };
            let grp_intr = if !tid_intr {
                let map = GROUP_PENDING.lock();
                map.get(&tgid).map_or(false, |q| {
                    q.iter().any(|s| s.sig >= 1 && s.sig <= 64
                        && (wait_set >> s.sig) & 1 == 0
                        && (mask     >> s.sig) & 1 == 0)
                })
            } else { false };
            if tid_intr || grp_intr { return -4; }
        }
        scheduler::with_proc_mut(pid, |p, pl| {
            pl.set_state(p, State::Blocked);
        });
        scheduler::schedule();
    }
}

// ── sys_sigaltstack [NR 131] ───────────────────────────────────────────────

pub fn sys_sigaltstack(ss_va: usize, old_ss_va: usize) -> isize {
    let pid = scheduler::current_pid() as usize;
    if old_ss_va != 0 && old_ss_va < USER_SPACE_END {
        let alt = ALTSTACK.lock().get(&pid).copied().unwrap_or(AltStack {
            ss_sp: 0, ss_flags: SS_DISABLE, ss_size: 0,
        });
        if !copy_to_user(old_ss_va,      &alt.ss_sp.to_ne_bytes())    { return -14; }
        if !copy_to_user(old_ss_va + 8,  &alt.ss_flags.to_ne_bytes()) { return -14; }
        let _ = copy_to_user(old_ss_va + 12, &0i32.to_ne_bytes());
        if !copy_to_user(old_ss_va + 16, &alt.ss_size.to_ne_bytes())  { return -14; }
    }
    if ss_va != 0 && ss_va < USER_SPACE_END {
        let mut sp_bytes    = [0u8; 8];
        let mut flags_bytes = [0u8; 4];
        let mut size_bytes  = [0u8; 8];
        if copy_from_user(&mut sp_bytes,    ss_va).is_err()     ||
           copy_from_user(&mut flags_bytes, ss_va + 8).is_err() ||
           copy_from_user(&mut size_bytes,  ss_va + 16).is_err() {
            return -14;
        }
        let ss_sp    = usize::from_ne_bytes(sp_bytes);
        let ss_flags = i32::from_ne_bytes(flags_bytes);
        let ss_size  = usize::from_ne_bytes(size_bytes);
        if ss_flags & SS_DISABLE != 0 {
            ALTSTACK.lock().remove(&pid);
        } else {
            if ss_size < 2048 { return -22; }
            ALTSTACK.lock().insert(pid, AltStack { ss_sp, ss_flags, ss_size });
        }
    }
    0
}

// ── sys_rt_sigaction [NR 13] ───────────────────────────────────────────────

pub fn sys_rt_sigaction(
    sig: u32, new_act_va: usize, old_act_va: usize, _sigsetsize: usize,
) -> isize {
    if sig == 0 || sig > 64 { return -22; }
    let pid = scheduler::current_pid() as usize;
    let idx = sig as usize;

    let handlers_arc = match scheduler::with_proc(pid, |p| p.signal_handlers.clone()) {
        Some(a) => a,
        None    => return -3,
    };

    let mut h = handlers_arc.lock();

    let old_handler  = h.handlers.get(idx).copied().unwrap_or(0);
    let old_flags    = h.flags.get(idx).copied().unwrap_or(0);
    let old_restorer = h.restorer;

    if new_act_va != 0 && new_act_va < USER_SPACE_END {
        let mut h_bytes = [0u8; 8];
        let mut f_bytes = [0u8; 8];
        let mut r_bytes = [0u8; 8];
        if copy_from_user(&mut h_bytes, new_act_va).is_ok()
            && copy_from_user(&mut f_bytes, new_act_va + 8).is_ok()
            && copy_from_user(&mut r_bytes, new_act_va + 16).is_ok()
        {
            if h.handlers.len() <= idx { h.handlers.resize(idx + 1, 0); }
            if h.flags.len()    <= idx { h.flags.resize(idx + 1, 0); }
            h.handlers[idx] = usize::from_ne_bytes(h_bytes);
            h.flags[idx]    = u64::from_ne_bytes(f_bytes) as u32;
            h.restorer      = usize::from_ne_bytes(r_bytes);
        }
    }
    drop(h);

    if old_act_va != 0 && old_act_va < USER_SPACE_END {
        if !copy_to_user(old_act_va,      &old_handler.to_ne_bytes())        { return -14; }
        if !copy_to_user(old_act_va + 8,  &(old_flags as u64).to_ne_bytes()) { return -14; }
        if !copy_to_user(old_act_va + 16, &old_restorer.to_ne_bytes())       { return -14; }
    }
    0
}

// ── sys_rt_sigprocmask [NR 14] ──────────────────────────────────────────────

pub fn sys_rt_sigprocmask(
    how: u32, set_va: usize, oldset_va: usize, sigsetsize: usize,
) -> isize {
    if sigsetsize != 8 { return -22; }
    let pid = scheduler::current_pid() as usize;
    let old = get_sigmask(pid);
    if oldset_va != 0 && oldset_va < USER_SPACE_END {
        if !copy_to_user(oldset_va, &old.to_ne_bytes()) { return -14; }
    }
    if set_va != 0 && set_va < USER_SPACE_END {
        let mut bytes = [0u8; 8];
        if copy_from_user(&mut bytes, set_va).is_err() { return -14; }
        let new_bits = u64::from_ne_bytes(bytes) & !((1u64 << 9) | (1u64 << 19));
        let new_mask = match how {
            SIG_BLOCK   => old | new_bits,
            SIG_UNBLOCK => old & !new_bits,
            SIG_SETMASK => new_bits,
            _           => return -22,
        };
        set_sigmask(pid, new_mask);
    }
    0
}

// ── sys_kill [NR 62] ─────────────────────────────────────────────────────────
//
// kill(pid, sig) routing:
//
//   pid > 0   -> group-directed to process with TGID == pid
//   pid == 0  -> group-directed to every process in caller's process group
//   pid == -1 -> broadcast to every process except pid 1 and caller
//   pid < -1  -> group-directed to process group |pid|
//
// POSIX permission checks (caller uid == target euid) are deferred to the
// capabilities audit; for now all sends are permitted (same as pid > 0 arm).

pub fn sys_kill(pid: i32, sig: i32) -> isize {
    if sig != 0 && (sig < 1 || sig > 64) { return -22; }

    match pid {
        // ── pid > 0: target a specific process group ──────────────────────
        p if p > 0 => {
            let tgid = p as usize;
            let exists = crate::proc::thread::threads_of(tgid).len() > 0
                || scheduler::with_proc(tgid, |_| ()).is_some();
            if !exists { return -3; }
            if sig == 0 { return 0; }
            send_signal_group(tgid, sig)
        }

        // ── pid == 0: send to caller's process group ──────────────────────
        0 => {
            let caller = scheduler::current_pid();
            let caller_pgid = scheduler::with_proc(caller, |p| p.pgid)
                .unwrap_or(0);
            if caller_pgid == 0 { return -3; }
            let targets = pids_in_pgrp(caller_pgid);
            if targets.is_empty() { return -3; }
            if sig == 0 { return 0; }
            for tgid in targets {
                send_signal_group(tgid, sig);
            }
            0
        }

        // ── pid == -1: broadcast (skip init and caller) ────────────────────
        -1 => {
            let caller_tgid = {
                let t = crate::proc::thread::tgid_of(scheduler::current_pid());
                if t != 0 { t } else { scheduler::current_pid() }
            };
            // Collect all TGIDs (process leaders only) in one pass.
            let all_tgids: Vec<usize> = scheduler::with_procs_ro(|procs| {
                procs.iter()
                    .filter(|p| p.pid == p.tgid && p.pid != 1 && p.pid != caller_tgid)
                    .map(|p| p.tgid)
                    .collect()
            });
            if all_tgids.is_empty() { return -3; }
            if sig == 0 { return 0; }
            for tgid in all_tgids {
                send_signal_group(tgid, sig);
            }
            0
        }

        // ── pid < -1: send to process group |pid| ────────────────────────
        p => {
            let pgid = (-p) as usize;
            let targets = pids_in_pgrp(pgid);
            if targets.is_empty() { return -3; }
            if sig == 0 { return 0; }
            for tgid in targets {
                send_signal_group(tgid, sig);
            }
            0
        }
    }
}

// ── Cleanup ───────────────────────────────────────────────────────────────────

/// Remove all per-TID signal state when a thread exits.
pub fn altstack_clear_pid(pid: usize) {
    ALTSTACK.lock().remove(&pid);
    SIGMASK.lock().remove(&pid);
    PENDING.lock().remove(&pid);
}

/// Remove GROUP_PENDING entry when the last thread of a group exits.
pub fn group_pending_clear(tgid: usize) {
    GROUP_PENDING.lock().remove(&tgid);
}
