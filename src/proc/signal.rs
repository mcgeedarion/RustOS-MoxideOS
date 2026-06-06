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
//! ## SA_RESTART
//!
//!   When a signal with SA_RESTART set interrupts a restartable syscall,
//!   `check_and_deliver_with_sepc` (called from the RISC-V ecall path)
//!   replays the syscall instead of returning -EINTR to userspace.
//!   The syscall must have previously called `restart::set_restart` with
//!   a `RestartBlock` describing the arguments for the replay.
//!
//! ## Post-S2 locking notes
//!
//!   - send_signal_group_info wakes all threads in the group.
//!   - check_and_deliver uses with_proc_mut for SIGSTOP.
//!   - sys_rt_sigsuspend / sys_rt_sigtimedwait use with_proc_mut.
//!
//! ## AArch64 extensions
//!
//!   `check_and_deliver_aarch64` and `sys_rt_sigreturn_aarch64` mirror
//!   the x86_64 counterparts, using `ExceptionFrame` instead of `SyscallFrame`.
//!   The signal frame pushed on the user stack is ABI-compatible with
//!   musl's `struct ucontext` for aarch64 (`uc_mcontext.regs[0..30]`,
//!   `uc_mcontext.sp`, `uc_mcontext.pc`, `uc_mcontext.pstate`).

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::Mutex;

use crate::proc::{process::State, scheduler};
use crate::uaccess::{copy_from_user, copy_to_user, USER_SPACE_END};

#[derive(Clone, Copy, Default, Debug)]
pub struct SigInfo {
    pub sig: u32,
    pub code: i32,
    pub pid: u32,
    pub uid: u32,
    pub status: i32,
    pub addr: usize,
    pub value: i64,
}

const SI_KERNEL: i32 = 128;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const SEGV_MAPERR: i32 = 1;
const SI_USER: i32 = 0;

/// Signals that are ignored by default (SIGCHLD=17, SIGURG=23, SIGWINCH=28).
const SIG_IGN_DEFAULT: u64 = (1u64 << 17) | (1u64 << 23) | (1u64 << 28);

/// Signals that stop by default (SIGTSTP=20, SIGTTIN=21, SIGTTOU=22,
/// SIGSTOP=19+1).
const SIG_STOP_DEFAULT: u64 = (1u64 << 19) | (1u64 << 20) | (1u64 << 21) | (1u64 << 22);

const SA_ONSTACK: u32 = 0x08000000;
const SA_RESTART: u32 = 0x10000000;
const SA_RESTORER: u32 = 0x04000000;
const SA_NODEFER: u32 = 0x40000000;

const SIG_BLOCK: u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

/// Thread-directed pending signals, keyed by TID.
static PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> = Mutex::new(BTreeMap::new());

/// Group-directed pending signals, keyed by TGID.
static GROUP_PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> = Mutex::new(BTreeMap::new());

/// Per-TID signal mask.
static SIGMASK: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

#[derive(Clone, Copy, Default)]
struct AltStack {
    ss_sp: usize,
    ss_flags: i32,
    ss_size: usize,
}

const SS_DISABLE: i32 = 2;
const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

static ALTSTACK: Mutex<BTreeMap<usize, AltStack>> = Mutex::new(BTreeMap::new());

fn pids_in_pgrp(pgid: usize) -> Vec<usize> {
    scheduler::with_procs_ro(|procs| {
        procs
            .iter()
            .filter(|p| p.pgid == pgid && p.pid == p.tgid)
            .map(|p| p.tgid)
            .collect()
    })
}

pub fn send_signal(tid: usize, sig: i32) -> isize {
    if sig <= 0 || sig > 64 {
        return -22;
    }
    send_signal_info(
        tid,
        SigInfo {
            sig: sig as u32,
            code: SI_KERNEL,
            ..Default::default()
        },
    );
    0
}

pub fn send_signal_user(tid: usize, sig: i32) -> isize {
    if sig <= 0 || sig > 64 {
        return -22;
    }
    let bypass = sig == 9 || sig == 19;
    if !bypass {
        let queue_len = {
            let map = PENDING.lock();
            map.get(&tid).map_or(0, |q| q.len())
        };
        if queue_len >= 32 {
            return -11;
        }
    }
    send_signal_info(
        tid,
        SigInfo {
            sig: sig as u32,
            code: SI_USER,
            pid: scheduler::current_pid() as u32,
            ..Default::default()
        },
    );
    0
}

pub fn send_signal_info(tid: usize, info: SigInfo) {
    if info.sig == 0 {
        return;
    }
    let sig = info.sig;
    PENDING
        .lock()
        .entry(tid)
        .or_insert_with(VecDeque::new)
        .push_back(info);
    scheduler::wake_for_signal(tid, sig);
}

pub fn send_signal_group(tgid: usize, sig: i32) -> isize {
    if sig <= 0 || sig > 64 {
        return -22;
    }
    send_signal_group_info(
        tgid,
        SigInfo {
            sig: sig as u32,
            code: SI_KERNEL,
            ..Default::default()
        },
    );
    0
}

pub fn send_signal_group_info(tgid: usize, info: SigInfo) {
    if info.sig == 0 {
        return;
    }
    let sig = info.sig;
    GROUP_PENDING
        .lock()
        .entry(tgid)
        .or_insert_with(VecDeque::new)
        .push_back(info);
    scheduler::with_procs_ro(|procs| {
        for p in procs.iter().filter(|p| p.tgid == tgid) {
            scheduler::wake_for_signal(p.pid, sig);
        }
    });
}

fn pop_pending(tid: usize) -> Option<SigInfo> {
    PENDING.lock().get_mut(&tid)?.pop_front()
}

fn pop_group_pending(tgid: usize) -> Option<SigInfo> {
    GROUP_PENDING.lock().get_mut(&tgid)?.pop_front()
}

#[derive(Clone, Copy, Default)]
pub struct SigAction {
    pub handler: usize,
    pub flags: u32,
    pub restorer: usize,
    pub mask: u64,
}

static SIGACTIONS: Mutex<BTreeMap<(usize, u32), SigAction>> = Mutex::new(BTreeMap::new());

pub fn get_sigaction(pid: usize, sig: u32) -> SigAction {
    SIGACTIONS
        .lock()
        .get(&(pid, sig))
        .copied()
        .unwrap_or_default()
}

pub fn set_sigaction(pid: usize, sig: u32, sa: SigAction) {
    SIGACTIONS.lock().insert((pid, sig), sa);
}

#[repr(C)]
struct SigFrameX86 {
    pretcode: u64,
    uc_flags: u64,
    uc_link: u64,
    uc_stack_ss_sp: u64,
    uc_stack_ss_flags: u32,
    uc_stack_ss_size: u64,
    // mcontext (r8..rip, cs, eflags, rsp, ss)
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rax: u64,
    rcx: u64,
    rsp: u64,
    rip: u64,
    eflags: u64,
    cs: u16,
    _pad: [u16; 3],
    ss: u16,
    _pad2: [u16; 3],
    // siginfo
    si_signo: u32,
    si_errno: u32,
    si_code: i32,
    si_addr: u64,
    // sigmask
    sig_mask: u64,
}

// musl's aarch64 ucontext_t.uc_mcontext layout:
//   regs[0..30]  x0-x30  (31 × u64)
//   sp           u64
//   pc           u64
//   pstate       u64
// We push: magic(u64) | saved_frame | siginfo | sig_mask
// The restorer (in user space) executes `svc #139` (rt_sigreturn).

#[repr(C)]
struct SigFrameAarch64 {
    magic: u64, // 0xDEAD_BEEF_CAFE_0000 for stack-frame identification
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    si_signo: u32,
    si_code: i32,
    si_addr: u64,
    sig_mask: u64,
    restorer: u64, // userspace restorer VA (SVC #139 stub)
}

const SIGFRAME_AARCH64_MAGIC: u64 = 0xDEAD_BEEF_CAFE_0000;

fn push_sigframe_x86(
    frame: &mut crate::arch::x86_64::syscall::SyscallFrame,
    sa: &SigAction,
    info: &SigInfo,
) -> bool {
    let user_rsp = (frame.rsp - core::mem::size_of::<SigFrameX86>()) & !15;
    if user_rsp < 0x1000 || user_rsp >= USER_SPACE_END {
        return false;
    }
    let sf = SigFrameX86 {
        pretcode: sa.restorer as u64,
        uc_flags: 0,
        uc_link: 0,
        uc_stack_ss_sp: 0,
        uc_stack_ss_flags: SS_DISABLE as u32,
        uc_stack_ss_size: 0,
        r8: 0,
        r9: 0,
        r10: 0,
        r11: frame.rflags as u64,
        r12: frame.r12 as u64,
        r13: frame.r13 as u64,
        r14: frame.r14 as u64,
        r15: frame.r15 as u64,
        rdi: frame.rdi as u64,
        rsi: frame.rsi as u64,
        rbp: frame.rbp as u64,
        rbx: frame.rbx as u64,
        rdx: frame.rdx as u64,
        rax: frame.rax as u64,
        rcx: frame.rip as u64,
        rsp: frame.rsp as u64,
        rip: frame.rip as u64,
        eflags: frame.rflags as u64,
        cs: 0x1b,
        _pad: [0; 3],
        ss: 0x23,
        _pad2: [0; 3],
        si_signo: info.sig,
        si_errno: 0,
        si_code: info.code,
        si_addr: info.addr as u64,
        sig_mask: sigmask_for(scheduler::current_pid()),
    };
    if !copy_to_user(user_rsp, unsafe {
        core::slice::from_raw_parts(
            &sf as *const _ as *const u8,
            core::mem::size_of::<SigFrameX86>(),
        )
    }) {
        return false;
    }
    frame.rsp = user_rsp;
    frame.rip = sa.handler;
    frame.rdi = info.sig as usize;
    frame.rsi = user_rsp + 16; // siginfo_t pointer
    frame.rdx = user_rsp; // ucontext_t pointer
    true
}

/// Push a signal frame onto the user stack and redirect ELR/SP to the handler.
///
/// Called by `check_and_deliver_aarch64` when a signal is deliverable.
/// Returns `true` on success, `false` if the user stack is not accessible.
fn push_sigframe_aarch64(
    frame: &mut crate::arch::aarch64::interrupts::ExceptionFrame,
    sa: &SigAction,
    info: &SigInfo,
) -> bool {
    let sp = (frame.sp_el0 as usize).wrapping_sub(core::mem::size_of::<SigFrameAarch64>()) & !15;
    if sp < 0x1000 || sp >= USER_SPACE_END {
        return false;
    }

    let mut regs = [0u64; 31];
    regs.copy_from_slice(&frame.x);

    let sf = SigFrameAarch64 {
        magic: SIGFRAME_AARCH64_MAGIC,
        regs,
        sp: frame.sp_el0,
        pc: frame.elr_el1,
        pstate: frame.spsr_el1,
        si_signo: info.sig,
        si_code: info.code,
        si_addr: info.addr as u64,
        sig_mask: sigmask_for(scheduler::current_pid()),
        restorer: sa.restorer as u64,
    };

    if !copy_to_user(sp, unsafe {
        core::slice::from_raw_parts(
            &sf as *const _ as *const u8,
            core::mem::size_of::<SigFrameAarch64>(),
        )
    }) {
        return false;
    }

    frame.sp_el0 = sp as u64;
    frame.elr_el1 = sa.handler as u64;
    frame.spsr_el1 = frame.spsr_el1 & !0xf; // keep condition flags, EL0t
    frame.x[0] = info.sig as u64; // first argument = signum
    frame.x[1] = (sp + 8) as u64; // siginfo_t pointer (after magic)
    frame.x[2] = sp as u64; // ucontext_t pointer
    frame.x[30] = sa.restorer as u64; // LR = restorer
    true
}

fn sigmask_for(tid: usize) -> u64 {
    SIGMASK.lock().get(&tid).copied().unwrap_or(0)
}

fn is_masked(tid: usize, sig: u32) -> bool {
    if sig == 0 || sig > 64 {
        return true;
    }
    let mask = sigmask_for(tid);
    (mask >> (sig - 1)) & 1 != 0
}

fn apply_default(pid: usize, info: &SigInfo) {
    let bit = 1u64 << (info.sig.saturating_sub(1));
    if SIG_IGN_DEFAULT & bit != 0 {
        return;
    }
    if SIG_STOP_DEFAULT & bit != 0 {
        scheduler::with_proc_mut(pid, |p| {
            p.state = State::Stopped;
        });
        return;
    }
    // Default terminate.
    crate::proc::exit::do_exit(pid, (info.sig as i32) << 8);
}

/// Called by `rust_syscall_handler` after every syscall (except rt_sigreturn).
pub fn check_and_deliver(frame: &mut crate::arch::x86_64::syscall::SyscallFrame) {
    let tid = scheduler::current_pid();
    let tgid = scheduler::with_proc(tid, |p| p.tgid).unwrap_or(tid);

    let info = pop_pending(tid).or_else(|| pop_group_pending(tgid));

    let info = match info {
        Some(i) if !is_masked(tid, i.sig) => i,
        Some(i) => {
            put_back_pending(tid, i);
            return;
        },
        None => return,
    };

    let sa = get_sigaction(tgid, info.sig);
    if sa.handler == 0 {
        apply_default(tid, &info);
        return;
    }
    if sa.handler == 1 {
        return;
    } // SIG_IGN

    if !push_sigframe_x86(frame, &sa, &info) {
        apply_default(tid, &info);
    }
}

/// Called from `syscall_asm_entry` on NR 15 (rt_sigreturn) for x86_64.
pub fn sys_rt_sigreturn(frame: &mut crate::arch::x86_64::syscall::SyscallFrame) {
    let sp = frame.rsp;
    let sf_size = core::mem::size_of::<SigFrameX86>();
    let sf_va = sp;
    let mut bytes = [0u8; core::mem::size_of::<SigFrameX86>()];
    if !copy_from_user(sf_va, &mut bytes) {
        return;
    }
    let sf: SigFrameX86 = unsafe { core::mem::transmute(bytes) };
    frame.rip = sf.rip as usize;
    frame.rflags = sf.eflags as usize;
    frame.rsp = sf.rsp as usize;
    frame.rax = sf.rax as usize;
    frame.rbx = sf.rbx as usize;
    frame.rbp = sf.rbp as usize;
    frame.rdi = sf.rdi as usize;
    frame.rsi = sf.rsi as usize;
    frame.rdx = sf.rdx as usize;
    frame.r12 = sf.r12 as usize;
    frame.r13 = sf.r13 as usize;
    frame.r14 = sf.r14 as usize;
    frame.r15 = sf.r15 as usize;
    let tid = scheduler::current_pid();
    *SIGMASK.lock().entry(tid).or_insert(0) = sf.sig_mask;
    let _ = sf_size;
}

/// Called by `aarch64_sync_handler` after every SVC (except rt_sigreturn).
///
/// Mirrors `check_and_deliver` but operates on `ExceptionFrame`.
pub fn check_and_deliver_aarch64(frame: &mut crate::arch::aarch64::interrupts::ExceptionFrame) {
    let tid = scheduler::current_pid();
    let tgid = scheduler::with_proc(tid, |p| p.tgid).unwrap_or(tid);

    let info = pop_pending(tid).or_else(|| pop_group_pending(tgid));

    let info = match info {
        Some(i) if !is_masked(tid, i.sig) => i,
        Some(i) => {
            put_back_pending(tid, i);
            return;
        },
        None => return,
    };

    let sa = get_sigaction(tgid, info.sig);
    if sa.handler == 0 {
        apply_default(tid, &info);
        return;
    }
    if sa.handler == 1 {
        return;
    } // SIG_IGN

    if !push_sigframe_aarch64(frame, &sa, &info) {
        apply_default(tid, &info);
    }
}

/// Called from `aarch64_sync_handler` when ESR_EC == SVC64 and x8 == 139
/// (rt_sigreturn).  Restores the pre-signal `ExceptionFrame` from the user
/// stack.
pub fn sys_rt_sigreturn_aarch64(frame: &mut crate::arch::aarch64::interrupts::ExceptionFrame) {
    let sp = frame.sp_el0 as usize;
    let sf_size = core::mem::size_of::<SigFrameAarch64>();

    let mut bytes = alloc::vec![0u8; sf_size];
    if !copy_from_user(sp, &mut bytes) {
        return;
    }

    // Verify the magic to detect a corrupt / spoofed frame.
    let magic = u64::from_ne_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
    if magic != SIGFRAME_AARCH64_MAGIC {
        return;
    }

    // SAFETY: SigFrameAarch64 is repr(C) with no padding, sizes match.
    let sf: SigFrameAarch64 =
        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const SigFrameAarch64) };

    // Restore GPRs and exception-state fields.
    frame.x.copy_from_slice(&sf.regs);
    frame.sp_el0 = sf.sp;
    frame.elr_el1 = sf.pc;
    frame.spsr_el1 = sf.pstate;

    // Restore the pre-signal signal mask.
    let tid = scheduler::current_pid();
    *SIGMASK.lock().entry(tid).or_insert(0) = sf.sig_mask;
}

fn put_back_pending(tid: usize, info: SigInfo) {
    PENDING
        .lock()
        .entry(tid)
        .or_insert_with(VecDeque::new)
        .push_front(info);
}

pub fn sys_rt_sigaction(
    pid: usize,
    sig: u32,
    new_sa: Option<SigAction>,
    old_sa: Option<&mut SigAction>,
) -> isize {
    if sig == 0 || sig > 64 {
        return -22;
    }
    if let Some(old) = old_sa {
        *old = get_sigaction(pid, sig);
    }
    if let Some(sa) = new_sa {
        set_sigaction(pid, sig, sa);
    }
    0
}

pub fn sys_rt_sigprocmask(
    how: u32,
    set: Option<u64>,
    oldset: Option<&mut u64>,
    pid: usize,
) -> isize {
    let mut mask = SIGMASK.lock();
    let current = mask.entry(pid).or_insert(0);
    if let Some(old) = oldset {
        *old = *current;
    }
    if let Some(s) = set {
        match how {
            SIG_BLOCK => *current |= s,
            SIG_UNBLOCK => *current &= !s,
            SIG_SETMASK => *current = s,
            _ => return -22,
        }
        // SIGKILL (9) and SIGSTOP (19) cannot be masked.
        *current &= !((1u64 << 8) | (1u64 << 18));
    }
    0
}

pub fn sys_rt_sigpending(pid: usize) -> u64 {
    let thread = PENDING.lock().get(&pid).map_or(0u64, |q| {
        q.iter()
            .fold(0u64, |acc, i| acc | (1u64 << i.sig.saturating_sub(1)))
    });
    let tgid = scheduler::with_proc(pid, |p| p.tgid).unwrap_or(pid);
    let group = GROUP_PENDING.lock().get(&tgid).map_or(0u64, |q| {
        q.iter()
            .fold(0u64, |acc, i| acc | (1u64 << i.sig.saturating_sub(1)))
    });
    thread | group
}

pub fn send_sigchld(parent_pid: usize, child_pid: usize, exit_code: i32) {
    send_signal_group_info(
        parent_pid,
        SigInfo {
            sig: 17,
            code: if exit_code >= 0 {
                CLD_EXITED
            } else {
                CLD_KILLED
            },
            pid: child_pid as u32,
            status: exit_code,
            ..Default::default()
        },
    );
}

pub fn send_sigsegv(pid: usize, fault_addr: usize) {
    send_signal_info(
        pid,
        SigInfo {
            sig: 11,
            code: SEGV_MAPERR,
            addr: fault_addr,
            ..Default::default()
        },
    );
}
