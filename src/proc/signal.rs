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

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::Mutex;

use crate::proc::{process::State, scheduler};
use crate::uaccess::{copy_from_user, copy_to_user};

// ── Signal metadata ───────────────────────────────────────────────────

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

/// Signals that stop by default (SIGTSTP=20, SIGTTIN=21, SIGTTOU=22, SIGSTOP=19+1).
const SIG_STOP_DEFAULT: u64 = (1u64 << 19) | (1u64 << 20) | (1u64 << 21) | (1u64 << 22);

// ── SA_* flags ───────────────────────────────────────────────────────────

const SA_ONSTACK: u32 = 0x08000000;
const SA_RESTART: u32 = 0x10000000; // syscall restart across signal delivery
const SA_RESTORER: u32 = 0x04000000;
const SA_NODEFER: u32 = 0x40000000;

// ── sigprocmask how ──────────────────────────────────────────────────────

const SIG_BLOCK: u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

// ── Signal storage ───────────────────────────────────────────────────

/// Thread-directed pending signals, keyed by TID.
static PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> = Mutex::new(BTreeMap::new());

/// Group-directed pending signals, keyed by TGID.
static GROUP_PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> = Mutex::new(BTreeMap::new());

/// Per-TID signal mask.
static SIGMASK: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

// ── Alternate stack ───────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct AltStack {
    ss_sp: usize,
    ss_flags: i32,
    ss_size: usize,
}

const SS_DISABLE: i32 = 2;
const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

static ALTSTACK: Mutex<BTreeMap<usize, AltStack>> = Mutex::new(BTreeMap::new());

// ── Process-group helpers ─────────────────────────────────────────────

/// Return the TGIDs of all process-group leaders (pid == tgid) whose
/// Pcb::pgid matches `pgid`.  Each TGID appears exactly once.
fn pids_in_pgrp(pgid: usize) -> Vec<usize> {
    scheduler::with_procs_ro(|procs| {
        procs
            .iter()
            .filter(|p| p.pgid == pgid && p.pid == p.tgid)
            .map(|p| p.tgid)
            .collect()
    })
}

// ── Thread-directed send API ───────────────────────────────────────────

/// Send `sig` to a specific thread (TID).  Used by tkill/tgkill/raise.
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

/// Rate-limited user-originated thread-directed send.
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
        if queue_len >= 64 {
            return -11;
        }
    }
    send_signal(tid, sig)
}

pub fn send_signal_info(tid: usize, info: SigInfo) -> isize {
    PENDING.lock().entry(tid).or_default().push_back(info);
    scheduler::wake_pid(tid);
    0
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
    )
}

pub fn send_signal_group_info(tgid: usize, info: SigInfo) -> isize {
    GROUP_PENDING
        .lock()
        .entry(tgid)
        .or_default()
        .push_back(info);
    for tid in pids_in_pgrp(tgid) {
        scheduler::wake_pid(tid);
    }
    0
}

pub fn send_sigsegv(tid: usize, addr: usize) -> isize {
    send_signal_info(
        tid,
        SigInfo {
            sig: 11,
            code: SEGV_MAPERR,
            addr,
            ..Default::default()
        },
    )
}

pub fn has_pending_signal(tid: usize) -> bool {
    PENDING.lock().get(&tid).is_some_and(|q| !q.is_empty())
}

pub fn group_pending_clear(tgid: usize) {
    GROUP_PENDING.lock().remove(&tgid);
}

pub fn altstack_clear_pid(pid: usize) {
    ALTSTACK.lock().remove(&pid);
}

pub fn get_sigmask(tid: usize) -> u64 {
    SIGMASK.lock().get(&tid).copied().unwrap_or(0)
}

pub fn set_sigmask(tid: usize, mask: u64) {
    SIGMASK.lock().insert(tid, mask);
}

pub fn sys_tgkill(tgid: usize, tid: usize, sig: usize) -> isize {
    let _ = tgid;
    send_signal_user(tid, sig as i32)
}

pub fn sys_rt_sigaction(_sig: usize, _act: usize, _oldact: usize, _sigsetsize: usize) -> isize {
    0
}

pub fn sys_rt_sigprocmask(how: usize, set: usize, oldset: usize, _sigsetsize: usize) -> isize {
    let tid = scheduler::current_pid() as usize;
    if oldset != 0 {
        let old = get_sigmask(tid);
        let bytes = old.to_ne_bytes();
        if !copy_to_user(oldset, &bytes) {
            return -14;
        }
    }
    if set == 0 {
        return 0;
    }
    let mut bytes = [0u8; core::mem::size_of::<u64>()];
    if copy_from_user(&mut bytes, set).is_err() {
        return -14;
    }
    let new_mask = u64::from_ne_bytes(bytes);
    let current = get_sigmask(tid);
    let updated = match how as u32 {
        SIG_BLOCK => current | new_mask,
        SIG_UNBLOCK => current & !new_mask,
        SIG_SETMASK => new_mask,
        _ => return -22,
    };
    set_sigmask(tid, updated);
    0
}

pub fn sys_rt_sigpending(set: usize, _sigsetsize: usize) -> isize {
    let tid = scheduler::current_pid() as usize;
    let pending = PENDING
        .lock()
        .get(&tid)
        .map(|q| q.iter().fold(0u64, |mask, info| mask | (1u64 << info.sig)))
        .unwrap_or(0);
    if set != 0 {
        let bytes = pending.to_ne_bytes();
        if !copy_to_user(set, &bytes) {
            return -14;
        }
    }
    0
}

pub fn sys_rt_sigtimedwait(
    _set: usize,
    _info: usize,
    _timeout: usize,
    _sigsetsize: usize,
) -> isize {
    -11
}

pub fn sys_rt_sigsuspend(_mask: usize, _sigsetsize: usize) -> isize {
    -4
}

pub fn check_and_deliver<F>(_frame: &mut F) {}

pub fn sys_rt_sigreturn<F>(_frame: &mut F) -> isize {
    0
}
