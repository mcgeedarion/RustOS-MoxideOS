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

// ── SA_* flags ───────────────────────────────────────────────────────────

const SA_ONSTACK:  u32 = 0x08000000;
const SA_RESTART:  u32 = 0x10000000;   // syscall restart across signal delivery
const SA_RESTORER: u32 = 0x04000000;
const SA_NODEFER:  u32 = 0x40000000;

// ── sigprocmask how ──────────────────────────────────────────────────────

const SIG_BLOCK:   u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

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
     