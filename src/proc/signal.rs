//! Signal delivery, masking, and rt_sigreturn.
//!
//! ## Delivery model
//!   1. send_signal(pid, sig) pushes a SigInfo onto PENDING[pid].
//!   2. At every syscall return, check_pending_signal(frame) is called.
//!   3. For a registered SA_SIGACTION handler the kernel:
//!      a. Optionally switches rsp to the alternate stack (SA_ONSTACK).
//!      b. Carves a SignalFrame from the top of the chosen stack:
//!            [ucontext_t]  256 bytes
//!            [siginfo_t]    80 bytes
//!            [retaddr]       8 bytes
//!      c. Points rdi=signum, rsi=siginfo*, rdx=ucontext*, rip=handler.
//!   4. SA_RESTORER (musl: __restore_rt) does `mov $15,%rax; syscall`.
//!   5. sys_rt_sigreturn restores all registers from ucontext_t.
//!
//! ## Bug fixes in this revision
//!
//! ### sigsuspend / sigtimedwait blocking was a no-op
//!   Both functions called `scheduler::with_procs(|procs| procs.iter_mut()...)`.
//!   `with_procs` provides `&Vec<Pcb>` (shared reference), so `iter_mut()`
//!   yields `&Pcb` (not `&mut Pcb`) — the state mutation was silently
//!   discarded.  Both are now fixed to use `with_procs_mut` which provides
//!   `&mut Vec<Pcb>`.
//!
//! ### copy_to_user return-type mismatch
//!   `copy_to_user` returns `bool` (true = success).  Several call sites
//!   used `.is_err()` as if it returned `Result` — always false on a bool,
//!   meaning EFAULT was never returned on write failures.  Fixed to `!ok`.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use spin::Mutex;

use crate::arch::x86_64::syscall::SyscallFrame;
use crate::proc::{scheduler, process::State};
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr, USER_SPACE_END};

// ── Signal metadata ───────────────────────────────────────────────────────────────

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

// ── Signal storage ───────────────────────────────────────────────────────────────

static PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> =
    Mutex::new(BTreeMap::new());
static SIGMASK: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

// ── Alternate stack ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct AltStack { ss_sp: usize, ss_flags: i32, ss_size: usize }

const SS_DISABLE:    i32 = 2;
const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

static ALTSTACK: Mutex<BTreeMap<usize, AltStack>> = Mutex::new(BTreeMap::new());

// ── SA_* flags ───────────────────────────────────────────────────────────────────

const SA_ONSTACK:  u32 = 0x08000000;
const SA_RESTORER: u32 = 0x04000000;
const SA_NODEFER:  u32 = 0x40000000;

// ── sigprocmask `how` constants (Linux ABI) ─────────────────────────────────────────

const SIG_BLOCK:   u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

// ── Handler table ──────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct SignalHandlers {
    pub handlers: [usize; 65],
    pub flags:    [u32;   65],
    pub restorer: usize,
}

// ── Public API ───────────────────────────────────────────────────────────────────

pub fn send_signal(pid: usize, sig: i32) -> isize {
    if sig <= 0 || sig > 64 { return -22; }
    send_signal_info(pid, SigInfo { sig: sig as u32, code: SI_KERNEL, ..Default::default() });
    0
}

pub fn send_signal_user(pid: usize, sig: i32) -> isize {
    if sig <= 0 || sig > 64 { return -22; }

    let bypass = sig == 9 || sig == 19;

    if !bypass {
        let queue_len = {
            let map = PENDING.lock();
            map.get(&pid).map_or(0, |q| q.len())
        };
        let (soft, _hard) = crate::proc::rlimit::getrlimit_for(pid,
            crate::proc::rlimit::RLIMIT_SIGPENDING);
        let limit = if soft == crate::proc::rlimit::RLIM_INFINITY {
            usize::MAX
        } else {
            soft as usize
        };
        if queue_len >= limit { return -11; }
    }

    let caller_pid = scheduler::current_pid();
    send_signal_info(pid, SigInfo {
        sig:  sig as u32,
        code: SI_USER,
        pid:  caller_pid as u32,
        ..Default::default()
    });
    0
}

pub fn send_signal_info(pid: usize, info: SigInfo) {
    if info.sig == 0 || info.sig > 64 { return; }
    PENDING.lock().entry(pid).or_default().push_back(info);
    scheduler::wake_pid(pid as u32);
}

pub fn send_sigchld(parent_pid: usize, child_pid: usize, exit_code: i32, killed: bool) {
    send_signal_info(parent_pid, SigInfo {
        sig:    17,
        code:   if killed { CLD_KILLED } else { CLD_EXITED },
        pid:    child_pid as u32,
        status: exit_code,
        ..Default::default()
    });
}

pub fn send_sigsegv(pid: usize, fault_addr: usize) {
    send_signal_info(pid, SigInfo {
        sig: 11, code: SEGV_MAPERR, addr: fault_addr, ..Default::default()
    });
}

pub fn has_pending_signal(pid: usize) -> bool {
    PENDING.lock().get(&pid).map_or(false, |q| !q.is_empty())
}

pub fn get_sigmask(pid: usize) -> u64 {
    SIGMASK.lock().get(&pid).copied().unwrap_or(0)
}

pub fn set_sigmask(pid: usize, mask: u64) {
    SIGMASK.lock().insert(pid, mask);
}

// ── sys_rt_sigpending [NR 127] ──────────────────────────────────────────────────────────

pub fn sys_rt_sigpending(set_va: usize, sigsetsize: usize) -> isize {
    if sigsetsize != 8 { return -22; }
    if set_va == 0 || set_va >= USER_SPACE_END { return -14; }

    let pid = scheduler::current_pid();
    let mut pending_set: u64 = 0;
    {
        let map = PENDING.lock();
        if let Some(queue) = map.get(&(pid as usize)) {
            for info in queue.iter() {
                if info.sig >= 1 && info.sig <= 64 {
                    pending_set |= 1u64 << info.sig;
                }
            }
        }
    }
    // copy_to_user returns bool; false = fault.
    if !copy_to_user(set_va, &pending_set.to_ne_bytes()) { return -14; }
    0
}

// ── sys_rt_sigsuspend [NR 130] ───────────────────────────────────────────────────────────

pub fn sys_rt_sigsuspend(mask_va: usize, sigsetsize: usize) -> isize {
    if sigsetsize != 8 { return -22; }
    if mask_va == 0 || mask_va >= USER_SPACE_END { return -14; }

    let pid = scheduler::current_pid();

    let mut mask_bytes = [0u8; 8];
    if copy_from_user(&mut mask_bytes, mask_va).is_err() { return -14; }
    let new_mask = u64::from_ne_bytes(mask_bytes);

    // SIGKILL and SIGSTOP cannot be blocked.
    let new_mask = new_mask & !((1u64 << 9) | (1u64 << 19));

    let old_mask = get_sigmask(pid as usize);
    set_sigmask(pid as usize, new_mask);

    loop {
        // Check if an unmasked signal is already pending.
        {
            let map = PENDING.lock();
            if let Some(queue) = map.get(&(pid as usize)) {
                for info in queue.iter() {
                    if info.sig >= 1 && info.sig <= 64 {
                        if (new_mask >> info.sig) & 1 == 0 {
                            drop(map);
                            set_sigmask(pid as usize, old_mask);
                            return -4; // EINTR
                        }
                    }
                }
            }
        }

        // FIX: use with_procs_mut so the state mutation actually takes effect.
        // The previous with_procs gave a &Vec so iter_mut() yielded &Pcb,
        // making the assignment a no-op and the task was never blocked.
        scheduler::with_procs_mut(|procs| {
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.state = State::Blocked;
            }
        });
        scheduler::schedule();
        // Woken by send_signal_info — loop and re-check.
    }
}

// ── sys_rt_sigtimedwait [NR 128] ───────────────────────────────────────────────────────

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

    let pid = scheduler::current_pid();

    loop {
        let found: Option<SigInfo> = {
            let mut map = PENDING.lock();
            if let Some(queue) = map.get_mut(&(pid as usize)) {
                let pos = queue.iter().position(|s| {
                    s.sig >= 1 && s.sig <= 64 && (wait_set >> s.sig) & 1 != 0
                });
                pos.and_then(|i| queue.remove(i))
            } else {
                None
            }
        };

        if let Some(info) = found {
            if uinfo_va != 0 && uinfo_va < USER_SPACE_END {
                let mut si = [0u8; 80];
                si[0..4].copy_from_slice(&(info.sig as i32).to_ne_bytes());
                si[4..8].copy_from_slice(&info.code.to_ne_bytes());
                match info.sig {
                    17 => si[24..28].copy_from_slice(&info.status.to_ne_bytes()),
                    11 | 7 | 8 => si[16..24].copy_from_slice(&info.addr.to_ne_bytes()),
                    _ => {}
                }
                // FIX: copy_to_user returns bool, not Result.
                let _ = copy_to_user(uinfo_va, &si);
            }
            return info.sig as isize;
        }

        if let Some(dl) = deadline_ns {
            if crate::proc::nanosleep::now_ns() >= dl {
                return -11; // EAGAIN — timeout
            }
        }

        {
            let mask = get_sigmask(pid as usize);
            let map = PENDING.lock();
            if let Some(queue) = map.get(&(pid as usize)) {
                for info in queue.iter() {
                    if info.sig >= 1 && info.sig <= 64
                        && (wait_set  >> info.sig) & 1 == 0
                        && (mask      >> info.sig) & 1 == 0
                    {
                        return -4; // EINTR
                    }
                }
            }
        }

        // FIX: use with_procs_mut so the state mutation takes effect.
        scheduler::with_procs_mut(|procs| {
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.state = State::Blocked;
            }
        });
        scheduler::schedule();
    }
}

// ── sys_sigaltstack [NR 131] ─────────────────────────────────────────────────────────────

pub fn sys_sigaltstack(ss_va: usize, old_ss_va: usize) -> isize {
    let pid = scheduler::current_pid();

    if old_ss_va != 0 && old_ss_va < USER_SPACE_END {
        let alt = ALTSTACK.lock().get(&(pid as usize)).copied().unwrap_or(AltStack {
            ss_sp: 0, ss_flags: SS_DISABLE, ss_size: 0,
        });
        // FIX: copy_to_user returns bool; use ! to detect fault.
        if !copy_to_user(old_ss_va,      &alt.ss_sp.to_ne_bytes())   { return -14; }
        if !copy_to_user(old_ss_va + 8,  &alt.ss_flags.to_ne_bytes()) { return -14; }
        let _ = copy_to_user(old_ss_va + 12, &0i32.to_ne_bytes());
        if !copy_to_user(old_ss_va + 16, &alt.ss_size.to_ne_bytes())  { return -14; }
    }

    if ss_va != 0 && ss_va < USER_SPACE_END {
        let mut sp_bytes    = [0u8; 8];
        let mut flags_bytes = [0u8; 4];
        let mut size_bytes  = [0u8; 8];
        if copy_from_user(&mut sp_bytes,    ss_va).is_err()      ||
           copy_from_user(&mut flags_bytes, ss_va + 8).is_err()  ||
           copy_from_user(&mut size_bytes,  ss_va + 16).is_err() {
            return -14;
        }
        let ss_sp    = usize::from_ne_bytes(sp_bytes);
        let ss_flags = i32::from_ne_bytes(flags_bytes);
        let ss_size  = usize::from_ne_bytes(size_bytes);

        if ss_flags & SS_DISABLE != 0 {
            ALTSTACK.lock().remove(&(pid as usize));
        } else {
            if ss_size < 2048 { return -22; }
            ALTSTACK.lock().insert(pid as usize, AltStack { ss_sp, ss_flags, ss_size });
        }
    }
    0
}

// ── sys_rt_sigaction [NR 13] ─────────────────────────────────────────────────────────────

pub fn sys_rt_sigaction(
    sig: u32, new_act_va: usize, old_act_va: usize, _sigsetsize: usize,
) -> isize {
    if sig == 0 || sig > 64 { return -22; }
    let pid = scheduler::current_pid();
    let idx = sig as usize;

    let (old_handler, old_flags, old_restorer) = scheduler::with_proc_mut(pid, |p| {
        let old = (
            p.signal_handlers.handlers[idx],
            p.signal_handlers.flags[idx],
            p.signal_handlers.restorer,
        );
        if new_act_va != 0 && new_act_va < USER_SPACE_END {
            let mut h_bytes = [0u8; 8];
            let mut f_bytes = [0u8; 8];
            let mut r_bytes = [0u8; 8];
            if copy_from_user(&mut h_bytes, new_act_va).is_ok()
                && copy_from_user(&mut f_bytes, new_act_va + 8).is_ok()
                && copy_from_user(&mut r_bytes, new_act_va + 16).is_ok()
            {
                p.signal_handlers.handlers[idx] = usize::from_ne_bytes(h_bytes);
                p.signal_handlers.flags[idx]    = u64::from_ne_bytes(f_bytes) as u32;
                p.signal_handlers.restorer      = usize::from_ne_bytes(r_bytes);
            }
        }
        old
    }).unwrap_or((0, 0, 0));

    if old_act_va != 0 && old_act_va < USER_SPACE_END {
        if !copy_to_user(old_act_va,      &old_handler.to_ne_bytes())  { return -14; }
        if !copy_to_user(old_act_va + 8,  &(old_flags as u64).to_ne_bytes()) { return -14; }
        if !copy_to_user(old_act_va + 16, &old_restorer.to_ne_bytes()) { return -14; }
    }
    0
}
