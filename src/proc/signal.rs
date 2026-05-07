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
//! ## New in this revision
//!   NR 127  rt_sigpending(set, sigsetsize)
//!   NR 128  rt_sigtimedwait(set, info, timeout, sigsetsize)
//!   NR 130  rt_sigsuspend(mask, sigsetsize)
//!
//! ### rt_sigpending
//!   Writes the set of currently pending-and-unmasked signals to *set.
//!   Actually follows Linux: writes ALL pending signals regardless of mask
//!   (the caller can AND with the current mask itself).  POSIX requires
//!   "signals that are both blocked AND pending"; Linux returns all pending.
//!   We match Linux: return pending & ~0 (everything queued).
//!
//! ### rt_sigsuspend
//!   Atomically replaces the signal mask with `mask`, then blocks until a
//!   signal that is NOT in `mask` is delivered (or any signal arrives if
//!   the handler is SIG_DFL and the signal isn't ignored).  On return the
//!   original mask is restored and -EINTR is returned.
//!
//!   Implementation:
//!     1. Save old mask, install new mask.
//!     2. Mark task Blocked.
//!     3. schedule() — will return once check_pending_signal (which runs
//!        on every wake) delivers an unmasked signal.
//!     4. Restore old mask.
//!     5. Return -EINTR (-4).
//!
//!   The subtle invariant: check_pending_signal fires AFTER we return from
//!   schedule(), so delivery happens at the next syscall exit checkpoint.
//!   That is correct — POSIX allows delivery to happen on sigreturn.
//!
//! ### rt_sigtimedwait
//!   Waits for any signal in `set` to become pending (i.e. a signal that
//!   the caller is deliberately waiting for).  Returns the signal number
//!   (positive) or -EAGAIN on timeout / -EINTR if interrupted by a
//!   different signal.
//!
//!   Unlike rt_sigsuspend the caller specifies a SET of signals to WAIT
//!   FOR, not a mask of signals to block.  The implementation:
//!     1. Check if any pending signal matches `set` — return immediately if so.
//!     2. Block the calling task (State::Blocked).
//!     3. schedule() until woken by send_signal.
//!     4. On each wake, re-check PENDING for a matching signal.
//!     5. On timeout, return -EAGAIN.
//!
//!   Timeout: if `timeout_va == 0` wait forever; otherwise read the
//!   timespec and use nanosleep-style deadline comparison.  Timer
//!   resolution is limited by the current scheduler tick until a
//!   preemptive timer is wired.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use spin::Mutex;

use crate::arch::x86_64::syscall::SyscallFrame;
use crate::proc::{scheduler, process::State};
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr, USER_SPACE_END};

// ── Signal metadata ───────────────────────────────────────────────────────────

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

// ── Signal storage ─────────────────────────────────────────────────────────────────────

static PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> =
    Mutex::new(BTreeMap::new());
static SIGMASK: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

// ── Alternate stack ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct AltStack { ss_sp: usize, ss_flags: i32, ss_size: usize }

const SS_DISABLE:    i32 = 2;
const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

static ALTSTACK: Mutex<BTreeMap<usize, AltStack>> = Mutex::new(BTreeMap::new());

// ── SA_* flags ───────────────────────────────────────────────────────────────────────────

const SA_ONSTACK:  u32 = 0x08000000;
const SA_RESTORER: u32 = 0x04000000;
const SA_NODEFER:  u32 = 0x40000000;

// ── sigprocmask `how` constants (Linux ABI) ────────────────────────────────────────────────

const SIG_BLOCK:   u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

// ── Handler table ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct SignalHandlers {
    pub handlers: [usize; 65],
    pub flags:    [u32;   65],
    pub restorer: usize,
}

// ── Public API ─────────────────────────────────────────────────────────────────────────

pub fn send_signal(pid: usize, sig: i32) -> isize {
    if sig <= 0 || sig > 64 { return -22; } // EINVAL
    send_signal_info(pid, SigInfo { sig: sig as u32, code: SI_KERNEL, ..Default::default() });
    0
}

pub fn send_signal_info(pid: usize, info: SigInfo) {
    if info.sig == 0 || info.sig > 64 { return; }
    PENDING.lock().entry(pid).or_default().push_back(info);
    scheduler::wake_pid(pid);
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

// ── sys_rt_sigpending [NR 127] ────────────────────────────────────────────────────────
//
// Writes a sigset_t (8 bytes on x86-64) to *set that contains all signals
// currently pending for the calling thread.  Matches Linux semantics:
// returns the full pending set (not intersected with the current mask).
// sigsetsize must be 8; return -EINVAL otherwise.

pub fn sys_rt_sigpending(set_va: usize, sigsetsize: usize) -> isize {
    if sigsetsize != 8 { return -22; } // EINVAL
    if set_va == 0 || set_va >= USER_SPACE_END { return -14; } // EFAULT

    let pid = scheduler::current_pid();
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
    if copy_to_user(set_va, &pending_set.to_ne_bytes()).is_err() { return -14; }
    0
}

// ── sys_rt_sigsuspend [NR 130] ────────────────────────────────────────────────────────
//
// Atomically installs `mask` as the current signal mask, then suspends the
// calling task until a signal that is not blocked by `mask` arrives.
//
// On return:
//   - The old signal mask is always restored.
//   - Returns -EINTR (always — POSIX requires this).
//   - The arriving signal's handler has been invoked via check_pending_signal
//     at the next syscall-exit checkpoint (after schedule() returns).
//
// ABI: mask_va points to a sigset_t (8 bytes); sigsetsize must be 8.

pub fn sys_rt_sigsuspend(mask_va: usize, sigsetsize: usize) -> isize {
    if sigsetsize != 8 { return -22; } // EINVAL
    if mask_va == 0 || mask_va >= USER_SPACE_END { return -14; } // EFAULT

    let pid = scheduler::current_pid();

    // Read the temporary mask.
    let mut mask_bytes = [0u8; 8];
    if copy_from_user(&mut mask_bytes, mask_va).is_err() { return -14; }
    let new_mask = u64::from_ne_bytes(mask_bytes);

    // SIGKILL (9) and SIGSTOP (19) cannot be blocked.
    let new_mask = new_mask & !((1u64 << 9) | (1u64 << 19));

    // Save old mask and install the temporary one atomically.
    let old_mask = get_sigmask(pid);
    set_sigmask(pid, new_mask);

    // Block until a signal that is NOT in new_mask is queued.
    // We spin in the scheduler: block ourselves, yield, and on each wake
    // check whether an unmasked signal is now pending.
    loop {
        // Check now — a signal may have arrived before we blocked.
        {
            let map = PENDING.lock();
            if let Some(queue) = map.get(&pid) {
                for info in queue.iter() {
                    if info.sig >= 1 && info.sig <= 64 {
                        // An unmasked (deliverable) signal is pending.
                        if (new_mask >> info.sig) & 1 == 0 {
                            drop(map);
                            // Restore original mask before returning.
                            // check_pending_signal will deliver the signal
                            // on the next syscall-exit pass.
                            set_sigmask(pid, old_mask);
                            return -4; // EINTR
                        }
                    }
                }
            }
        }

        // No deliverable signal yet — sleep.
        scheduler::with_procs(|procs| {
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.state = State::Blocked;
            }
        });
        scheduler::schedule();
        // Woken by send_signal_info — loop and re-check.
    }
}

// ── sys_rt_sigtimedwait [NR 128] ─────────────────────────────────────────────────────
//
// Suspends the calling task until one of the signals in `uset` becomes
// pending, or the timeout expires.
//
// ABI:
//   uset_va    — const sigset_t * (signals to WAIT FOR, not to block)
//   uinfo_va   — siginfo_t *      (out; may be NULL)
//   timeout_va — const timespec * (NULL = wait forever)
//   sigsetsize — must be 8
//
// Returns:
//   signal number (positive) on success
//   -EAGAIN  on timeout (-11)
//   -EINTR   if interrupted by a signal not in `uset` (-4)
//   -EINVAL  bad sigsetsize or empty uset
//   -EFAULT  bad pointer
//
// Key difference from rt_sigsuspend: the caller is waiting FOR these
// signals (they're typically blocked via rt_sigprocmask so they queue
// rather than invoke the default action), and the kernel dequeues the
// first match and returns its number.
//
// Timeout: we read a timespec and compute a deadline using now_ns().
// The scheduler is cooperative for now, so we poll on each reschedule.

pub fn sys_rt_sigtimedwait(
    uset_va:    usize,
    uinfo_va:   usize,
    timeout_va: usize,
    sigsetsize: usize,
) -> isize {
    if sigsetsize != 8 { return -22; } // EINVAL
    if uset_va == 0 || uset_va >= USER_SPACE_END { return -14; } // EFAULT

    // Read the wait set.
    let mut set_bytes = [0u8; 8];
    if copy_from_user(&mut set_bytes, uset_va).is_err() { return -14; }
    let wait_set = u64::from_ne_bytes(set_bytes);
    if wait_set == 0 { return -22; } // EINVAL — empty wait set

    // Read optional timeout.
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
        None // wait forever
    };

    let pid = scheduler::current_pid();

    loop {
        // ── Check for a matching pending signal ───────────────────────────────
        let found: Option<SigInfo> = {
            let mut map = PENDING.lock();
            if let Some(queue) = map.get_mut(&pid) {
                let pos = queue.iter().position(|s| {
                    s.sig >= 1 && s.sig <= 64 && (wait_set >> s.sig) & 1 != 0
                });
                pos.and_then(|i| queue.remove(i))
            } else {
                None
            }
        };

        if let Some(info) = found {
            // Optionally write siginfo_t back to the caller.
            if uinfo_va != 0 && uinfo_va < USER_SPACE_END {
                let mut si = [0u8; 80];
                si[0..4].copy_from_slice(&(info.sig as i32).to_ne_bytes());
                si[4..8].copy_from_slice(&info.code.to_ne_bytes());
                match info.sig {
                    17 => si[24..28].copy_from_slice(&info.status.to_ne_bytes()),
                    11 | 7 | 8 => si[16..24].copy_from_slice(&info.addr.to_ne_bytes()),
                    _ => {}
                }
                let _ = copy_to_user(uinfo_va, &si);
            }
            return info.sig as isize; // success: return signal number
        }

        // ── Check timeout ─────────────────────────────────────────────────────────
        if let Some(dl) = deadline_ns {
            if crate::proc::nanosleep::now_ns() >= dl {
                return -11; // EAGAIN — timeout
            }
        }

        // ── Check if a non-waited signal is pending (return -EINTR) ───────────
        {
            let mask = get_sigmask(pid);
            let map = PENDING.lock();
            if let Some(queue) = map.get(&pid) {
                for info in queue.iter() {
                    // An unmasked, non-waited signal is pending — abort.
                    if info.sig >= 1 && info.sig <= 64
                        && (wait_set  >> info.sig) & 1 == 0
                        && (mask      >> info.sig) & 1 == 0
                    {
                        return -4; // EINTR
                    }
                }
            }
        }

        // ── Sleep until woken by send_signal_info ──────────────────────────
        scheduler::with_procs(|procs| {
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.state = State::Blocked;
            }
        });
        scheduler::schedule();
    }
}

// ── sys_sigaltstack [NR 131] ──────────────────────────────────────────────────────────────

pub fn sys_sigaltstack(ss_va: usize, old_ss_va: usize) -> isize {
    let pid = scheduler::current_pid();

    if old_ss_va != 0 && old_ss_va < USER_SPACE_END {
        let alt = ALTSTACK.lock().get(&pid).copied().unwrap_or(AltStack {
            ss_sp: 0, ss_flags: SS_DISABLE, ss_size: 0,
        });
        let _ = copy_to_user(old_ss_va,      &alt.ss_sp.to_ne_bytes());
        let _ = copy_to_user(old_ss_va + 8,  &alt.ss_flags.to_ne_bytes());
        let _ = copy_to_user(old_ss_va + 12, &0i32.to_ne_bytes());
        let _ = copy_to_user(old_ss_va + 16, &alt.ss_size.to_ne_bytes());
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
            ALTSTACK.lock().remove(&pid);
        } else {
            if ss_size < 2048 { return -22; }
            ALTSTACK.lock().insert(pid, AltStack { ss_sp, ss_flags, ss_size });
        }
    }
    0
}

// ── sys_rt_sigaction [NR 13] ───────────────────────────────────────────────────────────────

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
        let _ = copy_to_user(old_act_va,      &old_handler.to_ne_bytes());
        let _ = copy_to_user(old_act_va + 8,  &(old_flags as u64).to_ne_bytes());
        let _ = copy_to_user(old_act_va + 16, &old_restorer.to_ne_bytes());
        let _ = copy_to_user(old_act_va + 24, &0u64.to_ne_bytes());
    }
    0
}

// ── sys_rt_sigprocmask [NR 14] ──────────────────────────────────────────────────────────────

pub fn sys_rt_sigprocmask(how: u32, set_va: usize, oldset_va: usize, _sz: usize) -> isize {
    let pid = scheduler::current_pid();
    let cur = get_sigmask(pid);

    if oldset_va != 0 && oldset_va < USER_SPACE_END {
        let _ = copy_to_user(oldset_va, &cur.to_ne_bytes());
    }
    if set_va == 0 || set_va >= USER_SPACE_END { return 0; }

    let mut set_bytes = [0u8; 8];
    if copy_from_user(&mut set_bytes, set_va).is_err() { return -14; }
    let new_set = u64::from_ne_bytes(set_bytes);

    let updated = match how {
        SIG_BLOCK   => cur | new_set,
        SIG_UNBLOCK => cur & !new_set,
        SIG_SETMASK => new_set,
        _ => return -22,
    };
    // SIGKILL (9) and SIGSTOP (19) cannot be masked.
    set_sigmask(pid, updated & !((1u64 << 9) | (1u64 << 19)));
    0
}

// ── Signal frame layout ────────────────────────────────────────────────────────────────────────

const UCONTEXT_SIZE:     usize = 256;
const SIGINFO_SIZE:      usize = 80;
const RETADDR_SIZE:      usize = 8;
const SIGNAL_FRAME_SIZE: usize = UCONTEXT_SIZE + SIGINFO_SIZE + RETADDR_SIZE;
const GREGS_OFFSET:      usize = 40;

#[inline] fn greg_off(i: usize) -> usize { GREGS_OFFSET + i * 8 }

const REG_R8:      usize = 0;
const REG_R9:      usize = 1;
const REG_R10:     usize = 2;
const REG_R11:     usize = 3;
const REG_R12:     usize = 4;
const REG_R13:     usize = 5;
const REG_R14:     usize = 6;
const REG_R15:     usize = 7;
const REG_RDI:     usize = 8;
const REG_RSI:     usize = 9;
const REG_RBP:     usize = 10;
const REG_RBX:     usize = 11;
const REG_RDX:     usize = 12;
const REG_RAX:     usize = 13;
const REG_RCX:     usize = 14;
const REG_RSP:     usize = 15;
const REG_RIP:     usize = 16;
const REG_EFL:     usize = 17;
const REG_CSGSFS:  usize = 18;
const REG_OLDMASK: usize = 21;
const REG_CR2:     usize = 22;

// ── check_pending_signal ─────────────────────────────────────────────────────────────────────

pub fn check_pending_signal(frame: &mut SyscallFrame) {
    let pid = scheduler::current_pid();
    if pid == 0 { return; }
    let mask = get_sigmask(pid);

    let info = {
        let mut q = PENDING.lock();
        let queue = match q.get_mut(&pid) { Some(q) => q, None => return };

        // Fast path: front signal is unmasked (the common case).
        if let Some(front) = queue.front() {
            if front.sig > 0 && (mask >> front.sig) & 1 == 0 {
                queue.pop_front().unwrap_or_default()
            } else {
                // Slow path: scan for first unmasked signal.
                let pos = queue.iter().position(|s| s.sig > 0 && (mask >> s.sig) & 1 == 0);
                match pos {
                    Some(i) => queue.remove(i).unwrap_or_default(),
                    None    => return,
                }
            }
        } else {
            return;
        }
    };
    if info.sig == 0 { return; }

    let (handler_va, sa_flags, restorer) = scheduler::with_proc(pid, |p| (
        p.signal_handlers.handlers[info.sig as usize],
        p.signal_handlers.flags[info.sig as usize],
        p.signal_handlers.restorer,
    )).unwrap_or((0, 0, 0));

    if handler_va == 0 {
        match info.sig {
            17 | 28 => {}
            _ => { crate::proc::exit::sys_exit(-(info.sig as i32)); }
        }
        return;
    }

    if sa_flags & SA_NODEFER == 0 {
        set_sigmask(pid, mask | (1u64 << info.sig));
    }

    let mut sp = frame.rsp;
    if sa_flags & SA_ONSTACK != 0 {
        if let Some(alt) = ALTSTACK.lock().get(&pid).copied() {
            if alt.ss_flags & SS_DISABLE == 0 && alt.ss_size >= 2048 {
                let alt_hi = alt.ss_sp.wrapping_add(alt.ss_size);
                if !(frame.rsp >= alt.ss_sp && frame.rsp < alt_hi) {
                    sp = alt_hi;
                    if alt.ss_flags & SS_AUTODISARM != 0 {
                        ALTSTACK.lock().entry(pid)
                            .and_modify(|a| a.ss_flags |= SS_DISABLE);
                    }
                }
            }
        }
    }

    let sp = (sp.wrapping_sub(128).wrapping_sub(SIGNAL_FRAME_SIZE)) & !0xF;

    if !validate_user_ptr(sp, SIGNAL_FRAME_SIZE) {
        PENDING.lock().entry(pid).or_default().push_front(info);
        return;
    }

    let uc_va  = sp;
    let si_va  = sp + UCONTEXT_SIZE;
    let ret_va = sp + UCONTEXT_SIZE + SIGINFO_SIZE;

    let mut kframe = [0u8; SIGNAL_FRAME_SIZE];

    kframe[16..24].copy_from_slice(&frame.rsp.to_ne_bytes());

    macro_rules! wgreg {
        ($idx:expr, $val:expr) => {
            let off = GREGS_OFFSET + $idx * 8;
            kframe[off..off+8].copy_from_slice(&($val as u64).to_ne_bytes());
        };
    }
    wgreg!(REG_R8,      frame.r8);
    wgreg!(REG_R9,      frame.r9);
    wgreg!(REG_R10,     frame.r10);
    wgreg!(REG_R11,     frame.r11);
    wgreg!(REG_R12,     frame.r12);
    wgreg!(REG_R13,     frame.r13);
    wgreg!(REG_R14,     frame.r14);
    wgreg!(REG_R15,     frame.r15);
    wgreg!(REG_RDI,     frame.rdi);
    wgreg!(REG_RSI,     frame.rsi);
    wgreg!(REG_RBP,     frame.rbp);
    wgreg!(REG_RBX,     frame.rbx);
    wgreg!(REG_RDX,     frame.rdx);
    wgreg!(REG_RAX,     frame.rax);
    wgreg!(REG_RCX,     frame.rcx);
    wgreg!(REG_RSP,     frame.rsp);
    wgreg!(REG_RIP,     frame.rip);
    wgreg!(REG_EFL,     frame.r11);
    wgreg!(REG_CSGSFS,  0x002B_0033u64);
    wgreg!(REG_OLDMASK, mask);
    wgreg!(REG_CR2,     info.addr as u64);
    kframe[240..248].copy_from_slice(&mask.to_ne_bytes());

    let si = &mut kframe[UCONTEXT_SIZE..UCONTEXT_SIZE + SIGINFO_SIZE];
    si[0..4].copy_from_slice(&(info.sig as i32).to_ne_bytes());
    si[8..12].copy_from_slice(&info.code.to_ne_bytes());
    match info.sig {
        17 => si[24..28].copy_from_slice(&info.status.to_ne_bytes()),
        11 | 7 | 8 => si[16..24].copy_from_slice(&info.addr.to_ne_bytes()),
        _ => {}
    }

    let ret_addr = if sa_flags & SA_RESTORER != 0 && restorer != 0 {
        restorer
    } else {
        match build_inline_trampoline(sp) {
            Some(va) => va,
            None => {
                PENDING.lock().entry(pid).or_default().push_front(info);
                return;
            }
        }
    };
    kframe[UCONTEXT_SIZE + SIGINFO_SIZE..].copy_from_slice(&ret_addr.to_ne_bytes());

    if copy_to_user(sp, &kframe).is_err() {
        PENDING.lock().entry(pid).or_default().push_front(info);
        return;
    }

    frame.rdi = info.sig as usize;
    frame.rsi = si_va;
    frame.rdx = uc_va;
    frame.rip = handler_va;
    frame.rsp = ret_va;
}

// ── sys_rt_sigreturn [NR 15] ───────────────────────────────────────────────────────────────

pub fn sys_rt_sigreturn(frame: &mut SyscallFrame) -> isize {
    let pid = scheduler::current_pid();
    let uc_va = frame.rsp.wrapping_sub(UCONTEXT_SIZE + SIGINFO_SIZE);
    if !validate_user_ptr(uc_va, UCONTEXT_SIZE + 8) { return -14; }

    let mut kframe = [0u8; UCONTEXT_SIZE + 8];
    if copy_from_user(&mut kframe, uc_va).is_err() { return -14; }

    macro_rules! rgreg {
        ($idx:expr) => {{
            let off = GREGS_OFFSET + $idx * 8;
            usize::from_ne_bytes(kframe[off..off+8].try_into().unwrap())
        }};
    }

    frame.r8     = rgreg!(REG_R8);
    frame.r9     = rgreg!(REG_R9);
    frame.r10    = rgreg!(REG_R10);
    frame.r11    = rgreg!(REG_EFL);
    frame.r12    = rgreg!(REG_R12);
    frame.r13    = rgreg!(REG_R13);
    frame.r14    = rgreg!(REG_R14);
    frame.r15    = rgreg!(REG_R15);
    frame.rdi    = rgreg!(REG_RDI);
    frame.rsi    = rgreg!(REG_RSI);
    frame.rbp    = rgreg!(REG_RBP);
    frame.rbx    = rgreg!(REG_RBX);
    frame.rdx    = rgreg!(REG_RDX);
    frame.rax    = rgreg!(REG_RAX);
    frame.rcx    = rgreg!(REG_RCX);
    frame.rsp    = rgreg!(REG_RSP);
    frame.rip    = rgreg!(REG_RIP);

    let old_mask = u64::from_ne_bytes(kframe[240..248].try_into().unwrap());
    set_sigmask(pid, old_mask);
    0
}

// ── Inline trampoline (fallback when SA_RESTORER not set) ──────────────────────────────

fn build_inline_trampoline(sp: usize) -> Option<usize> {
    // mov rax, 15 (NR_rt_sigreturn); syscall
    const CODE: [u8; 9] = [0x48, 0xC7, 0xC0, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05];
    let va = sp.wrapping_sub(16);
    copy_to_user(va, &CODE).ok().map(|_| va)
}

// ── altstack_clear_pid / proc_name_clear ──────────────────────────────────────────────
//
// Called by do_exit to clean up per-pid side tables.

pub fn altstack_clear_pid(pid: usize) {
    ALTSTACK.lock().remove(&pid);
    SIGMASK.lock().remove(&pid);
    PENDING.lock().remove(&pid);
}
