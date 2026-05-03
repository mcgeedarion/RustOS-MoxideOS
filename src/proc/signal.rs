//! Signal delivery: rt_sigaction, rt_sigprocmask, rt_sigreturn,
//! build_sigframe, check_pending_signal.
//!
//! ## Signal delivery flow
//!
//!   1. send_signal(pid, sig) enqueues `sig` in PENDING[pid].
//!   2. At syscall RETURN, check_pending_signal(frame) is called.
//!   3. If there is an unmasked pending signal:
//!      a. Look up the handler in Pcb.signal_handlers.
//!      b. SIG_DFL → do_exit or stop (default action).
//!      c. SIG_IGN → discard.
//!      d. User handler → build_sigframe: push RtSigframe onto the user
//!         stack, redirect frame.rip → handler, frame.rsp → new user RSP.
//!   4. The user handler runs; when done it calls the restorer trampoline
//!      (embedded in RtSigframe) which executes `syscall` NR 15.
//!   5. sys_rt_sigreturn pops the saved registers and restores the frame.
//!
//! ## RtSigframe layout on the user stack (grows downward)
//!
//!   usp_original
//!       [padding to 16-byte alignment]
//!       [RtSigframe: restorer_code(8) + signo(8) + saved_regs(17×8)]
//!   usp_new-8  ← handler return address pushed here (= &restorer_code)
//!   usp_new    ← new frame.rsp passed to handler

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use spin::Mutex;
use crate::proc::scheduler;
use crate::proc::process::State;
use crate::arch::x86_64::syscall::SyscallFrame;

// ── Signal numbers (Linux ABI) ──────────────────────────────────────────
pub const SIGHUP:  u32 =  1;
pub const SIGINT:  u32 =  2;
pub const SIGQUIT: u32 =  3;
pub const SIGILL:  u32 =  4;
pub const SIGTRAP: u32 =  5;
pub const SIGABRT: u32 =  6;
pub const SIGBUS:  u32 =  7;
pub const SIGFPE:  u32 =  8;
pub const SIGKILL: u32 =  9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;

// ── Global signal queues + masks ─────────────────────────────────────────

static PENDING: Mutex<BTreeMap<usize, VecDeque<u32>>> = Mutex::new(BTreeMap::new());
static SIGMASK:  Mutex<BTreeMap<usize, u64>>           = Mutex::new(BTreeMap::new());

/// Enqueue `sig` for delivery to `pid`.
pub fn send_signal(pid: usize, sig: u32) {
    if sig == 0 || sig > 64 { return; }
    PENDING.lock().entry(pid).or_default().push_back(sig);
    scheduler::wake_pid(pid);
}

pub fn get_sigmask(pid: usize) -> u64 {
    SIGMASK.lock().get(&pid).copied().unwrap_or(0)
}

pub fn set_sigmask(pid: usize, mask: u64) {
    // SIGKILL (9) and SIGSTOP (19) cannot be blocked
    let mask = mask & !(1u64 << 8) & !(1u64 << 18);
    SIGMASK.lock().insert(pid, mask);
}

// ── rt_sigaction [NR 13] ─────────────────────────────────────────────────

#[repr(C)]
struct UserSigaction {
    sa_handler:  usize,
    sa_flags:    u64,
    sa_restorer: usize,
    sa_mask:     u64,
}

pub fn sys_rt_sigaction(sig: u32, new_va: usize, old_va: usize, _size: usize) -> isize {
    if sig == 0 || sig > 64 { return -22; }
    let pid = scheduler::current_pid();
    if pid == 0 { return -3; }

    if old_va > 0x1000 {
        let procs = scheduler::procs_lock();
        if let Some(p) = procs.iter().find(|p| p.pid == pid) {
            let sa = &p.signal_handlers.table[sig as usize];
            unsafe {
                let out = old_va as *mut UserSigaction;
                (*out).sa_handler  = sa.handler;
                (*out).sa_flags    = sa.flags as u64;
                (*out).sa_restorer = 0;
                (*out).sa_mask     = sa.mask;
            }
        }
        scheduler::procs_unlock();
    }

    if new_va > 0x1000 {
        let usa = unsafe { &*(new_va as *const UserSigaction) };
        let procs = scheduler::procs_lock();
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            let sa = &mut p.signal_handlers.table[sig as usize];
            sa.handler = usa.sa_handler;
            sa.flags   = usa.sa_flags as u32;
            sa.mask    = usa.sa_mask;
        }
        scheduler::procs_unlock();
    }
    0
}

// ── rt_sigprocmask [NR 14] ───────────────────────────────────────────────

pub fn sys_rt_sigprocmask(how: u32, set_va: usize, oldset_va: usize, _size: usize) -> isize {
    const SIG_BLOCK:   u32 = 0;
    const SIG_UNBLOCK: u32 = 1;
    const SIG_SETMASK: u32 = 2;

    let pid = scheduler::current_pid();
    let cur = get_sigmask(pid);

    if oldset_va > 0x1000 {
        unsafe { (oldset_va as *mut u64).write_volatile(cur); }
    }
    if set_va > 0x1000 {
        let new = unsafe { (set_va as *const u64).read_volatile() };
        let updated = match how {
            SIG_BLOCK   => cur |  new,
            SIG_UNBLOCK => cur & !new,
            SIG_SETMASK => new,
            _           => return -22,
        };
        set_sigmask(pid, updated);
    }
    0
}

// ── RtSigframe ───────────────────────────────────────────────────────────

/// The kernel-pushed signal frame on the user stack.
#[repr(C)]
struct RtSigframe {
    /// Restorer trampoline: `mov eax, 15; syscall; nop` (8 bytes).
    restorer_code: [u8; 8],
    signo:         u64,
    saved_rax:  usize,
    saved_rcx:  usize,
    saved_r11:  usize,
    saved_rsp:  usize,
    saved_rdi:  usize,
    saved_rsi:  usize,
    saved_rdx:  usize,
    saved_r10:  usize,
    saved_r8:   usize,
    saved_r9:   usize,
    saved_rbx:  usize,
    saved_rbp:  usize,
    saved_r12:  usize,
    saved_r13:  usize,
    saved_r14:  usize,
    saved_r15:  usize,
}

/// `mov eax, 15; syscall; nop`
const RESTORER_CODE: [u8; 8] = [0xb8, 0x0f, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x90];

/// Build a signal frame on the user stack and redirect the SyscallFrame
/// so that SYSRETQ delivers the user to `handler_va`.
pub fn build_sigframe(frame: &mut SyscallFrame, sig: u32, handler_va: usize, sa_mask: u64) {
    const SF_SIZE: usize = core::mem::size_of::<RtSigframe>();

    // New user RSP: room for RtSigframe, aligned to 16 bytes
    let usp = (frame.rsp - SF_SIZE) & !0xFusize;
    let sf  = usp as *mut RtSigframe;

    unsafe {
        (*sf).restorer_code = RESTORER_CODE;
        (*sf).signo         = sig as u64;
        (*sf).saved_rax     = frame.rax;
        (*sf).saved_rcx     = frame.rcx;
        (*sf).saved_r11     = frame.r11;
        (*sf).saved_rsp     = frame.rsp;
        (*sf).saved_rdi     = frame.rdi;
        (*sf).saved_rsi     = frame.rsi;
        (*sf).saved_rdx     = frame.rdx;
        (*sf).saved_r10     = frame.r10;
        (*sf).saved_r8      = frame.r8;
        (*sf).saved_r9      = frame.r9;
        (*sf).saved_rbx     = frame.rbx;
        (*sf).saved_rbp     = frame.rbp;
        (*sf).saved_r12     = frame.r12;
        (*sf).saved_r13     = frame.r13;
        (*sf).saved_r14     = frame.r14;
        (*sf).saved_r15     = frame.r15;
    }

    // Push restorer VA as handler return address (handler will `ret` into it)
    let ra_slot = (usp - 8) as *mut usize;
    unsafe { *ra_slot = usp; } // restorer_code is at start of RtSigframe

    // Redirect user execution
    frame.rcx = handler_va; // SYSRETQ: user RIP = RCX
    frame.rip = handler_va;
    frame.rsp = usp - 8;    // pushed return address
    frame.rdi = sig as usize;

    // Block additional signals during handler
    let pid = scheduler::current_pid();
    let cur = get_sigmask(pid);
    set_sigmask(pid, cur | sa_mask);
}

// ── rt_sigreturn [NR 15] ─────────────────────────────────────────────────

/// Restore SyscallFrame from the RtSigframe pushed by build_sigframe.
/// Called from syscall_rust_entry BEFORE check_pending.
pub fn sys_rt_sigreturn(frame: &mut SyscallFrame) -> isize {
    // On entry: frame.rsp = usp-8 (the slot we pushed restorer VA into).
    // The RtSigframe itself starts at frame.rsp + 8.
    let sf_va = frame.rsp + 8;
    if sf_va < 0x1000 || sf_va > 0x0000_7FFF_FFFF_F000 { return -14; }

    let sf = sf_va as *const RtSigframe;
    unsafe {
        frame.rax = (*sf).saved_rax;
        frame.rcx = (*sf).saved_rcx;
        frame.r11 = (*sf).saved_r11;
        frame.rsp = (*sf).saved_rsp;
        frame.rdi = (*sf).saved_rdi;
        frame.rsi = (*sf).saved_rsi;
        frame.rdx = (*sf).saved_rdx;
        frame.r10 = (*sf).saved_r10;
        frame.r8  = (*sf).saved_r8;
        frame.r9  = (*sf).saved_r9;
        frame.rbx = (*sf).saved_rbx;
        frame.rbp = (*sf).saved_rbp;
        frame.r12 = (*sf).saved_r12;
        frame.r13 = (*sf).saved_r13;
        frame.r14 = (*sf).saved_r14;
        frame.r15 = (*sf).saved_r15;
        frame.rip = (*sf).saved_rcx;
    }
    frame.rax as isize
}

// ── check_pending_signal ─────────────────────────────────────────────────

/// Called at every syscall return before SYSRETQ.
/// Delivers the first unmasked pending signal for the current task.
pub fn check_pending_signal(frame: &mut SyscallFrame) {
    let pid  = scheduler::current_pid();
    if pid == 0 { return; }
    let mask = get_sigmask(pid);

    let sig = {
        let mut pending = PENDING.lock();
        let queue = match pending.get_mut(&pid) { Some(q) => q, None => return };
        let pos = queue.iter().position(|&s| {
            s == SIGKILL || s == SIGSTOP || (mask >> (s.wrapping_sub(1))) & 1 == 0
        });
        match pos {
            Some(i) => queue.remove(i).unwrap(),
            None    => return,
        }
    };

    let (handler, sa_mask, _flags) = {
        let procs = scheduler::procs_lock();
        let v = procs.iter().find(|p| p.pid == pid).map(|p| {
            let sa = &p.signal_handlers.table[sig as usize];
            (sa.handler, sa.mask, sa.flags)
        }).unwrap_or((0, 0, 0));
        scheduler::procs_unlock();
        v
    };

    match handler {
        0 => {
            match sig {
                SIGCHLD | SIGCONT => {}
                SIGSTOP => {
                    let procs = scheduler::procs_lock();
                    if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                        p.state = State::Blocked;
                    }
                    scheduler::procs_unlock();
                    scheduler::schedule();
                }
                _ => { crate::proc::exit::do_exit(pid, -(sig as i32)); }
            }
        }
        1 => {}
        handler_va => { build_sigframe(frame, sig, handler_va, sa_mask); }
    }
}
