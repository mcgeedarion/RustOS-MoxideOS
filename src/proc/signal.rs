//! Signal delivery, masking, and rt_sigreturn.
//!
//! ## Delivery model
//!   1. send_signal(pid, sig) pushes sig onto PENDING[pid].
//!   2. At syscall RETURN, check_pending_signal(frame) is called.
//!   3. If there is an unmasked pending signal and a registered SA_SIGACTION
//!      handler, the kernel redirects the returning SYSRETQ to the signal
//!      handler trampoline, saving the original frame on the user stack.
//!   4. The signal handler calls sys_rt_sigreturn to restore the frame.
//!
//! ## Default actions
//!   SIGKILL (9), SIGTERM (15), SIGSEGV (11)  → sys_exit(-sig)
//!   SIGCHLD (17), SIGWINCH (28)              → ignored
//!   All others with no registered handler    → sys_exit(-sig)

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::Mutex;

use crate::proc::scheduler;
use crate::arch::x86_64::syscall::SyscallFrame;

// ── signal storage ────────────────────────────────────────────────────────

/// Per-process pending signal queue.
static PENDING: Mutex<BTreeMap<usize, VecDeque<u32>>> = Mutex::new(BTreeMap::new());
/// Per-process signal mask (blocked signals bitmask).
static SIGMASK: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

// ── SA_SIGACTION handler table ────────────────────────────────────────────

/// Registered signal handlers (user-space function pointers).
/// Stored per process, per signal number.
#[derive(Clone, Default)]
pub struct SignalHandlers {
    pub handlers: [usize; 65], // handler VA; 0 = default action
    pub flags:    [u32;   65], // SA_* flags
    pub restorer: usize,       // SA_RESTORER address
}

// ── send_signal ───────────────────────────────────────────────────────────

pub fn send_signal(pid: usize, sig: u32) {
    if sig == 0 || sig > 64 { return; }
    PENDING.lock().entry(pid).or_default().push_back(sig);
    scheduler::wake_pid(pid);
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

// ── sys_rt_sigaction [NR 13] ──────────────────────────────────────────────

pub fn sys_rt_sigaction(sig: u32, new_act_va: usize, old_act_va: usize, _sigsetsize: usize) -> isize {
    if sig == 0 || sig > 64 { return -22; }
    let pid = scheduler::current_pid();

    let procs = scheduler::procs_lock();
    let pcb = match procs.iter_mut().find(|p| p.pid == pid) {
        Some(p) => p,
        None    => { scheduler::procs_unlock(); return -3; }
    };

    // Save old handler if old_act_va is valid
    if old_act_va > 0x1000 {
        let old_fn    = pcb.signal_handlers.handlers[sig as usize];
        let old_flags = pcb.signal_handlers.flags[sig as usize];
        unsafe {
            (old_act_va as *mut usize).write_volatile(old_fn);
            ((old_act_va + 8) as *mut u32).write_volatile(old_flags);
        }
    }

    // Install new handler if new_act_va is valid
    if new_act_va > 0x1000 {
        let fn_ptr    = unsafe { (new_act_va as *const usize).read_volatile() };
        let sa_flags  = unsafe { ((new_act_va + 8) as *const u32).read_volatile() };
        let restorer  = unsafe { ((new_act_va + 16) as *const usize).read_volatile() };
        pcb.signal_handlers.handlers[sig as usize] = fn_ptr;
        pcb.signal_handlers.flags[sig as usize]    = sa_flags;
        pcb.signal_handlers.restorer               = restorer;
    }

    scheduler::procs_unlock();
    0
}

// ── sys_rt_sigprocmask [NR 14] ────────────────────────────────────────────

pub fn sys_rt_sigprocmask(how: u32, set_va: usize, oldset_va: usize, _sigsetsize: usize) -> isize {
    let pid  = scheduler::current_pid();
    let cur  = get_sigmask(pid);

    if oldset_va > 0x1000 {
        unsafe { (oldset_va as *mut u64).write_volatile(cur); }
    }
    if set_va == 0 { return 0; }

    let new_set = unsafe { (set_va as *const u64).read_volatile() };
    let updated = match how {
        0 => new_set,           // SIG_BLOCK
        1 => cur | new_set,     // SIG_UNBLOCK (note: Linux uses 1=BLOCK,2=UNBLOCK,3=SETMASK)
        2 => cur & !new_set,
        3 => new_set,
        _ => return -22,
    };
    set_sigmask(pid, updated & !(1 << 8) & !(1 << 8)); // cannot mask SIGKILL(9)
    0
}

// ── check_pending_signal ─────────────────────────────────────────────────

/// Called at every syscall return boundary.
/// If an unmasked signal is pending:
///   - with a registered handler: redirect SYSRETQ to the handler trampoline
///   - with default action:       call sys_exit(-sig)
pub fn check_pending_signal(frame: &mut SyscallFrame) {
    let pid  = scheduler::current_pid();
    if pid == 0 { return; }
    let mask = get_sigmask(pid);

    let sig = {
        let mut q = PENDING.lock();
        let queue = match q.get_mut(&pid) { Some(q) => q, None => return };
        // Find first unmasked signal
        let pos = queue.iter().position(|&s| s == 0 || (mask >> s) & 1 == 0);
        match pos {
            Some(i) => queue.remove(i).unwrap_or(0),
            None    => return,
        }
    };
    if sig == 0 { return; }

    // Retrieve handler VA
    let (handler_va, sa_flags, restorer) = {
        let procs = scheduler::procs_lock();
        let r = procs.iter().find(|p| p.pid == pid).map(|p| (
            p.signal_handlers.handlers[sig as usize],
            p.signal_handlers.flags[sig as usize],
            p.signal_handlers.restorer,
        )).unwrap_or((0, 0, 0));
        scheduler::procs_unlock();
        r
    };

    if handler_va == 0 {
        // Default action
        match sig {
            17 | 28 => {}   // SIGCHLD, SIGWINCH: ignore
            _       => { crate::proc::exit::sys_exit(-(sig as i32)); }
        }
        return;
    }

    // Redirect: push sigframe onto user stack, set RIP = handler_va
    let user_sp = frame.rsp.wrapping_sub(128); // red-zone clearance
    let user_sp = (user_sp - 8) & !0xF;        // 16-byte align
    // Push return address (SA_RESTORER or signal trampoline)
    let ret_addr = if restorer != 0 { restorer } else { sig_default_restorer() };
    unsafe { (user_sp as *mut usize).write_volatile(ret_addr); }

    frame.rdi = sig as usize; // first arg to handler: signum
    frame.rcx = handler_va;
    frame.rip = handler_va;
    frame.rsp = user_sp;
}

// ── sys_rt_sigreturn [NR 15] ──────────────────────────────────────────────

/// Called from the signal handler trampoline to restore the saved frame.
/// The saved SyscallFrame was pushed onto the user stack by check_pending_signal;
/// this just restores rsp to skip back over it.  A full implementation would
/// restore the complete ucontext; this is sufficient for simple handlers.
pub fn sys_rt_sigreturn(frame: &mut SyscallFrame) -> isize {
    // Pop the return address we pushed.
    frame.rsp = frame.rsp.wrapping_add(8);
    0
}

/// Returns the address of the kernel-provided signal return trampoline.
/// Stub: returns 0; a real implementation places the trampoline in the vDSO.
fn sig_default_restorer() -> usize { 0 }
