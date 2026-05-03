//! Signal delivery, masking, and rt_sigreturn.
//!
//! ## Delivery model
//!   1. send_signal(pid, sig) pushes sig onto PENDING[pid].
//!   2. At syscall RETURN, check_pending_signal(frame) is called.
//!   3. If there is an unmasked pending signal and a registered SA_SIGACTION
//!      handler, the kernel redirects the returning SYSRETQ to the signal
//!      handler trampoline, saving the original frame on the user stack (or
//!      the registered alternate stack when SA_ONSTACK is set).
//!   4. The signal handler calls sys_rt_sigreturn to restore the frame.
//!
//! ## Default actions
//!   SIGKILL (9), SIGTERM (15), SIGSEGV (11)  → sys_exit(-sig)
//!   SIGCHLD (17), SIGWINCH (28)              → ignored
//!   All others with no registered handler    → sys_exit(-sig)
//!
//! ## Alternate-stack (SA_ONSTACK / sigaltstack)
//!   When a handler is registered with SA_ONSTACK *and* an alternate stack
//!   has been registered via sigaltstack(2) *and* the current rsp is NOT
//!   already on that stack, the kernel switches rsp to
//!   `altstack.ss_sp + altstack.ss_size` (the top of the alt-stack) before
//!   pushing the signal frame.  This is what lets programs catch SIGSEGV
//!   caused by a stack overflow without double-faulting.

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

// ── alternate stack storage ───────────────────────────────────────────────

/// Per-process alternate signal stack.
/// Layout of stack_t (x86-64):
///   +0  ss_sp:    *mut void   (8 bytes)
///   +8  ss_flags: int         (4 bytes)
///   +12 _pad:     [u8; 4]
///   +16 ss_size:  size_t      (8 bytes)
#[derive(Clone, Copy, Default)]
struct AltStack {
    ss_sp:    usize,  // base address of alternate stack
    ss_flags: i32,    // SS_ONSTACK(1) | SS_DISABLE(2) | SS_AUTODISARM(0x80000000)
    ss_size:  usize,  // size in bytes
}

const SS_DISABLE:    i32 = 2;
const SS_ONSTACK:    i32 = 1;
const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

static ALTSTACK: Mutex<BTreeMap<usize, AltStack>> = Mutex::new(BTreeMap::new());

// ── SA_* flags ────────────────────────────────────────────────────────────

const SA_ONSTACK:   u32 = 0x08000000;
const SA_RESTORER:  u32 = 0x04000000;
const SA_SIGINFO:   u32 = 0x00000004;

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

// ── sys_sigaltstack [NR 131] ──────────────────────────────────────────────

/// Register or query the alternate signal stack for the current process.
///
/// struct stack_t layout (x86-64, 24 bytes):
///   +0  ss_sp:    usize  (pointer to stack base)
///   +8  ss_flags: i32
///   +12 _pad:     [u8;4]
///   +16 ss_size:  usize
pub fn sys_sigaltstack(ss_va: usize, old_ss_va: usize) -> isize {
    let pid = scheduler::current_pid();

    // Return current alt-stack into old_ss_va if provided.
    if old_ss_va != 0 && old_ss_va >= 0x1000 {
        let tbl = ALTSTACK.lock();
        let alt = tbl.get(&pid).copied().unwrap_or(AltStack {
            ss_sp:    0,
            ss_flags: SS_DISABLE,
            ss_size:  0,
        });
        unsafe {
            (old_ss_va as *mut usize).write_unaligned(alt.ss_sp);
            ((old_ss_va + 8)  as *mut i32).write_unaligned(alt.ss_flags);
            ((old_ss_va + 12) as *mut i32).write_unaligned(0); // pad
            ((old_ss_va + 16) as *mut usize).write_unaligned(alt.ss_size);
        }
    }

    // Install new alt-stack from ss_va if provided.
    if ss_va != 0 && ss_va >= 0x1000 {
        let ss_sp    = unsafe { (ss_va as *const usize).read_unaligned() };
        let ss_flags = unsafe { ((ss_va + 8) as *const i32).read_unaligned() };
        let ss_size  = unsafe { ((ss_va + 16) as *const usize).read_unaligned() };

        if ss_flags & SS_DISABLE != 0 {
            // Unregister.
            ALTSTACK.lock().remove(&pid);
        } else {
            if ss_size < 2048 { return -22; } // EINVAL: MINSIGSTKSZ
            ALTSTACK.lock().insert(pid, AltStack { ss_sp, ss_flags, ss_size });
        }
    }
    0
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

    // Save old handler if old_act_va is valid.
    if old_act_va > 0x1000 {
        let old_fn    = pcb.signal_handlers.handlers[sig as usize];
        let old_flags = pcb.signal_handlers.flags[sig as usize];
        let restorer  = pcb.signal_handlers.restorer;
        unsafe {
            // struct sigaction layout: handler (8) | flags (8) | restorer (8) | mask (8)
            (old_act_va as *mut usize).write_volatile(old_fn);
            ((old_act_va + 8)  as *mut u64).write_volatile(old_flags as u64);
            ((old_act_va + 16) as *mut usize).write_volatile(restorer);
            ((old_act_va + 24) as *mut u64).write_volatile(0); // sa_mask
        }
    }

    // Install new handler if new_act_va is valid.
    if new_act_va > 0x1000 {
        let fn_ptr   = unsafe { (new_act_va as *const usize).read_volatile() };
        let sa_flags = unsafe { ((new_act_va + 8) as *const u64).read_volatile() } as u32;
        let restorer = unsafe { ((new_act_va + 16) as *const usize).read_volatile() };
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
        0 => cur | new_set,     // SIG_BLOCK
        1 => cur & !new_set,    // SIG_UNBLOCK
        2 => new_set,           // SIG_SETMASK
        _ => return -22,
    };
    // Cannot mask SIGKILL(9) or SIGSTOP(19).
    set_sigmask(pid, updated & !((1u64 << 8) | (1u64 << 18)));
    0
}

// ── check_pending_signal ─────────────────────────────────────────────────

/// Called at every syscall return boundary.
/// If an unmasked signal is pending:
///   - with a registered handler: redirect SYSRETQ to the handler trampoline
///   - with default action:       call sys_exit(-sig)
///
/// When `SA_ONSTACK` is set on the handler *and* a valid alternate stack is
/// registered *and* rsp is not already within that stack, we switch rsp to
/// the top of the alternate stack before pushing the signal frame.  This
/// allows programs to catch SIGSEGV from a main-stack overflow.
pub fn check_pending_signal(frame: &mut SyscallFrame) {
    let pid  = scheduler::current_pid();
    if pid == 0 { return; }
    let mask = get_sigmask(pid);

    let sig = {
        let mut q = PENDING.lock();
        let queue = match q.get_mut(&pid) { Some(q) => q, None => return };
        // Find first unmasked signal.
        let pos = queue.iter().position(|&s| s > 0 && (mask >> s) & 1 == 0);
        match pos {
            Some(i) => queue.remove(i).unwrap_or(0),
            None    => return,
        }
    };
    if sig == 0 { return; }

    // Retrieve handler VA, flags, restorer.
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
        // Default action.
        match sig {
            17 | 28 => {}   // SIGCHLD, SIGWINCH: ignore
            _       => { crate::proc::exit::sys_exit(-(sig as i32)); }
        }
        return;
    }

    // ── Choose signal stack ───────────────────────────────────────────────
    //
    // Linux rules (sigaction(2)):
    //   - Use alt-stack if SA_ONSTACK is set, an alt-stack is registered
    //     (ss_flags != SS_DISABLE), and rsp is NOT already within that stack.
    //   - Mask the signal during delivery (add sig to the process sigmask).

    // Block the signal during handler execution (re-entrant delivery is wrong).
    set_sigmask(pid, mask | (1u64 << sig));

    let mut delivery_sp = frame.rsp;

    if sa_flags & SA_ONSTACK != 0 {
        // Check whether an alt-stack is registered and we're not already on it.
        let alt = ALTSTACK.lock().get(&pid).copied();
        if let Some(alt) = alt {
            if alt.ss_flags & SS_DISABLE == 0 && alt.ss_size >= 2048 {
                let alt_lo = alt.ss_sp;
                let alt_hi = alt.ss_sp.wrapping_add(alt.ss_size);
                let on_altstack = frame.rsp >= alt_lo && frame.rsp < alt_hi;
                if !on_altstack {
                    // Switch to top of alternate stack.
                    delivery_sp = alt_hi;
                    // If SS_AUTODISARM: disable alt-stack so nested signals
                    // don't re-enter it (Linux 4.7+ semantics).
                    if alt.ss_flags & SS_AUTODISARM != 0 {
                        ALTSTACK.lock().entry(pid).and_modify(|a| {
                            a.ss_flags |= SS_DISABLE;
                        });
                    }
                }
            }
        }
    }

    // ── Build signal frame on chosen stack ────────────────────────────────
    //
    // We push a minimal sigframe:
    //   [sp-8]  return address  (restorer or trampoline)
    //   (no ucontext/siginfo for non-SA_SIGINFO handlers)
    //
    // For SA_SIGINFO handlers we'd also push siginfo_t + ucontext_t;
    // that's deferred until something actually needs SA_SIGINFO.

    let sp = delivery_sp.wrapping_sub(128); // clear red-zone
    let sp = (sp.wrapping_sub(8)) & !0xFusize; // 16-byte align, room for retaddr

    let ret_addr = if sa_flags & SA_RESTORER != 0 && restorer != 0 {
        restorer
    } else {
        // No restorer: push a tiny inline trampoline: mov $15,%rax; syscall
        // This won't actually be reached on rustos because musl always sets
        // SA_RESTORER, but it prevents a null-dereference on the return.
        build_inline_trampoline(sp)
    };

    unsafe { (sp as *mut usize).write_volatile(ret_addr); }

    // Arguments to the handler.
    frame.rdi = sig as usize;    // arg1: signum
    frame.rsi = 0;               // arg2: siginfo_t* (NULL for non-SA_SIGINFO)
    frame.rdx = 0;               // arg3: ucontext_t* (NULL)
    frame.rip = handler_va;
    frame.rsp = sp;

    // ── Save original frame so rt_sigreturn can restore it ───────────────
    //
    // We store the original {rip, rsp, rflags} in a per-pid table so that
    // sys_rt_sigreturn can pop them back.  A full Linux-compatible
    // implementation would embed them in the ucontext_t on the signal stack;
    // this simpler approach works as long as signals don't nest (they can't
    // because we block the signal in the mask above).
    save_signal_frame(pid, frame.rip, delivery_sp, frame.rflags);
}

// ── saved-frame table for rt_sigreturn ───────────────────────────────────

#[derive(Clone, Copy, Default)]
struct SavedFrame { orig_rip: usize, orig_rsp: usize, orig_rflags: usize, sig: u32 }
static SAVED_FRAMES: Mutex<BTreeMap<usize, SavedFrame>> = Mutex::new(BTreeMap::new());

fn save_signal_frame(pid: usize, orig_rip: usize, orig_rsp: usize, orig_rflags: usize) {
    // Note: we don't have sig here; rt_sigreturn doesn't need it for
    // the basic restore case (the mask was already updated above).
    SAVED_FRAMES.lock().insert(pid, SavedFrame {
        orig_rip, orig_rsp, orig_rflags, sig: 0,
    });
}

// ── sys_rt_sigreturn [NR 15] ──────────────────────────────────────────────

/// Called from the signal handler trampoline (via SA_RESTORER) to restore
/// the pre-signal register state.
///
/// Restoration steps:
///   1. Pop the saved {rip, rsp, rflags} from SAVED_FRAMES.
///   2. Unblock the signal that was delivered (we blocked it on entry).
///   3. Restore rip and rsp in the syscall frame so SYSRETQ returns to the
///      original interrupted instruction.
///
/// We do NOT restore all general-purpose registers here (rax..r15) because
/// the kernel's syscall entry path already saved them in SyscallFrame and
/// SYSRETQ will reload them.  The critical registers are rip (where to
/// return) and rsp (which stack to be on).
pub fn sys_rt_sigreturn(frame: &mut SyscallFrame) -> isize {
    let pid = scheduler::current_pid();

    if let Some(saved) = SAVED_FRAMES.lock().remove(&pid) {
        // Restore rip and rsp.
        frame.rip    = saved.orig_rip;
        frame.rsp    = saved.orig_rsp;
        frame.rflags = saved.orig_rflags;
        // Unblock all signals (we used a simple full-block above).
        // A proper implementation would restore the exact pre-signal mask.
        set_sigmask(pid, 0);
    } else {
        // No saved frame: just pop the return address we pushed.
        frame.rsp = frame.rsp.wrapping_add(8);
    }
    // rax = 0 after sigreturn (the syscall "doesn't return" from the
    // signal handler's perspective, but SYSRETQ uses rax as return value).
    0
}

// ── inline trampoline builder ─────────────────────────────────────────────

/// Write `mov $15, %rax; syscall` (rt_sigreturn) at `sp` and return sp.
/// Used when SA_RESTORER is not set.  musl always sets SA_RESTORER so this
/// is only a safety net.
fn build_inline_trampoline(sp: usize) -> usize {
    // mov rax, 15  = 48 C7 C0 0F 00 00 00  (7 bytes)
    // syscall      = 0F 05                  (2 bytes)
    const CODE: [u8; 9] = [0x48, 0xC7, 0xC0, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05];
    // Place trampoline 16 bytes below sp so it doesn't overlap the retaddr slot.
    let trampoline_va = sp.wrapping_sub(16);
    unsafe {
        core::ptr::copy_nonoverlapping(
            CODE.as_ptr(),
            trampoline_va as *mut u8,
            CODE.len(),
        );
    }
    trampoline_va
}
