//! Signal delivery, masking, and rt_sigreturn.
//!
//! ## Delivery model
//!
//!   1. send_signal(pid, sig) pushes a SigInfo onto PENDING[pid].
//!   2. At every trap return (ecall, page fault, IPI/timer interrupt),
//!      `check_and_deliver(frame)` is called.
//!   3. For a registered SA_SIGACTION handler the kernel:
//!      a. Optionally switches sp to the alternate stack (SA_ONSTACK).
//!      b. Carves an arch-specific SignalFrame from the top of the
//!         chosen user stack — see `push_sigframe_riscv` / `push_sigframe_x86`.
//!      c. Sets up registers so userspace jumps to the handler.
//!   4. SA_RESTORER / sig_return_trampoline does `rt_sigreturn` ecall/syscall.
//!   5. sys_rt_sigreturn restores the saved frame from the SignalFrame.
//!
//! ## RISC-V SignalFrame layout (grows down, all 8-byte aligned)
//!
//!   user_sp before delivery
//!    │
//!    ▼  [0..272)  saved TrapFrame  (all 34 × 8 bytes of the kernel TrapFrame
//!                                   — sepc = interrupted PC, sp = user sp, …)
//!       [272..352) siginfo_t       (80 bytes: sig, code, pid, addr)
//!       [352..360) restorer VA     (8 bytes: where ra points)
//!    ── new user sp ─────────────────────────────────────────────────────
//!
//!   On entry to the handler:
//!     a0 = signum
//!     a1 = &siginfo (sigframe + 272)
//!     a2 = 0        (no ucontext_t yet)
//!     ra = restorer
//!     sepc = handler VA
//!     sp = new user sp (sigframe base, 16-byte aligned)
//!
//! ## x86_64 SignalFrame layout
//!
//!   user rsp before delivery
//!    │
//!    ▼  [0..256)   ucontext_t  (rip, rsp, rflags, all GP regs)
//!       [256..336) siginfo_t   (80 bytes)
//!       [336..344) retaddr     (8 bytes: restorer VA)
//!    ── new user rsp ────────────────────────────────────────────────────
//!
//!   On entry to the handler:
//!     rdi = signum
//!     rsi = &siginfo_t  (frame + 256)
//!     rdx = &ucontext_t (frame + 0)
//!     rip = handler VA
//!
//! ## Default actions (no registered handler)
//!
//!   SIGTERM (15), SIGKILL (9) — terminate the process.
//!   SIGSTOP (19)              — block the task.
//!   SIGCHLD (17), SIGURG (23), SIGWINCH (28) — ignored.
//!   All others                — terminate.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use spin::Mutex;

use crate::proc::{scheduler, process::State};
use crate::uaccess::{copy_from_user, copy_to_user, validate_user_ptr, USER_SPACE_END};

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

// Signals whose default action is ignore.
const SIG_IGN_DEFAULT: u64 =
    (1u64 << 17) | // SIGCHLD
    (1u64 << 23) | // SIGURG
    (1u64 << 28);  // SIGWINCH

// Signals that stop the task by default.
const SIG_STOP_DEFAULT: u64 = (1u64 << 19) | (1u64 << 20) | (1u64 << 21) | (1u64 << 22);

// ── Signal storage ────────────────────────────────────────────────────

static PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> =
    Mutex::new(BTreeMap::new());
static SIGMASK: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

// ── Alternate stack ───────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct AltStack { ss_sp: usize, ss_flags: i32, ss_size: usize }

const SS_DISABLE:    i32 = 2;
const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

static ALTSTACK: Mutex<BTreeMap<usize, AltStack>> = Mutex::new(BTreeMap::new());

// ── SA_* flags ────────────────────────────────────────────────────────

const SA_ONSTACK:  u32 = 0x08000000;
const SA_RESTORER: u32 = 0x04000000;
const SA_NODEFER:  u32 = 0x40000000;

// ── sigprocmask how constants ─────────────────────────────────────────

const SIG_BLOCK:   u32 = 0;
const SIG_UNBLOCK: u32 = 1;
const SIG_SETMASK: u32 = 2;

// ── Handler table ─────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct SignalHandlers {
    pub handlers: [usize; 65],
    pub flags:    [u32;   65],
    pub restorer: usize,
}

// ── Public send API ───────────────────────────────────────────────────

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
        let (soft, _hard) = crate::proc::rlimit::getrlimit_for(
            pid, crate::proc::rlimit::RLIMIT_SIGPENDING);
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

// ── check_and_deliver ─────────────────────────────────────────────────
//
// Called at every trap-return site (ecall exit, page-fault, timer/IPI).
// Pops one unmasked signal from the queue and either:
//   a) runs the default action (terminate / stop / ignore), or
//   b) pushes an arch-specific SignalFrame and redirects execution.
//
// The `frame` pointer is the TrapFrame sitting on the kernel stack,
// which the trap-entry stub will restore when this handler returns.
// Modifying `frame.sepc` / `frame.a0` etc. directly changes what the
// CPU sees when it executes `sret`.
//
// This function is arch-agnostic: it dispatches to the arch-specific
// push_sigframe_* helper which does the actual frame surgery.

#[cfg(target_arch = "riscv64")]
pub fn check_and_deliver(frame: &mut crate::arch::riscv64::trap::TrapFrame) {
    let pid = scheduler::current_pid() as usize;

    loop {
        // Pop the first unmasked signal from the queue.
        let info = {
            let mask = get_sigmask(pid);
            let mut map = PENDING.lock();
            let queue = match map.get_mut(&pid) {
                Some(q) => q,
                None    => return,
            };
            let pos = queue.iter().position(|s| {
                s.sig >= 1 && s.sig <= 64
                    && (mask >> s.sig) & 1 == 0   // not masked
            });
            match pos {
                Some(i) => queue.remove(i).unwrap(),
                None    => return,
            }
        };

        let sig = info.sig as usize;

        // Fetch the registered handler (0 = SIG_DFL, 1 = SIG_IGN).
        let (handler, sa_flags, restorer) = scheduler::with_proc(pid, |p| (
            p.signal_handlers.handlers[sig],
            p.signal_handlers.flags[sig],
            p.signal_handlers.restorer,
        )).unwrap_or((0, 0, 0));

        match handler {
            // ── SIG_DFL ──────────────────────────────────────────────
            0 => {
                if (SIG_IGN_DEFAULT >> sig) & 1 != 0 {
                    continue; // ignored by default
                }
                if (SIG_STOP_DEFAULT >> sig) & 1 != 0 {
                    scheduler::with_proc_mut(pid, |p| p.state = State::Blocked);
                    scheduler::schedule();
                    continue;
                }
                // Terminate.
                crate::proc::exit::do_exit(pid, -(sig as i32));
                return;
            }
            // ── SIG_IGN ──────────────────────────────────────────────
            1 => { continue; }
            // ── User handler ─────────────────────────────────────────
            handler_va => {
                // Block the signal during its own handler (unless SA_NODEFER).
                if sa_flags & SA_NODEFER == 0 {
                    let old = get_sigmask(pid);
                    set_sigmask(pid, old | (1u64 << sig));
                }
                push_sigframe_riscv(frame, &info, handler_va, restorer, sa_flags);
                return; // deliver one signal per trap exit
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub fn check_and_deliver(frame: &mut crate::arch::x86_64::syscall::SyscallFrame) {
    let pid = scheduler::current_pid() as usize;

    loop {
        let info = {
            let mask = get_sigmask(pid);
            let mut map = PENDING.lock();
            let queue = match map.get_mut(&pid) {
                Some(q) => q,
                None    => return,
            };
            let pos = queue.iter().position(|s| {
                s.sig >= 1 && s.sig <= 64
                    && (mask >> s.sig) & 1 == 0
            });
            match pos {
                Some(i) => queue.remove(i).unwrap(),
                None    => return,
            }
        };

        let sig = info.sig as usize;

        let (handler, sa_flags, restorer) = scheduler::with_proc(pid, |p| (
            p.signal_handlers.handlers[sig],
            p.signal_handlers.flags[sig],
            p.signal_handlers.restorer,
        )).unwrap_or((0, 0, 0));

        match handler {
            0 => {
                if (SIG_IGN_DEFAULT >> sig) & 1 != 0 { continue; }
                if (SIG_STOP_DEFAULT >> sig) & 1 != 0 {
                    scheduler::with_proc_mut(pid, |p| p.state = State::Blocked);
                    scheduler::schedule();
                    continue;
                }
                crate::proc::exit::do_exit(pid, -(sig as i32));
                return;
            }
            1 => { continue; }
            handler_va => {
                if sa_flags & SA_NODEFER == 0 {
                    let old = get_sigmask(pid);
                    set_sigmask(pid, old | (1u64 << sig));
                }
                push_sigframe_x86(frame, &info, handler_va, restorer, sa_flags);
                return;
            }
        }
    }
}

// ── push_sigframe_riscv ───────────────────────────────────────────────
//
// Carves a RiscvSigFrame from the user stack and redirects the TrapFrame
// so that sret lands at the handler.
//
// Frame layout on the user stack (grows down):
//
//   [user sp before signal]
//     -272  saved TrapFrame  (copy of the kernel TrapFrame — all 34 words)
//     -352  siginfo_t        (80 bytes: sig, errno, code, pid, addr)
//     -360  restorer VA      (8 bytes)
//    ────── new user sp (16-byte aligned) ─────────────────────────────
//
// After frame is pushed:
//   frame.sepc = handler_va   — CPU jumps here on sret
//   frame.a0   = signum       — first argument to handler
//   frame.a1   = &siginfo     — second argument
//   frame.a2   = 0            — no ucontext_t
//   frame.sp   = new_user_sp  — user stack pointer
//   frame.ra   = restorer     — handler returns here; restorer does rt_sigreturn

#[cfg(target_arch = "riscv64")]
fn push_sigframe_riscv(
    frame:      &mut crate::arch::riscv64::trap::TrapFrame,
    info:       &SigInfo,
    handler_va: usize,
    restorer:   usize,
    sa_flags:   u32,
) {
    use crate::arch::riscv64::trap::TRAP_FRAME_SIZE;

    // ── Choose stack ──────────────────────────────────────────────────
    let pid = scheduler::current_pid() as usize;
    let base_sp = if sa_flags & SA_ONSTACK != 0 {
        let alt = ALTSTACK.lock().get(&pid).copied().unwrap_or(AltStack::default());
        if alt.ss_flags & SS_DISABLE == 0 && alt.ss_sp != 0 {
            if alt.ss_flags & SS_AUTODISARM != 0 {
                ALTSTACK.lock().remove(&pid);
            }
            alt.ss_sp + alt.ss_size
        } else {
            frame.sp   // current user sp
        }
    } else {
        frame.sp
    };

    // ── Carve frame ───────────────────────────────────────────────────
    // Layout (from high to low address):
    //   [restorer_slot]  8 bytes    ← highest
    //   [siginfo_t]     80 bytes
    //   [saved TrapFrame] TRAP_FRAME_SIZE bytes  ← lowest = new sp
    const SIGINFO_SIZE: usize = 80;
    const RESTORER_SLOT: usize = 8;
    const FRAME_TOTAL: usize = TRAP_FRAME_SIZE + SIGINFO_SIZE + RESTORER_SLOT;

    // Align down to 16 bytes after subtracting the whole frame.
    let new_sp = (base_sp - FRAME_TOTAL) & !0xf;

    // Safety: we write into user address space. If the user stack is
    // unmapped this will page-fault; the fault handler will send SIGSEGV.
    let saved_frame_va  = new_sp;
    let siginfo_va      = new_sp + TRAP_FRAME_SIZE;
    let restorer_va     = new_sp + TRAP_FRAME_SIZE + SIGINFO_SIZE;

    // 1. Save the full TrapFrame (272 bytes) so sigreturn can restore it.
    unsafe {
        core::ptr::copy_nonoverlapping(
            frame as *const _ as *const u8,
            saved_frame_va as *mut u8,
            TRAP_FRAME_SIZE,
        );
    }

    // 2. Write siginfo_t (80 bytes, Linux layout).
    //    offset  0: si_signo (i32)
    //    offset  4: si_errno (i32) = 0
    //    offset  8: si_code  (i32)
    //    offset 12: _pad
    //    offset 16: si_addr  (u64)   for SIGSEGV/SIGBUS/SIGFPE/SIGILL
    //    offset 24: si_pid   (u32)   for SIGCHLD / kill()
    //    offset 28: si_uid   (u32)
    unsafe {
        let si = siginfo_va as *mut u8;
        core::ptr::write_bytes(si, 0, SIGINFO_SIZE);
        (si.add(0)  as *mut i32).write(info.sig as i32);
        (si.add(8)  as *mut i32).write(info.code);
        (si.add(16) as *mut u64).write(info.addr as u64);
        (si.add(24) as *mut u32).write(info.pid);
        (si.add(28) as *mut u32).write(info.uid);
    }

    // 3. Write restorer VA.
    unsafe {
        (restorer_va as *mut usize).write(restorer);
    }

    // 4. Redirect the TrapFrame so sret enters the handler.
    frame.sepc = handler_va;
    frame.a0   = info.sig as usize;    // signum
    frame.a1   = siginfo_va;           // &siginfo_t
    frame.a2   = 0;                    // no ucontext_t
    frame.sp   = new_sp;               // new user sp
    frame.ra   = restorer;             // return address out of handler
}

// ── push_sigframe_x86 ─────────────────────────────────────────────────
//
// Carves an x86_64 signal frame from the user RSP and redirects RIP.
//
// Frame layout on user stack (grows down):
//   [user rsp before signal]
//     -8    retaddr (restorer VA)
//     -88   siginfo_t (80 bytes)
//     -344  ucontext_t (256 bytes)  ← new user rsp
//
// On entry to handler:
//   rdi = signum
//   rsi = &siginfo_t  (frame + 256)
//   rdx = &ucontext_t (frame + 0)
//   rip = handler_va

#[cfg(target_arch = "x86_64")]
fn push_sigframe_x86(
    frame:      &mut crate::arch::x86_64::syscall::SyscallFrame,
    info:       &SigInfo,
    handler_va: usize,
    restorer:   usize,
    sa_flags:   u32,
) {
    let pid = scheduler::current_pid() as usize;
    let base_rsp = if sa_flags & SA_ONSTACK != 0 {
        let alt = ALTSTACK.lock().get(&pid).copied().unwrap_or(AltStack::default());
        if alt.ss_flags & SS_DISABLE == 0 && alt.ss_sp != 0 {
            if alt.ss_flags & SS_AUTODISARM != 0 { ALTSTACK.lock().remove(&pid); }
            alt.ss_sp + alt.ss_size
        } else { frame.rsp }
    } else { frame.rsp };

    // Frame: 256 (ucontext) + 80 (siginfo) + 8 (retaddr) = 344 bytes.
    const UCTX_SIZE:    usize = 256;
    const SIGINFO_SIZE: usize = 80;
    const RETADDR_SIZE: usize = 8;
    const FRAME_TOTAL:  usize = UCTX_SIZE + SIGINFO_SIZE + RETADDR_SIZE;

    let new_rsp     = (base_rsp - FRAME_TOTAL) & !0xf;
    let uctx_va     = new_rsp;
    let siginfo_va  = new_rsp + UCTX_SIZE;
    let retaddr_va  = new_rsp + UCTX_SIZE + SIGINFO_SIZE;

    // 1. Write ucontext_t (256 bytes, simplified — saves rip, rsp, rflags,
    //    and all GP regs so rt_sigreturn can restore them).
    //    Linux ucontext_t layout (offsets we care about):
    //      +0   uc_flags
    //      +8   uc_link
    //      +16  uc_stack (ss_sp, ss_flags, ss_size)
    //      +40  uc_mcontext (gregs[23] starting at +56):
    //             gregs[0..15] = r8-r15, rdi, rsi, rbp, rbx, rdx, rax, rcx, rsp
    //             gregs[16]    = rip
    //             gregs[17]    = eflags
    //    We use a simplified layout: zero everything, then store the
    //    registers we need for sigreturn at well-known offsets.
    unsafe {
        core::ptr::write_bytes(uctx_va as *mut u8, 0, UCTX_SIZE);
        // Store rip at uc_mcontext.rip  (offset 160 = 40 + 15*8)
        // Store rsp at uc_mcontext.rsp  (offset 152 = 40 + 14*8)
        // Store rflags at uc_mcontext.eflags (offset 168 = 40 + 16*8 + 8)
        let base = uctx_va as *mut usize;
        base.add(20).write(frame.rip);    // offset 160: rip
        base.add(19).write(frame.rsp);    // offset 152: rsp
        base.add(21).write(frame.rflags); // offset 168: rflags
    }

    // 2. Write siginfo_t.
    unsafe {
        let si = siginfo_va as *mut u8;
        core::ptr::write_bytes(si, 0, SIGINFO_SIZE);
        (si.add(0)  as *mut i32).write(info.sig as i32);
        (si.add(8)  as *mut i32).write(info.code);
        (si.add(16) as *mut u64).write(info.addr as u64);
        (si.add(24) as *mut u32).write(info.pid);
        (si.add(28) as *mut u32).write(info.uid);
    }

    // 3. Write restorer at retaddr slot (below siginfo).
    unsafe { (retaddr_va as *mut usize).write(restorer); }

    // 4. Redirect the SyscallFrame.
    frame.rip    = handler_va;
    frame.rdi    = info.sig as usize;   // arg0: signum
    frame.rsi    = siginfo_va;          // arg1: &siginfo_t
    frame.rdx    = uctx_va;             // arg2: &ucontext_t
    frame.rsp    = new_rsp;
    frame.rflags = 0x202;
}

// ── sys_rt_sigreturn ─────────────────────────────────────────────────────
//
// NR 15 on x86_64, NR 139 on RISC-V.
// Restores the saved register state from the SignalFrame at the current
// user stack pointer, undoing what push_sigframe_* set up.

#[cfg(target_arch = "riscv64")]
pub fn sys_rt_sigreturn(frame: &mut crate::arch::riscv64::trap::TrapFrame) -> isize {
    use crate::arch::riscv64::trap::TRAP_FRAME_SIZE;

    // The saved TrapFrame is at frame.sp (which is the new_sp we set in
    // push_sigframe_riscv — the lowest address of the signal frame).
    let saved_va = frame.sp;

    // Basic sanity: must be in user space and 8-byte aligned.
    if saved_va == 0 || saved_va >= USER_SPACE_END || saved_va & 7 != 0 {
        return -14;
    }

    // Restore the saved TrapFrame over the current one.
    unsafe {
        core::ptr::copy_nonoverlapping(
            saved_va as *const u8,
            frame as *mut _ as *mut u8,
            TRAP_FRAME_SIZE,
        );
    }

    // Restore the sigmask that was active before the signal.
    // We unblock the signal that was being handled. We use the
    // saved sstatus to identify which signal; for simplicity we
    // just clear the lowest set bit of the current per-signal block
    // added by SA_NODEFER logic — the real implementation would
    // save the pre-delivery mask in the sigframe.
    // For now, clear the whole per-handler addition by reading the
    // restorer VA slot to find which signal we were in.
    // Simplified: restore the old mask stored just after the TrapFrame.
    let pid = scheduler::current_pid() as usize;
    // The siginfo is at saved_va + TRAP_FRAME_SIZE.
    // si_signo is the first i32 there.
    let signo = unsafe {
        core::ptr::read_unaligned((saved_va + TRAP_FRAME_SIZE) as *const i32)
    } as usize;
    if signo >= 1 && signo <= 64 {
        let old = get_sigmask(pid);
        set_sigmask(pid, old & !(1u64 << signo));
    }

    // Return value is taken from the restored frame's a0 — the frame
    // restore happens above so the trap handler will reload a0 from
    // the frame.  Return 0 here (the TrapFrame.a0 already has the
    // correct value from when the signal was delivered).
    0
}

#[cfg(target_arch = "x86_64")]
pub fn sys_rt_sigreturn(frame: &mut crate::arch::x86_64::syscall::SyscallFrame) -> isize {
    // The ucontext_t is at frame.rsp (new_rsp set in push_sigframe_x86).
    let uctx_va = frame.rsp;
    if uctx_va == 0 || uctx_va >= USER_SPACE_END { return -14; }

    // Restore rip, rsp, rflags from the ucontext layout we wrote.
    unsafe {
        let base = uctx_va as *const usize;
        frame.rip    = base.add(20).read(); // offset 160
        frame.rsp    = base.add(19).read(); // offset 152
        frame.rflags = base.add(21).read(); // offset 168
    }

    // Unblock the signal we were handling.
    let siginfo_va = uctx_va + 256;
    let signo = unsafe {
        core::ptr::read_unaligned(siginfo_va as *const i32)
    } as usize;
    let pid = scheduler::current_pid() as usize;
    if signo >= 1 && signo <= 64 {
        let old = get_sigmask(pid);
        set_sigmask(pid, old & !(1u64 << signo));
    }
    0
}

// ── sys_rt_sigpending [NR 127] ────────────────────────────────────────

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
    if !copy_to_user(set_va, &pending_set.to_ne_bytes()) { return -14; }
    0
}

// ── sys_rt_sigsuspend [NR 130] ────────────────────────────────────────

pub fn sys_rt_sigsuspend(mask_va: usize, sigsetsize: usize) -> isize {
    if sigsetsize != 8 { return -22; }
    if mask_va == 0 || mask_va >= USER_SPACE_END { return -14; }
    let pid = scheduler::current_pid();
    let mut mask_bytes = [0u8; 8];
    if copy_from_user(&mut mask_bytes, mask_va).is_err() { return -14; }
    let new_mask = u64::from_ne_bytes(mask_bytes) & !((1u64 << 9) | (1u64 << 19));
    let old_mask = get_sigmask(pid as usize);
    set_sigmask(pid as usize, new_mask);
    loop {
        {
            let map = PENDING.lock();
            if let Some(queue) = map.get(&(pid as usize)) {
                for info in queue.iter() {
                    if info.sig >= 1 && info.sig <= 64 {
                        if (new_mask >> info.sig) & 1 == 0 {
                            drop(map);
                            set_sigmask(pid as usize, old_mask);
                            return -4;
                        }
                    }
                }
            }
        }
        scheduler::with_procs_mut(|procs| {
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.state = State::Blocked;
            }
        });
        scheduler::schedule();
    }
}

// ── sys_rt_sigtimedwait [NR 128] ─────────────────────────────────────

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
            } else { None }
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
                let _ = copy_to_user(uinfo_va, &si);
            }
            return info.sig as isize;
        }
        if let Some(dl) = deadline_ns {
            if crate::proc::nanosleep::now_ns() >= dl { return -11; }
        }
        {
            let mask = get_sigmask(pid as usize);
            let map = PENDING.lock();
            if let Some(queue) = map.get(&(pid as usize)) {
                for info in queue.iter() {
                    if info.sig >= 1 && info.sig <= 64
                        && (wait_set >> info.sig) & 1 == 0
                        && (mask     >> info.sig) & 1 == 0
                    {
                        return -4;
                    }
                }
            }
        }
        scheduler::with_procs_mut(|procs| {
            if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
                p.state = State::Blocked;
            }
        });
        scheduler::schedule();
    }
}

// ── sys_sigaltstack [NR 131] ──────────────────────────────────────────

pub fn sys_sigaltstack(ss_va: usize, old_ss_va: usize) -> isize {
    let pid = scheduler::current_pid();
    if old_ss_va != 0 && old_ss_va < USER_SPACE_END {
        let alt = ALTSTACK.lock().get(&(pid as usize)).copied().unwrap_or(AltStack {
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
            ALTSTACK.lock().remove(&(pid as usize));
        } else {
            if ss_size < 2048 { return -22; }
            ALTSTACK.lock().insert(pid as usize, AltStack { ss_sp, ss_flags, ss_size });
        }
    }
    0
}

// ── sys_rt_sigaction [NR 13] ──────────────────────────────────────────

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
        if !copy_to_user(old_act_va,      &old_handler.to_ne_bytes())         { return -14; }
        if !copy_to_user(old_act_va + 8,  &(old_flags as u64).to_ne_bytes())  { return -14; }
        if !copy_to_user(old_act_va + 16, &old_restorer.to_ne_bytes())        { return -14; }
    }
    0
}

// ── sys_sigprocmask [NR 14 / NR 135] ─────────────────────────────────

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
