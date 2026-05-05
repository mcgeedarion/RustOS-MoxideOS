//! Signal delivery, masking, and rt_sigreturn.
//!
//! ## Delivery model
//!   1. send_signal(pid, sig) pushes a SigInfo onto PENDING[pid].
//!   2. At every syscall return, check_pending_signal(frame) is called.
//!   3. For a registered SA_SIGACTION handler the kernel:
//!      a. Optionally switches rsp to the alternate stack (SA_ONSTACK).
//!      b. Carves a SignalFrame from the top of the chosen stack:
//!            [ucontext_t]  256 bytes  (register snapshot + sigmask, padded)
//!            [siginfo_t]    80 bytes  (signal metadata)
//!            [retaddr]       8 bytes  (SA_RESTORER or inline trampoline)
//!      c. Points rdi=signum, rsi=siginfo*, rdx=ucontext*, rip=handler.
//!   4. SA_RESTORER (musl: __restore_rt) does `mov $15,%rax; syscall`.
//!   5. sys_rt_sigreturn reads the saved ucontext_t and restores all
//!      general-purpose registers plus rip/rsp/rflags.
//!
//! ## Alternate-stack (SA_ONSTACK / sigaltstack)
//!   When SA_ONSTACK is set, an alt-stack is registered, and rsp is not
//!   already within that stack, delivery switches rsp to the stack top.
//!   SS_AUTODISARM disables the alt-stack on entry to prevent re-entry.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use spin::Mutex;

use crate::proc::scheduler;
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::uaccess::{copy_to_user, copy_from_user, USER_SPACE_END};

// ── Signal metadata ──────────────────────────────────────────────────────────

/// Pending-signal entry — carries siginfo fields for SA_SIGINFO handlers.
#[derive(Clone, Copy, Default, Debug)]
pub struct SigInfo {
    pub sig:    u32,
    pub code:   i32,   // si_code
    pub pid:    u32,   // si_pid  (SIGCHLD / kill)
    pub uid:    u32,   // si_uid
    pub status: i32,   // si_status (SIGCHLD exit code)
    pub addr:   usize, // si_addr   (SIGSEGV / SIGBUS / SIGFPE)
    pub value:  i64,   // si_value.sival_int (SIGRT*)
}

// si_code constants (same values as Linux)
const SI_KERNEL:  i32 = 128;
const SI_USER:    i32 = 0;
const CLD_EXITED: i32 = 1;
const CLD_KILLED: i32 = 2;
const SEGV_MAPERR: i32 = 1;

// ── Signal storage ──────────────────────────────────────────────────────────

static PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> =
    Mutex::new(BTreeMap::new());
static SIGMASK: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

// ── Alternate stack ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct AltStack { ss_sp: usize, ss_flags: i32, ss_size: usize }

const SS_DISABLE:    i32 = 2;
const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

static ALTSTACK: Mutex<BTreeMap<usize, AltStack>> = Mutex::new(BTreeMap::new());

// ── SA_* flags ─────────────────────────────────────────────────────────────

const SA_ONSTACK:  u32 = 0x08000000;
const SA_RESTORER: u32 = 0x04000000;
const SA_NODEFER:  u32 = 0x40000000;

// ── Handler table ───────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct SignalHandlers {
    pub handlers: [usize; 65],
    pub flags:    [u32;   65],
    pub restorer: usize,
}

// ── Public API ─────────────────────────────────────────────────────────────

pub fn send_signal(pid: usize, sig: u32) {
    send_signal_info(pid, SigInfo { sig, code: SI_KERNEL, ..Default::default() });
}

pub fn send_signal_info(pid: usize, info: SigInfo) {
    if info.sig == 0 || info.sig > 64 { return; }
    PENDING.lock().entry(pid).or_default().push_back(info);
    scheduler::wake_pid(pid);
}

/// Send SIGCHLD with CLD_EXITED / CLD_KILLED metadata.
pub fn send_sigchld(parent_pid: usize, child_pid: usize, exit_code: i32, killed: bool) {
    send_signal_info(parent_pid, SigInfo {
        sig:    17, // SIGCHLD
        code:   if killed { CLD_KILLED } else { CLD_EXITED },
        pid:    child_pid as u32,
        status: exit_code,
        ..Default::default()
    });
}

/// Send SIGSEGV with the faulting address.
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

// ── sys_sigaltstack [NR 131] ─────────────────────────────────────────────────

pub fn sys_sigaltstack(ss_va: usize, old_ss_va: usize) -> isize {
    let pid = scheduler::current_pid();

    // Write current alt-stack info to userspace if requested.
    if old_ss_va != 0 && old_ss_va < USER_SPACE_END {
        let alt = ALTSTACK.lock().get(&pid).copied().unwrap_or(AltStack {
            ss_sp: 0, ss_flags: SS_DISABLE, ss_size: 0,
        });
        // stack_t layout: ss_sp(usize) + ss_flags(i32) + pad(i32) + ss_size(usize)
        let _ = copy_to_user(old_ss_va,      &alt.ss_sp.to_ne_bytes());
        let _ = copy_to_user(old_ss_va + 8,  &alt.ss_flags.to_ne_bytes());
        let _ = copy_to_user(old_ss_va + 12, &0i32.to_ne_bytes());
        let _ = copy_to_user(old_ss_va + 16, &alt.ss_size.to_ne_bytes());
    }

    // Read new alt-stack from userspace if provided.
    if ss_va != 0 && ss_va < USER_SPACE_END {
        let mut sp_bytes    = [0u8; 8];
        let mut flags_bytes = [0u8; 4];
        let mut size_bytes  = [0u8; 8];
        if copy_from_user(ss_va,      &mut sp_bytes).is_err()    ||
           copy_from_user(ss_va + 8,  &mut flags_bytes).is_err() ||
           copy_from_user(ss_va + 16, &mut size_bytes).is_err() {
            return -14; // EFAULT
        }
        let ss_sp    = usize::from_ne_bytes(sp_bytes);
        let ss_flags = i32::from_ne_bytes(flags_bytes);
        let ss_size  = usize::from_ne_bytes(size_bytes);

        if ss_flags & SS_DISABLE != 0 {
            ALTSTACK.lock().remove(&pid);
        } else {
            if ss_size < 2048 { return -22; } // EINVAL: too small
            ALTSTACK.lock().insert(pid, AltStack { ss_sp, ss_flags, ss_size });
        }
    }
    0
}

// ── sys_rt_sigaction [NR 13] ─────────────────────────────────────────────────

pub fn sys_rt_sigaction(
    sig: u32, new_act_va: usize, old_act_va: usize, _sigsetsize: usize,
) -> isize {
    if sig == 0 || sig > 64 { return -22; } // EINVAL
    let pid = scheduler::current_pid();

    // Retrieve or update signal handler via with_procs (RAII, no manual unlock).
    let (old_handler, old_flags, old_restorer) = scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            let idx = sig as usize;
            let old = (p.signal_handlers.handlers[idx],
                       p.signal_handlers.flags[idx],
                       p.signal_handlers.restorer);
            // Apply new action while the lock is held.
            if new_act_va != 0 && new_act_va < USER_SPACE_END {
                let mut h_bytes = [0u8; 8];
                let mut f_bytes = [0u8; 8];
                let mut r_bytes = [0u8; 8];
                if copy_from_user(new_act_va,      &mut h_bytes).is_ok() &&
                   copy_from_user(new_act_va + 8,  &mut f_bytes).is_ok() &&
                   copy_from_user(new_act_va + 16, &mut r_bytes).is_ok()
                {
                    p.signal_handlers.handlers[idx] = usize::from_ne_bytes(h_bytes);
                    p.signal_handlers.flags[idx]    = u64::from_ne_bytes(f_bytes) as u32;
                    p.signal_handlers.restorer      = usize::from_ne_bytes(r_bytes);
                }
            }
            old
        } else { (0, 0, 0) }
    });

    // Write old action to userspace.
    if old_act_va != 0 && old_act_va < USER_SPACE_END {
        let _ = copy_to_user(old_act_va,      &old_handler.to_ne_bytes());
        let _ = copy_to_user(old_act_va + 8,  &(old_flags as u64).to_ne_bytes());
        let _ = copy_to_user(old_act_va + 16, &old_restorer.to_ne_bytes());
        let _ = copy_to_user(old_act_va + 24, &0u64.to_ne_bytes()); // sa_mask
    }
    0
}

// ── sys_rt_sigprocmask [NR 14] ──────────────────────────────────────────────

pub fn sys_rt_sigprocmask(how: u32, set_va: usize, oldset_va: usize, _sz: usize) -> isize {
    let pid = scheduler::current_pid();
    let cur = get_sigmask(pid);

    if oldset_va != 0 && oldset_va < USER_SPACE_END {
        let _ = copy_to_user(oldset_va, &cur.to_ne_bytes());
    }
    if set_va == 0 || set_va >= USER_SPACE_END { return 0; }

    let mut set_bytes = [0u8; 8];
    if copy_from_user(set_va, &mut set_bytes).is_err() { return -14; } // EFAULT
    let new_set = u64::from_ne_bytes(set_bytes);

    let updated = match how {
        0 => cur | new_set,  // SIG_BLOCK
        1 => cur & !new_set, // SIG_UNBLOCK
        2 => new_set,        // SIG_SETMASK
        _ => return -22,     // EINVAL
    };
    // SIGKILL (9) and SIGSTOP (19) cannot be masked.
    set_sigmask(pid, updated & !((1u64 << 9) | (1u64 << 19)));
    0
}

// ── Signal frame layout ───────────────────────────────────────────────────────
//
// Stack layout carved by check_pending_signal (grows downward):
//
//   sp (16-byte aligned after red-zone clearance)
//   + 0             ucontext_t   256 bytes  ← rdx for SA_SIGINFO
//   + 256           siginfo_t     80 bytes  ← rsi for SA_SIGINFO
//   + 336           retaddr        8 bytes  ← rsp handed to handler
//
// ucontext_t internal layout:
//   +0    uc_flags      u64
//   +8    uc_link       u64
//   +16   uc_stack      stack_t (24 bytes)
//   +40   uc_mcontext  gregs[23] (23 × 8 = 184 bytes)
//   +224  fpregs ptr   u64 (0)
//   +232  reserved[1]  u64 (0)
//   +240  uc_sigmask   u64
//   +248  padding[1]   u64
//   total 256 bytes
//
// siginfo_t (80 bytes):
//   +0  si_signo  i32
//   +4  si_errno  i32
//   +8  si_code   i32
//   +12 _pad      i32
//   +16 _fields union (si_pid/si_addr/si_status depending on signal)
//
// gregset_t order (Linux x86-64, sys/ucontext.h):
//   [0]=r8  [1]=r9  [2]=r10 [3]=r11 [4]=r12 [5]=r13 [6]=r14 [7]=r15
//   [8]=rdi [9]=rsi [10]=rbp [11]=rbx [12]=rdx [13]=rax [14]=rcx
//   [15]=rsp [16]=rip [17]=efl [18]=csgsfs [19]=err [20]=trapno
//   [21]=oldmask [22]=cr2

const UCONTEXT_SIZE:     usize = 256;
const SIGINFO_SIZE:      usize = 80;
const RETADDR_SIZE:      usize = 8;
const SIGNAL_FRAME_SIZE: usize = UCONTEXT_SIZE + SIGINFO_SIZE + RETADDR_SIZE;

const GREGS_OFFSET: usize = 40; // uc_mcontext starts at +40 in ucontext_t

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

// ── check_pending_signal ─────────────────────────────────────────────────────

pub fn check_pending_signal(frame: &mut SyscallFrame) {
    let pid = scheduler::current_pid();
    if pid == 0 { return; }
    let mask = get_sigmask(pid);

    // Dequeue the first unmasked pending signal.
    let info = {
        let mut q = PENDING.lock();
        let queue = match q.get_mut(&pid) { Some(q) => q, None => return };
        let pos = queue.iter().position(|s| s.sig > 0 && (mask >> s.sig) & 1 == 0);
        match pos {
            Some(i) => queue.remove(i).unwrap_or_default(),
            None    => return,
        }
    };
    if info.sig == 0 { return; }

    // Retrieve handler info via with_procs (no manual lock/unlock).
    let (handler_va, sa_flags, restorer) = scheduler::with_procs(|procs| {
        procs.iter().find(|p| p.pid == pid).map(|p| (
            p.signal_handlers.handlers[info.sig as usize],
            p.signal_handlers.flags[info.sig as usize],
            p.signal_handlers.restorer,
        )).unwrap_or((0, 0, 0))
    });

    // Default action for unhandled signals.
    if handler_va == 0 {
        match info.sig {
            17 | 28 => {} // SIGCHLD / SIGWINCH: default is ignore
            _ => { crate::proc::exit::sys_exit(-(info.sig as i32)); }
        }
        return;
    }

    // Block this signal during handler delivery (unless SA_NODEFER).
    if sa_flags & SA_NODEFER == 0 {
        set_sigmask(pid, mask | (1u64 << info.sig));
    }

    // ── Choose delivery stack ──────────────────────────────────────────

    let mut sp = frame.rsp;
    if sa_flags & SA_ONSTACK != 0 {
        if let Some(alt) = ALTSTACK.lock().get(&pid).copied() {
            if alt.ss_flags & SS_DISABLE == 0 && alt.ss_size >= 2048 {
                let alt_hi = alt.ss_sp.wrapping_add(alt.ss_size);
                // Only switch if RSP is not already on the alt stack.
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

    // ── Carve signal frame ────────────────────────────────────────────

    let sp = (sp.wrapping_sub(128)                     // clear x86-64 red zone
                .wrapping_sub(SIGNAL_FRAME_SIZE)) & !0xF; // 16-byte align

    let uc_va  = sp;
    let si_va  = sp + UCONTEXT_SIZE;
    let ret_va = sp + UCONTEXT_SIZE + SIGINFO_SIZE;

    // Zero the entire frame before writing fields.
    unsafe { core::ptr::write_bytes(sp as *mut u8, 0, SIGNAL_FRAME_SIZE); }

    // ── Write ucontext_t ─────────────────────────────────────────────────

    // uc_stack: snapshot of RSP / stack at delivery time.
    unsafe {
        ((uc_va + 16) as *mut usize).write_unaligned(frame.rsp); // ss_sp
        ((uc_va + 24) as *mut i32 ).write_unaligned(0);          // ss_flags
        ((uc_va + 32) as *mut usize).write_unaligned(0);         // ss_size
    }

    // mcontext / gregset_t
    macro_rules! wgreg {
        ($idx:expr, $val:expr) => {
            unsafe {
                ((uc_va + greg_off($idx)) as *mut u64).write_unaligned($val as u64);
            }
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
    wgreg!(REG_EFL,     frame.rflags);
    wgreg!(REG_CSGSFS,  0x002B_0033u64);
    wgreg!(REG_OLDMASK, mask);
    wgreg!(REG_CR2,     info.addr as u64);

    // uc_sigmask (+240)
    unsafe { ((uc_va + 240) as *mut u64).write_unaligned(mask); }

    // ── Write siginfo_t ──────────────────────────────────────────────────

    unsafe {
        (si_va           as *mut i32).write_unaligned(info.sig as i32); // si_signo
        ((si_va + 4)     as *mut i32).write_unaligned(0);               // si_errno
        ((si_va + 8)     as *mut i32).write_unaligned(info.code);       // si_code
        // _fields union at +16: write both pid and addr; handler uses the
        // appropriate field based on signo (they overlap in the union).
        ((si_va + 16) as *mut i32).write_unaligned(info.pid as i32);    // si_pid
        ((si_va + 20) as *mut i32).write_unaligned(info.uid as i32);    // si_uid
        match info.sig {
            17 => ((si_va + 24) as *mut i32).write_unaligned(info.status), // SIGCHLD si_status
            11 | 7 | 8 => ((si_va + 16) as *mut usize).write_unaligned(info.addr), // fault si_addr
            _ => {}
        }
    }

    // ── Write return address ─────────────────────────────────────────────

    // SA_RESTORER (set by musl/glibc) is always preferred.
    // The inline trampoline is only a last-resort fallback and requires
    // the target VA to be mapped executable — which is not guaranteed.
    let ret_addr = if sa_flags & SA_RESTORER != 0 && restorer != 0 {
        restorer
    } else {
        build_inline_trampoline(sp)
    };
    unsafe { (ret_va as *mut usize).write_volatile(ret_addr); }

    // ── Redirect CPU to handler ──────────────────────────────────────

    frame.rdi = info.sig as usize; // arg1: signum
    frame.rsi = si_va;             // arg2: siginfo_t*
    frame.rdx = uc_va;             // arg3: ucontext_t*
    frame.rip = handler_va;
    frame.rsp = ret_va;            // ABI: retaddr lives at [rsp]
}

// ── sys_rt_sigreturn [NR 15] ─────────────────────────────────────────────────

/// Restore CPU state from the ucontext_t saved in the signal frame.
///
/// At the time of the call:
///   rsp = ret_va = sp + UCONTEXT_SIZE + SIGINFO_SIZE
///
/// Therefore:
///   uc_va = rsp - UCONTEXT_SIZE - SIGINFO_SIZE = sp
pub fn sys_rt_sigreturn(frame: &mut SyscallFrame) -> isize {
    let pid = scheduler::current_pid();

    // Compute uc_va from the current rsp.
    // rsp was set to ret_va = sp + UCONTEXT_SIZE + SIGINFO_SIZE, so:
    let uc_va = frame.rsp
        .wrapping_sub(UCONTEXT_SIZE + SIGINFO_SIZE);

    // Validate: must be a non-null user-space address.
    if uc_va == 0 || uc_va >= USER_SPACE_END { return -14; } // EFAULT

    macro_rules! rgreg {
        ($idx:expr) => {
            unsafe { ((uc_va + greg_off($idx)) as *const u64).read_unaligned() as usize }
        };
    }

    frame.r8     = rgreg!(REG_R8);
    frame.r9     = rgreg!(REG_R9);
    frame.r10    = rgreg!(REG_R10);
    frame.r11    = rgreg!(REG_R11);
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
    frame.rflags = rgreg!(REG_EFL);

    // Restore the pre-signal sigmask from uc_sigmask (+240).
    let old_mask = unsafe { ((uc_va + 240) as *const u64).read_unaligned() };
    set_sigmask(pid, old_mask);
    0
}

// ── Inline trampoline (fallback only) ──────────────────────────────────────

/// Write a `mov rax, 15; syscall` (SYS_rt_sigreturn) trampoline just below
/// `sp`. Used only when SA_RESTORER is not set — which musl always sets, so
/// this path should only be hit for hand-rolled or legacy signal handlers.
///
/// WARNING: the VA must be mapped executable (PROT_EXEC). This is not
/// guaranteed for stack memory. Callers should ensure SA_RESTORER is set
/// by all supported libc implementations.
fn build_inline_trampoline(sp: usize) -> usize {
    // mov rax, 15   =  48 C7 C0 0F 00 00 00  (7 bytes)
    // syscall       =  0F 05                  (2 bytes)
    const CODE: [u8; 9] = [0x48, 0xC7, 0xC0, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05];
    let va = sp.wrapping_sub(16);
    unsafe { core::ptr::copy_nonoverlapping(CODE.as_ptr(), va as *mut u8, CODE.len()); }
    va
}
