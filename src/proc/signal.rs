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

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use spin::Mutex;

use crate::proc::scheduler;
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::uaccess::{copy_to_user, copy_from_user, USER_SPACE_END};

// ── Signal metadata ────────────────────────────────────────────────────

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

// ── Signal storage ────────────────────────────────────────────────────

static PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> =
    Mutex::new(BTreeMap::new());
static SIGMASK: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

// ── Alternate stack ────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct AltStack { ss_sp: usize, ss_flags: i32, ss_size: usize }

const SS_DISABLE:    i32 = 2;
const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

static ALTSTACK: Mutex<BTreeMap<usize, AltStack>> = Mutex::new(BTreeMap::new());

// ── SA_* flags ────────────────────────────────────────────────────────────

const SA_ONSTACK:  u32 = 0x08000000;
const SA_RESTORER: u32 = 0x04000000;
const SA_NODEFER:  u32 = 0x40000000;

// ── Handler table ─────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct SignalHandlers {
    pub handlers: [usize; 65],
    pub flags:    [u32;   65],
    pub restorer: usize,
}

// ── Public API ────────────────────────────────────────────────────────────

pub fn send_signal(pid: usize, sig: u32) {
    send_signal_info(pid, SigInfo { sig, code: SI_KERNEL, ..Default::default() });
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

// ── sys_sigaltstack [NR 131] ──────────────────────────────────────────────

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

// ── sys_rt_sigaction [NR 13] ───────────────────────────────────────────────

pub fn sys_rt_sigaction(
    sig: u32, new_act_va: usize, old_act_va: usize, _sigsetsize: usize,
) -> isize {
    if sig == 0 || sig > 64 { return -22; }
    let pid = scheduler::current_pid();

    let (old_handler, old_flags, old_restorer) = scheduler::with_procs(|procs| {
        if let Some(p) = procs.iter_mut().find(|p| p.pid == pid) {
            let idx = sig as usize;
            let old = (p.signal_handlers.handlers[idx],
                       p.signal_handlers.flags[idx],
                       p.signal_handlers.restorer);
            if new_act_va != 0 && new_act_va < USER_SPACE_END {
                let mut h_bytes = [0u8; 8];
                let mut f_bytes = [0u8; 8];
                let mut r_bytes = [0u8; 8];
                if copy_from_user(&mut h_bytes, new_act_va).is_ok()      &&
                   copy_from_user(&mut f_bytes, new_act_va + 8).is_ok()  &&
                   copy_from_user(&mut r_bytes, new_act_va + 16).is_ok()
                {
                    p.signal_handlers.handlers[idx] = usize::from_ne_bytes(h_bytes);
                    p.signal_handlers.flags[idx]    = u64::from_ne_bytes(f_bytes) as u32;
                    p.signal_handlers.restorer      = usize::from_ne_bytes(r_bytes);
                }
            }
            old
        } else { (0, 0, 0) }
    });

    if old_act_va != 0 && old_act_va < USER_SPACE_END {
        let _ = copy_to_user(old_act_va,      &old_handler.to_ne_bytes());
        let _ = copy_to_user(old_act_va + 8,  &(old_flags as u64).to_ne_bytes());
        let _ = copy_to_user(old_act_va + 16, &old_restorer.to_ne_bytes());
        let _ = copy_to_user(old_act_va + 24, &0u64.to_ne_bytes());
    }
    0
}

// ── sys_rt_sigprocmask [NR 14] ─────────────────────────────────────────────

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
        0 => cur | new_set,
        1 => cur & !new_set,
        2 => new_set,
        _ => return -22,
    };
    set_sigmask(pid, updated & !((1u64 << 9) | (1u64 << 19)));
    0
}

// ── Signal frame layout ───────────────────────────────────────────────────

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

// ── check_pending_signal ──────────────────────────────────────────────────

pub fn check_pending_signal(frame: &mut SyscallFrame) {
    let pid = scheduler::current_pid();
    if pid == 0 { return; }
    let mask = get_sigmask(pid);

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

    let (handler_va, sa_flags, restorer) = scheduler::with_procs(|procs| {
        procs.iter().find(|p| p.pid == pid).map(|p| (
            p.signal_handlers.handlers[info.sig as usize],
            p.signal_handlers.flags[info.sig as usize],
            p.signal_handlers.restorer,
        )).unwrap_or((0, 0, 0))
    });

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
    let uc_va  = sp;
    let si_va  = sp + UCONTEXT_SIZE;
    let ret_va = sp + UCONTEXT_SIZE + SIGINFO_SIZE;

    unsafe { core::ptr::write_bytes(sp as *mut u8, 0, SIGNAL_FRAME_SIZE); }

    unsafe {
        ((uc_va + 16) as *mut usize).write_unaligned(frame.rsp);
        ((uc_va + 24) as *mut i32 ).write_unaligned(0);
        ((uc_va + 32) as *mut usize).write_unaligned(0);
    }

    macro_rules! wgreg {
        ($idx:expr, $val:expr) => {
            unsafe { ((uc_va + greg_off($idx)) as *mut u64).write_unaligned($val as u64); }
        };
    }
    wgreg!(REG_R8,      frame.r8);
    wgreg!(REG_R9,      frame.r9);
    wgreg!(REG_R10,     frame.r10);
    wgreg!(REG_R11,     frame.r11);   // r11 = RFLAGS saved by SYSCALL hardware
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
    wgreg!(REG_EFL,     frame.r11);   // EFL = r11 (RFLAGS)
    wgreg!(REG_CSGSFS,  0x002B_0033u64);
    wgreg!(REG_OLDMASK, mask);
    wgreg!(REG_CR2,     info.addr as u64);

    unsafe { ((uc_va + 240) as *mut u64).write_unaligned(mask); }

    unsafe {
        (si_va           as *mut i32).write_unaligned(info.sig as i32);
        ((si_va + 4)     as *mut i32).write_unaligned(0);
        ((si_va + 8)     as *mut i32).write_unaligned(info.code);
        ((si_va + 16) as *mut i32).write_unaligned(info.pid as i32);
        ((si_va + 20) as *mut i32).write_unaligned(info.uid as i32);
        match info.sig {
            17 => ((si_va + 24) as *mut i32).write_unaligned(info.status),
            11 | 7 | 8 => ((si_va + 16) as *mut usize).write_unaligned(info.addr),
            _ => {}
        }
    }

    let ret_addr = if sa_flags & SA_RESTORER != 0 && restorer != 0 {
        restorer
    } else {
        build_inline_trampoline(sp)
    };
    unsafe { (ret_va as *mut usize).write_volatile(ret_addr); }

    frame.rdi = info.sig as usize;
    frame.rsi = si_va;
    frame.rdx = uc_va;
    frame.rip = handler_va;
    frame.rsp = ret_va;
}

// ── sys_rt_sigreturn [NR 15] ──────────────────────────────────────────────

pub fn sys_rt_sigreturn(frame: &mut SyscallFrame) -> isize {
    let pid = scheduler::current_pid();
    let uc_va = frame.rsp.wrapping_sub(UCONTEXT_SIZE + SIGINFO_SIZE);
    if uc_va == 0 || uc_va >= USER_SPACE_END { return -14; }

    macro_rules! rgreg {
        ($idx:expr) => {
            unsafe { ((uc_va + greg_off($idx)) as *const u64).read_unaligned() as usize }
        };
    }

    frame.r8     = rgreg!(REG_R8);
    frame.r9     = rgreg!(REG_R9);
    frame.r10    = rgreg!(REG_R10);
    frame.r11    = rgreg!(REG_EFL);   // restore RFLAGS into r11
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
    // r11 already set to EFL above; rcx already set to RIP above

    let old_mask = unsafe { ((uc_va + 240) as *const u64).read_unaligned() };
    set_sigmask(pid, old_mask);
    0
}

// ── Inline trampoline (fallback) ─────────────────────────────────────────────

fn build_inline_trampoline(sp: usize) -> usize {
    const CODE: [u8; 9] = [0x48, 0xC7, 0xC0, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05];
    let va = sp.wrapping_sub(16);
    unsafe { core::ptr::copy_nonoverlapping(CODE.as_ptr(), va as *mut u8, CODE.len()); }
    va
}
