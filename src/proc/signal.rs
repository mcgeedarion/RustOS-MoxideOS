//! Signal delivery, masking, and rt_sigreturn.
//!
//! ## Delivery model
//!   1. send_signal(pid, sig) pushes a SigInfo onto PENDING[pid].
//!   2. At every syscall return, check_pending_signal(frame) is called.
//!   3. For a registered SA_SIGACTION handler the kernel:
//!      a. Optionally switches rsp to the alternate stack (SA_ONSTACK).
//!      b. Carves a SignalFrame from the top of the chosen stack:
//!            [ucontext_t]  128 bytes  (register snapshot + sigmask)
//!            [siginfo_t]    80 bytes  (signal metadata)
//!            retaddr slot    8 bytes  (SA_RESTORER or inline trampoline)
//!      c. Points rdi→siginfo, rsi→ucontext, sets rip=handler.
//!   4. SA_RESTORER (musl: __restore_rt) does `mov $15,%rax; syscall`.
//!   5. sys_rt_sigreturn reads the saved ucontext_t and restores all
//!      general-purpose registers plus rip/rsp/rflags.
//!
//! ## SA_SIGINFO fields populated
//!   SIGSEGV  si_addr = faulting address (from frame.rcx ≈ fault VA)
//!   SIGCHLD  si_pid  = child pid, si_status = exit code
//!   SIGBUS   si_addr = faulting address
//!   SIGFPE   si_addr = faulting address
//!   kill(2)  si_pid  = sender pid
//!   Default  si_code = SI_KERNEL
//!
//! ## Alternate-stack (SA_ONSTACK / sigaltstack)
//!   When SA_ONSTACK is set, an alt-stack is registered, and rsp is not
//!   already within that stack, delivery switches rsp to the stack top.
//!   SS_AUTODISARM disables the alt-stack on entry to prevent re-entry.

extern crate alloc;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use spin::Mutex;

use crate::proc::scheduler;
use crate::arch::x86_64::syscall::SyscallFrame;

// ── signal metadata ──────────────────────────────────────────────────────────

/// Richer pending-signal entry — carries siginfo fields for SA_SIGINFO.
#[derive(Clone, Copy, Default)]
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
const SI_KERNEL: i32 =  128;
const SI_USER:   i32 =  0;
const CLD_EXITED:    i32 = 1;
const CLD_KILLED:    i32 = 2;
const SEGV_MAPERR:   i32 = 1;
const BUS_ADRALN:    i32 = 1;
const FPE_INTDIV:    i32 = 1;

// ── signal storage ──────────────────────────────────────────────────────────

static PENDING: Mutex<BTreeMap<usize, VecDeque<SigInfo>>> =
    Mutex::new(BTreeMap::new());
static SIGMASK: Mutex<BTreeMap<usize, u64>> = Mutex::new(BTreeMap::new());

// ── alternate stack ──────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct AltStack { ss_sp: usize, ss_flags: i32, ss_size: usize }

const SS_DISABLE:    i32 = 2;
const SS_AUTODISARM: i32 = 0x80000000u32 as i32;

static ALTSTACK: Mutex<BTreeMap<usize, AltStack>> = Mutex::new(BTreeMap::new());

// ── SA_* flags ────────────────────────────────────────────────────────────

const SA_ONSTACK:   u32 = 0x08000000;
const SA_RESTORER:  u32 = 0x04000000;
const SA_SIGINFO:   u32 = 0x00000004;
const SA_RESTART:   u32 = 0x10000000;
const SA_NODEFER:   u32 = 0x40000000;

// ── handler table ────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct SignalHandlers {
    pub handlers: [usize; 65],
    pub flags:    [u32;   65],
    pub restorer: usize,
}

// ── public API ─────────────────────────────────────────────────────────────

pub fn send_signal(pid: usize, sig: u32) {
    send_signal_info(pid, SigInfo {
        sig, code: SI_KERNEL, ..Default::default()
    });
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
        uid:    0,
        status: exit_code,
        addr:   0,
        value:  0,
    });
}

/// Send SIGSEGV with the faulting address.
pub fn send_sigsegv(pid: usize, fault_addr: usize) {
    send_signal_info(pid, SigInfo {
        sig:  11,
        code: SEGV_MAPERR,
        addr: fault_addr,
        ..Default::default()
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
    if old_ss_va >= 0x1000 {
        let tbl = ALTSTACK.lock();
        let alt = tbl.get(&pid).copied().unwrap_or(AltStack {
            ss_sp: 0, ss_flags: SS_DISABLE, ss_size: 0,
        });
        unsafe {
            (old_ss_va           as *mut usize).write_unaligned(alt.ss_sp);
            ((old_ss_va + 8)     as *mut i32).write_unaligned(alt.ss_flags);
            ((old_ss_va + 12)    as *mut i32).write_unaligned(0);
            ((old_ss_va + 16)    as *mut usize).write_unaligned(alt.ss_size);
        }
    }
    if ss_va >= 0x1000 {
        let ss_sp    = unsafe { (ss_va           as *const usize).read_unaligned() };
        let ss_flags = unsafe { ((ss_va + 8)     as *const i32).read_unaligned() };
        let ss_size  = unsafe { ((ss_va + 16)    as *const usize).read_unaligned() };
        if ss_flags & SS_DISABLE != 0 {
            ALTSTACK.lock().remove(&pid);
        } else {
            if ss_size < 2048 { return -22; }
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
    if old_act_va >= 0x1000 {
        unsafe {
            (old_act_va           as *mut usize).write_volatile(pcb.signal_handlers.handlers[sig as usize]);
            ((old_act_va + 8)     as *mut u64).write_volatile(pcb.signal_handlers.flags[sig as usize] as u64);
            ((old_act_va + 16)    as *mut usize).write_volatile(pcb.signal_handlers.restorer);
            ((old_act_va + 24)    as *mut u64).write_volatile(0);
        }
    }
    if new_act_va >= 0x1000 {
        pcb.signal_handlers.handlers[sig as usize] =
            unsafe { (new_act_va        as *const usize).read_volatile() };
        pcb.signal_handlers.flags[sig as usize] =
            unsafe { ((new_act_va + 8)  as *const u64).read_volatile() } as u32;
        pcb.signal_handlers.restorer =
            unsafe { ((new_act_va + 16) as *const usize).read_volatile() };
    }
    scheduler::procs_unlock();
    0
}

// ── sys_rt_sigprocmask [NR 14] ────────────────────────────────────────────

pub fn sys_rt_sigprocmask(how: u32, set_va: usize, oldset_va: usize, _sz: usize) -> isize {
    let pid = scheduler::current_pid();
    let cur = get_sigmask(pid);
    if oldset_va >= 0x1000 {
        unsafe { (oldset_va as *mut u64).write_volatile(cur); }
    }
    if set_va == 0 { return 0; }
    let new_set = unsafe { (set_va as *const u64).read_volatile() };
    let updated = match how {
        0 => cur | new_set,
        1 => cur & !new_set,
        2 => new_set,
        _ => return -22,
    };
    set_sigmask(pid, updated & !((1u64 << 8) | (1u64 << 18))); // cannot mask SIGKILL/SIGSTOP
    0
}

// ─────────────────────────────────────────────────────────────────────────────
// Signal frame layout on the user stack
// ─────────────────────────────────────────────────────────────────────────────
//
// High addresses (current rsp before signal)
//
//   [pretcode]          8 bytes  ← rsp after pushing retaddr
//   --- 16-byte aligned here ---
//   [siginfo_t]        80 bytes  ← rsi for SA_SIGINFO handler
//   [ucontext_t]      228 bytes  ← rdx for SA_SIGINFO handler
//
// Low addresses (new rsp handed to handler)
//
// ucontext_t layout (x86-64 Linux, glibc/musl compatible):
//   +0    uc_flags      u64
//   +8    uc_link       u64  (pointer to next context, 0)
//   +16   uc_stack      stack_t (24 bytes: sp/flags/size)
//   +40   uc_mcontext  (gregs[23] + fpregs ptr + reserved)
//            gregs[0..23]:  r8,r9,r10,r11,r12,r13,r14,r15,
//                           rdi,rsi,rbp,rbx,rdx,rax,rcx,rsp,
//                           rip,efl,csgsfs,err,trapno,oldmask,cr2
//            fpregs ptr:    u64 (pointer to fpstate, 0 for us)
//   +168  fpregs        u64  (0)
//   +176  reserved[8]   u64s (0)
//   +240  uc_sigmask    u64  (blocked signals at time of signal entry)
//   total: 248 bytes, round up to 256 for alignment
//
// siginfo_t layout (x86-64 Linux, 80 bytes):
//   +0   si_signo    i32
//   +4   si_errno    i32
//   +8   si_code     i32
//   +12  _pad        i32
//   +16  _fields union (we use the largest relevant variant):
//          kill:  si_pid(i32) + si_uid(i32)
//          fault: si_addr(u64)
//          child: si_pid(i32) + si_uid(i32) + si_status(i32) + si_utime(i64) + si_stime(i64)
//          timer: si_timerid + si_overrun + si_value
//   +80  end
//
// We always write si_pid at +16 and si_addr at +24 (overlapping union)
// — the handler uses one or the other based on signo, not both.

const UCONTEXT_SIZE:  usize = 256; // padded to 256 for clean alignment
const SIGINFO_SIZE:   usize = 80;
const RETADDR_SIZE:   usize = 8;
const SIGNAL_FRAME_SIZE: usize = UCONTEXT_SIZE + SIGINFO_SIZE + RETADDR_SIZE;

// Byte offsets for mcontext gregs array inside ucontext_t.
// Indexes match Linux's gregset_t order (from sys/ucontext.h):
//   REG_R8=0, REG_R9=1, REG_R10=2, REG_R11=3, REG_R12=4, REG_R13=5,
//   REG_R14=6, REG_R15=7, REG_RDI=8, REG_RSI=9, REG_RBP=10, REG_RBX=11,
//   REG_RDX=12, REG_RAX=13, REG_RCX=14, REG_RSP=15, REG_RIP=16,
//   REG_EFL=17, REG_CSGSFS=18, REG_ERR=19, REG_TRAPNO=20,
//   REG_OLDMASK=21, REG_CR2=22
const UC_MCONTEXT_OFFSET: usize = 40;  // uc_mcontext starts here in ucontext_t
const GREGS_OFFSET: usize = UC_MCONTEXT_OFFSET; // gregs[0] is first field of mcontext

#[inline]
fn greg_off(i: usize) -> usize { GREGS_OFFSET + i * 8 }

// Indexes into gregset_t
const REG_R8:     usize = 0;
const REG_R9:     usize = 1;
const REG_R10:    usize = 2;
const REG_R11:    usize = 3;
const REG_R12:    usize = 4;
const REG_R13:    usize = 5;
const REG_R14:    usize = 6;
const REG_R15:    usize = 7;
const REG_RDI:    usize = 8;
const REG_RSI:    usize = 9;
const REG_RBP:    usize = 10;
const REG_RBX:    usize = 11;
const REG_RDX:    usize = 12;
const REG_RAX:    usize = 13;
const REG_RCX:    usize = 14;
const REG_RSP:    usize = 15;
const REG_RIP:    usize = 16;
const REG_EFL:    usize = 17;
const REG_CSGSFS: usize = 18;
const REG_OLDMASK:usize = 21;
const REG_CR2:    usize = 22;

// ── check_pending_signal ─────────────────────────────────────────────────

pub fn check_pending_signal(frame: &mut SyscallFrame) {
    let pid  = scheduler::current_pid();
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

    let (handler_va, sa_flags, restorer) = {
        let procs = scheduler::procs_lock();
        let r = procs.iter().find(|p| p.pid == pid).map(|p| (
            p.signal_handlers.handlers[info.sig as usize],
            p.signal_handlers.flags[info.sig as usize],
            p.signal_handlers.restorer,
        )).unwrap_or((0, 0, 0));
        scheduler::procs_unlock();
        r
    };

    if handler_va == 0 {
        match info.sig {
            17 | 28 => {}
            _ => { crate::proc::exit::sys_exit(-(info.sig as i32)); }
        }
        return;
    }

    // Block signal during handler (unless SA_NODEFER).
    if sa_flags & SA_NODEFER == 0 {
        set_sigmask(pid, mask | (1u64 << info.sig));
    }

    // ── Choose delivery stack ───────────────────────────────────────────────

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

    // ── Carve signal frame ──────────────────────────────────────────────────
    //
    // Stack layout (grows downward):
    //   sp_frame           ← ucontext_t (256 bytes)
    //   sp_frame+256       ← siginfo_t  (80 bytes)
    //   sp_frame+336       ← retaddr    (8 bytes)
    //   sp_frame+344       ← 16-byte aligned (== original sp after red-zone)
    //
    // Handler receives:
    //   rdi = info.sig
    //   rsi = sp_frame + 256   (siginfo_t*)
    //   rdx = sp_frame         (ucontext_t*)
    //   rsp = sp_frame + 336   (retaddr slot; ABI requires *rsp = retaddr)
    //   rip = handler_va

    let sp = sp.wrapping_sub(128); // red-zone clearance
    let sp = (sp.wrapping_sub(SIGNAL_FRAME_SIZE)) & !0xFusize; // align

    let uc_va   = sp;
    let si_va   = sp + UCONTEXT_SIZE;
    let ret_va  = sp + UCONTEXT_SIZE + SIGINFO_SIZE;

    // Zero entire frame.
    unsafe { core::ptr::write_bytes(sp as *mut u8, 0, SIGNAL_FRAME_SIZE); }

    // ── Write ucontext_t ─────────────────────────────────────────────────────
    //
    // uc_flags = 0, uc_link = 0 (already zero)
    // uc_stack: the *current* stack at time of delivery
    unsafe {
        // uc_stack.ss_sp    (+16)
        ((uc_va + 16) as *mut usize).write_unaligned(frame.rsp);
        // uc_stack.ss_flags (+24)
        ((uc_va + 24) as *mut i32).write_unaligned(0);
        // uc_stack.ss_size  (+32)
        ((uc_va + 32) as *mut usize).write_unaligned(0);
    }

    // mcontext / gregset_t — write all 23 gregs
    macro_rules! wgreg {
        ($idx:expr, $val:expr) => {
            unsafe {
                ((uc_va + greg_off($idx)) as *mut u64)
                    .write_unaligned($val as u64);
            }
        };
    }
    wgreg!(REG_R8,      frame.r8);
    wgreg!(REG_R9,      frame.r9);
    wgreg!(REG_R10,     frame.r10);
    wgreg!(REG_R11,     frame.r11);   // saved rflags in SYSCALL ABI
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
    wgreg!(REG_RCX,     frame.rcx);   // == frame.rip on SYSCALL entry
    wgreg!(REG_RSP,     frame.rsp);
    wgreg!(REG_RIP,     frame.rip);
    wgreg!(REG_EFL,     frame.rflags);
    wgreg!(REG_CSGSFS,  0x002B_0033u64); // typical user CS/GS/FS selector combo
    wgreg!(REG_OLDMASK, mask);
    wgreg!(REG_CR2,     info.addr as u64); // fault address (0 if not a fault)

    // uc_sigmask (+240)
    unsafe {
        ((uc_va + 240) as *mut u64).write_unaligned(mask);
    }

    // ── Write siginfo_t ─────────────────────────────────────────────────────

    unsafe {
        (si_va as *mut i32).write_unaligned(info.sig as i32); // si_signo
        ((si_va + 4) as *mut i32).write_unaligned(0);          // si_errno
        ((si_va + 8) as *mut i32).write_unaligned(info.code);  // si_code
        // _fields union (+16)
        // Write both pid (i32) and addr (u64) — handler reads the
        // appropriate field based on signo.
        ((si_va + 16) as *mut i32).write_unaligned(info.pid as i32);  // si_pid
        ((si_va + 20) as *mut i32).write_unaligned(info.uid as i32);  // si_uid
        match info.sig {
            // SIGCHLD: also write si_status
            17 => ((si_va + 24) as *mut i32).write_unaligned(info.status),
            // Fault signals: si_addr overlaps the union at +16 on some
            // archs, but on x86-64 Linux it's at +16 for si_addr in the
            // _sigfault variant (separate from the _kill variant).
            // glibc siginfo.h: _sigfault.si_addr is the FIRST field, at +16.
            11 | 7 | 8 => ((si_va + 16) as *mut usize).write_unaligned(info.addr),
            _ => {}
        }
    }

    // ── Write return address ─────────────────────────────────────────────────

    let ret_addr = if sa_flags & SA_RESTORER != 0 && restorer != 0 {
        restorer
    } else {
        build_inline_trampoline(sp)
    };
    unsafe { (ret_va as *mut usize).write_volatile(ret_addr); }

    // ── Redirect CPU to handler ──────────────────────────────────────────────

    frame.rdi = info.sig as usize;   // arg1: signum
    frame.rsi = si_va;               // arg2: siginfo_t*   (0 if !SA_SIGINFO, but harmless)
    frame.rdx = uc_va;               // arg3: ucontext_t*
    frame.rip = handler_va;
    frame.rsp = ret_va;              // stack pointer: ABI expects retaddr at [rsp]
}

// ── sys_rt_sigreturn [NR 15] ──────────────────────────────────────────────

/// Restore CPU state from the ucontext_t embedded in the signal frame.
///
/// The SA_RESTORER (musl: __restore_rt) calls `syscall(SYS_rt_sigreturn)`
/// with no arguments.  At that point rsp points at the retaddr slot
/// (sp + UCONTEXT_SIZE + SIGINFO_SIZE), so:
///
///   uc_va  = rsp - UCONTEXT_SIZE - SIGINFO_SIZE
///           = rsp - 336
///
/// We read the gregs array from uc_va + GREGS_OFFSET and restore every
/// general-purpose register plus rip / rsp / rflags into SyscallFrame.
/// SYSRETQ then pops rcx→rip and r11→rflags and jumps to the original
/// interrupted instruction.
pub fn sys_rt_sigreturn(frame: &mut SyscallFrame) -> isize {
    let pid = scheduler::current_pid();

    // rsp currently points at the retaddr we pushed.
    // ucontext_t lives SIGINFO_SIZE + UCONTEXT_SIZE bytes below retaddr.
    let uc_va = frame.rsp
        .wrapping_add(RETADDR_SIZE)          // skip retaddr slot
        .wrapping_sub(UCONTEXT_SIZE + SIGINFO_SIZE + RETADDR_SIZE);
    // Simplified: uc is at ret_va - UCONTEXT_SIZE - SIGINFO_SIZE
    // = (sp + UCONTEXT_SIZE + SIGINFO_SIZE) - UCONTEXT_SIZE - SIGINFO_SIZE = sp
    // So uc_va == the original sp value we computed in check_pending_signal.
    let uc_va = frame.rsp
        .wrapping_sub(UCONTEXT_SIZE + SIGINFO_SIZE);

    macro_rules! rgreg {
        ($idx:expr) => {
            unsafe {
                ((uc_va + greg_off($idx)) as *const u64).read_unaligned() as usize
            }
        };
    }

    // Validate the ucontext pointer is in user space before trusting it.
    if uc_va >= 0x1000 && uc_va < 0x0000_7FFF_FFFF_0000 {
        frame.r8      = rgreg!(REG_R8);
        frame.r9      = rgreg!(REG_R9);
        frame.r10     = rgreg!(REG_R10);
        frame.r11     = rgreg!(REG_R11);
        frame.r12     = rgreg!(REG_R12);
        frame.r13     = rgreg!(REG_R13);
        frame.r14     = rgreg!(REG_R14);
        frame.r15     = rgreg!(REG_R15);
        frame.rdi     = rgreg!(REG_RDI);
        frame.rsi     = rgreg!(REG_RSI);
        frame.rbp     = rgreg!(REG_RBP);
        frame.rbx     = rgreg!(REG_RBX);
        frame.rdx     = rgreg!(REG_RDX);
        frame.rax     = rgreg!(REG_RAX);
        frame.rcx     = rgreg!(REG_RCX);
        frame.rsp     = rgreg!(REG_RSP);
        frame.rip     = rgreg!(REG_RIP);
        frame.rflags  = rgreg!(REG_EFL);

        // Restore pre-signal sigmask from uc_sigmask.
        let old_mask = unsafe {
            ((uc_va + 240) as *const u64).read_unaligned()
        };
        set_sigmask(pid, old_mask);
    } else {
        // Corrupt ucontext (shouldn't happen with musl) — just skip retaddr.
        frame.rsp = frame.rsp.wrapping_add(RETADDR_SIZE);
        set_sigmask(pid, 0);
    }
    0
}

// ── inline trampoline ───────────────────────────────────────────────────────────

fn build_inline_trampoline(sp: usize) -> usize {
    // mov rax, 15  = 48 C7 C0 0F 00 00 00  (7 bytes)
    // syscall      = 0F 05                  (2 bytes)
    const CODE: [u8; 9] = [0x48, 0xC7, 0xC0, 0x0F, 0x00, 0x00, 0x00, 0x0F, 0x05];
    let va = sp.wrapping_sub(16);
    unsafe {
        core::ptr::copy_nonoverlapping(CODE.as_ptr(), va as *mut u8, CODE.len());
    }
    va
}
