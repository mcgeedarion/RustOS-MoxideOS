//! ptrace(2) — process tracing and debugging interface.
//!
//! ## Architecture
//! The full ptrace dispatch (sys_ptrace_impl) lives in syscall/stubs.rs and
//! is called from here via a thin wrapper.  This module owns:
//!   - All PTRACE_* / PTRACE_O_* constants
//!   - The PtraceState enum (embedded in proc/process.rs Task)
//!   - build_user_regs_pub / apply_user_regs_pub (shared with proc_debug.rs)
//!   - ptrace_syscall_stop (called by proc/signal.rs)

extern crate alloc;

use crate::proc::scheduler;
use crate::proc::signal::send_signal;

// ── Constants (kept for wait.rs / signal.rs consumers) ──────────────────────

pub const PTRACE_TRACEME:     i32 = 0;
pub const PTRACE_PEEKTEXT:    i32 = 1;
pub const PTRACE_PEEKDATA:    i32 = 2;
pub const PTRACE_PEEKUSER:    i32 = 3;
pub const PTRACE_POKETEXT:    i32 = 4;
pub const PTRACE_POKEDATA:    i32 = 5;
pub const PTRACE_POKEUSER:    i32 = 6;
pub const PTRACE_CONT:        i32 = 7;
pub const PTRACE_KILL:        i32 = 8;
pub const PTRACE_SINGLESTEP:  i32 = 9;
pub const PTRACE_GETREGS:     i32 = 12;
pub const PTRACE_SETREGS:     i32 = 13;
pub const PTRACE_ATTACH:      i32 = 16;
pub const PTRACE_DETACH:      i32 = 17;
pub const PTRACE_SYSCALL:     i32 = 24;
pub const PTRACE_SETOPTIONS:  i32 = 0x4200;
pub const PTRACE_GETEVENTMSG: i32 = 0x4201;

pub const PTRACE_O_TRACESYSGOOD: u64 = 0x00000001;
pub const PTRACE_O_TRACEFORK:    u64 = 0x00000002;
pub const PTRACE_O_TRACEVFORK:   u64 = 0x00000004;
pub const PTRACE_O_TRACECLONE:   u64 = 0x00000008;
pub const PTRACE_O_TRACEEXEC:    u64 = 0x00000010;
pub const PTRACE_O_TRACEEXIT:    u64 = 0x00000040;
pub const PTRACE_O_EXITKILL:     u64 = 0x00100000;
pub const PTRACE_O_MASK:         u64 = 0x001000ff;

// ── Register layout constants (shared with proc_debug.rs) ───────────────────

pub const FRAME_SZ:  usize = 17 * 8;

const F_R15: usize = 0;
const F_R14: usize = 1;
const F_R13: usize = 2;
const F_R12: usize = 3;
const F_RBP: usize = 4;
const F_RBX: usize = 5;
const F_RAX: usize = 6;
const F_RDI: usize = 7;
const F_RSI: usize = 8;
const F_RDX: usize = 9;
const F_R10: usize = 10;
const F_R8:  usize = 11;
const F_R9:  usize = 12;
const F_RCX: usize = 13;
const F_R11: usize = 14; // RFLAGS on SYSRET path
const F_RSP: usize = 15;
const F_RIP: usize = 16;

// Linux user_regs_struct offsets
pub const UREG_R15:      usize = 0;
pub const UREG_R14:      usize = 1;
pub const UREG_R13:      usize = 2;
pub const UREG_R12:      usize = 3;
pub const UREG_RBP:      usize = 4;
pub const UREG_RBX:      usize = 5;
pub const UREG_R11:      usize = 6;
pub const UREG_R10:      usize = 7;
pub const UREG_R9:       usize = 8;
pub const UREG_R8:       usize = 9;
pub const UREG_RAX:      usize = 10;
pub const UREG_RCX:      usize = 11;
pub const UREG_RDX:      usize = 12;
pub const UREG_RSI:      usize = 13;
pub const UREG_RDI:      usize = 14;
pub const UREG_ORIG_RAX: usize = 15;
pub const UREG_RIP:      usize = 16;
pub const UREG_CS:       usize = 17;
pub const UREG_EFLAGS:   usize = 18;
pub const UREG_RSP:      usize = 19;
pub const UREG_SS:       usize = 20;
pub const UREG_FS_BASE:  usize = 21;
pub const UREG_GS_BASE:  usize = 22;
pub const UREG_DS:       usize = 23;
pub const UREG_ES:       usize = 24;
pub const UREG_FS:       usize = 25;
pub const UREG_GS:       usize = 26;
pub const UREG_COUNT:    usize = 27;

const USER_CS64: u64 = 0x33;
const USER_SS:   u64 = 0x2b;

// ── PtraceState ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PtraceState {
    None,
    Tracee {
        tracer:  usize,
        options: u64,
        in_syscall_stop: bool,
    },
    Stopped {
        tracer:  usize,
        options: u64,
        sig:     u32,
    },
}

impl Default for PtraceState {
    fn default() -> Self { PtraceState::None }
}

// ── Public register helpers (used by proc_debug.rs and syscall/stubs.rs) ────

unsafe fn frame_ptr(kstack_top: usize) -> *mut usize {
    (kstack_top - FRAME_SZ) as *mut usize
}

/// Build a Linux `user_regs_struct` from the saved kernel stack frame.
pub fn build_user_regs_pub(kstack_top: usize, fs_base: usize) -> [u64; UREG_COUNT] {
    let f = unsafe { core::slice::from_raw_parts(frame_ptr(kstack_top), 17) };
    let mut regs = [0u64; UREG_COUNT];
    regs[UREG_R15]      = f[F_R15]  as u64;
    regs[UREG_R14]      = f[F_R14]  as u64;
    regs[UREG_R13]      = f[F_R13]  as u64;
    regs[UREG_R12]      = f[F_R12]  as u64;
    regs[UREG_RBP]      = f[F_RBP]  as u64;
    regs[UREG_RBX]      = f[F_RBX]  as u64;
    regs[UREG_R11]      = f[F_R11]  as u64;
    regs[UREG_R10]      = f[F_R10]  as u64;
    regs[UREG_R9]       = f[F_R9]   as u64;
    regs[UREG_R8]       = f[F_R8]   as u64;
    regs[UREG_RAX]      = f[F_RAX]  as u64;
    regs[UREG_RCX]      = f[F_RCX]  as u64;
    regs[UREG_RDX]      = f[F_RDX]  as u64;
    regs[UREG_RSI]      = f[F_RSI]  as u64;
    regs[UREG_RDI]      = f[F_RDI]  as u64;
    regs[UREG_ORIG_RAX] = f[F_RAX]  as u64;
    regs[UREG_RIP]      = f[F_RIP]  as u64;
    regs[UREG_CS]       = USER_CS64;
    regs[UREG_EFLAGS]   = f[F_R11]  as u64;
    regs[UREG_RSP]      = f[F_RSP]  as u64;
    regs[UREG_SS]       = USER_SS;
    regs[UREG_FS_BASE]  = fs_base   as u64;
    regs[UREG_GS_BASE]  = 0;
    regs[UREG_DS]       = 0;
    regs[UREG_ES]       = 0;
    regs[UREG_FS]       = 0;
    regs[UREG_GS]       = 0;
    regs
}

/// Apply a `user_regs_struct` back to the saved kernel stack frame.
pub fn apply_user_regs_pub(kstack_top: usize, regs: &[u64; UREG_COUNT]) {
    let f = unsafe { core::slice::from_raw_parts_mut(frame_ptr(kstack_top), 17) };
    f[F_R15] = regs[UREG_R15]    as usize;
    f[F_R14] = regs[UREG_R14]    as usize;
    f[F_R13] = regs[UREG_R13]    as usize;
    f[F_R12] = regs[UREG_R12]    as usize;
    f[F_RBP] = regs[UREG_RBP]    as usize;
    f[F_RBX] = regs[UREG_RBX]    as usize;
    f[F_RAX] = regs[UREG_RAX]    as usize;
    f[F_RDI] = regs[UREG_RDI]    as usize;
    f[F_RSI] = regs[UREG_RSI]    as usize;
    f[F_RDX] = regs[UREG_RDX]    as usize;
    f[F_R10] = regs[UREG_R10]    as usize;
    f[F_R8]  = regs[UREG_R8]     as usize;
    f[F_R9]  = regs[UREG_R9]     as usize;
    f[F_RCX] = regs[UREG_RIP]    as usize;
    f[F_R11] = regs[UREG_EFLAGS] as usize;
    f[F_RSP] = regs[UREG_RSP]    as usize;
    f[F_RIP] = regs[UREG_RIP]    as usize;
}

// ── sys_ptrace ──────────────────────────────────────────────────────────────

/// NR 101  ptrace(request, pid, addr, data)
///
/// The full implementation lives in syscall/stubs.rs as sys_ptrace_impl;
/// this thin wrapper is kept here so signal.rs / proc_debug.rs can call it
/// without depending on the syscall crate directly.
pub fn sys_ptrace(req: i32, pid: i32, addr: usize, data: usize) -> isize {
    crate::syscall::stubs::sys_ptrace_impl(req, pid, addr, data)
}

// ── ptrace_syscall_stop (still needed by signal.rs) ──────────────────────────

pub fn ptrace_syscall_stop() {
    let pid = scheduler::current_pid();
    let (tracer, options) =
        match scheduler::with_proc(pid, |p| p.ptrace_state) {
            Some(PtraceState::Tracee { tracer, in_syscall_stop: true, options })
                => (tracer, options),
            _ => return,
        };
    let sig: u32 = if options & PTRACE_O_TRACESYSGOOD != 0 { 5 | 0x80 } else { 5 };
    scheduler::with_proc_mut(pid, |p, _pl| {
        p.ptrace_state = PtraceState::Stopped { tracer, options, sig };
    });
    send_signal(tracer, sig as i32);
    scheduler::block_pid(pid);
}
