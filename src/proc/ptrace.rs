//! ptrace(2) — process tracing and debugging interface.
//!
//! ## Bug fixes
//!
//! ### build_user_regs: UREG_CS was 0x1b (32-bit compat CS)
//!   64-bit user CS must be 0x33. gdb inspects this field to select
//!   32-bit vs 64-bit mode; 0x1b caused all register display and
//!   disassembly to be parsed in 32-bit mode.
//!
//! ### ptrace_syscall_stop: send_signal(tracer, sig) type mismatch
//!   sig is u32 but send_signal expects i32. Won't compile. Fixed with
//!   explicit `sig as i32` cast.

extern crate alloc;

use crate::arch::api::{Paging, PageFlags};
use crate::arch::Arch;
use crate::proc::scheduler;
use crate::proc::signal::send_signal;
use crate::uaccess::{copy_from_user, copy_to_user};

// ── Constants ───────────────────────────────────────────────────────────────────

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

const FRAME_SZ:  usize = 17 * 8;
const RFLAGS_TF: usize = 1 << 8;

// FIX: 64-bit ring-3 CS is 0x33 (RPL=3, TI=0, index=6).
// 0x1b is the 32-bit compat user CS — using it caused gdb to treat the
// inferior as a 32-bit process and misparse all register values.
const USER_CS64: u64 = 0x33;
const USER_SS:   u64 = 0x2b;

// ── PtraceState ────────────────────────────────────────────────────────────────

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

// ── SyscallFrame field offsets ──────────────────────────────────────────────────────

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
const F_RCX: usize = 13; // user RIP
const F_R11: usize = 14; // user RFLAGS
const F_RSP: usize = 15;
const F_RIP: usize = 16;

// ── Linux user_regs_struct offsets ────────────────────────────────────────────────────

const UREG_R15:      usize = 0;
const UREG_R14:      usize = 1;
const UREG_R13:      usize = 2;
const UREG_R12:      usize = 3;
const UREG_RBP:      usize = 4;
const UREG_RBX:      usize = 5;
const UREG_R11:      usize = 6;
const UREG_R10:      usize = 7;
const UREG_R9:       usize = 8;
const UREG_R8:       usize = 9;
const UREG_RAX:      usize = 10;
const UREG_RCX:      usize = 11;
const UREG_RDX:      usize = 12;
const UREG_RSI:      usize = 13;
const UREG_RDI:      usize = 14;
const UREG_ORIG_RAX: usize = 15;
const UREG_RIP:      usize = 16;
const UREG_CS:       usize = 17;
const UREG_EFLAGS:   usize = 18;
const UREG_RSP:      usize = 19;
const UREG_SS:       usize = 20;
const UREG_FS_BASE:  usize = 21;
const UREG_GS_BASE:  usize = 22;
const UREG_DS:       usize = 23;
const UREG_ES:       usize = 24;
const UREG_FS:       usize = 25;
const UREG_GS:       usize = 26;
const UREG_COUNT:    usize = 27;

// ── Frame accessor ────────────────────────────────────────────────────────────────

unsafe fn frame_ptr(kstack_top: usize) -> *mut usize {
    (kstack_top - FRAME_SZ) as *mut usize
}

// ── Build a Linux user_regs_struct ────────────────────────────────────────────────────

fn build_user_regs(kstack_top: usize, fs_base: usize) -> [u64; UREG_COUNT] {
    let f = unsafe { core::slice::from_raw_parts(frame_ptr(kstack_top), 17) };
    let mut regs = [0u64; UREG_COUNT];
    regs[UREG_R15]      = f[F_R15]  as u64;
    regs[UREG_R14]      = f[F_R14]  as u64;
    regs[UREG_R13]      = f[F_R13]  as u64;
    regs[UREG_R12]      = f[F_R12]  as u64;
    regs[UREG_RBP]      = f[F_RBP]  as u64;
    regs[UREG_RBX]      = f[F_RBX]  as u64;
    regs[UREG_R11]      = f[F_R11]  as u64; // RFLAGS
    regs[UREG_R10]      = f[F_R10]  as u64;
    regs[UREG_R9]       = f[F_R9]   as u64;
    regs[UREG_R8]       = f[F_R8]   as u64;
    regs[UREG_RAX]      = f[F_RAX]  as u64;
    regs[UREG_RCX]      = f[F_RCX]  as u64; // user RIP (saved in rcx by SYSCALL)
    regs[UREG_RDX]      = f[F_RDX]  as u64;
    regs[UREG_RSI]      = f[F_RSI]  as u64;
    regs[UREG_RDI]      = f[F_RDI]  as u64;
    regs[UREG_ORIG_RAX] = f[F_RAX]  as u64;
    regs[UREG_RIP]      = f[F_RIP]  as u64;
    // FIX: 64-bit user CS is 0x33, not 0x1b (32-bit compat).
    regs[UREG_CS]       = USER_CS64;
    regs[UREG_EFLAGS]   = f[F_R11]  as u64; // r11 = rflags saved by SYSCALL
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

// ── Apply user_regs_struct back to the frame ─────────────────────────────────────────

fn apply_user_regs(kstack_top: usize, regs: &[u64; UREG_COUNT]) {
    let f = unsafe { core::slice::from_raw_parts_mut(frame_ptr(kstack_top), 17) };
    f[F_R15] = regs[UREG_R15]     as usize;
    f[F_R14] = regs[UREG_R14]     as usize;
    f[F_R13] = regs[UREG_R13]     as usize;
    f[F_R12] = regs[UREG_R12]     as usize;
    f[F_RBP] = regs[UREG_RBP]     as usize;
    f[F_RBX] = regs[UREG_RBX]     as usize;
    f[F_RAX] = regs[UREG_RAX]     as usize;
    f[F_RDI] = regs[UREG_RDI]     as usize;
    f[F_RSI] = regs[UREG_RSI]     as usize;
    f[F_RDX] = regs[UREG_RDX]     as usize;
    f[F_R10] = regs[UREG_R10]     as usize;
    f[F_R8]  = regs[UREG_R8]      as usize;
    f[F_R9]  = regs[UREG_R9]      as usize;
    f[F_RCX] = regs[UREG_RIP]     as usize; // RIP lives in rcx slot
    f[F_R11] = regs[UREG_EFLAGS]  as usize; // RFLAGS lives in r11 slot
    f[F_RSP] = regs[UREG_RSP]     as usize;
    f[F_RIP] = regs[UREG_RIP]     as usize;
}

// ── PEEKUSER / POKEUSER ────────────────────────────────────────────────────────────────

fn peekuser_word(kstack_top: usize, fs_base: usize, byte_off: usize) -> u64 {
    let word_idx = byte_off / 8;
    if word_idx < UREG_COUNT {
        let regs = build_user_regs(kstack_top, fs_base);
        regs[word_idx]
    } else {
        0
    }
}

fn pokeuser_word(kstack_top: usize, byte_off: usize, val: u64) -> isize {
    let word_idx = byte_off / 8;
    if word_idx >= UREG_COUNT { return 0; }
    let f = unsafe { core::slice::from_raw_parts_mut(frame_ptr(kstack_top), 17) };
    match word_idx {
        UREG_R15     => f[F_R15]  = val as usize,
        UREG_R14     => f[F_R14]  = val as usize,
        UREG_R13     => f[F_R13]  = val as usize,
        UREG_R12     => f[F_R12]  = val as usize,
        UREG_RBP     => f[F_RBP]  = val as usize,
        UREG_RBX     => f[F_RBX]  = val as usize,
        UREG_R11     => f[F_R11]  = val as usize,
        UREG_R10     => f[F_R10]  = val as usize,
        UREG_R9      => f[F_R9]   = val as usize,
        UREG_R8      => f[F_R8]   = val as usize,
        UREG_RAX | UREG_ORIG_RAX => f[F_RAX] = val as usize,
        UREG_RCX     => f[F_RCX]  = val as usize,
        UREG_RDX     => f[F_RDX]  = val as usize,
        UREG_RSI     => f[F_RSI]  = val as usize,
        UREG_RDI     => f[F_RDI]  = val as usize,
        UREG_RIP     => { f[F_RCX] = val as usize; f[F_RIP] = val as usize; }
        UREG_EFLAGS  => f[F_R11]  = val as usize,
        UREG_RSP     => f[F_RSP]  = val as usize,
        _ => {}
    }
    0
}

// ── PEEKDATA / POKEDATA ────────────────────────────────────────────────────────────────

fn peek_tracee_word(cr3: usize, addr: usize) -> Option<u64> {
    let pa = <Arch as Paging>::virt_to_phys(cr3, addr)?;
    Some(unsafe { (pa as *const u64).read_unaligned() })
}

fn poke_tracee_word(cr3: usize, addr: usize, val: u64) -> bool {
    let pa = match <Arch as Paging>::virt_to_phys(cr3, addr) {
        Some(p) => p,
        None    => return false,
    };
    unsafe { (pa as *mut u64).write_unaligned(val); }
    true
}

// ── Permission check ────────────────────────────────────────────────────────────────

fn may_trace(tracer_pid: usize, target_pid: usize) -> bool {
    scheduler::with_proc(target_pid, |p| p.ppid == tracer_pid).unwrap_or(false)
    || scheduler::with_proc(tracer_pid, |p| {
        p.caps.has_cap(crate::security::CAP_SYS_PTRACE)
    }).unwrap_or(false)
}

// ── sys_ptrace ────────────────────────────────────────────────────────────────────

pub fn sys_ptrace(req: i32, pid: i32, addr: usize, data: usize) -> isize {
    let caller = scheduler::current_pid();
    let target = pid as usize;

    match req {
        PTRACE_TRACEME => {
            scheduler::with_proc_mut(caller, |p| {
                if p.ptrace_state != crate::proc::ptrace::PtraceState::None {
                    return -16isize;
                }
                p.ptrace_state = PtraceState::Tracee {
                    tracer: p.ppid,
                    options: 0,
                    in_syscall_stop: false,
                };
                0isize
            }).unwrap_or(-3)
        }

        PTRACE_ATTACH => {
            if target == caller { return -1; }
            if !may_trace(caller, target) { return -1; }
            let ok = scheduler::with_proc_mut(target, |p| {
                if p.ptrace_state != PtraceState::None { return false; }
                p.ptrace_state = PtraceState::Tracee {
                    tracer: caller,
                    options: 0,
                    in_syscall_stop: false,
                };
                true
            }).unwrap_or(false);
            if !ok { return -16; }
            send_signal(target, 19);
            0
        }

        PTRACE_DETACH => {
            let found = scheduler::with_proc_mut(target, |p| {
                match p.ptrace_state {
                    PtraceState::Tracee { tracer, .. } |
                    PtraceState::Stopped { tracer, .. } if tracer == caller => {
                        p.ptrace_state = PtraceState::None;
                        if p.kstack_top != 0 {
                            let f = unsafe {
                                core::slice::from_raw_parts_mut(frame_ptr(p.kstack_top), 17)
                            };
                            f[F_R11] &= !RFLAGS_TF;
                        }
                        true
                    }
                    _ => false,
                }
            }).unwrap_or(false);
            if !found { return -3; }
            if data != 0 { send_signal(target, data as i32); }
            scheduler::wake_pid(target);
            0
        }

        PTRACE_CONT => {
            let found = scheduler::with_proc_mut(target, |p| {
                match p.ptrace_state {
                    PtraceState::Stopped { tracer, options, .. } if tracer == caller => {
                        p.ptrace_state = PtraceState::Tracee {
                            tracer,
                            options,
                            in_syscall_stop: false,
                        };
                        true
                    }
                    PtraceState::Tracee { tracer, .. } if tracer == caller => true,
                    _ => false,
                }
            }).unwrap_or(false);
            if !found { return -3; }
            if data != 0 { send_signal(target, data as i32); }
            scheduler::wake_pid(target);
            0
        }

        PTRACE_KILL => {
            send_signal(target, 9);
            0
        }

        PTRACE_SINGLESTEP => {
            let found = scheduler::with_proc_mut(target, |p| {
                match p.ptrace_state {
                    PtraceState::Stopped { tracer, options, .. } if tracer == caller => {
                        p.ptrace_state = PtraceState::Tracee {
                            tracer,
                            options,
                            in_syscall_stop: false,
                        };
                        if p.kstack_top != 0 {
                            let f = unsafe {
                                core::slice::from_raw_parts_mut(frame_ptr(p.kstack_top), 17)
                            };
                            f[F_R11] |= RFLAGS_TF;
                        }
                        true
                    }
                    _ => false,
                }
            }).unwrap_or(false);
            if !found { return -3; }
            if data != 0 { send_signal(target, data as i32); }
            scheduler::wake_pid(target);
            0
        }

        PTRACE_SYSCALL => {
            let found = scheduler::with_proc_mut(target, |p| {
                match p.ptrace_state {
                    PtraceState::Stopped { tracer, options, .. } if tracer == caller => {
                        p.ptrace_state = PtraceState::Tracee {
                            tracer,
                            options,
                            in_syscall_stop: true,
                        };
                        true
                    }
                    _ => false,
                }
            }).unwrap_or(false);
            if !found { return -3; }
            if data != 0 { send_signal(target, data as i32); }
            scheduler::wake_pid(target);
            0
        }

        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
            let cr3 = match scheduler::with_proc(target, |p| p.user_satp) {
                Some(c) if c != 0 => c,
                _ => return -3,
            };
            match peek_tracee_word(cr3, addr) {
                Some(word) => {
                    if data != 0 {
                        if !copy_to_user(data, &word.to_le_bytes()) { return -14; }
                    }
                    word as isize
                }
                None => -14,
            }
        }

        PTRACE_POKETEXT | PTRACE_POKEDATA => {
            let cr3 = match scheduler::with_proc(target, |p| p.user_satp) {
                Some(c) if c != 0 => c,
                _ => return -3,
            };
            if poke_tracee_word(cr3, addr, data as u64) { 0 } else { -14 }
        }

        PTRACE_PEEKUSER => {
            let (kstack_top, fs_base) = match scheduler::with_proc(target, |p| {
                (p.kstack_top, p.ctx.fs_base)
            }) {
                Some(v) => v,
                None    => return -3,
            };
            if kstack_top == 0 { return -3; }
            let word = peekuser_word(kstack_top, fs_base, addr);
            if data != 0 {
                if !copy_to_user(data, &word.to_le_bytes()) { return -14; }
            }
            word as isize
        }

        PTRACE_POKEUSER => {
            let kstack_top = match scheduler::with_proc(target, |p| p.kstack_top) {
                Some(k) if k != 0 => k,
                _ => return -3,
            };
            pokeuser_word(kstack_top, addr, data as u64)
        }

        PTRACE_GETREGS => {
            let (kstack_top, fs_base) = match scheduler::with_proc(target, |p| {
                (p.kstack_top, p.ctx.fs_base)
            }) {
                Some(v) => v,
                None    => return -3,
            };
            if kstack_top == 0 { return -3; }
            let regs = build_user_regs(kstack_top, fs_base);
            let bytes = unsafe {
                core::slice::from_raw_parts(regs.as_ptr() as *const u8, UREG_COUNT * 8)
            };
            if !copy_to_user(data, bytes) { return -14; }
            0
        }

        PTRACE_SETREGS => {
            let kstack_top = match scheduler::with_proc(target, |p| p.kstack_top) {
                Some(k) if k != 0 => k,
                _ => return -3,
            };
            let mut buf = [0u8; UREG_COUNT * 8];
            if copy_from_user(&mut buf, addr).is_err() { return -14; }
            let mut regs = [0u64; UREG_COUNT];
            for i in 0..UREG_COUNT {
                regs[i] = u64::from_le_bytes(buf[i*8..(i+1)*8].try_into().unwrap());
            }
            apply_user_regs(kstack_top, &regs);
            0
        }

        PTRACE_SETOPTIONS => {
            let opts = (data as u64) & PTRACE_O_MASK;
            scheduler::with_proc_mut(target, |p| {
                match &mut p.ptrace_state {
                    PtraceState::Tracee  { options, .. } => { *options = opts; }
                    PtraceState::Stopped { options, .. } => { *options = opts; }
                    PtraceState::None => {}
                }
            });
            0
        }

        PTRACE_GETEVENTMSG => {
            let event = match scheduler::with_proc(target, |p| p.ptrace_event) {
                Some(e) => e,
                None    => return -3,
            };
            if !copy_to_user(data, &event.to_le_bytes()) { return -14; }
            0
        }

        _ => -22,
    }
}

// ── Called by the syscall entry path ───────────────────────────────────────────────────

pub fn ptrace_syscall_stop() {
    let pid = scheduler::current_pid();
    let (tracer, options) =
        match scheduler::with_proc(pid, |p| p.ptrace_state) {
            Some(PtraceState::Tracee { tracer, in_syscall_stop: true, options })
                => (tracer, options),
            _ => return,
        };
    // FIX: sig was u32, send_signal expects i32. Added explicit cast.
    let sig: u32 = if options & PTRACE_O_TRACESYSGOOD != 0 { 5 | 0x80 } else { 5 };
    scheduler::with_proc_mut(pid, |p| {
        p.ptrace_state = PtraceState::Stopped { tracer, options, sig };
    });
    send_signal(tracer, sig as i32);
    scheduler::block_pid(pid);
}
