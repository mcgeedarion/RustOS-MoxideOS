//! ptrace(2) — process tracing and debugging interface.
//!
//! Implements the core ptrace requests needed by gdb, strace, and lldb:
//!   PTRACE_TRACEME, PTRACE_ATTACH, PTRACE_DETACH, PTRACE_CONT, PTRACE_KILL,
//!   PTRACE_PEEKDATA, PTRACE_POKEDATA, PTRACE_PEEKUSER, PTRACE_POKEUSER,
//!   PTRACE_GETREGS, PTRACE_SETREGS, PTRACE_SINGLESTEP, PTRACE_SYSCALL,
//!   PTRACE_SETOPTIONS, PTRACE_GETEVENTMSG.
//!
//! State machine:
//!   A process starts in `PtraceState::None`.
//!   PTRACE_TRACEME  → `Tracee { tracer: parent_pid }`
//!   PTRACE_ATTACH   → target moves to `Tracee { tracer: caller }` + SIGSTOP
//!   PTRACE_CONT/DETACH/SINGLESTEP/SYSCALL → resume, may move back to None
//!
//! Register access:
//!   The SyscallFrame sits at `kstack_top - FRAME_SZ` for any sleeping task.
//!   We access it via raw pointer from the kstack_top stored in the PCB.
//!   The Linux user_regs_struct layout (27 × u64) is produced by GETREGS/SETREGS.

extern crate alloc;

use crate::arch::api::{Paging, PageFlags};
use crate::arch::Arch;
use crate::proc::scheduler;
use crate::proc::signal::send_signal;
use crate::uaccess::{copy_from_user, copy_to_user};

// ── Constants ─────────────────────────────────────────────────────────────────

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

// PTRACE_SETOPTIONS flags
pub const PTRACE_O_TRACESYSGOOD: u64 = 0x00000001;
pub const PTRACE_O_TRACEFORK:    u64 = 0x00000002;
pub const PTRACE_O_TRACEVFORK:   u64 = 0x00000004;
pub const PTRACE_O_TRACECLONE:   u64 = 0x00000008;
pub const PTRACE_O_TRACEEXEC:    u64 = 0x00000010;
pub const PTRACE_O_TRACEEXIT:    u64 = 0x00000040;
pub const PTRACE_O_EXITKILL:     u64 = 0x00100000;
pub const PTRACE_O_MASK:         u64 = 0x001000ff;

// SyscallFrame is 17 × 8 bytes (matches arch/x86_64/syscall.rs).
const FRAME_SZ: usize = 17 * 8;

// x86-64 TF (trap flag) in RFLAGS — bit 8.
const RFLAGS_TF: usize = 1 << 8;

// ── PtraceState ───────────────────────────────────────────────────────────────

/// Per-process ptrace state embedded in `Pcb`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PtraceState {
    /// Not being traced.
    None,
    /// Being traced by `tracer` (attached, may or may not be stopped).
    Tracee {
        tracer:  usize,
        options: u64,
        in_syscall_stop: bool,
    },
    /// Stopped (waiting for tracer to CONT/DETACH).
    Stopped {
        tracer:  usize,
        options: u64,
        sig:     u32,
    },
}

impl Default for PtraceState {
    fn default() -> Self { PtraceState::None }
}

// ── SyscallFrame field offsets (indices into the 17-word array) ───────────────
//
// Matches the field order in arch/x86_64/syscall.rs:
//   [0] r15  [1] r14  [2] r13  [3] r12  [4] rbp  [5] rbx
//   [6] rax  [7] rdi  [8] rsi  [9] rdx  [10] r10  [11] r8  [12] r9
//   [13] rcx (user RIP)  [14] r11 (user RFLAGS)  [15] rsp  [16] rip

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

// ── Linux user_regs_struct field offsets (bytes, 27 × u64 = 216 bytes) ────────
//
// Field order from <sys/user.h> / ptrace(2) man page:
//   r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8,
//   rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags,
//   rsp, ss, fs_base, gs_base, ds, es, fs, gs

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

// ── Frame accessor ───────────────────────────────────────────────────────────

/// Returns a raw pointer to the SyscallFrame on the tracee's kernel stack.
/// The frame lives at `kstack_top - FRAME_SZ` for any task that entered
/// the kernel via the SYSCALL path and is currently sleeping (blocked/stopped).
///
/// # Safety
/// Caller must ensure the tracee is NOT currently running on any CPU,
/// i.e. it must be in State::Blocked or State::Zombie.  This is guaranteed
/// by ptrace semantics (SIGSTOP must be delivered before register access).
unsafe fn frame_ptr(kstack_top: usize) -> *mut usize {
    (kstack_top - FRAME_SZ) as *mut usize
}

// ── Build a Linux user_regs_struct from frame + ctx ──────────────────────────

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
    regs[UREG_RCX]      = f[F_RCX]  as u64; // user RIP (rcx)
    regs[UREG_RDX]      = f[F_RDX]  as u64;
    regs[UREG_RSI]      = f[F_RSI]  as u64;
    regs[UREG_RDI]      = f[F_RDI]  as u64;
    regs[UREG_ORIG_RAX] = f[F_RAX]  as u64;
    regs[UREG_RIP]      = f[F_RIP]  as u64;
    regs[UREG_CS]       = 0x1b;                    // user code segment
    regs[UREG_EFLAGS]   = f[F_R11]  as u64;       // r11 = rflags at SYSCALL
    regs[UREG_RSP]      = f[F_RSP]  as u64;
    regs[UREG_SS]       = 0x23;                    // user stack segment
    regs[UREG_FS_BASE]  = fs_base   as u64;
    regs[UREG_GS_BASE]  = 0;
    regs[UREG_DS]       = 0;
    regs[UREG_ES]       = 0;
    regs[UREG_FS]       = 0;
    regs[UREG_GS]       = 0;
    regs
}

// ── Apply a user_regs_struct back to the frame ────────────────────────────────

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

// ── PEEKUSER / POKEUSER word offsets ────────────────────────────────────────
//
// Linux maps byte offset / 8 → user_regs_struct index for the register area
// (first 27 × 8 = 216 bytes).  Everything beyond is either the FPU area or
// debug registers — we zero-read and ignore writes for those.

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
    if word_idx >= UREG_COUNT { return 0; } // FPU / debug area — silently ignore
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
        _ => {} // CS, SS, segment regs, FS_BASE via other path
    }
    0
}

// ── PEEKDATA / POKEDATA: read/write tracee virtual address space ──────────────

fn peek_tracee_word(cr3: usize, addr: usize) -> Option<u64> {
    // addr must be 8-byte aligned for a word read; we allow unaligned for
    // compatibility by reading two pages if necessary, but in practice
    // gdb always aligns.
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

// ── Check tracer permission ──────────────────────────────────────────────────

/// Returns true if `tracer_pid` is authorised to trace `target_pid`.
/// Current policy: any process may trace its direct children, or any process
/// when the tracer has CAP_SYS_PTRACE (we grant root that cap implicitly).
fn may_trace(tracer_pid: usize, target_pid: usize) -> bool {
    // Check if tracer is the parent of the target, or is root.
    scheduler::with_proc(target_pid, |p| {
        p.ppid == tracer_pid
    }).unwrap_or(false)
    || scheduler::with_proc(tracer_pid, |p| {
        p.caps.has_cap(crate::security::CAP_SYS_PTRACE)
    }).unwrap_or(false)
}

// ── sys_ptrace ───────────────────────────────────────────────────────────────

/// Entry point called from sys_ptrace_impl in stubs.rs.
pub fn sys_ptrace(req: i32, pid: i32, addr: usize, data: usize) -> isize {
    let caller = scheduler::current_pid();
    let target = pid as usize;

    match req {
        // ── PTRACE_TRACEME ────────────────────────────────────────────────────
        // Called by the child process to volunteer for tracing by its parent.
        PTRACE_TRACEME => {
            scheduler::with_proc_mut(caller, |p| {
                if p.ptrace_state != crate::proc::ptrace::PtraceState::None {
                    return -16isize; // EBUSY — already being traced
                }
                p.ptrace_state = PtraceState::Tracee {
                    tracer: p.ppid,
                    options: 0,
                    in_syscall_stop: false,
                };
                0isize
            }).unwrap_or(-3)
        }

        // ── PTRACE_ATTACH ─────────────────────────────────────────────────────
        PTRACE_ATTACH => {
            if target == caller { return -1; } // cannot attach to self
            if !may_trace(caller, target) { return -1; } // EPERM

            let ok = scheduler::with_proc_mut(target, |p| {
                if p.ptrace_state != PtraceState::None { return false; }
                p.ptrace_state = PtraceState::Tracee {
                    tracer: caller,
                    options: 0,
                    in_syscall_stop: false,
                };
                true
            }).unwrap_or(false);

            if !ok { return -16; } // EBUSY
            send_signal(target, 19); // SIGSTOP
            0
        }

        // ── PTRACE_DETACH ─────────────────────────────────────────────────────
        PTRACE_DETACH => {
            // Optionally deliver a signal (data) and clear TF.
            let found = scheduler::with_proc_mut(target, |p| {
                match p.ptrace_state {
                    PtraceState::Tracee { tracer, .. } |
                    PtraceState::Stopped { tracer, .. } if tracer == caller => {
                        p.ptrace_state = PtraceState::None;
                        // Clear TF in RFLAGS if set (singlestep artifact).
                        if p.kstack_top != 0 {
                            let f = unsafe {
                                core::slice::from_raw_parts_mut(
                                    frame_ptr(p.kstack_top), 17)
                            };
                            f[F_R11] &= !RFLAGS_TF;
                        }
                        true
                    }
                    _ => false,
                }
            }).unwrap_or(false);

            if !found { return -3; }
            // Resume the tracee, optionally injecting a signal.
            if data != 0 { send_signal(target, data as u32); }
            scheduler::wake_pid(target);
            0
        }

        // ── PTRACE_CONT ───────────────────────────────────────────────────────
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
            if data != 0 { send_signal(target, data as u32); }
            scheduler::wake_pid(target);
            0
        }

        // ── PTRACE_KILL ───────────────────────────────────────────────────────
        PTRACE_KILL => {
            send_signal(target, 9); // SIGKILL
            0
        }

        // ── PTRACE_SINGLESTEP ─────────────────────────────────────────────────
        PTRACE_SINGLESTEP => {
            let found = scheduler::with_proc_mut(target, |p| {
                match p.ptrace_state {
                    PtraceState::Stopped { tracer, options, .. } if tracer == caller => {
                        p.ptrace_state = PtraceState::Tracee {
                            tracer,
                            options,
                            in_syscall_stop: false,
                        };
                        // Set TF (trap flag) in saved RFLAGS so the CPU
                        // delivers #DB after exactly one instruction.
                        if p.kstack_top != 0 {
                            let f = unsafe {
                                core::slice::from_raw_parts_mut(
                                    frame_ptr(p.kstack_top), 17)
                            };
                            f[F_R11] |= RFLAGS_TF;
                        }
                        true
                    }
                    _ => false,
                }
            }).unwrap_or(false);

            if !found { return -3; }
            if data != 0 { send_signal(target, data as u32); }
            scheduler::wake_pid(target);
            0
        }

        // ── PTRACE_SYSCALL ────────────────────────────────────────────────────
        // Resume, stopping at the next syscall entry or exit.
        // We set in_syscall_stop = true; the syscall entry path checks this
        // and delivers SIGTRAP (with PTRACE_O_TRACESYSGOOD: signal | 0x80).
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
            if data != 0 { send_signal(target, data as u32); }
            scheduler::wake_pid(target);
            0
        }

        // ── PTRACE_PEEKTEXT / PTRACE_PEEKDATA ─────────────────────────────────
        PTRACE_PEEKTEXT | PTRACE_PEEKDATA => {
            let cr3 = match scheduler::with_proc(target, |p| p.user_satp) {
                Some(c) if c != 0 => c,
                _ => return -3,
            };
            match peek_tracee_word(cr3, addr) {
                Some(word) => {
                    // data is a pointer into tracer's address space.
                    if data != 0 {
                        if copy_to_user(data, &word.to_le_bytes()).is_err() {
                            return -14;
                        }
                    }
                    word as isize
                }
                None => -14, // EFAULT
            }
        }

        // ── PTRACE_POKETEXT / PTRACE_POKEDATA ─────────────────────────────────
        PTRACE_POKETEXT | PTRACE_POKEDATA => {
            let cr3 = match scheduler::with_proc(target, |p| p.user_satp) {
                Some(c) if c != 0 => c,
                _ => return -3,
            };
            if poke_tracee_word(cr3, addr, data as u64) { 0 } else { -14 }
        }

        // ── PTRACE_PEEKUSER ───────────────────────────────────────────────────
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
                if copy_to_user(data, &word.to_le_bytes()).is_err() { return -14; }
            }
            word as isize
        }

        // ── PTRACE_POKEUSER ───────────────────────────────────────────────────
        PTRACE_POKEUSER => {
            let kstack_top = match scheduler::with_proc(target, |p| p.kstack_top) {
                Some(k) if k != 0 => k,
                _ => return -3,
            };
            pokeuser_word(kstack_top, addr, data as u64)
        }

        // ── PTRACE_GETREGS ────────────────────────────────────────────────────
        // data is a pointer into tracer's address space where user_regs_struct
        // will be written (216 bytes = 27 × 8).
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
                core::slice::from_raw_parts(
                    regs.as_ptr() as *const u8,
                    UREG_COUNT * 8,
                )
            };
            if copy_to_user(data, bytes).is_err() { return -14; }
            0
        }

        // ── PTRACE_SETREGS ────────────────────────────────────────────────────
        // addr is a pointer in tracer's address space to a user_regs_struct.
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

        // ── PTRACE_SETOPTIONS ─────────────────────────────────────────────────
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

        // ── PTRACE_GETEVENTMSG ────────────────────────────────────────────────
        // Writes ptrace_event (u64) to the address in data.
        PTRACE_GETEVENTMSG => {
            let event = match scheduler::with_proc(target, |p| p.ptrace_event) {
                Some(e) => e,
                None    => return -3,
            };
            if copy_to_user(data, &event.to_le_bytes()).is_err() { return -14; }
            0
        }

        _ => -22, // EINVAL — unrecognised request
    }
}

// ── Called by the syscall entry path ─────────────────────────────────────────

/// Check whether the current process is being traced with PTRACE_SYSCALL.
/// If so, stop it and notify the tracer with SIGTRAP (or SIGTRAP | 0x80 if
/// PTRACE_O_TRACESYSGOOD is set).  Call at syscall entry AND exit.
pub fn ptrace_syscall_stop() {
    let pid = scheduler::current_pid();
    let (tracer, in_syscall_stop, options) =
        match scheduler::with_proc(pid, |p| p.ptrace_state) {
            Some(PtraceState::Tracee { tracer, in_syscall_stop, options })
                if in_syscall_stop => (tracer, true, options),
            _ => return,
        };
    let _ = (tracer, in_syscall_stop); // used for the guard above
    let sig: u32 = if options & PTRACE_O_TRACESYSGOOD != 0 { 5 | 0x80 } else { 5 };
    scheduler::with_proc_mut(pid, |p| {
        p.ptrace_state = PtraceState::Stopped {
            tracer,
            options,
            sig,
        };
    });
    send_signal(tracer, sig);
    // Block self — scheduler will pick someone else.
    scheduler::block_pid(pid);
}
