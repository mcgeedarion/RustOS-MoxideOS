//! clone3 syscall implementation.
//!
//! ## CLONE_SIGHAND
//!
//! When CLONE_SIGHAND is set the child shares the parent's signal handler
//! table (the same Arc<Mutex<SignalHandlers>>).  Any sigaction() call by
//! either the parent or any sibling thread immediately affects all of them.
//!
//! When CLONE_SIGHAND is NOT set (plain fork / vfork) the child gets a
//! deep copy via `Pcb::fork_signal_handlers()`, so the parent and child
//! have independent dispositions after the fork.
//!
//! ## CLONE_VM and mm_lock
//!
//! When CLONE_VM is set (threads sharing an address space) the child reuses
//! the parent's `mm_lock` Arc so that ALL threads in the group block on the
//! same `RwLock<()>` during uaccess validate+copy.  A concurrent munmap in
//! any thread will therefore block uaccess in every other thread in the group
//! until the VMA mutation is complete.
//!
//! When CLONE_VM is NOT set (fork/vfork) the child gets an independent
//! `mm_lock` (the default from `Pcb::zeroed()` via the PCB clone path).
//! The child's address space is logically independent after the fork, so its
//! mm_lock must not block on the parent's munmap activity.
//!
//! ## Arch-specific first-entry paths
//!
//! ### x86_64
//!   `push_syscall_frame` builds a 17-slot iretq frame at kstack_top - 136.
//!   `child_ctx.rip` = `sysret_trampoline`.
//!
//! ### RISC-V
//!   `push_trap_frame_riscv` builds a full 34-word `TrapFrame` at
//!   `kstack_top - TRAP_FRAME_SIZE`.
//!
//! ## TaskRunState
//!
//! Every newly cloned child starts as `TaskRunState::Cold` with the correct
//! `pc` and `sp` captured from the built `child_ctx` before the Pcb is
//! enqueued.  `proc_table::enqueue` calls `Task::new(pcb_ptr)` which reads
//! `pcb.pc` and `pcb.sp` at that moment, so those fields MUST be written
//! to the Pcb before the enqueue call.  This is enforced by the explicit
//! `child_pcb.pc = …` / `child_pcb.sp = …` assignments below, which mirror
//! the values already encoded in `child_ctx`.

extern crate alloc;
use crate::mm::kstack::alloc_kstack;
use crate::proc::context::Context;
use crate::proc::namespace::NsSet;
use crate::proc::process::{Pcb, State};
use crate::proc::ptrace::PtraceState;
use crate::proc::rlimit::RlimitSet;
use crate::proc::scheduler;
use crate::proc::thread;
use crate::security::seccomp::FilterChain;
use crate::security::CapSet;
use crate::syscall::errno::{efault, einval, enomem};
use crate::uaccess::{copy_from_user, copy_to_user, USER_SPACE_END};
use alloc::sync::Arc;
use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::syscall::sysret_trampoline;

#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
fn sysret_trampoline() {}

const USER_CS: usize = 0x23;
const USER_SS: usize = 0x1b;

pub const CLONE_VM: u64 = 0x0000_0100;
pub const CLONE_FS: u64 = 0x0000_0200;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const CLONE_SIGHAND: u64 = 0x0000_0800;
pub const CLONE_PIDFD: u64 = 0x0000_1000;
pub const CLONE_PTRACE: u64 = 0x0000_2000;
pub const CLONE_VFORK: u64 = 0x0000_4000;
pub const CLONE_PARENT: u64 = 0x0000_8000;
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const CLONE_NEWNS: u64 = 0x0002_0000;
pub const CLONE_SYSVSEM: u64 = 0x0004_0000;
pub const CLONE_SETTLS: u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub const CLONE_DETACHED: u64 = 0x0040_0000;
pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;

// Wire layout of `struct clone_args` as defined by Linux.
// All fields are u64; total size is 88 bytes for the 11-field form.
// The kernel accepts any size >= CLONE_ARGS_SIZE_VER0 (64 bytes);
// fields beyond what the caller provides are zero-filled.
#[repr(C)]
pub struct CloneArgs {
    pub flags: u64,
    pub pidfd: u64,
    pub child_tid: u64,
    pub parent_tid: u64,
    pub exit_signal: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub tls: u64,
    pub set_tid: u64,
    pub set_tid_size: u64,
    pub cgroup: u64,
}

/// Minimum accepted `args_size`: the 8-field v0 struct (64 bytes).
const CLONE_ARGS_SIZE_VER0: usize = 64;
/// Full 11-field struct size (88 bytes).
const CLONE_ARGS_SIZE_FULL: usize = core::mem::size_of::<CloneArgs>();

// Replaces the previous `unsafe { core::mem::transmute(kbuf) }` cast.
// All fields are u64 at fixed offsets; parsing them explicitly:
//   (a) is safe regardless of padding or future field additions;
//   (b) allows the kernel to zero-fill fields the caller did not supply
//       (callers using the v0 struct omit set_tid, set_tid_size, cgroup);
//   (c) makes the wire layout self-documenting.
fn parse_clone_args(buf: &[u8]) -> CloneArgs {
    // Helper: read a u64 at byte offset `off`; return 0 if out of range.
    let u64_at = |off: usize| -> u64 {
        buf.get(off..off + 8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_ne_bytes)
            .unwrap_or(0)
    };
    CloneArgs {
        flags: u64_at(0),
        pidfd: u64_at(8),
        child_tid: u64_at(16),
        parent_tid: u64_at(24),
        exit_signal: u64_at(32),
        stack: u64_at(40),
        stack_size: u64_at(48),
        tls: u64_at(56),
        // v1+ fields — zero if caller passed a smaller struct
        set_tid: u64_at(64),
        set_tid_size: u64_at(72),
        cgroup: u64_at(80),
    }
}

pub fn sys_clone3(args_va: usize, args_size: usize) -> isize {
    // Validate the user pointer and reported size.
    if args_va == 0
        || args_va >= USER_SPACE_END
        || args_va.saturating_add(CLONE_ARGS_SIZE_FULL) > USER_SPACE_END
    {
        return efault();
    }
    // Linux rejects anything smaller than the v0 struct.
    if args_size < CLONE_ARGS_SIZE_VER0 {
        return einval();
    }

    // Copy at most CLONE_ARGS_SIZE_FULL bytes; zero-fill the rest so that
    // parse_clone_args() can safely read all 11 fields regardless of what
    // the caller provided.
    let copy_len = args_size.min(CLONE_ARGS_SIZE_FULL);
    let mut kbuf = [0u8; CLONE_ARGS_SIZE_FULL];
    if copy_from_user(&mut kbuf[..copy_len], args_va).is_err() {
        return efault();
    }
    let ca = parse_clone_args(&kbuf);

    let flags = ca.flags;
    let is_vm_clone = flags & CLONE_VM != 0;
    let parent_pid = scheduler::current_pid();
    let parent_tgid = thread::tgid_of(parent_pid);

    let kstack_top = match alloc_kstack() {
        Some(k) => k,
        None => return enomem(),
    };
    let child_pid = scheduler::next_pid();
    let child_tgid = if is_vm_clone { parent_tgid } else { child_pid };

    let (child_satp, parent_pc, parent_ppid) =
        scheduler::with_proc(parent_pid, |p| (p.user_satp, p.pc, p.ppid)).unwrap_or((0, 0, 1));

    let child_ppid = if flags & CLONE_PARENT != 0 {
        parent_ppid
    } else if flags & CLONE_THREAD != 0 {
        parent_tgid
    } else {
        parent_pid
    };

    let child_tls = if flags & CLONE_SETTLS != 0 {
        ca.tls as usize
    } else {
        0
    };

    let user_sp = if ca.stack != 0 {
        (ca.stack + ca.stack_size) as usize
    } else {
        0
    };

    // These values are written to child_pcb.pc / child_pcb.sp BEFORE
    // scheduler::enqueue() is called.  proc_table::enqueue() constructs a
    // Task via Task::new(pcb_ptr), which reads pcb.pc and pcb.sp at that
    // moment to initialise TaskRunState::Cold { pc, sp }.  If the assignment
    // order were reversed the Cold payload would capture zeros.
    #[cfg(target_arch = "x86_64")]
    let (child_ctx, child_first_pc, child_first_sp) = {
        push_syscall_frame(kstack_top, parent_pc, 0x202, user_sp);
        let ctx = Context {
            rip: sysret_trampoline as usize,
            rsp: kstack_top - 17 * 8,
            fs_base: child_tls,
            ..Context::zero()
        };
        let first_pc = parent_pc;
        let first_sp = if user_sp != 0 { user_sp } else { kstack_top };
        (ctx, first_pc, first_sp)
    };

    #[cfg(target_arch = "riscv64")]
    let (child_ctx, child_first_pc, child_first_sp) = {
        let entry_pc = parent_pc;
        let effective_sp = if user_sp != 0 { user_sp } else { kstack_top };
        push_trap_frame_riscv(kstack_top, entry_pc, effective_sp, child_tls);
        let frame_sp = kstack_top - crate::arch::riscv64::trap::TRAP_FRAME_SIZE;
        let ctx = Context {
            ra: crate::proc::context::task_entry_trampoline as usize,
            sp: frame_sp,
            s0: 0,
            ..Context::zero()
        };
        (ctx, entry_pc, effective_sp)
    };

    if flags & CLONE_PARENT_SETTID != 0 {
        let _ = crate::uaccess::copy_to_user_value(ca.parent_tid as usize, &(child_pid as u32).to_ne_bytes());
    }
    if flags & CLONE_PIDFD != 0 {
        let fd = crate::fs::pidfd::alloc(child_pid);
        let _ = crate::uaccess::copy_to_user_value(ca.pidfd as usize, &(fd as i32).to_ne_bytes());
    }

    let child_tid_va = if flags & CLONE_CHILD_SETTID != 0 {
        let va = ca.child_tid as usize;
        if va != 0 && va < USER_SPACE_END {
            let _ = crate::uaccess::copy_to_user_value(va, &(child_pid as u32).to_ne_bytes());
        }
        va
    } else {
        0
    };

    // Start with a clone of the parent PCB so most fields are inherited.
    // Then override the fields that must differ in the child.
    let mut child_pcb: Pcb =
        scheduler::with_proc(parent_pid, |p| p.clone()).unwrap_or_else(make_blank_pcb);

    // CLONE_SIGHAND: share the Arc — all threads see sigaction() changes instantly.
    // Otherwise: deep-copy so parent and child have independent dispositions.
    child_pcb.signal_handlers = if flags & CLONE_SIGHAND != 0 {
        scheduler::with_proc(parent_pid, |p| p.signal_handlers.clone()).unwrap_or_else(|| {
            Arc::new(spin::Mutex::new(
                crate::proc::fork::SignalHandlers::default(),
            ))
        })
    } else {
        scheduler::with_proc(parent_pid, |p| p.fork_signal_handlers()).unwrap_or_else(|| {
            Arc::new(spin::Mutex::new(
                crate::proc::fork::SignalHandlers::default(),
            ))
        })
    };

    // CLONE_VM: reuse parent's Arc so all threads in the group block together
    // on the same RwLock during uaccess validate+copy (see module doc).
    // Otherwise: independent lock — the child's address space is its own.
    child_pcb.mm_lock = if is_vm_clone {
        scheduler::with_proc(parent_pid, |p| p.share_mm_lock())
            .unwrap_or_else(|| Arc::new(spin::RwLock::new(())))
    } else {
        Arc::new(spin::RwLock::new(()))
    };

    child_pcb.pid = child_pid;
    child_pcb.tgid = child_tgid;
    child_pcb.ppid = child_ppid;
    child_pcb.pgid = scheduler::with_proc(parent_pid, |p| p.pgid).unwrap_or(child_pid);
    child_pcb.state = State::Ready;
    child_pcb.exit_code = 0;
    child_pcb.user_satp = child_satp;
    child_pcb.kstack_top = kstack_top;
    child_pcb.ctx = child_ctx;
    // pc / sp MUST be set before enqueue() so Task::new() captures them.
    child_pcb.pc = child_first_pc;
    child_pcb.sp = child_first_sp;
    child_pcb.exit_signal = ca.exit_signal as u32;
    child_pcb.vfork_parent = if flags & CLONE_VFORK != 0 {
        parent_pid
    } else {
        0
    };
    child_pcb.child_tid_va = child_tid_va;
    child_pcb.child_tid_val = child_pid as u32;
    child_pcb.clear_child_tid_va = if flags & CLONE_CHILD_CLEARTID != 0 {
        ca.child_tid as usize
    } else {
        0
    };
    child_pcb.tls_base = child_tls;
    child_pcb.robust_list_head = 0;
    child_pcb.robust_list_len = 0;
    child_pcb.ptrace_state = PtraceState::None;
    child_pcb.ptrace_event = 0;
    child_pcb.pending_signals.clear();

    if flags & CLONE_NEWNS != 0 {
        child_pcb.ns =
            scheduler::with_proc(parent_pid, |p| p.ns.clone_for_unshare()).unwrap_or_default();
    }

    let child_pid_usize = child_pid as usize;
    scheduler::enqueue(child_pcb);

    if flags & CLONE_VFORK != 0 {
        scheduler::suspend_current_until_child_exec(child_pid_usize);
    }

    child_pid as isize
}

fn make_blank_pcb() -> Pcb {
    Pcb::zeroed()
}

#[cfg(target_arch = "x86_64")]
fn push_syscall_frame(kstack_top: usize, pc: usize, rflags: usize, user_sp: usize) {
    let frame = unsafe { core::slice::from_raw_parts_mut((kstack_top - 17 * 8) as *mut usize, 17) };
    frame.iter_mut().for_each(|x| *x = 0);
    frame[0] = USER_SS;
    frame[1] = if user_sp != 0 { user_sp } else { kstack_top };
    frame[2] = rflags;
    frame[3] = USER_CS;
    frame[4] = pc;
}

#[cfg(target_arch = "riscv64")]
fn push_trap_frame_riscv(kstack_top: usize, pc: usize, user_sp: usize, tls: usize) {
    use crate::arch::riscv64::trap::{TrapFrame, TRAP_FRAME_SIZE};
    let frame_ptr = (kstack_top - TRAP_FRAME_SIZE) as *mut TrapFrame;
    unsafe {
        frame_ptr.write_bytes(0, 1);
        (*frame_ptr).sepc = pc;
        (*frame_ptr).regs[2] = if user_sp != 0 { user_sp } else { kstack_top }; // sp
        (*frame_ptr).regs[4] = tls; // tp
    }
}
