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
//! ## Arch-specific first-entry paths
//!
//! ### x86_64
//!   `push_syscall_frame` builds a 17-slot iretq frame at kstack_top - 136.
//!   `child_ctx.rip` = `sysret_trampoline`.
//!
//! ### RISC-V
//!   `push_trap_frame_riscv` builds a full 34-word `TrapFrame` at
//!   `kstack_top - TRAP_FRAME_SIZE`.

extern crate alloc;
use alloc::vec::Vec;
use alloc::sync::Arc;
use crate::mm::kstack::alloc_kstack;
use crate::proc::context::Context;
use crate::proc::process::{Pcb, State};
use crate::proc::ptrace::PtraceState;
use crate::proc::rlimit::RlimitSet;
use crate::proc::scheduler;
use crate::proc::thread;
use crate::security::CapSet;
use crate::proc::namespace::NsSet;
use crate::security::seccomp::FilterChain;
use crate::uaccess::{copy_from_user, copy_to_user, USER_SPACE_END};

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::syscall::sysret_trampoline;

#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
fn sysret_trampoline() {}

const USER_CS: usize = 0x23;
const USER_SS: usize = 0x1b;

// ── CLONE_* flag bits ──────────────────────────────────────────────────────

pub const CLONE_VM:             u64 = 0x0000_0100;
pub const CLONE_FS:             u64 = 0x0000_0200;
pub const CLONE_FILES:          u64 = 0x0000_0400;
pub const CLONE_SIGHAND:        u64 = 0x0000_0800;
pub const CLONE_PIDFD:          u64 = 0x0000_1000;
pub const CLONE_PTRACE:         u64 = 0x0000_2000;
pub const CLONE_VFORK:          u64 = 0x0000_4000;
pub const CLONE_PARENT:         u64 = 0x0000_8000;
pub const CLONE_THREAD:         u64 = 0x0001_0000;
pub const CLONE_NEWNS:          u64 = 0x0002_0000;
pub const CLONE_SYSVSEM:        u64 = 0x0004_0000;
pub const CLONE_SETTLS:         u64 = 0x0008_0000;
pub const CLONE_PARENT_SETTID:  u64 = 0x0010_0000;
pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
pub const CLONE_DETACHED:       u64 = 0x0040_0000;
pub const CLONE_CHILD_SETTID:   u64 = 0x0100_0000;

#[repr(C)]
pub struct CloneArgs {
    pub flags:        u64,
    pub pidfd:        u64,
    pub child_tid:    u64,
    pub parent_tid:   u64,
    pub exit_signal:  u64,
    pub stack:        u64,
    pub stack_size:   u64,
    pub tls:          u64,
    pub set_tid:      u64,
    pub set_tid_size: u64,
    pub cgroup:       u64,
}

// ── sys_clone3 ────────────────────────────────────────────────────────────

pub fn sys_clone3(args_va: usize, args_size: usize) -> isize {
    let clone_args_sz = core::mem::size_of::<CloneArgs>();
    if args_va == 0
        || args_va >= USER_SPACE_END
        || args_va.saturating_add(clone_args_sz) > USER_SPACE_END
    {
        return -14;
    }
    if args_size < clone_args_sz { return -22; }

    let mut kbuf = [0u8; core::mem::size_of::<CloneArgs>()];
    if copy_from_user(&mut kbuf, args_va).is_err() { return -14; }
    let ca: CloneArgs = unsafe { core::mem::transmute(kbuf) };

    let flags       = ca.flags;
    let is_vm_clone = flags & CLONE_VM != 0;
    let parent_pid  = scheduler::current_pid();
    let parent_tgid = thread::tgid_of(parent_pid);

    let kstack_top = match alloc_kstack() {
        Some(k) => k,
        None    => return -12,
    };
    let child_pid  = scheduler::next_pid();
    let child_tgid = if is_vm_clone { parent_tgid } else { child_pid };

    let (child_satp, parent_pc, parent_ppid) = scheduler::with_proc(parent_pid, |p| {
        (p.user_satp, p.pc, p.ppid)
    }).unwrap_or((0, 0, 1));

    let child_ppid = if flags & CLONE_PARENT != 0 {
        parent_ppid
    } else if flags & CLONE_THREAD != 0 {
        parent_tgid
    } else {
        parent_pid
    };

    let child_tls = if flags & CLONE_SETTLS != 0 { ca.tls as usize } else { 0 };

    let user_sp = if ca.stack != 0 {
        (ca.stack + ca.stack_size) as usize
    } else {
        0
    };

    #[cfg(target_arch = "x86_64")]
    let child_ctx = {
        push_syscall_frame(kstack_top, parent_pc, 0x202, user_sp);
        Context {
            rip:     sysret_trampoline as usize,
            rsp:     kstack_top - 17 * 8,
            fs_base: child_tls,
            ..Context::zero()
        }
    };

    #[cfg(target_arch = "riscv64")]
    let child_ctx = {
        let entry_pc = parent_pc;
        push_trap_frame_riscv(kstack_top, entry_pc, user_sp, child_tls);
        let frame_sp = kstack_top - crate::arch::riscv64::trap::TRAP_FRAME_SIZE;
        Context {
            ra:  crate::proc::context::task_entry_trampoline as usize,
            sp:  frame_sp,
            s0:  0,
            ..Context::zero()
        }
    };

    if flags & CLONE_PARENT_SETTID != 0 {
        let _ = copy_to_user(ca.parent_tid as usize, &(child_pid as u32).to_ne_bytes());
    }
    if flags & CLONE_PIDFD != 0 {
        let fd = crate::fs::pidfd::alloc(child_pid);
        let _ = copy_to_user(ca.pidfd as usize, &(fd as i32).to_ne_bytes());
    }

    let child_tid_va = if flags & CLONE_CHILD_SETTID != 0 {
        let va = ca.child_tid as usize;
        if va != 0 && va < USER_SPACE_END {
            let _ = copy_to_user(va, &(child_pid as u32).to_ne_bytes());
        }
        va
    } else {
        0
    };

    // ── Build child PCB ─────────────────────────────────────────────────
    //
    // Start with a clone of the parent PCB so most fields are inherited.
    // Then override the fields that must differ in the child.
    let mut child_pcb: Pcb = scheduler::with_proc(parent_pid, |p| p.clone())
        .unwrap_or_else(make_blank_pcb);

    // ── Signal handler table ─────────────────────────────────────────────
    //
    // CLONE_SIGHAND: share the parent's Arc — child and parent see the same
    //   table; sigaction() by either immediately affects the other.
    //
    // No CLONE_SIGHAND (fork/vfork): deep-copy so child is independent.
    //   Uses Pcb::fork_signal_handlers() which locks the parent's table,
    //   clones the inner value, and wraps it in a new Arc<Mutex<…>>.
    child_pcb.signal_handlers = if flags & CLONE_SIGHAND != 0 {
        // Share the existing Arc (both point to the same Mutex<SignalHandlers>).
        scheduler::with_proc(parent_pid, |p| p.signal_handlers.clone())
            .unwrap_or_else(|| Arc::new(spin::Mutex::new(
                crate::proc::fork::SignalHandlers::default())))
    } else {
        // Deep copy: child gets its own independent table.
        scheduler::with_proc(parent_pid, |p| p.fork_signal_handlers())
            .unwrap_or_else(|| Arc::new(spin::Mutex::new(
                crate::proc::fork::SignalHandlers::default())))
    };

    child_pcb.pid        = child_pid;
    child_pcb.tgid       = child_tgid;
    child_pcb.ppid       = child_ppid;
    child_pcb.pgid       = scheduler::with_proc(parent_pid, |p| p.pgid)
                               .unwrap_or(child_pid);
    child_pcb.state      = State::Ready;
    child_pcb.exit_code  = 0;
    child_pcb.user_satp  = child_satp;
    child_pcb.kstack_top = kstack_top;
    child_pcb.ctx        = child_ctx;
    child_pcb.exit_signal        = ca.exit_signal as u32;
    child_pcb.vfork_parent       = if flags & CLONE_VFORK != 0 { parent_pid } else { 0 };
    child_pcb.child_tid_va       = child_tid_va;
    child_pcb.child_tid_val      = child_pid as u32;
    child_pcb.clear_child_tid_va = if flags & CLONE_CHILD_CLEARTID != 0 {
        ca.child_tid as usize
    } else {
        0
    };
    child_pcb.tls_base = child_tls;
    child_pcb.robust_list_head = 0;
    child_pcb.robust_list_len  = 0;
    child_pcb.ptrace_state = PtraceState::None;
    child_pcb.ptrace_event = 0;
    // Clear per-thread pending signal queue for the child.
    child_pcb.pen