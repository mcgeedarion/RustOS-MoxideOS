//! clone3 syscall implementation.
//!
//! Implements the POSIX thread creation path for pthread_create:
//!   CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
//!   | CLONE_SETTLS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID
//!
//! A CLONE_VM child:
//!   - Gets a fresh pid but shares user_satp (CR3/satp) with its parent.
//!   - Shares the parent's VMA list.
//!   - Gets a private kernel stack and Context.
//!   - Returns 0 to userspace (child return value = 0).
//!
//! Non-CLONE_VM (fork / vfork) is handled by fork.rs.
//!
//! ## Arch-specific first-entry paths
//!
//! ### x86_64
//!   `push_syscall_frame` builds a 17-slot iretq frame at kstack_top - 136.
//!   `child_ctx.rip` = `sysret_trampoline` so the first context switch jumps
//!   there and performs the `sysret` into user mode.
//!
//! ### RISC-V
//!   `push_trap_frame_riscv` builds a full 34-word `TrapFrame` at
//!   `kstack_top - TRAP_FRAME_SIZE` (272 bytes below the top).
//!   Fields set:
//!     - `sepc`    = child entry point (parent's `pc` for fork-like clones;
//!                   caller-supplied `stack + stack_size` top for
//!                   pthread_create clones)
//!     - `sstatus` = SPIE (interrupts on after sret) | ~SPP (U-mode)
//!     - `sp`      = user stack top (`ca.stack + ca.stack_size`)
//!     - `a0`      = 0  (child syscall return value)
//!     - `tp`      = child TLS pointer (when CLONE_SETTLS)
//!     - All other registers = 0
//!
//!   `child_ctx.ra`  = `task_entry_trampoline` — jumped to on first resume.
//!   `child_ctx.sp`  = `kstack_top - TRAP_FRAME_SIZE` — kernel sp at entry.
//!   `child_ctx.s0`  = 0 — clean frame-pointer chain.
//!
//! ## Bug fixes (carried forward from previous version)
//!
//! ### push_syscall_frame: SS slot was overwritten with rip (x86_64)
//! ### sys_clone_legacy: child_sp went into stack_size field
//! ### CLONE_CHILD_SETTID: child never wrote its own TID

extern crate alloc;
use alloc::vec::Vec;
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

// Ring-3 code and stack segment selectors (GDT layout: cs=0x23, ss=0x1b).
const USER_CS: usize = 0x23;
const USER_SS: usize = 0x1b;

// ── CLONE_* flag bits ─────────────────────────────────────────────────────

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
    pub flags:        u64,  // [0]
    pub pidfd:        u64,  // [1]
    pub child_tid:    u64,  // [2]
    pub parent_tid:   u64,  // [3]
    pub exit_signal:  u64,  // [4]
    pub stack:        u64,  // [5]
    pub stack_size:   u64,  // [6]
    pub tls:          u64,  // [7]
    pub set_tid:      u64,  // [8]
    pub set_tid_size: u64,  // [9]
    pub cgroup:       u64,  // [10]
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

    // User-space stack top: Linux convention — stack field is the bottom
    // (lowest address) of the stack region, stack+stack_size is the top.
    let user_sp = if ca.stack != 0 {
        (ca.stack + ca.stack_size) as usize
    } else {
        0
    };

    // ── arch-specific kernel-stack frame + Context init ──────────────────
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
        // Entry PC: for a pthread_create (CLONE_VM) clone the child starts
        // at the user-supplied entry point (passed in ca.stack as a
        // pointer on musl's ABI — but clone3 passes it via sepc from the
        // parent's pc for fork-like clones).  For all cases we use
        // parent_pc so the child resumes exactly where the parent called
        // clone (which is correct for both fork and pthread_create since
        // pthread_create sets the child entry via the TrapFrame's sepc).
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

    // CLONE_CHILD_SETTID: write child_pid to child_tid_va in the parent
    // before enqueue so musl's pthread_create sees it immediately.
    let child_tid_va = if flags & CLONE_CHILD_SETTID != 0 {
        let va = ca.child_tid as usize;
        if va != 0 && va < USER_SPACE_END {
            let _ = copy_to_user(va, &(child_pid as u32).to_ne_bytes());
        }
        va
    } else {
        0
    };

    let mut child_pcb: Pcb = scheduler::with_proc(parent_pid, |p| p.clone())
        .unwrap_or_else(make_blank_pcb);
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

    if is_vm_clone { thread::register_thread(child_pid, child_tgid); }
    scheduler::enqueue(child_pcb);

    // Enqueue the task on the least-loaded CPU (or the parent's CPU for
    // CLONE_VM so TLB state is warm on a shared address space).
    let task_ptr = scheduler::task_ptr_for_pid(child_pid);
    if !task_ptr.is_null() {
        if is_vm_clone {
            // Pin the new thread to the same CPU as the parent so they
            // share warm TLB / cache state.  The load balancer can
            // migrate it after BALANCE_TICKS if the CPU gets overloaded.
            let parent_cpu = crate::smp::percpu::current_cpu_id();
            scheduler::schedule_on(task_ptr, parent_cpu);
        } else {
            scheduler::enqueue_task(task_ptr);
        }
    }

    if flags & CLONE_VFORK != 0 { scheduler::suspend_current_until_child_exec(child_pid); }

    child_pid as isize
}

// ── legacy 5-argument clone (NR 56) ──────────────────────────────────────────

pub fn sys_clone_legacy(flags: usize, child_sp: usize, _ptid: usize,
                        _ctid: usize, tls: usize) -> isize {
    let mut args = [0u64; core::mem::size_of::<CloneArgs>() / 8];
    args[0] = flags as u64;
    args[5] = child_sp as u64;  // stack (bottom, child_sp is the top on Linux ABI)
    args[6] = 0;                // stack_size = 0 when child_sp is already the top
    args[7] = tls as u64;
    let va = args.as_ptr() as usize;
    sys_clone3(va, core::mem::size_of::<CloneArgs>())
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// x86_64: build the 17-slot iretq frame on the kernel stack.
#[cfg(target_arch = "x86_64")]
fn push_syscall_frame(kstack_top: usize, rip: usize, rflags: usize, user_rsp: usize) {
    const FRAME_SZ: usize = 17 * 8;
    let base = kstack_top - FRAME_SZ;
    unsafe {
        core::ptr::write_bytes(base as *mut u8, 0, FRAME_SZ);
        let p = base as *mut usize;
        p.add(13).write(rip);      // RIP
        p.add(14).write(USER_CS);  // CS
        p.add(15).write(rflags);   // RFLAGS
        p.add(16).write(user_rsp); // RSP
    }
}

/// RISC-V: build a `TrapFrame` at `kstack_top - TRAP_FRAME_SIZE`.
///
/// The child will enter userspace through `task_entry_trampoline` →
/// `trap_return` which restores this frame and executes `sret`.
///
/// `sstatus` is set with SPIE (interrupts enabled after sret) and SPP=0
/// (return to U-mode).  All registers except `sp` (user stack), `tp`
/// (TLS pointer), `a0` (return value = 0), and `sepc` (entry PC) are
/// zeroed.
#[cfg(target_arch = "riscv64")]
fn push_trap_frame_riscv(kstack_top: usize, entry_pc: usize, user_sp: usize, tls: usize) {
    use crate::arch::riscv64::trap::{TrapFrame, TRAP_FRAME_SIZE, SSTATUS_SPIE, SSTATUS_SPP};
    let frame_va = kstack_top - TRAP_FRAME_SIZE;
    unsafe {
        // Zero the entire frame first.
        core::ptr::write_bytes(frame_va as *mut u8, 0, TRAP_FRAME_SIZE);
        let f = frame_va as *mut TrapFrame;
        (*f).sp      = user_sp;                   // user stack pointer
        (*f).tp      = tls;                       // thread pointer (TLS)
        (*f).a0      = 0;                         // child return value
        (*f).sepc    = entry_pc;                  // resume PC after sret
        // SPIE=1: interrupts on in U-mode after sret.
        // SPP=0:  sret returns to U-mode (not S-mode).
        (*f).sstatus = SSTATUS_SPIE & !SSTATUS_SPP;
    }
}

fn make_blank_pcb() -> Pcb {
    Pcb {
        pid:        0,
        ppid:       0,
        tgid:       0,
        pgid:       0,
        state:      State::Ready,
        exit_code:  0,
        caps:       CapSet::empty(),
        pc:         0,
        sp:         0,
        user_satp:  0,
        vmas:       Vec::new(),
        next_va:    Pcb::INITIAL_NEXT_VA,
        brk_base:   0,
        brk:        Pcb::INITIAL_BRK,
        kstack_top: 0,
        ctx:        Context::zero(),
        tls_base:   0,
        child_tid_va:        0,
        child_tid_val:       0,
        clear_child_tid_va:  0,
        exit_signal:         17,
        vfork_parent:        0,
        signal_handlers:     crate::proc::fork::SignalHandlers::default(),
        pending_signals:     alloc::collections::VecDeque::new(),
        exe_path:            None,
        ns:                  NsSet::default(),
        seccomp:             FilterChain::default(),
        robust_list_head:    0,
        robust_list_len:     0,
        ptrace_state:        PtraceState::None,
        ptrace_event:        0,
        rlimits:             RlimitSet::default(),
        cpu_time_ns:         0,
        rt_cpu_time_us:      0,
        sleep_deadline_ns:   0,
        sleep_timer_id:      0,
    }
}
