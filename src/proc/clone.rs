//! clone3 syscall implementation.
//!
//! Implements the POSIX thread creation path for pthread_create:
//!   CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
//!   | CLONE_SETTLS | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID
//!
//! A CLONE_VM child:
//!   - Gets a fresh pid but shares user_satp (CR3) with its parent.
//!   - Shares the parent's VMA namespace via thread::register_thread.
//!   - Gets a private kernel stack and Context.
//!   - Starts at sysret_trampoline with rax=0 (child return value).
//!   - Has child_tid_va written by child_first_run_hook on first-run.
//!
//! Non-CLONE_VM (fork / vfork) is handled by copying user_satp and
//! owned_pages as before; this file only adds the CLONE_VM fast path.

extern crate alloc;
use alloc::vec::Vec;
use crate::proc::process::{Pcb, State};
use crate::proc::context::Context;
use crate::proc::scheduler;
use crate::proc::thread;
use crate::arch::x86_64::syscall::sysret_trampoline;
use crate::mm::kstack::alloc_kstack;

// ── CLONE_* flag bits (x86-64 Linux ABI) ────────────────────────────────

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

/// clone3_args userspace structure layout (64-bit).
/// Matches Linux struct clone_args from <linux/sched.h>.
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

// ── sys_clone3 ─────────────────────────────────────────────────────────────

/// clone3(args_va, args_size) -> child_pid / -errno  [NR 435]
///
/// Parent returns child_pid > 0.
/// Child returns 0 via sysret_trampoline (rax slot zeroed in SyscallFrame).
pub fn sys_clone3(args_va: usize, _args_size: usize) -> isize {
    if args_va == 0 || args_va < 0x1000 { return -14; } // EFAULT
    let ca: &CloneArgs = unsafe { &*(args_va as *const CloneArgs) };

    let flags       = ca.flags;
    let is_vm_clone = flags & CLONE_VM != 0;

    let parent_pid  = scheduler::current_pid();
    let parent_tgid = thread::tgid_of(parent_pid);

    // Allocate a fresh kernel stack for the child
    let kstack_top = match alloc_kstack() {
        Some(k) => k,
        None    => return -12, // ENOMEM
    };

    let child_pid = scheduler::next_pid();

    // Determine child CR3 and tgid
    let (child_cr3, child_tgid) = {
        let procs   = scheduler::procs_lock();
        let par_cr3 = procs.iter().find(|p| p.pid == parent_pid)
                          .map(|p| p.user_satp).unwrap_or(0);
        scheduler::procs_unlock();
        if is_vm_clone {
            (par_cr3, parent_tgid)   // share address space
        } else {
            (par_cr3, child_pid)     // new process = own tgid
        }
    };

    // Retrieve parent RIP for the SyscallFrame return address
    let (parent_rip, parent_rflags) = {
        let procs = scheduler::procs_lock();
        let v = procs.iter().find(|p| p.pid == parent_pid)
                     .map(|p| (p.pc, 0x202usize))
                     .unwrap_or((0, 0x202));
        scheduler::procs_unlock();
        v
    };

    // User RSP: top of the stack supplied by pthread_create / clone3 caller
    let user_rsp = if ca.stack != 0 {
        (ca.stack + ca.stack_size) as usize
    } else {
        0
    };

    // Push a zeroed SyscallFrame onto the new kernel stack.
    // sysret_trampoline will pop it: rax=0 (child return), rcx=rip, r11=rflags
    push_syscall_frame(kstack_top, parent_rip, parent_rflags, user_rsp);

    // Assemble child Context
    let child_ctx = Context {
        rip:     sysret_trampoline as usize,
        rsp:     kstack_top - 17 * 8, // top of the frame we just wrote
        fs_base: if flags & CLONE_SETTLS != 0 { ca.tls as usize } else { 0 },
        ..Context::zero()
    };

    // CLONE_PARENT_SETTID: write child_pid into parent VA now
    if flags & CLONE_PARENT_SETTID != 0 && ca.parent_tid > 0x1000 {
        unsafe { (ca.parent_tid as *mut u32).write_volatile(child_pid as u32); }
    }

    // CLONE_PIDFD: allocate pidfd and write fd# into parent VA
    if flags & CLONE_PIDFD != 0 {
        let fd = crate::fs::pidfd::alloc(child_pid);
        if ca.pidfd > 0x1000 {
            unsafe { (ca.pidfd as *mut i32).write_volatile(fd as i32); }
        }
    }

    // Determine ppid for child PCB
    let child_ppid = if flags & CLONE_PARENT != 0 {
        let procs = scheduler::procs_lock();
        let v = procs.iter().find(|p| p.pid == parent_pid).map(|p| p.ppid).unwrap_or(1);
        scheduler::procs_unlock();
        v
    } else if flags & CLONE_THREAD != 0 {
        parent_tgid
    } else {
        parent_pid
    };

    // Clone parent PCB, overwrite thread-specific fields
    let child_pcb: Pcb = {
        let procs    = scheduler::procs_lock();
        let mut child = procs.iter().find(|p| p.pid == parent_pid)
                            .cloned().unwrap_or_else(make_blank_pcb);
        scheduler::procs_unlock();

        child.pid          = child_pid;
        child.ppid         = child_ppid;
        child.state        = State::Ready;
        child.exit_code    = 0;
        child.user_satp    = child_cr3;
        child.kstack_top   = kstack_top;
        child.ctx          = child_ctx;
        child.owned_pages  = Vec::new(); // thread does not own pages
        child.exit_signal  = ca.exit_signal as u32;
        child.vfork_parent = if flags & CLONE_VFORK != 0 { parent_pid } else { 0 };
        // CLONE_CHILD_SETTID
        child.child_tid_va  = if flags & CLONE_CHILD_SETTID != 0 { ca.child_tid as usize } else { 0 };
        child.child_tid_val = child_pid as u32;
        // CLONE_CHILD_CLEARTID
        child.clear_child_tid_va = if flags & CLONE_CHILD_CLEARTID != 0 { ca.child_tid as usize } else { 0 };
        child
    };

    // Register thread group membership BEFORE enqueueing
    if is_vm_clone {
        thread::register_thread(child_pid, child_tgid);
    }

    scheduler::enqueue(child_pcb);

    // CLONE_VFORK: parent blocks until child calls exec or exit
    if flags & CLONE_VFORK != 0 {
        scheduler::suspend_current_until_child_exec(child_pid);
    }

    child_pid as isize
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Push a zeroed SyscallFrame (17 usizes = 136 bytes) below kstack_top.
/// sysret_trampoline will pop this frame and SYSRETQ into user mode.
///
/// Frame layout (push order, low addr first):
///   [0]=r15 [1]=r14 [2]=r13 [3]=r12 [4]=rbp [5]=rbx
///   [6]=rax=0  (child fork/clone return value)
///   [7]=rdi [8]=rsi [9]=rdx [10]=r10 [11]=r8 [12]=r9
///   [13]=rcx=rip   (SYSRETQ reads user RIP from RCX)
///   [14]=r11=rflags (SYSRETQ reads RFLAGS from R11)
///   [15]=rsp=user_rsp
///   [16]=rip (redundant copy used by context-switch path)
fn push_syscall_frame(kstack_top: usize, rip: usize, rflags: usize, user_rsp: usize) {
    const FRAME_SZ: usize = 17 * 8;
    let base = kstack_top - FRAME_SZ;
    let p    = base as *mut usize;
    unsafe {
        p.add(0).write(0);
        p.add(1).write(0);
        p.add(2).write(0);
        p.add(3).write(0);
        p.add(4).write(0);
        p.add(5).write(0);
        p.add(6).write(0);         // rax = 0
        p.add(7).write(0);
        p.add(8).write(0);
        p.add(9).write(0);
        p.add(10).write(0);
        p.add(11).write(0);
        p.add(12).write(0);
        p.add(13).write(rip);      // rcx -> user RIP
        p.add(14).write(rflags);   // r11 -> user RFLAGS
        p.add(15).write(user_rsp); // rsp -> user stack
        p.add(16).write(rip);      // rip copy
    }
}

fn make_blank_pcb() -> Pcb {
    Pcb {
        pid: 0, ppid: 0, state: State::Ready, exit_code: 0,
        caps: crate::security::CapSet,
        pc: 0, sp: 0, user_satp: 0, kernel_satp: 0, trapframe_pa: 0,
        kstack_top: 0, ctx: Context::zero(), owned_pages: Vec::new(),
        child_tid_va: 0, child_tid_val: 0, clear_child_tid_va: 0,
        exit_signal: 17, vfork_parent: 0,
        signal_handlers: crate::proc::fork::SignalHandlers::default(),
    }
}
