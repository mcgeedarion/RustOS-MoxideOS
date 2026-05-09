//! sys_fork (NR 57) — implemented using clone_for_fork (CoW + VMA clone).

extern crate alloc;
use crate::mm::kstack::alloc_kstack;
use crate::proc::context::Context;
use crate::proc::cow_fault::clone_for_fork;
use crate::proc::process::{Pcb, State};
use crate::proc::ptrace::PtraceState;
use crate::proc::scheduler;

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::syscall::sysret_trampoline;

#[cfg(not(target_arch = "x86_64"))]
#[allow(dead_code)]
fn sysret_trampoline() {}

/// sys_fork() -> child_pid (parent) / 0 (child)  [NR 57]
///
/// The child PCB is built by cloning the full parent PCB and then patching
/// only the fields that must differ in the child.  This ensures that every
/// field added to Pcb in the future (rlimits, ns, seccomp, brk_base, …) is
/// automatically inherited without requiring a manual update here.
pub fn sys_fork() -> isize {
    let parent_pid = scheduler::current_pid();

    // Snapshot the parent's address-space fields we need before we mutate
    // anything.  The full PCB clone happens inside the scheduler lock below.
    let parent_cr3 = match scheduler::with_proc(parent_pid, |p| p.user_satp) {
        Some(cr3) if cr3 != 0 => cr3,
        _ => return -1,
    };

    let child_pid = scheduler::next_pid();
    let child_cr3 = clone_for_fork(parent_pid, child_pid, parent_cr3);

    let kstack_top = match alloc_kstack() {
        Some(k) => k,
        None => {
            if child_cr3 != 0 {
                unsafe { crate::proc::exec::free_child_address_space(child_cr3); }
            }
            return -12;
        }
    };

    // Clone the full parent PCB — every field is inherited by default.
    let mut child_pcb: Pcb = match scheduler::with_proc(parent_pid, |p| p.clone()) {
        Some(pcb) => pcb,
        None => return -1,
    };

    // Push a sysret frame so the child returns 0 from the fork syscall.
    push_syscall_frame(kstack_top, child_pcb.pc, 0x202, child_pcb.sp);

    let child_ctx = Context {
        rip: sysret_trampoline as usize,
        rsp: kstack_top - 17 * 8,
        ..Context::zero()
    };

    // ── Patch only the fields that differ in the child ────────────────────
    child_pcb.pid              = child_pid;
    child_pcb.ppid             = parent_pid;
    child_pcb.tgid             = child_pid;   // child is its own thread-group leader
    child_pcb.state            = State::Ready;
    child_pcb.exit_code        = 0;
    child_pcb.user_satp        = child_cr3;   // CoW page table copy
    child_pcb.kstack_top       = kstack_top;
    child_pcb.ctx              = child_ctx;
    // POSIX: child_tid / clear_child_tid are reset unless CLONE_CHILD_SETTID
    // is set — for plain fork() they are zeroed.
    child_pcb.child_tid_va       = 0;
    child_pcb.child_tid_val      = child_pid as u32;
    child_pcb.clear_child_tid_va = 0;
    child_pcb.exit_signal        = 17;        // SIGCHLD
    child_pcb.vfork_parent       = 0;
    child_pcb.ptrace_state       = PtraceState::None;
    child_pcb.ptrace_event       = 0;
    child_pcb.robust_list_head   = 0;
    child_pcb.robust_list_len    = 0;
    // tls_base, brk_base, brk, next_va, vmas, rlimits, ns, seccomp,
    // signal_handlers, caps, exe_path — all inherited from the parent clone.

    scheduler::enqueue(child_pcb);
    child_pid as isize
}

fn push_syscall_frame(kstack_top: usize, rip: usize, rflags: usize, user_rsp: usize) {
    const FRAME_SZ: usize = 17 * 8;
    let base = kstack_top - FRAME_SZ;
    let p    = base as *mut usize;
    unsafe {
        for i in 0..17 { p.add(i).write(0); }
        p.add(13).write(rip);
        p.add(14).write(rflags);
        p.add(15).write(user_rsp);
        p.add(16).write(rip);
    }
}
