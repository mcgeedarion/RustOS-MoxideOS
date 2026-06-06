//! sys_fork (NR 57) — implemented using clone_for_fork (CoW + VMA clone).
//!
//! ## Arch-specific first-entry paths
//!
//! Identical to clone.rs:
//!   - x86_64: `push_syscall_frame` + `rip = sysret_trampoline`
//!   - RISC-V: `push_trap_frame_riscv` + `ra = task_entry_trampoline`
//!
//! ## Bug fixes (carried forward)
//!
//! ### push_syscall_frame: CS and RSP slots were wrong (x86_64)
//!   [14]=cs (USER_CS=0x23), [15]=rflags, [16]=rsp.
//!   Old: [14]=rflags, [15]=rsp, [16]=rip — caused #GP on first user return.

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

const USER_CS: usize = 0x23;

/// sys_fork() -> child_pid (parent) / 0 (child)  [NR 57]
pub fn sys_fork() -> isize {
    let parent_pid = scheduler::current_pid();

    // RLIMIT_NPROC check.
    {
        use crate::proc::rlimit::{RLIMIT_NPROC, RLIM_INFINITY};
        let (soft, _hard) = crate::proc::rlimit::getrlimit_for(parent_pid, RLIMIT_NPROC);
        if soft != RLIM_INFINITY {
            let count = scheduler::proc_count() as u64;
            if count >= soft {
                return -11;
            }
        }
    }

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
                unsafe {
                    crate::proc::exec::free_child_address_space(child_cr3);
                }
            }
            return -12;
        },
    };

    let mut child_pcb: Pcb = match scheduler::with_proc(parent_pid, |p| p.clone()) {
        Some(pcb) => pcb,
        None => return -1,
    };

    #[cfg(target_arch = "x86_64")]
    let child_ctx = {
        push_syscall_frame(kstack_top, child_pcb.pc, 0x202, child_pcb.sp);
        Context {
            rip: sysret_trampoline as usize,
            rsp: kstack_top - 17 * 8,
            ..Context::zero()
        }
    };

    #[cfg(target_arch = "riscv64")]
    let child_ctx = {
        // For fork the child resumes at the same PC/SP as the parent
        // (CoW address space copy ensures they have independent pages).
        push_trap_frame_riscv(kstack_top, child_pcb.pc, child_pcb.sp, child_pcb.tls_base);
        let frame_sp = kstack_top - crate::arch::riscv64::trap::TRAP_FRAME_SIZE;
        Context {
            ra: crate::proc::context::task_entry_trampoline as usize,
            sp: frame_sp,
            s0: 0,
            ..Context::zero()
        }
    };

    child_pcb.pid = child_pid;
    child_pcb.ppid = parent_pid;
    child_pcb.tgid = child_pid;
    child_pcb.pgid = scheduler::with_proc(parent_pid, |p| p.pgid).unwrap_or(child_pid);
    child_pcb.state = State::Ready;
    child_pcb.exit_code = 0;
    child_pcb.user_satp = child_cr3;
    child_pcb.kstack_top = kstack_top;
    child_pcb.ctx = child_ctx;
    child_pcb.child_tid_va = 0;
    child_pcb.child_tid_val = child_pid as u32;
    child_pcb.clear_child_tid_va = 0;
    child_pcb.exit_signal = 17;
    child_pcb.vfork_parent = 0;
    child_pcb.ptrace_state = PtraceState::None;
    child_pcb.ptrace_event = 0;
    child_pcb.robust_list_head = 0;
    child_pcb.robust_list_len = 0;
    child_pcb.cpu_time_ns = 0;
    child_pcb.rt_cpu_time_us = 0;

    // Enqueue PCB into global table first, then enqueue the Task on the
    // least-loaded CPU runqueue.  Fork children always go through
    // enqueue_task (load-balanced) since they have a private address space
    // and there's no TLB-warmth reason to pin them to the parent's CPU.
    scheduler::enqueue(child_pcb);
    let task_ptr = scheduler::task_ptr_for_pid(child_pid);
    if !task_ptr.is_null() {
        scheduler::enqueue_task(task_ptr);
    }

    crate::fs::process_fd::proc_fd_fork(parent_pid, child_pid);
    child_pid as isize
}

#[cfg(target_arch = "x86_64")]
fn push_syscall_frame(kstack_top: usize, rip: usize, rflags: usize, user_rsp: usize) {
    const FRAME_SZ: usize = 17 * 8;
    let base = kstack_top - FRAME_SZ;
    let p = base as *mut usize;
    unsafe {
        for i in 0..17 {
            p.add(i).write(0);
        }
        p.add(13).write(rip); // RIP
        p.add(14).write(USER_CS); // CS
        p.add(15).write(rflags); // RFLAGS
        p.add(16).write(user_rsp); // RSP
    }
}

/// RISC-V: build a `TrapFrame` at `kstack_top - TRAP_FRAME_SIZE`.
///
/// For fork the child resumes at the parent's PC (CoW pages are independent
/// so the same virtual address is safe in both address spaces).  `a0 = 0`
/// so the child sees a return value of 0 from the `ecall`, matching Linux
/// semantics.
#[cfg(target_arch = "riscv64")]
fn push_trap_frame_riscv(kstack_top: usize, entry_pc: usize, user_sp: usize, tls: usize) {
    use crate::arch::riscv64::trap::{TrapFrame, SSTATUS_SPIE, SSTATUS_SPP, TRAP_FRAME_SIZE};
    let frame_va = kstack_top - TRAP_FRAME_SIZE;
    unsafe {
        core::ptr::write_bytes(frame_va as *mut u8, 0, TRAP_FRAME_SIZE);
        let f = frame_va as *mut TrapFrame;
        (*f).sp = user_sp;
        (*f).tp = tls;
        (*f).a0 = 0; // child return value = 0
        (*f).sepc = entry_pc;
        (*f).sstatus = SSTATUS_SPIE & !SSTATUS_SPP;
    }
}
