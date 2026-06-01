//! AArch64 SVC #0 syscall entry.
//!
//! ## ABI (Linux arm64 / AAPCS64)
//!
//!   x8  — syscall number
//!   x0  — arg0 / return value
//!   x1  — arg1
//!   x2  — arg2
//!   x3  — arg3
//!   x4  — arg4
//!   x5  — arg5
//!
//! ELR_EL1 on SVC entry points at the SVC instruction itself; we advance
//! it by 4 so that eret returns to the instruction after SVC.

use super::interrupts::ExceptionFrame;
use crate::proc::scheduler;

/// Called from `aarch64_sync_handler` when ESR_EL1.EC == 0x15 (SVC64).
pub fn handle(frame: &mut ExceptionFrame) {
    let nr    = frame.x[8];
    let args  = [frame.x[0], frame.x[1], frame.x[2],
                 frame.x[3], frame.x[4], frame.x[5]];

    // Advance ELR past the SVC instruction before any possible reschedule.
    frame.elr_el1 = frame.elr_el1.wrapping_add(4);

    if nr == 139 {
        // rt_sigreturn — restore pre-signal frame in-place.
        crate::proc::signal::sys_rt_sigreturn_aarch64(frame);
        return;
    }

    // Mark CPU as inside syscall for scheduler time-accounting.
    let cpu = scheduler::current_cpu_id();
    unsafe { crate::smp::percpu::PERCPU_BLOCKS[cpu].in_syscall += 1; }

    let ret = crate::syscall::dispatch(
        nr as usize,
        args[0] as usize, args[1] as usize, args[2] as usize,
        args[3] as usize, args[4] as usize, args[5] as usize,
    );
    frame.x[0] = ret as u64;

    unsafe { crate::smp::percpu::PERCPU_BLOCKS[cpu].in_syscall -= 1; }

    // Deliver any pending signals before returning to EL0.
    crate::proc::signal::check_and_deliver_aarch64(frame);
}
