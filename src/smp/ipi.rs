//! Inter-Processor Interrupts (IPI).
//!
//! IPI vector layout (x86_64, vectors 0xF0–0xFF):
//!   0xF0 — TLB shootdown
//!   0xF1 — scheduler reschedule
//!   0xF2 — function call (deferred work)
//!   0xFE — panic halt (NMI preferred but vector fallback)
//!
//! RISC-V: uses SBI SEND_IPI (EID 0x735049) to set SIP.SSIP on the target
//! hart.  The target takes a supervisor software interrupt (scause = 1) and
//! calls `ipi::dispatch(cpu_id)` from the trap handler.
//!
//! ## IPI pending bits  (`PercpuBlock::ipi_pending`, AtomicU32)
//!   bit 0 = TlbShootdown  → handle_tlb_shootdown(cpu_id)
//!   bit 1 = Reschedule    → proc::scheduler::schedule()
//!   bit 2 = FuncCall      → (future deferred-work queue)
//!   bit 3 = PanicHalt     → halt this hart / CPU
//!
//! ## Send protocol
//!   1. Set target's `ipi_pending` bit(s) with `fetch_or(..., Release)`.
//!   2. Call `send(target_cpu, kind)` which invokes the arch-specific mechanism (x86: APIC ICR
//!      write; RISC-V: SBI SEND_IPI ecall).
//!
//! ## Receive protocol (RISC-V, trap handler scause code 1)
//!   1. Clear SIP.SSIP to acknowledge the interrupt.
//!   2. Call `ipi::dispatch(cpu_id)` — reads & clears `ipi_pending` atomically then dispatches each
//!      set bit.
//!
//! ## `schedule_on(task, cpu)` integration
//!   When the scheduler pins a task to a specific remote CPU via
//!   `schedule_on`, it calls `send_reschedule(cpu)` after enqueuing the task
//!   onto that CPU's runqueue.  The remote CPU wakes from `wfi` (or preempts
//!   its current timeslice) and calls `schedule()`, which picks up the newly
//!   enqueued task.

use crate::smp::{cpu_info, num_online_cpus, MAX_CPUS};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// IPI vector base (x86_64).
pub const IPI_TLB_SHOOTDOWN: u8 = 0xF0;
pub const IPI_RESCHEDULE: u8 = 0xF1;
pub const IPI_FUNC_CALL: u8 = 0xF2;
pub const IPI_PANIC_HALT: u8 = 0xFE;

/// Bit positions in `PercpuBlock::ipi_pending`.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum IpiKind {
    TlbShootdown = 0,
    Reschedule = 1,
    FuncCall = 2,
    PanicHalt = 3,
}

/// Per-CPU TLB shootdown request.
#[derive(Clone, Copy, Default)]
pub struct ShootdownReq {
    pub start: u64,
    pub end: u64,
    pub asid: u16,
    pub done: bool,
}

static mut SHOOTDOWN_REQS: [ShootdownReq; MAX_CPUS] = [ShootdownReq {
    start: 0,
    end: 0,
    asid: 0,
    done: false,
}; MAX_CPUS];

static SHOOTDOWN_ACK: AtomicU64 = AtomicU64::new(0);

#[inline]
fn set_pending(cpu: u32, kind: IpiKind) {
    unsafe {
        crate::smp::percpu::PERCPU_BLOCKS[cpu as usize]
            .ipi_pending
            .fetch_or(1 << (kind as u8), Ordering::Release);
    }
}

/// Send an IPI to a single target CPU.
///
/// Caller MUST have already called `set_pending` (or set the bit via
/// `fetch_or` directly) before calling this so the handler is guaranteed to
/// see the pending bit even if it runs before this function returns.
#[inline]
pub fn send(target_cpu: u32, kind: IpiKind) {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(info) = cpu_info(target_cpu) {
            let vec = match kind {
                IpiKind::TlbShootdown => IPI_TLB_SHOOTDOWN,
                IpiKind::Reschedule => IPI_RESCHEDULE,
                IpiKind::FuncCall => IPI_FUNC_CALL,
                IpiKind::PanicHalt => IPI_PANIC_HALT,
            };
            crate::arch::x86_64::apic::send_ipi(info.hw_id, vec);
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        let _ = kind;
        if let Some(info) = cpu_info(target_cpu) {
            crate::arch::riscv64::smp::send_ipi(info.hw_id as usize);
        }
    }
}

/// Set the pending bit for `kind` on `target_cpu` then fire the IPI.
/// This is the primary public send API — always use this over calling
/// `set_pending` + `send` separately unless you need a batched send.
#[inline]
pub fn send_to(target_cpu: u32, kind: IpiKind) {
    set_pending(target_cpu, kind);
    send(target_cpu, kind);
}

/// Broadcast an IPI to all CPUs except the current one.
pub fn broadcast_except_self(kind: IpiKind) {
    let me = crate::smp::percpu::current_cpu_id();
    for cpu in 0..num_online_cpus() {
        if cpu != me {
            send_to(cpu, kind);
        }
    }
}

/// Send a reschedule IPI to `target_cpu` (no-op if target == self).
/// This is what `enqueue_task` and `schedule_on` call after pushing a
/// task onto a remote CPU's runqueue.
#[inline]
pub fn send_reschedule(target_cpu: u32) {
    let me = crate::smp::percpu::current_cpu_id();
    if target_cpu != me {
        send_to(target_cpu, IpiKind::Reschedule);
    }
}

/// Alias kept for backwards compatibility with `smp::ipi::reschedule`.
#[inline]
pub fn reschedule(target_cpu: u32) {
    send_reschedule(target_cpu);
}

/// Called from the supervisor software interrupt handler (RISC-V scause = 1)
/// after SIP.SSIP has been cleared.  Atomically drains all pending IPI bits
/// and dispatches each one.
pub fn dispatch(cpu_id: u32) {
    let blk = unsafe { &crate::smp::percpu::PERCPU_BLOCKS[cpu_id as usize] };
    let pending = blk.ipi_pending.swap(0, Ordering::AcqRel);
    if pending == 0 {
        return;
    } // spurious SSIP

    if pending & (1 << IpiKind::TlbShootdown as u8) != 0 {
        handle_tlb_shootdown(cpu_id);
    }
    if pending & (1 << IpiKind::Reschedule as u8) != 0 {
        crate::proc::scheduler::schedule();
    }
    if pending & (1 << IpiKind::FuncCall as u8) != 0 {
        // Future: drain per-CPU deferred-work ring.
    }
    if pending & (1 << IpiKind::PanicHalt as u8) != 0 {
        crate::println!("smp: cpu {} halted by IPI_PANIC_HALT", cpu_id);
        loop {
            #[cfg(target_arch = "riscv64")]
            unsafe {
                core::arch::asm!("wfi", options(nostack, nomem));
            }
            #[cfg(target_arch = "x86_64")]
            unsafe {
                core::arch::asm!("hlt", options(nostack, nomem));
            }
        }
    }
}

/// Flush `[start, end)` on all CPUs that may have `asid` mapped.
/// Blocks until all CPUs acknowledge via `SHOOTDOWN_ACK`.
pub fn tlb_shootdown(start: u64, end: u64, asid: u16) {
    let me = crate::smp::percpu::current_cpu_id();
    let n = num_online_cpus();
    if n <= 1 {
        return;
    }

    let mut ack_mask: u64 = 0;
    for cpu in 0..n {
        if cpu != me {
            ack_mask |= 1u64 << cpu;
            unsafe {
                SHOOTDOWN_REQS[cpu as usize] = ShootdownReq {
                    start,
                    end,
                    asid,
                    done: false,
                };
            }
        }
    }
    SHOOTDOWN_ACK.store(ack_mask, Ordering::Release);
    broadcast_except_self(IpiKind::TlbShootdown);
    local_tlb_flush(start, end);
    while SHOOTDOWN_ACK.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
}

/// Called from `dispatch` on the recipient CPU.
pub fn handle_tlb_shootdown(cpu_id: u32) {
    let req = unsafe { &mut SHOOTDOWN_REQS[cpu_id as usize] };
    local_tlb_flush(req.start, req.end);
    req.done = true;
    SHOOTDOWN_ACK.fetch_and(!(1u64 << cpu_id), Ordering::Release);
}

#[inline]
fn local_tlb_flush(start: u64, end: u64) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let mut va = start & !0xFFF;
        while va < end {
            core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
            va += 0x1000;
        }
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("sfence.vma", options(nostack));
    }
}

/// Halt all other CPUs (used by panic handler).
pub fn halt_all_except_self() {
    broadcast_except_self(IpiKind::PanicHalt);
}

// ===== GUESS: APIC vector constants for kernel timer/IPI integration =====
/// GUESS: LAPIC timer vector — chosen to avoid CPU exceptions (<32) and IPI
/// range (0xF0-0xFE). Real value depends on IDT layout; pick 0x40.
pub const APIC_TIMER_VECTOR: u8 = 0x40;
