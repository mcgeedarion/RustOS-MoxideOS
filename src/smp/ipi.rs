//! Inter-Processor Interrupts (IPI).
//!
//! IPI vector layout (x86_64, vectors 0xF0–0xFF):
//!   0xF0 — TLB shootdown
//!   0xF1 — scheduler reschedule
//!   0xF2 — function call (deferred work)
//!   0xFE — panic halt (NMI preferred but vector fallback)
//!
//! RISC-V: uses CLINT software-interrupt (SIP.SSIP).

use core::sync::atomic::{AtomicU64, Ordering};
use crate::smp::{MAX_CPUS, num_online_cpus, cpu_info};

/// IPI vector base (x86_64).
pub const IPI_TLB_SHOOTDOWN: u8 = 0xF0;
pub const IPI_RESCHEDULE:    u8 = 0xF1;
pub const IPI_FUNC_CALL:     u8 = 0xF2;
pub const IPI_PANIC_HALT:    u8 = 0xFE;

/// Bit positions in `PercpuBlock::ipi_pending`.
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub enum IpiKind {
    TlbShootdown = 0,
    Reschedule   = 1,
    FuncCall     = 2,
    PanicHalt    = 3,
}

/// Per-CPU TLB shootdown request: the VA range to flush.
/// Using a global array indexed by cpu_id — only one outstanding shootdown
/// per CPU at a time (BSP serialises them via `SHOOTDOWN_LOCK`).
#[derive(Clone, Copy, Default)]
pub struct ShootdownReq {
    pub start: u64,
    pub end:   u64,
    pub asid:  u16,   // 0 = all address spaces
    pub done:  bool,
}

static mut SHOOTDOWN_REQS: [ShootdownReq; MAX_CPUS] = [ShootdownReq {
    start: 0, end: 0, asid: 0, done: false,
}; MAX_CPUS];

/// Bitmask of CPUs that still haven't acknowledged the current shootdown.
static SHOOTDOWN_ACK: AtomicU64 = AtomicU64::new(0);

/// Send an IPI to a single target CPU.
#[inline]
pub fn send(target_cpu: u32, kind: IpiKind) {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(info) = cpu_info(target_cpu) {
            let vec = match kind {
                IpiKind::TlbShootdown => IPI_TLB_SHOOTDOWN,
                IpiKind::Reschedule   => IPI_RESCHEDULE,
                IpiKind::FuncCall     => IPI_FUNC_CALL,
                IpiKind::PanicHalt    => IPI_PANIC_HALT,
            };
            crate::arch::x86_64::apic::send_ipi(info.hw_id, vec);
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        if let Some(info) = cpu_info(target_cpu) {
            crate::arch::riscv64::smp::send_ipi(info.hw_id);
            // The kind is communicated via `ipi_pending` bits already set.
        }
        let _ = kind;
    }
}

/// Broadcast an IPI to all CPUs except the current one.
pub fn broadcast_except_self(kind: IpiKind) {
    let me = crate::smp::percpu::current_cpu_id();
    for cpu in 0..num_online_cpus() {
        if cpu != me {
            // Mark pending bit so the handler knows what to do.
            if let Some(info) = cpu_info(cpu) {
                unsafe {
                    let blk_ptr = &crate::smp::percpu::PERCPU_BLOCKS[cpu as usize];
                    blk_ptr.ipi_pending.fetch_or(1 << (kind as u8), Ordering::Release);
                }
            }
            send(cpu, kind);
        }
    }
}

/// Flush `[start, end)` on all CPUs that have `asid` mapped.
/// Blocks until all CPUs acknowledge.
pub fn tlb_shootdown(start: u64, end: u64, asid: u16) {
    let me = crate::smp::percpu::current_cpu_id();
    let n = num_online_cpus();
    if n <= 1 { return; }

    // Build ack mask (all CPUs except self).
    let mut ack_mask: u64 = 0;
    for cpu in 0..n {
        if cpu != me {
            ack_mask |= 1u64 << cpu;
            unsafe {
                SHOOTDOWN_REQS[cpu as usize] = ShootdownReq {
                    start, end, asid, done: false,
                };
            }
        }
    }
    SHOOTDOWN_ACK.store(ack_mask, Ordering::Release);

    broadcast_except_self(IpiKind::TlbShootdown);

    // Flush our own TLB range first.
    local_tlb_flush(start, end);

    // Spin until all remote CPUs acknowledge.
    while SHOOTDOWN_ACK.load(Ordering::Acquire) != 0 {
        core::hint::spin_loop();
    }
}

/// Called from the TLB-shootdown IPI handler on each AP.
pub fn handle_tlb_shootdown(cpu_id: u32) {
    let req = unsafe { &mut SHOOTDOWN_REQS[cpu_id as usize] };
    local_tlb_flush(req.start, req.end);
    req.done = true;
    // Clear our bit in the ack mask.
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
        // sfence.vma flushes the entire TLB; range flush is optional.
        core::arch::asm!("sfence.vma", options(nostack));
    }
}

/// Send a reschedule IPI to `target_cpu` (no-op if target == self).
#[inline]
pub fn reschedule(target_cpu: u32) {
    let me = crate::smp::percpu::current_cpu_id();
    if target_cpu != me {
        send(target_cpu, IpiKind::Reschedule);
    }
}

/// Halt all other CPUs (used by panic handler).
pub fn halt_all_except_self() {
    broadcast_except_self(IpiKind::PanicHalt);
}
