//! RISC-V supervisor-mode trap handler.
//!
//! ## Entry stub
//!   `riscv_trap_entry` saves all 32 GPRs + sepc + sstatus onto the kernel
//!   stack (272 bytes = 34 × 8), passes a `*mut TrapFrame` as `a0`, and calls
//!   `riscv_trap_handler`. On return it restores everything and `sret`s.
//!
//! ## trap_return (new-task / exec first entry)
//!   A `.global trap_return` label is embedded in `riscv_trap_entry` just
//!   before the restore sequence.  `task_entry_trampoline` (context.rs)
//!   jumps here so new tasks enter userspace through the same path.
//!
//! ## Signal delivery hook
//!   After every ecall (scause = 8) the handler calls
//!   `signal::check_and_deliver(frame)` so that pending signals are delivered
//!   before the task returns to userspace.

use crate::arch::riscv64::csr::*;
use crate::arch::riscv64::mem_layout::{scause as SC, sie as SIE, sstatus as SS, trap as TF};
use crate::mm::mmap::{VmaKind, PROT_EXEC, PROT_READ, PROT_WRITE};
use core::arch::asm;

/// Trap frame saved by `riscv_trap_entry` (34 × 8 = 272 bytes).
///
/// Field order matches the `sd` / `ld` offsets in the naked entry stub.
/// index  0: ra      index  1: sp     index  2: gp     index  3: tp
/// index  4: t0      index  5: t1     index  6: t2
/// index  7: s0      index  8: s1
/// index  9: a0 … index 16: a7
/// index 17: s2 … index 26: s11
/// index 27: t3 … index 30: t6
/// index 31: sepc    index 32: sstatus
/// index 33: (pad)
#[repr(C)]
pub struct TrapFrame {
    pub ra: usize,
    pub sp: usize,
    pub gp: usize,
    pub tp: usize,
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub s0: usize,
    pub s1: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    pub sepc: usize,
    pub sstatus: usize,
}

pub const TRAP_FRAME_SIZE: usize = TF::FRAME_SIZE;

// Re-export for consumers that use these directly.
pub use crate::arch::riscv64::mem_layout::sstatus::SPIE as SSTATUS_SPIE;
pub use crate::arch::riscv64::mem_layout::sstatus::SPP as SSTATUS_SPP;

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn riscv_trap_entry() {
    asm!(
        "addi sp, sp, -{frame_size}",
        "sd   ra,  0*8(sp)",
        "sd   gp,  2*8(sp)",
        "sd   tp,  3*8(sp)",
        "sd   t0,  4*8(sp)",
        "sd   t1,  5*8(sp)",
        "sd   t2,  6*8(sp)",
        "sd   s0,  7*8(sp)",
        "sd   s1,  8*8(sp)",
        "sd   a0,  9*8(sp)",
        "sd   a1, 10*8(sp)",
        "sd   a2, 11*8(sp)",
        "sd   a3, 12*8(sp)",
        "sd   a4, 13*8(sp)",
        "sd   a5, 14*8(sp)",
        "sd   a6, 15*8(sp)",
        "sd   a7, 16*8(sp)",
        "sd   s2, 17*8(sp)",
        "sd   s3, 18*8(sp)",
        "sd   s4, 19*8(sp)",
        "sd   s5, 20*8(sp)",
        "sd   s6, 21*8(sp)",
        "sd   s7, 22*8(sp)",
        "sd   s8, 23*8(sp)",
        "sd   s9, 24*8(sp)",
        "sd   s10,25*8(sp)",
        "sd   s11,26*8(sp)",
        "sd   t3, 27*8(sp)",
        "sd   t4, 28*8(sp)",
        "sd   t5, 29*8(sp)",
        "sd   t6, 30*8(sp)",
        "addi t0, sp, {frame_size}",
        "sd   t0, 1*8(sp)",
        "csrr t0, sepc",
        "sd   t0, 31*8(sp)",
        "csrr t0, sstatus",
        "sd   t0, 32*8(sp)",
        "mv   a0, sp",
        "call {handler}",
        ".global trap_return",
        "trap_return:",
        "ld   t0, 31*8(sp)",
        "csrw sepc, t0",
        "ld   t0, 32*8(sp)",
        "csrw sstatus, t0",
        "ld   ra,  0*8(sp)",
        "ld   gp,  2*8(sp)",
        "ld   tp,  3*8(sp)",
        "ld   t0,  4*8(sp)",
        "ld   t1,  5*8(sp)",
        "ld   t2,  6*8(sp)",
        "ld   s0,  7*8(sp)",
        "ld   s1,  8*8(sp)",
        "ld   a0,  9*8(sp)",
        "ld   a1, 10*8(sp)",
        "ld   a2, 11*8(sp)",
        "ld   a3, 12*8(sp)",
        "ld   a4, 13*8(sp)",
        "ld   a5, 14*8(sp)",
        "ld   a6, 15*8(sp)",
        "ld   a7, 16*8(sp)",
        "ld   s2, 17*8(sp)",
        "ld   s3, 18*8(sp)",
        "ld   s4, 19*8(sp)",
        "ld   s5, 20*8(sp)",
        "ld   s6, 21*8(sp)",
        "ld   s7, 22*8(sp)",
        "ld   s8, 23*8(sp)",
        "ld   s9, 24*8(sp)",
        "ld   s10,25*8(sp)",
        "ld   s11,26*8(sp)",
        "ld   t3, 27*8(sp)",
        "ld   t4, 28*8(sp)",
        "ld   t5, 29*8(sp)",
        "ld   t6, 30*8(sp)",
        "ld   sp,  1*8(sp)",
        "sret",
        frame_size = const TF::FRAME_SIZE,
        handler    = sym riscv_trap_handler,
        options(noreturn)
    );
}

#[no_mangle]
pub extern "C" fn riscv_trap_handler(frame: &mut TrapFrame) {
    let scause = get_scause();
    let is_intr = scause & SC::INTERRUPT_BIT != 0;
    let code = scause & !SC::INTERRUPT_BIT;
    if is_intr {
        handle_interrupt(frame, code);
    } else {
        handle_exception(frame, code);
    }
}

fn handle_interrupt(frame: &mut TrapFrame, code: usize) {
    match code {
        SC::INT_S_SOFTWARE => {
            unsafe {
                asm!("csrci sip, 2", options(nostack, nomem));
            }
            let cpu_id = crate::smp::percpu::current_cpu_id();
            crate::smp::ipi::dispatch(cpu_id);
            crate::proc::signal::check_and_deliver(frame);
        },
        SC::INT_S_TIMER => {
            let sie = csrr!("sie");
            csrw!("sie", sie & !SIE::STIE);
            crate::time::tick_advance(crate::proc::scheduler::TICK_NS);
            crate::time::timer::expire_timers();
            crate::proc::scheduler::schedule();
            crate::arch::riscv64::clint::set_next_event(0, crate::proc::scheduler::TICK_NS);
            let sie2 = csrr!("sie");
            csrw!("sie", sie2 | SIE::STIE);
            crate::proc::signal::check_and_deliver(frame);
        },
        SC::INT_S_EXTERNAL => {
            crate::drivers::plic::handle_irq();
        },
        _ => {},
    }
}

fn handle_exception(frame: &mut TrapFrame, code: usize) {
    match code {
        SC::EXC_BREAKPOINT => {
            #[cfg(feature = "gdbstub")]
            {
                let pid = crate::proc::scheduler::current_pid();
                unsafe {
                    crate::gdbstub::gdb_trap_rv(
                        frame as *mut TrapFrame as *mut crate::gdbstub::RvSavedRegs,
                        pid as u32,
                    );
                }
                return;
            }
            #[cfg(not(feature = "gdbstub"))]
            {
                let pid = crate::proc::scheduler::current_pid();
                crate::proc::signal::send_signal(pid as usize, 5); // SIGTRAP
                crate::proc::signal::check_and_deliver(frame);
            }
        },

        SC::EXC_ECALL_U => {
            let nr = frame.a7;
            if nr == 139 {
                frame.sepc = frame.sepc.wrapping_add(TF::INSN_SIZE);
                crate::proc::signal::sys_rt_sigreturn(frame);
                return;
            }
            let ret = crate::syscall::dispatch(
                nr, frame.a0, frame.a1, frame.a2, frame.a3, frame.a4, frame.a5,
            );
            frame.a0 = ret as usize;
            frame.sepc = frame.sepc.wrapping_add(TF::INSN_SIZE);
            crate::proc::signal::check_and_deliver(frame);
        },

        SC::EXC_INSN_PAGE_FAULT | SC::EXC_LOAD_PAGE_FAULT | SC::EXC_STORE_PAGE_FAULT => {
            let stval = csrr!("stval");
            let faulting_va = stval & !crate::arch::riscv64::mem_layout::page::MASK;
            let pid = crate::proc::scheduler::current_pid();
            if let Some(vma) = crate::mm::mmap::find_vma(pid, stval) {
                if code == SC::EXC_STORE_PAGE_FAULT && vma.prot & PROT_WRITE == 0 {
                    crate::proc::signal::send_sigsegv(pid as usize, stval);
                    crate::proc::signal::check_and_deliver(frame);
                    return;
                }
                if code == SC::EXC_INSN_PAGE_FAULT && vma.prot & PROT_EXEC == 0 {
                    crate::proc::signal::send_sigsegv(pid as usize, stval);
                    crate::proc::signal::check_and_deliver(frame);
                    return;
                }
                let pa = match crate::mm::pmm::alloc_page() {
                    Some(pa) => pa,
                    None => {
                        crate::proc::signal::send_sigsegv(pid as usize, stval);
                        crate::proc::signal::check_and_deliver(frame);
                        return;
                    },
                };
                unsafe {
                    core::ptr::write_bytes(
                        pa as *mut u8,
                        0,
                        crate::arch::riscv64::mem_layout::page::SIZE,
                    );
                }
                use crate::arch::riscv64::mem_layout::sv39;
                let mut pte_bits: u64 = sv39::PTE_V as u64 | sv39::PTE_U as u64;
                if vma.prot & PROT_READ != 0 {
                    pte_bits |= sv39::PTE_R as u64;
                }
                if vma.prot & PROT_WRITE != 0 {
                    pte_bits |= sv39::PTE_W as u64;
                }
                if vma.prot & PROT_EXEC != 0 {
                    pte_bits |= sv39::PTE_X as u64;
                }
                if pte_bits & 0b1110 == 0 {
                    pte_bits |= sv39::PTE_R as u64;
                }
                riscv_map_page(faulting_va, pa, pte_bits);
                unsafe {
                    asm!("sfence.vma {va}, zero", va = in(reg) faulting_va);
                }
                return;
            }
            crate::proc::signal::send_sigsegv(pid as usize, stval);
            crate::proc::signal::check_and_deliver(frame);
        },

        SC::EXC_ILLEGAL_INSN => {
            let pid = crate::proc::scheduler::current_pid();
            crate::proc::signal::send_signal(pid as usize, 4); // SIGILL
            crate::proc::signal::check_and_deliver(frame);
        },

        _ => {
            let pid = crate::proc::scheduler::current_pid();
            crate::proc::signal::send_signal(pid as usize, 11); // SIGSEGV
            crate::proc::signal::check_and_deliver(frame);
        },
    }
}

pub fn trap_init() {
    set_stvec(riscv_trap_entry as usize);
    let sie = csrr!("sie");
    csrw!("sie", sie | SIE::ALL);
    let sstatus = csrr!("sstatus");
    csrw!("sstatus", sstatus | SS::SIE);
}

#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn sret_trampoline() -> ! {
    asm!(
        "csrw sepc, a0",
        "mv   sp, a1",
        "li   t0, 0x120", // SPP | SPIE
        "csrc sstatus, t0",
        "li   t0, 0x20", // SPIE
        "csrs sstatus, t0",
        "sret",
        options(noreturn)
    );
}

fn riscv_map_page(va: usize, pa: usize, pte_bits: u64) {
    use crate::arch::riscv64::mem_layout::{page as P, sv39 as SV};
    let satp = get_satp();
    let root = (satp & SV::SATP_PPN_MASK) << P::SHIFT;
    let vpn = [SV::vpn0(va), SV::vpn1(va), SV::vpn2(va)];
    let ppn = (pa >> P::SHIFT) as u64;
    unsafe {
        let mut pt = root as *mut u64;
        for level in (1..=2).rev() {
            let pte_ptr = pt.add(vpn[level]);
            let pte = core::ptr::read_volatile(pte_ptr);
            if pte & 1 == 0 {
                let next_pa = crate::mm::pmm::alloc_page()
                    .expect("OOM while walking page table in trap handler");
                core::ptr::write_bytes(next_pa as *mut u8, 0, P::SIZE);
                core::ptr::write_volatile(
                    pte_ptr,
                    ((next_pa as u64 >> P::SHIFT) << SV::PPN_SHIFT as u64) | SV::PTE_V as u64,
                );
                pt = next_pa as *mut u64;
            } else {
                pt = (((pte >> SV::PPN_SHIFT as u64) << P::SHIFT as u64) as usize) as *mut u64;
            }
        }
        let leaf = pt.add(vpn[0]);
        core::ptr::write_volatile(leaf, (ppn << SV::PPN_SHIFT as u64) | pte_bits);
    }
}
