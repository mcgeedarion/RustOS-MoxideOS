//! RISC-V supervisor-mode trap handler.
//!
//! ## Entry stub
//!   `riscv_trap_entry` is a naked function placed in `.text` that:
//!     1. Saves all 32 GPRs + sepc + sstatus onto the kernel stack.
//!     2. Passes a pointer to that frame as the first argument.
//!     3. Calls `riscv_trap_handler`.
//!     4. Restores registers and executes `sret`.
//!
//! ## Trap sources
//!   Exceptions (scause MSB = 0):
//!     0  Instruction address misaligned
//!     2  Illegal instruction
//!     5  Load access fault
//!     7  Store/AMO access fault
//!     8  Environment call from U-mode (ecall → syscall)
//!     12 Instruction page fault
//!     13 Load page fault
//!     15 Store page fault
//!
//!   Interrupts (scause MSB = 1):
//!     1  Supervisor software interrupt
//!     5  Supervisor timer interrupt
//!     9  Supervisor external interrupt → PLIC claim/complete loop
//!
//! ## Syscall ABI (RISC-V Linux)
//!   a7 = syscall number
//!   a0..a5 = arguments
//!   a0 = return value
//!
//! ## Timer tick (scause = 0x8000_0000_0000_0005)
//!
//!   Every supervisor timer interrupt:
//!     1. `time::tick_advance(TICK_NS)` — advance the monotonic clock.
//!     2. `time::timer::expire_timers()` — fire due wheel entries (nanosleep
//!        wakeups, ITIMER_REAL, timerfd callbacks, …).
//!     3. `proc::scheduler::schedule()` — context switch if needed.
//!     4. `clint::set_next_event(hart, TICK_NS)` — re-arm mtimecmp so the
//!        next tick fires TICK_NS nanoseconds from now.
//!     5. Re-enable STIE in `sie`.
//!
//! ## Anonymous mmap page-fault flow (demand paging)
//!
//! When user-space touches a page inside a VmaKind::Anonymous (or Heap/Stack)
//! region that has no PTE yet, scause = 13 (load) or 15 (store).
//!
//!   1. stval = faulting VA (not necessarily page-aligned).
//!   2. `find_vma` looks up the VMA containing that address.
//!   3. Allocate a fresh zeroed page from PMM.
//!   4. Map it into the current Sv39 address space with PTE bits derived
//!      from the VMA’s `prot` field (R/W/X + U, never more than prot allows).
//!   5. Issue `sfence.vma` to flush the TLB for that VA.
//!   6. Return — `sret` replays the faulting instruction.
//!
//! File-backed VMAs (VmaKind::FileBacked) are not yet demand-paged from disk;
//! they zero-fill for now (TODO: call vfs::pread into the new page).

use core::arch::asm;
use crate::arch::riscv64::csr::*;
use crate::mm::mmap::{VmaKind, PROT_READ, PROT_WRITE, PROT_EXEC};

/// Trap frame saved by `riscv_trap_entry`.
/// Layout must exactly match the store order in the entry asm.
#[repr(C)]
pub struct TrapFrame {
    pub ra: usize,  pub sp:  usize, pub gp:  usize, pub tp:  usize,
    pub t0: usize,  pub t1:  usize, pub t2:  usize,
    pub s0: usize,  pub s1:  usize,
    pub a0: usize,  pub a1:  usize, pub a2:  usize, pub a3:  usize,
    pub a4: usize,  pub a5:  usize, pub a6:  usize, pub a7:  usize,
    pub s2: usize,  pub s3:  usize, pub s4:  usize, pub s5:  usize,
    pub s6: usize,  pub s7:  usize, pub s8:  usize, pub s9:  usize,
    pub s10: usize, pub s11: usize,
    pub t3: usize,  pub t4:  usize, pub t5:  usize, pub t6:  usize,
    pub sepc:    usize,
    pub sstatus: usize,
}

const TRAP_FRAME_SIZE: usize = 34 * 8;

#[naked]
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
        frame_size = const TRAP_FRAME_SIZE,
        handler    = sym riscv_trap_handler,
        options(noreturn)
    );
}

#[no_mangle]
pub extern "C" fn riscv_trap_handler(frame: &mut TrapFrame) {
    let scause  = get_scause();
    let is_intr = scause >> 63 != 0;
    let code    = scause & !(1usize << 63);
    if is_intr { handle_interrupt(frame, code); }
    else       { handle_exception(frame, code); }
}

fn handle_interrupt(_frame: &mut TrapFrame, code: usize) {
    match code {
        // ────────────────────────────────────────────────────────────────
        // Supervisor timer interrupt (code 5).
        // ────────────────────────────────────────────────────────────────
        5 => {
            let sie = csrr!("sie");
            csrw!("sie", sie & !(1usize << 5));
            crate::time::tick_advance(crate::proc::scheduler::TICK_NS);
            crate::time::timer::expire_timers();
            crate::proc::scheduler::schedule();
            crate::arch::riscv64::clint::set_next_event(
                0, crate::proc::scheduler::TICK_NS,
            );
            let sie2 = csrr!("sie");
            csrw!("sie", sie2 | (1usize << 5));
        }

        // ────────────────────────────────────────────────────────────────
        // Supervisor external interrupt (code 9) — PLIC.
        //
        // The PLIC's claim/complete loop in plic::handle_irq():
        //   1. Reads the claim register — gets the highest-priority pending IRQ.
        //   2. Looks up and calls the registered handler (e.g.
        //      virtio_net_mmio::virtio_net_mmio_irq).
        //   3. Writes the IRQ back to the complete register.
        //   4. Loops until claim returns 0 (no more pending).
        // ────────────────────────────────────────────────────────────────
        9 => { crate::drivers::plic::handle_irq(); }

        _ => {}
    }
}

fn handle_exception(frame: &mut TrapFrame, code: usize) {
    match code {
        8 => {
            let nr = frame.a7;
            let ret = crate::syscall::dispatch(
                nr, frame.a0, frame.a1, frame.a2, frame.a3, frame.a4, frame.a5,
            );
            frame.a0   = ret as usize;
            frame.sepc = frame.sepc.wrapping_add(4);
        }

        12 | 13 | 15 => {
            let stval      = csrr!("stval");
            let faulting_va = stval & !0xFFF;
            let pid        = crate::proc::scheduler::current_pid();

            if let Some(vma) = crate::mm::mmap::find_vma(pid, stval) {
                if code == 15 && vma.prot & PROT_WRITE == 0 {
                    crate::proc::signal::send_sigsegv(pid, stval); return;
                }
                if code == 12 && vma.prot & PROT_EXEC == 0 {
                    crate::proc::signal::send_sigsegv(pid, stval); return;
                }
                let pa = match crate::mm::pmm::alloc_page() {
                    Some(pa) => pa,
                    None => { crate::proc::signal::send_sigsegv(pid, stval); return; }
                };
                unsafe { core::ptr::write_bytes(pa as *mut u8, 0, 4096); }
                let mut pte_bits: u64 = (1 << 0) | (1 << 4);
                if vma.prot & PROT_READ  != 0 { pte_bits |= 1 << 1; }
                if vma.prot & PROT_WRITE != 0 { pte_bits |= 1 << 2; }
                if vma.prot & PROT_EXEC  != 0 { pte_bits |= 1 << 3; }
                if pte_bits & 0b1110 == 0      { pte_bits |= 1 << 1; }
                riscv_map_page(faulting_va, pa, pte_bits);
                unsafe { asm!("sfence.vma {va}, zero", va = in(reg) faulting_va); }
                return;
            }
            crate::proc::signal::send_sigsegv(pid, stval);
        }

        2 => {
            let pid = crate::proc::scheduler::current_pid();
            crate::proc::signal::send_signal(pid, 4);
        }
        _ => {
            let pid = crate::proc::scheduler::current_pid();
            crate::proc::signal::send_signal(pid, 11);
        }
    }
}

pub fn trap_init() {
    set_stvec(riscv_trap_entry as usize);
    // Enable SSIE (software), STIE (timer), SEIE (external/PLIC).
    let sie = csrr!("sie");
    csrw!("sie", sie | (1 << 1) | (1 << 5) | (1 << 9));
    // Enable supervisor-mode interrupts globally (sstatus.SIE = 1).
    let sstatus = csrr!("sstatus");
    csrw!("sstatus", sstatus | (1 << 1));
}

// ── sret trampoline ──────────────────────────────────────────────────────────────────

#[naked]
#[no_mangle]
pub unsafe extern "C" fn sret_trampoline() -> ! {
    asm!(
        "csrw sepc, a0",
        "mv   sp, a1",
        "li   t0, 0x120",
        "csrc sstatus, t0",
        "li   t0, 0x20",
        "csrs sstatus, t0",
        "sret",
        options(noreturn)
    );
}

// ── Sv39 page-mapping helper ───────────────────────────────────────────────────────────

fn riscv_map_page(va: usize, pa: usize, pte_bits: u64) {
    let satp  = get_satp();
    let root  = (satp & 0x0FFF_FFFF_FFFF) << 12;
    let vpn   = [(va >> 12) & 0x1FF, (va >> 21) & 0x1FF, (va >> 30) & 0x1FF];
    let ppn   = (pa >> 12) as u64;
    unsafe {
        let mut pt = root as *mut u64;
        for level in (1..=2).rev() {
            let pte_ptr = pt.add(vpn[level]);
            let pte = core::ptr::read_volatile(pte_ptr);
            if pte & 1 == 0 {
                let next_pa = crate::mm::pmm::alloc_page()
                    .expect("OOM while walking page table in trap handler");
                core::ptr::write_bytes(next_pa as *mut u8, 0, 4096);
                core::ptr::write_volatile(pte_ptr, ((next_pa as u64 >> 12) << 10) | 1);
                pt = next_pa as *mut u64;
            } else {
                pt = (((pte >> 10) << 12) as usize) as *mut u64;
            }
        }
        let leaf = pt.add(vpn[0]);
        core::ptr::write_volatile(leaf, (ppn << 10) | pte_bits);
    }
}
