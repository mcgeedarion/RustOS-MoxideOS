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
//!     9  Supervisor external interrupt
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

use core::arch::asm;
use crate::arch::riscv64::csr::*;

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
    pub sepc:    usize,  // saved program counter
    pub sstatus: usize,  // saved status register
}

// TrapFrame is 34 * 8 = 272 bytes.
const TRAP_FRAME_SIZE: usize = 34 * 8;

/// Naked trap entry stub.
///
/// stvec is set to point here (Direct mode, bottom 2 bits = 0).
/// On entry: all registers still hold user/kernel values.
/// Saves all GPRs + sepc + sstatus, then calls `riscv_trap_handler(frame)`.
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

/// Rust trap handler.  Called from `riscv_trap_entry` with
/// a pointer to the trap frame on the kernel stack.
#[no_mangle]
pub extern "C" fn riscv_trap_handler(frame: &mut TrapFrame) {
    let scause  = get_scause();
    let is_intr = scause >> 63 != 0;
    let code    = scause & !(1usize << 63);

    if is_intr {
        handle_interrupt(frame, code);
    } else {
        handle_exception(frame, code);
    }
}

fn handle_interrupt(_frame: &mut TrapFrame, code: usize) {
    match code {
        // ──────────────────────────────────────────────────────────────
        // Supervisor timer interrupt (scause code 5).
        //
        // Sequence:
        //   1. Clear STIE *first* so the interrupt won’t re-fire while we
        //      are still inside the handler.
        //   2. Advance the monotonic clock by one tick.
        //   3. Expire due timer-wheel entries (nanosleep wakeups, etc.).
        //   4. Run the scheduler — may switch to a newly-woken task.
        //   5. Re-arm mtimecmp so the next tick fires TICK_NS from now.
        //   6. Re-enable STIE so future ticks are delivered.
        // ──────────────────────────────────────────────────────────────
        5 => {
            // 1. Clear STIE to de-assert while handling.
            let sie = csrr!("sie");
            csrw!("sie", sie & !(1usize << 5));

            // 2. Advance monotonic clock.
            crate::time::tick_advance(crate::proc::scheduler::TICK_NS);

            // 3. Fire due timer-wheel entries.
            crate::time::timer::expire_timers();

            // 4. Scheduler tick (may switch tasks).
            crate::proc::scheduler::schedule();

            // 5. Re-arm mtimecmp for the next tick on hart 0.
            //    For SMP, each hart should use its own hartid.
            crate::arch::riscv64::clint::set_next_event(
                0,
                crate::proc::scheduler::TICK_NS,
            );

            // 6. Re-enable STIE.
            let sie2 = csrr!("sie");
            csrw!("sie", sie2 | (1usize << 5));
        }
        // ──────────────────────────────────────────────────────────────
        // Supervisor external interrupt (PLIC).
        // ──────────────────────────────────────────────────────────────
        9 => {
            // crate::drivers::plic::handle_irq();
        }
        _ => {}
    }
}

fn handle_exception(frame: &mut TrapFrame, code: usize) {
    match code {
        // ─── ecall from U-mode ───────────────────────────────────────────────────────
        8 => {
            let nr = frame.a7;
            let ret = crate::syscall::dispatch(
                nr,
                frame.a0, frame.a1, frame.a2,
                frame.a3, frame.a4, frame.a5,
            );
            frame.a0   = ret as usize;
            frame.sepc = frame.sepc.wrapping_add(4);
        }
        // ─── Page faults ───────────────────────────────────────────────────────────
        12 | 13 | 15 => {
            let stval = csrr!("stval");
            let pid   = crate::proc::scheduler::current_pid();
            if let Some(_vma) = crate::mm::mmap::find_vma(pid as u32, stval) {
                if let Some(pa) = crate::mm::pmm::alloc_page() {
                    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, 4096); }
                    riscv_map_page(stval & !0xFFF, pa);
                    return;
                }
            }
            crate::proc::signal::send_sigsegv(pid, stval);
        }
        // ─── Illegal instruction ─────────────────────────────────────────────────────
        2 => {
            let pid = crate::proc::scheduler::current_pid();
            crate::proc::signal::send_signal(pid, 4); // SIGILL
        }
        _ => {
            let pid = crate::proc::scheduler::current_pid();
            crate::proc::signal::send_signal(pid, 11); // SIGSEGV
        }
    }
}

/// Install the trap vector and enable supervisor interrupts.
///
/// Call this early in `kernel_main_riscv64`, before any code that could
/// fault (heap init, paging, etc.).
pub fn trap_init() {
    // Point stvec at our entry stub (Direct mode, vectored bit = 0).
    set_stvec(riscv_trap_entry as usize);

    // Enable SSIE (supervisor software), STIE (timer), SEIE (external).
    let sie = csrr!("sie");
    csrw!("sie", sie | (1 << 1) | (1 << 5) | (1 << 9));

    // Enable supervisor-mode interrupts globally (sstatus.SIE = 1).
    let sstatus = csrr!("sstatus");
    csrw!("sstatus", sstatus | (1 << 1));
}

// ─── Page table helpers (Sv39) ──────────────────────────────────────────────────────────────

/// Map a single 4 KiB page in the current Sv39 page table.
/// `va` and `pa` must be 4 KiB aligned.
fn riscv_map_page(va: usize, pa: usize) {
    let satp  = get_satp();
    let root  = (satp & 0x0FFF_FFFF_FFFF) << 12;
    let vpn   = [(va >> 12) & 0x1FF, (va >> 21) & 0x1FF, (va >> 30) & 0x1FF];
    let ppn   = pa >> 12;
    unsafe {
        let mut pt = root as *mut u64;
        for level in (1..=2).rev() {
            let pte_ptr = pt.add(vpn[level]);
            let pte = core::ptr::read_volatile(pte_ptr);
            if pte & 1 == 0 {
                let next = crate::mm::pmm::alloc_page().unwrap_or(0);
                core::ptr::write_bytes(next as *mut u8, 0, 4096);
                core::ptr::write_volatile(pte_ptr, ((next >> 12) << 10) | 1);
                pt = next as *mut u64;
            } else {
                pt = (((pte >> 10) << 12) as usize) as *mut u64;
            }
        }
        let leaf = pt.add(vpn[0]);
        // RWX + Valid + User
        core::ptr::write_volatile(leaf, ((ppn as u64) << 10) | 0xCF);
    }
}
