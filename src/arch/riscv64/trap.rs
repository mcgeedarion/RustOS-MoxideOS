//! RISC-V supervisor-mode trap handler.
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

use crate::arch::riscv64::csr::*;

/// Trap frame saved by the trap entry stub.
/// Fields are in the order the entry stub pushes them (see trap_entry.S
/// or an inline asm version).
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
    pub sepc: usize,
    pub sstatus: usize,
}

/// Rust trap handler.  Called from the naked asm entry stub with
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
        5 => {
            // Supervisor timer interrupt — acknowledge by clearing SIE.STIE
            // and advancing the timer compare register.
            // (Concrete implementation depends on whether we have CLINT or PLIC.)
            // For now just clear the pending timer interrupt via SIE.
            let sie = csrr!("sie");
            csrw!("sie", sie & !(1usize << 5)); // clear STIE
        }
        9 => {
            // Supervisor external interrupt (PLIC).
            // Claim + complete cycle handled in drivers/plic.rs.
            // crate::drivers::plic::handle_irq();
        }
        _ => {}
    }
}

fn handle_exception(frame: &mut TrapFrame, code: usize) {
    match code {
        // ─── ecall from U-mode (syscall) ───────────────────────────────────
        8 => {
            let nr = frame.a7;
            let ret = crate::syscall::dispatch(
                nr,
                frame.a0, frame.a1, frame.a2,
                frame.a3, frame.a4, frame.a5,
            );
            frame.a0  = ret as usize;
            frame.sepc = frame.sepc.wrapping_add(4); // advance past ecall
        }
        // ─── Page faults ───────────────────────────────────────────────────
        12 | 13 | 15 => {
            let stval = csrr!("stval"); // faulting VA
            let pid   = crate::proc::scheduler::current_pid();
            // Check if fault VA is in a registered VMA (lazy allocation).
            if let Some(vma) = crate::mm::mmap::find_vma(pid as u32, stval) {
                // Allocate and map one page.
                if let Some(pa) = crate::mm::pmm::alloc_page() {
                    unsafe { core::ptr::write_bytes(pa as *mut u8, 0, 4096); }
                    riscv_map_page(stval & !0xFFF, pa);
                    return;
                }
            }
            // Unhandled page fault → SIGSEGV.
            crate::proc::signal::send_sigsegv(pid, stval);
        }
        // ─── Illegal instruction ───────────────────────────────────────────
        2 => {
            let pid = crate::proc::scheduler::current_pid();
            crate::proc::signal::send_signal(pid, 4); // SIGILL
        }
        _ => {
            // Unhandled exception — kill the process.
            let pid = crate::proc::scheduler::current_pid();
            crate::proc::signal::send_signal(pid, 11); // SIGSEGV
        }
    }
}

/// Set up stvec to point at our trap entry stub.
pub fn trap_init() {
    extern "C" { fn riscv_trap_entry(); }
    set_stvec(riscv_trap_entry as usize);
    // Enable supervisor interrupts: SSIE (software) | STIE (timer) | SEIE (external)
    let sie = csrr!("sie");
    csrw!("sie", sie | (1 << 1) | (1 << 5) | (1 << 9));
}

// ─── Page table helpers (Sv39) ────────────────────────────────────────────────

/// Map a single 4 KiB page in the current Sv39 page table.
/// `va` and `pa` must be 4 KiB aligned.
fn riscv_map_page(va: usize, pa: usize) {
    // Read current SATP to get root page table PA.
    let satp  = get_satp();
    let root  = (satp & 0x0FFF_FFFF_FFFF) << 12;
    let vpn   = [(va >> 12) & 0x1FF, (va >> 21) & 0x1FF, (va >> 30) & 0x1FF];
    let ppn   = pa >> 12;
    const PTE_V: usize = 1;
    const PTE_R: usize = 2;
    const PTE_W: usize = 4;
    const PTE_U: usize = 16;

    unsafe {
        let mut table = root as *mut usize;
        for level in (1..=2).rev() {
            let pte_ptr = table.add(vpn[level]);
            let pte     = pte_ptr.read_volatile();
            if pte & PTE_V == 0 {
                // Allocate a new page table.
                let new_pa = crate::mm::pmm::alloc_page().expect("OOM in riscv_map_page");
                core::ptr::write_bytes(new_pa as *mut u8, 0, 4096);
                let new_ppn = new_pa >> 12;
                pte_ptr.write_volatile((new_ppn << 10) | PTE_V);
                table = new_pa as *mut usize;
            } else {
                table = ((pte >> 10) << 12) as *mut usize;
            }
        }
        let leaf = table.add(vpn[0]);
        leaf.write_volatile((ppn << 10) | PTE_V | PTE_R | PTE_W | PTE_U);
        // Flush TLB for this VA.
        core::arch::asm!("sfence.vma {va}, zero", va = in(reg) va);
    }
}
