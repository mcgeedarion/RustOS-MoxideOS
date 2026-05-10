//! Interrupt Descriptor Table (IDT) setup and exception dispatch.
//!
//! ## ISR calling convention
//! Every stub saves ALL caller-saved and callee-saved GPRs before calling
//! a Rust handler, then restores them before IRETQ.  This is required
//! because Rust functions compiled with the standard SysV ABI will freely
//! clobber rax/rcx/rdx/rsi/rdi/r8-r11 (caller-saved) without saving them.
//!
//! Stack layout on entry to each Rust handler (after the stub macro):
//!   [rsp+0]  r15 .. rdi  (15 × 8 = 120 bytes of saved GPRs)
//!   [rsp+120] error_code  (pushed by CPU for #PF, #DF, etc.)
//!                         or a dummy 0 pushed by the stub for others
//!   [rsp+128] RIP / CS / RFLAGS / RSP(user) / SS  — CPU interrupt frame
//!
//! ## Exception routing
//!   vector 1  (#DB debug)  — db_handler  → gdbstub::gdb_trap (feature-gated)
//!   vector 3  (#BP INT3)   — bp_handler  → gdbstub::gdb_trap (feature-gated)
//!   vector 14 (#PF)        — page_fault_handler
//!   vector 32 (timer IRQ)  — timer_irq_handler
//!   vectors 0-31 (other)   — generic_exception_handler

use core::sync::atomic::{AtomicBool, Ordering};

// ── Macro: full GPR save/restore frame ─────────────────────────────────────
//
// Push order: rdi, rsi, rdx, rcx, rax, r8, r9, r10, r11, rbx, rbp, r12, r13, r14, r15
// This order is what SavedRegs in gdbstub/rsp.rs expects.

macro_rules! push_all {
    () => { concat!(
        "push rdi\n",
        "push rsi\n",
        "push rdx\n",
        "push rcx\n",
        "push rax\n",
        "push r8\n",
        "push r9\n",
        "push r10\n",
        "push r11\n",
        "push rbx\n",
        "push rbp\n",
        "push r12\n",
        "push r13\n",
        "push r14\n",
        "push r15\n",
    )}
}

macro_rules! pop_all {
    () => { concat!(
        "pop r15\n",
        "pop r14\n",
        "pop r13\n",
        "pop r12\n",
        "pop rbp\n",
        "pop rbx\n",
        "pop r11\n",
        "pop r10\n",
        "pop r9\n",
        "pop r8\n",
        "pop rax\n",
        "pop rcx\n",
        "pop rdx\n",
        "pop rsi\n",
        "pop rdi\n",
    )}
}

/// An x86-64 IDT gate descriptor (16 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IdtEntry {
    offset_low:  u16,
    selector:    u16,
    ist:         u8,
    flags:       u8,
    offset_mid:  u16,
    offset_high: u32,
    _reserved:   u32,
}

impl IdtEntry {
    const fn zero() -> Self {
        Self { offset_low: 0, selector: 0, ist: 0, flags: 0,
               offset_mid: 0, offset_high: 0, _reserved: 0 }
    }

    fn set(&mut self, handler: usize, flags: u8) {
        self.offset_low  = handler as u16;
        self.selector    = 0x08;
        self.ist         = 0;
        self.flags       = flags;
        self.offset_mid  = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self._reserved   = 0;
    }
}

#[repr(C, packed)]
struct IdtPointer { limit: u16, base: u64 }

static mut IDT: [IdtEntry; 256] = [IdtEntry::zero(); 256];
static IDT_LOADED: AtomicBool = AtomicBool::new(false);

/// Initialise and load the IDT.
/// Must be called after the GDT is in place (selector 0x08 = kernel code).
pub fn idt_init() {
    if IDT_LOADED.swap(true, Ordering::SeqCst) { return; }
    unsafe {
        IDT[1].set(db_asm  as usize, 0x8E); // #DB  debug exception
        IDT[3].set(bp_asm  as usize, 0x8E); // #BP  INT3 breakpoint
        IDT[14].set(page_fault_asm as usize, 0x8E);
        IDT[32].set(timer_irq_asm  as usize, 0x8E);
        for i in 0usize..32 {
            if i != 1 && i != 3 && i != 14 {
                IDT[i].set(generic_exc_asm as usize, 0x8E);
            }
        }
        let ptr = IdtPointer {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base:  IDT.as_ptr() as u64,
        };
        core::arch::asm!("lidt [{p}]", p = in(reg) &ptr, options(nostack));
    }
}

// ── #DB debug-exception handler ───────────────────────────────────────────────

/// Called from db_asm with rsp pointing at the base of the SavedRegs frame.
/// When gdbstub is enabled, hands control to the GDB RSP stub.
/// Otherwise falls through to the generic halt path.
#[no_mangle]
pub unsafe extern "C" fn db_handler(regs: *mut crate::gdbstub::rsp::SavedRegs) {
    #[cfg(feature = "gdbstub")]
    {
        crate::gdbstub::gdb_trap(regs);
        return;
    }
    #[cfg(not(feature = "gdbstub"))]
    generic_exception_handler(0);
}

/// Called from bp_asm with rsp pointing at the base of the SavedRegs frame.
#[no_mangle]
pub unsafe extern "C" fn bp_handler(regs: *mut crate::gdbstub::rsp::SavedRegs) {
    #[cfg(feature = "gdbstub")]
    {
        crate::gdbstub::gdb_trap(regs);
        return;
    }
    #[cfg(not(feature = "gdbstub"))]
    generic_exception_handler(0);
}

// ── #DB ASM stub (vector 1) ───────────────────────────────────────────────────
//
// #DB does not push an error code.  We push a dummy 0 to keep the stack
// layout uniform, save all GPRs, then pass rsp (= &SavedRegs) to db_handler.

#[naked]
unsafe extern "C" fn db_asm() {
    core::arch::asm!(
        "push 0",      // dummy error code
        push_all!(),
        "mov rdi, rsp", // rdi = *mut SavedRegs
        "call db_handler",
        pop_all!(),
        "add rsp, 8",   // discard dummy error code
        "iretq",
        options(noreturn)
    );
}

// ── #BP ASM stub (vector 3) ───────────────────────────────────────────────────
//
// #BP (INT3) does not push an error code.  Same layout as #DB.

#[naked]
unsafe extern "C" fn bp_asm() {
    core::arch::asm!(
        "push 0",      // dummy error code
        push_all!(),
        "mov rdi, rsp", // rdi = *mut SavedRegs
        "call bp_handler",
        pop_all!(),
        "add rsp, 8",   // discard dummy error code
        "iretq",
        options(noreturn)
    );
}

// ── Page-fault handler ─────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn page_fault_handler(faulting_va: usize, error_code: u64) {
    // ── 1. Demand-zero / demand-fill (P=0, U=1) ───────────────────────────
    if error_code & 0x1 == 0 && error_code & 0x4 != 0 {
        if crate::mm::page_fault::handle_demand_fault(faulting_va) {
            return;
        }
    }

    // ── 2. CoW write fault (P=1, W=1, U=1) ───────────────────────────────
    if crate::proc::cow_fault::handle_cow_fault(faulting_va, error_code) {
        return;
    }

    // ── 3. Genuine access violation ───────────────────────────────────────
    let pid = crate::proc::scheduler::current_pid();
    crate::console::println!(
        "SIGSEGV pid={} va={:#x} err={:#x}",
        pid, faulting_va, error_code
    );
    if pid != 0 {
        crate::proc::signal::send_signal(pid, 11);
        crate::proc::scheduler::schedule();
        return;
    }
    loop { crate::arch::api::Cpu::halt(); }
}

// ── ASM stubs ──────────────────────────────────────────────────────────────

/// Page-fault entry stub.
#[naked]
unsafe extern "C" fn page_fault_asm() {
    core::arch::asm!(
        "push rax",
        "mov rax, cr2",
        "xchg rax, [rsp+8]",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",
        "mov rdi, [rsp + 120]",
        "mov rsi, [rsp + 128]",
        "call page_fault_handler",
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rcx",
        "pop rdx",
        "pop rsi",
        "pop rdi",
        "add rsp, 16",
        "iretq",
        options(noreturn)
    );
}

/// Timer IRQ entry stub (no error code pushed by CPU).
#[naked]
unsafe extern "C" fn timer_irq_asm() {
    core::arch::asm!(
        "push 0",
        push_all!(),
        "xor rdi, rdi",
        "call timer_irq_handler",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}

/// Generic exception stub.
#[naked]
unsafe extern "C" fn generic_exc_asm() {
    core::arch::asm!(
        "push 0",
        push_all!(),
        "xor rdi, rdi",
        "call generic_exception_handler",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}
