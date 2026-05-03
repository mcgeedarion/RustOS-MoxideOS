//! Interrupt Descriptor Table (IDT) setup and exception dispatch.
//!
//! ## Exception routing
//!   vector 14 (#PF) — page_fault_handler:
//!     1. P=0 + U=1  → mm::page_fault::handle_demand_fault (demand-zero/fill)
//!     2. P=1+W=1+U=1→ proc::cow_fault::handle_cow_fault    (CoW write)
//!     3. otherwise  → SIGSEGV to process, hlt on kernel fault
//!   timer IRQ       — apic.rs wires timer_irq_handler
//!   page_fault_handler  (routed to cow_fault)
//!   all others       — generic_exception_handler (logs + halts)
//!
//! Call idt_init() once during kernel startup after the GDT is loaded.

use core::sync::atomic::{AtomicBool, Ordering};

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
        IDT[14].set(page_fault_asm as usize, 0x8E);
        IDT[32].set(timer_irq_asm  as usize, 0x8E);
        for i in 0usize..32 {
            if i != 14 { IDT[i].set(generic_exc_asm as usize, 0x8E); }
        }
        let ptr = IdtPointer {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base:  IDT.as_ptr() as u64,
        };
        core::arch::asm!("lidt [{p}]", p = in(reg) &ptr, options(nostack));
    }
}

// ── Page-fault handler ───────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn page_fault_handler(faulting_va: usize, error_code: u64) {
    // ── 1. Demand-zero / demand-fill (P=0, U=1) ───────────────────────────
    // Not-present fault in user mode: try to back a VMA page.
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
        // Deliver SIGSEGV (11) to the faulting process.
        // check_pending_signal at the next syscall return will call sys_exit.
        crate::proc::signal::send_signal(pid, 11);
        crate::proc::scheduler::schedule();
        return;
    }
    // Kernel-mode fault: no recovery.
    loop { unsafe { core::arch::asm!("hlt", options(nostack)); } }
}

#[naked]
#[no_mangle]
unsafe extern "C" fn generic_isr() {
    core::arch::asm!(
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}

// ── ASM trampolines (read CR2, push error code, call Rust handler) ────────

#[naked]
unsafe extern "C" fn page_fault_asm() {
    core::arch::asm!(
        // error code is on stack; CR2 = faulting VA
        "push rax",
        "mov rax, cr2",
        "xchg rax, [rsp+8]",  // error_code in rdx slot; faulting_va in rdi slot
        "mov rsi, [rsp]",     // error_code
        "mov rdi, rax",       // faulting_va
        "add rsp, 16",
        "call page_fault_handler",
        "iretq",
        options(noreturn)
    );
}

#[naked]
unsafe extern "C" fn timer_irq_asm() {
    core::arch::asm!(
        "push 0",
        "call timer_irq_handler",
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}

#[naked]
unsafe extern "C" fn generic_exc_asm() {
    core::arch::asm!(
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}
