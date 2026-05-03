//! x86-64 Interrupt Descriptor Table.
//!
//! Sets up a 256-entry IDT with:
//!   vector 14 (#PF)  — page_fault_handler  (routed to cow_fault)
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

/// Initialise and load the IDT. Idempotent.
pub fn idt_init() {
    if IDT_LOADED.swap(true, Ordering::SeqCst) { return; }
    unsafe {
        IDT[14].set(page_fault_isr as usize, 0x8E);
        for v in 0..256usize {
            if v == 14 { continue; }
            IDT[v].set(generic_isr as usize, 0x8E);
        }
        let idtr = IdtPointer {
            limit: (core::mem::size_of_val(&IDT) - 1) as u16,
            base:  IDT.as_ptr() as u64,
        };
        core::arch::asm!("lidt [{0}]", in(reg) &idtr, options(nostack));
    }
}

// ── ISRs ─────────────────────────────────────────────────────────────────

#[naked]
#[no_mangle]
unsafe extern "C" fn page_fault_isr() {
    core::arch::asm!(
        "push rax",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "mov  rdi, cr2",
        "mov  rsi, [rsp + 72]",
        "call page_fault_handler",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}

#[no_mangle]
pub extern "C" fn page_fault_handler(faulting_va: usize, error_code: u64) {
    if crate::proc::cow_fault::handle_cow_fault(faulting_va, error_code) {
        return;
    }
    crate::console::println!(
        "SEGFAULT pid={} va={:#x} err={:#x}",
        crate::proc::scheduler::current_pid(),
        faulting_va,
        error_code
    );
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
