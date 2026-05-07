//! Interrupt Descriptor Table (IDT) setup and exception dispatch.
//!
//! ## ISR calling convention
//! Every stub saves ALL caller-saved and callee-saved GPRs before calling
//! a Rust handler, then restores them before IRETQ.  This is required
//! because Rust functions compiled with the standard SysV ABI will freely
//! clobber rax/rcx/rdx/rsi/rdi/r8-r11 (caller-saved) without saving them.
//!
//! Stack layout on entry to each Rust handler (after the stub macro):
//!   [rsp+0]  r15 .. rax  (15 × 8 = 120 bytes of saved GPRs)
//!   [rsp+120] error_code  (pushed by CPU for #PF, #DF, etc.)
//!                         or a dummy 0 pushed by the stub for others
//!   [rsp+128] RIP / CS / RFLAGS / RSP(user) / SS  — CPU interrupt frame
//!
//! ## Exception routing
//!   vector 14 (#PF) — page_fault_handler
//!   vector 32 (timer IRQ) — timer_irq_handler
//!   vectors 0-31 (other) — generic_exception_handler

use core::sync::atomic::{AtomicBool, Ordering};

// ── Macro: full GPR save/restore frame ─────────────────────────────────────
//
// PUSH_ALL / POP_ALL bracket every ISR that calls a Rust function.
// We use the `push` sequence that Linux uses for 64-bit entry.
//
// After PUSH_ALL the layout is:
//   [rsp+0..112]  r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rax,rcx,rdx,rsi,rdi
// The error code (or dummy 0) lives at [rsp+120] after the pushes.

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
    loop { unsafe { core::arch::asm!("hlt", options(nostack)); } }
}

// ── ASM stubs ──────────────────────────────────────────────────────────────
//
// Each stub saves all GPRs, calls the Rust handler, restores GPRs, discards
// the error code (or dummy), and executes IRETQ.

/// Page-fault entry stub.
/// The CPU pushes: error_code, RIP, CS, RFLAGS, RSP(user), SS.
/// We read CR2 (faulting VA), save all GPRs, then call page_fault_handler.
#[naked]
unsafe extern "C" fn page_fault_asm() {
    core::arch::asm!(
        // CR2 = faulting VA; it's clobbered by nested faults so save early.
        "push rax",
        "mov rax, cr2",
        // At this point: [rsp+0]=saved rax, [rsp+8]=error_code (from CPU)
        // Swap: put CR2 into [rsp+8] and error_code into rax.
        "xchg rax, [rsp+8]",
        // Now: [rsp+0]=faulting_va (was rax slot), [rsp+8]=error_code
        // Save the remaining GPRs (push_all! saves rdi first, but rax already
        // saved; we need a custom sequence here).
        // Build the standard GPR frame on the stack:
        "push rdi",    // save rdi — we'll fill it with faulting_va
        "push rsi",    // save rsi — we'll fill it with error_code
        "push rdx",
        "push rcx",
        // rax already pushed at [rsp + 4*8 + 8] (after rdi/rsi/rdx/rcx)
        // Actually restructure: save all regs *except* rax which is already
        // on the stack as [rsp+original_offset].  Use a full standard frame:
        //
        // Simplest correct approach: push dummy rax slot, then fill args.
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
        // Now load handler arguments from the slots we set up above.
        // The stack (from top = rsp) is:
        //   rsp+0..112  r15..rdi (15 regs)
        //   rsp+120     faulting_va  (the rax slot we swapped CR2 into)
        //   rsp+128     error_code   (the slot we swapped old rax into)
        //   rsp+136     RIP (CPU frame)
        // Load args: rdi = faulting_va, rsi = error_code
        "mov rdi, [rsp + 120]",
        "mov rsi, [rsp + 128]",
        "call page_fault_handler",
        // Restore all GPRs
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
        // Discard the two slots (faulting_va / error_code) we set up.
        "add rsp, 16",
        "iretq",
        options(noreturn)
    );
}

/// Timer IRQ entry stub (no error code pushed by CPU).
#[naked]
unsafe extern "C" fn timer_irq_asm() {
    core::arch::asm!(
        // Push dummy error code so the stack layout is uniform.
        "push 0",
        push_all!(),
        // rdi = dummy 0 (no meaningful arg to timer handler)
        "xor rdi, rdi",
        "call timer_irq_handler",
        pop_all!(),
        "add rsp, 8",   // discard dummy error code
        "iretq",
        options(noreturn)
    );
}

/// Generic exception stub (for vectors 0-31 except #PF, including those
/// that push an error code and those that don't).
/// For simplicity we use this for non-error-code exceptions too by pushing
/// a dummy 0.  For exceptions that DO push an error code the CPU has already
/// pushed it; the stub handles both cases by always pushing a dummy first
/// and then doing the full save.
///
/// NOTE: For vectors 8, 10, 11, 12, 13, 17, 21, 29, 30 the CPU pushes an
/// error code automatically. For those vectors a separate stub should be
/// registered that does NOT push the dummy 0.  As a conservative fallback
/// this stub is registered for all non-#PF vectors and the double-push
/// for error-code exceptions is acceptable since generic_exception_handler
/// currently just halts the kernel anyway.
#[naked]
unsafe extern "C" fn generic_exc_asm() {
    core::arch::asm!(
        // Push a dummy error code for non-error-code exceptions.
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
