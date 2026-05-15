//! Interrupt Descriptor Table (IDT) — x86-64 implementation.
//!
//! ## Architecture overview
//!
//!  ┌──────────────────────────────────────────────────────────────────┐
//!  │  CPU exception / IRQ                                             │
//!  │        │                                                         │
//!  │        ▼  (hardware-pushed frame: RIP/CS/RFLAGS/RSP/SS)         │
//!  │  [vector N ASM stub]                                             │
//!  │        │  push dummy-or-real error code                          │
//!  │        │  save all 15 GPRs  (push_all! macro)                    │
//!  │        │  rdi = &InterruptFrame    (points at saved state)       │
//!  │        ▼                                                         │
//!  │  Rust dispatch  →  exception handler  |  registered IRQ handler  │
//!  └──────────────────────────────────────────────────────────────────┘
//!
//! ## Stack layout entering every Rust handler
//!
//! ```text
//! rsp → ┌──────────────────────┐  ← &InterruptFrame (rdi)
//!       │  r15  .. rdi         │  120 bytes  (15 × 8)  GPR save area
//!       ├──────────────────────┤
//!       │  error_code          │  8 bytes   (CPU-pushed or dummy 0)
//!       ├──────────────────────┤
//!       │  rip                 │  ┐
//!       │  cs                  │  │  CPU-pushed
//!       │  rflags              │  │  interrupt frame
//!       │  rsp (user/prev)     │  │  (always present in 64-bit mode)
//!       │  ss                  │  ┘
//!       └──────────────────────┘
//! ```
//!
//! ## Exception routing
//!
//! | Vector | Mnemonic | IST | Notes |
//! |--------|----------|-----|-------|
//! | 0      | #DE      | —   | divide error |
//! | 1      | #DB      | —   | debug (→ gdbstub) |
//! | 2      | #NMI     | 1   | IST1 — non-maskable interrupt |
//! | 3      | #BP      | —   | INT3 breakpoint (→ gdbstub) |
//! | 4      | #OF      | —   | overflow |
//! | 5      | #BR      | —   | bound range |
//! | 6      | #UD      | —   | invalid opcode |
//! | 7      | #NM      | —   | device not available |
//! | 8      | #DF      | 1   | IST1 — double fault (error_code=0) |
//! | 10     | #TS      | —   | invalid TSS (error_code=selector) |
//! | 11     | #NP      | —   | segment not present (error_code) |
//! | 12     | #SS      | —   | stack-segment fault (error_code) |
//! | 13     | #GP      | —   | general protection (error_code) |
//! | 14     | #PF      | —   | page fault (CR2 + error_code) |
//! | 16     | #MF      | —   | x87 FP exception |
//! | 17     | #AC      | —   | alignment check (error_code=0) |
//! | 18     | #MC      | 1   | IST1 — machine check |
//! | 19     | #XM      | —   | SIMD FP exception |
//! | 20     | #VE      | —   | virtualisation exception |
//! | 21     | #CP      | —   | control protection (error_code) |
//! | 32     | IRQ0     | —   | APIC timer |
//! | 33–255 | IRQ1+    | —   | dynamically registered drivers |
//!
//! ## Dynamic IRQ registration
//!
//! Drivers call `register_irq(vector, handler)` after `idt_init()`.  The
//! handler receives `&InterruptFrame` and must send EOI to the APIC itself.
//!
//! ```rust
//! idt::register_irq(0x21, my_keyboard_handler);
//! ```

use crate::sync::spinlock::SpinLock;
use core::sync::atomic::{AtomicBool, Ordering};

// ── Public frame type passed to every handler ─────────────────────────────

/// CPU + GPR state at the time of an interrupt or exception.
///
/// The struct is `repr(C)` and matches the exact stack layout described in
/// the module-level comment.  Cast `*mut u64` ↔ `*mut InterruptFrame` is safe
/// as long as the pointer was produced by one of the ASM stubs below.
#[repr(C)]
pub struct InterruptFrame {
    // GPRs — in push order (push_all! macro, bottom of the stack block is r15)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    // Error code (CPU-pushed for faults that have one, else stub-pushed 0)
    pub error_code: u64,
    // CPU-pushed interrupt frame
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64, // user/previous-privilege RSP
    pub ss: u64,
}

// ── Dynamic handler registry ──────────────────────────────────────────────

pub type IrqHandler = fn(&mut InterruptFrame);

static IRQ_HANDLERS: SpinLock<[Option<IrqHandler>; 256]> = SpinLock::new([None; 256]);

/// Register `handler` for interrupt vector `vector` (0–255).
///
/// Can be called after `idt_init()` from driver init code.  Overwrites any
/// previous registration.  The handler runs with interrupts **disabled**.
pub fn register_irq(vector: u8, handler: IrqHandler) {
    IRQ_HANDLERS.lock()[vector as usize] = Some(handler);
}

/// Deregister the handler for `vector`, falling back to the default stub.
pub fn unregister_irq(vector: u8) {
    IRQ_HANDLERS.lock()[vector as usize] = None;
}

// ── Macro: full GPR save/restore ─────────────────────────────────────────

macro_rules! push_all {
    () => {
        concat!(
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
        )
    };
}

macro_rules! pop_all {
    () => {
        concat!(
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
        )
    };
}

// ── IDT gate descriptor (16 bytes, Intel SDM Vol.3 §6.14.1) ──────────────

const GATE_INT: u8 = 0x8E; // Present | DPL=0 | 64-bit interrupt gate (IF cleared)
const GATE_TRAP: u8 = 0x8F; // Present | DPL=0 | 64-bit trap gate     (IF preserved)

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    flags: u8,
    offset_mid: u16,
    offset_high: u32,
    _reserved: u32,
}

impl IdtEntry {
    const fn zero() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            flags: 0,
            offset_mid: 0,
            offset_high: 0,
            _reserved: 0,
        }
    }

    fn set(&mut self, handler: usize, flags: u8, ist: u8) {
        self.offset_low = handler as u16;
        self.selector = crate::arch::x86_64::gdt::SELECTOR_KERNEL_CS;
        self.ist = ist & 0x07;
        self.flags = flags;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self._reserved = 0;
    }
}

#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

// The IDT is shared across all CPUs — gate descriptors point to global stubs.
// Per-CPU state lives in the TSS (stacks) and the handler registry.
static mut IDT: [IdtEntry; 256] = [IdtEntry::zero(); 256];
static IDT_LOADED: AtomicBool = AtomicBool::new(false);

// ── Public init ───────────────────────────────────────────────────────────

/// Build and load the IDT on the BSP.
///
/// **Must** be called after `gdt_init()` because the TSS (and therefore IST
/// stacks) must be live before we load the IDT pointer.
/// Safe to call multiple times — only the first call takes effect.
pub fn idt_init() {
    if IDT_LOADED.swap(true, Ordering::SeqCst) {
        return;
    }
    unsafe {
        // ── Exceptions without CPU-pushed error code (stub pushes 0) ────────
        IDT[0].set(exc_noerr_asm::<0> as usize, GATE_INT, 0); // #DE
        IDT[4].set(exc_noerr_asm::<4> as usize, GATE_INT, 0); // #OF
        IDT[5].set(exc_noerr_asm::<5> as usize, GATE_INT, 0); // #BR
        IDT[6].set(exc_noerr_asm::<6> as usize, GATE_INT, 0); // #UD
        IDT[7].set(exc_noerr_asm::<7> as usize, GATE_INT, 0); // #NM
        IDT[9].set(exc_noerr_asm::<9> as usize, GATE_INT, 0); // legacy coproc
        IDT[16].set(exc_noerr_asm::<16> as usize, GATE_INT, 0); // #MF
        IDT[19].set(exc_noerr_asm::<19> as usize, GATE_INT, 0); // #XM
        IDT[20].set(exc_noerr_asm::<20> as usize, GATE_INT, 0); // #VE

        // ── Exceptions with CPU-pushed error code ─────────────────────────
        IDT[10].set(exc_err_asm::<10> as usize, GATE_INT, 0); // #TS
        IDT[11].set(exc_err_asm::<11> as usize, GATE_INT, 0); // #NP
        IDT[12].set(exc_err_asm::<12> as usize, GATE_INT, 0); // #SS
        IDT[13].set(exc_err_asm::<13> as usize, GATE_INT, 0); // #GP
        IDT[17].set(exc_err_asm::<17> as usize, GATE_INT, 0); // #AC
        IDT[21].set(exc_err_asm::<21> as usize, GATE_INT, 0); // #CP

        // ── Special / IST-switched exceptions ───────────────────────────
        IDT[1].set(db_asm as usize, GATE_TRAP, 0); // #DB  (trap gate)
        IDT[2].set(nmi_asm as usize, GATE_INT, 1); // #NMI IST1
        IDT[3].set(bp_asm as usize, GATE_TRAP, 0); // #BP  (trap gate)
        IDT[8].set(exc_err_asm::<8> as usize, GATE_INT, 1); // #DF  IST1
        IDT[14].set(page_fault_asm as usize, GATE_INT, 0); // #PF
        IDT[18].set(exc_noerr_asm::<18> as usize, GATE_INT, 1); // #MC  IST1

        // Reserved vectors 15, 22–31 — catch-all prevents triple-fault.
        for v in [15u8, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31] {
            IDT[v as usize].set(exc_noerr_asm::<255> as usize, GATE_INT, 0);
        }

        // ── IRQ vectors 32–255 ──────────────────────────────────────────
        IDT[32].set(timer_irq_asm as usize, GATE_INT, 0); // APIC timer
        for v in 33u8..=255 {
            IDT[v as usize].set(generic_irq_asm_stub as usize, GATE_INT, 0);
        }

        load();
    }
}

/// Load (or reload) the IDT pointer on the calling CPU.
///
/// Called once by `idt_init()` (BSP) and once by each AP from `ap_entry()`
/// after `gdt::init_ap()`.  All CPUs share the same IDT table; only the
/// `lidt` instruction needs to be re-executed per CPU.
pub fn load() {
    unsafe {
        let ptr = IdtPointer {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: IDT.as_ptr() as u64,
        };
        core::arch::asm!("lidt [{p}]", p = in(reg) &ptr, options(nostack));
    }
}

// ── Generic IRQ dispatch (vectors 33–255) ─────────────────────────────────

#[no_mangle]
pub extern "C" fn generic_irq_dispatch(frame: &mut InterruptFrame, vector: u64) {
    let v = vector as usize;
    let handler = IRQ_HANDLERS.lock()[v];
    if let Some(h) = handler {
        h(frame);
    } else {
        crate::console::println!("[IDT] spurious IRQ vector={:#x} — no handler registered", v);
        crate::arch::x86_64::apic::send_eoi();
    }
}

// ── Exception C handlers ──────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn generic_exception_handler(frame: &mut InterruptFrame, vector: u64) {
    let mnemonic = EXCEPTION_NAMES
        .get(vector as usize)
        .copied()
        .unwrap_or("UNKNOWN");
    crate::console::println!(
        "[EXCEPTION] #{} (vec={:#x}) err={:#x} rip={:#x} rsp={:#x} rflags={:#x}",
        mnemonic,
        vector,
        frame.error_code,
        frame.rip,
        frame.rsp,
        frame.rflags
    );
    dump_registers(frame);

    let pid = crate::proc::scheduler::current_pid();
    if pid != 0 {
        crate::proc::signal::send_signal(pid, 11);
        crate::proc::scheduler::schedule();
    } else {
        loop {
            crate::arch::api::Cpu::halt();
        }
    }
}

#[no_mangle]
pub extern "C" fn nmi_handler(frame: &mut InterruptFrame) {
    crate::console::println!("[NMI] rip={:#x} rsp={:#x}", frame.rip, frame.rsp);
    // TODO: inspect NMI source (ECC, watchdog, IOCK#).
}

#[no_mangle]
pub unsafe extern "C" fn db_handler(frame: *mut InterruptFrame) {
    #[cfg(feature = "gdbstub")]
    {
        let pid = crate::proc::scheduler::current_pid();
        crate::gdbstub::gdb_trap(frame as *mut crate::gdbstub::SavedRegs, pid);
        return;
    }
    #[allow(unreachable_code)]
    generic_exception_handler(&mut *frame, 1);
}

#[no_mangle]
pub unsafe extern "C" fn bp_handler(frame: *mut InterruptFrame) {
    #[cfg(feature = "gdbstub")]
    {
        let pid = crate::proc::scheduler::current_pid();
        crate::gdbstub::gdb_trap(frame as *mut crate::gdbstub::SavedRegs, pid);
        return;
    }
    #[allow(unreachable_code)]
    generic_exception_handler(&mut *frame, 3);
}

#[no_mangle]
pub extern "C" fn page_fault_handler(frame: &mut InterruptFrame, faulting_va: u64) {
    let error_code = frame.error_code;
    let va = faulting_va as usize;
    let present = error_code & 0x1 != 0;
    let user = error_code & 0x4 != 0;

    if !present {
        if crate::mm::page_fault::handle_demand_fault(va) {
            return;
        }
    }
    if crate::proc::cow_fault::handle_cow_fault(va, error_code) {
        return;
    }

    let pid = crate::proc::scheduler::current_pid();
    crate::console::println!(
        "[#PF] pid={} va={:#x} err={:#x} present={} user={} rip={:#x}",
        pid,
        va,
        error_code,
        present,
        user,
        frame.rip
    );
    if pid != 0 {
        crate::proc::signal::send_signal(pid, 11);
        crate::proc::scheduler::schedule();
        return;
    }
    dump_registers(frame);
    loop {
        crate::arch::api::Cpu::halt();
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn dump_registers(f: &InterruptFrame) {
    crate::console::println!(
        "  rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}",
        f.rax,
        f.rbx,
        f.rcx,
        f.rdx
    );
    crate::console::println!(
        "  rsi={:#018x} rdi={:#018x} rbp={:#018x} rsp={:#018x}",
        f.rsi,
        f.rdi,
        f.rbp,
        f.rsp
    );
    crate::console::println!(
        "  r8 ={:#018x} r9 ={:#018x} r10={:#018x} r11={:#018x}",
        f.r8,
        f.r9,
        f.r10,
        f.r11
    );
    crate::console::println!(
        "  r12={:#018x} r13={:#018x} r14={:#018x} r15={:#018x}",
        f.r12,
        f.r13,
        f.r14,
        f.r15
    );
    crate::console::println!("  rip={:#018x} rflags={:#018x}", f.rip, f.rflags);
}

static EXCEPTION_NAMES: &[&str] = &[
    "DE", "DB", "NMI", "BP", "OF", "BR", "UD", "NM", "DF", "?9", "TS", "NP", "SS", "GP", "PF",
    "?15", "MF", "AC", "MC", "XM", "VE", "CP",
];

// ── ASM stubs ─────────────────────────────────────────────────────────────

#[naked]
unsafe extern "C" fn exc_noerr_asm<const N: u64>() {
    core::arch::asm!(
        "push 0",
        push_all!(),
        "mov rdi, rsp",
        "mov rsi, {N}",
        "call generic_exception_handler",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        N = const N,
        options(noreturn)
    );
}

#[naked]
unsafe extern "C" fn exc_err_asm<const N: u64>() {
    core::arch::asm!(
        push_all!(),
        "mov rdi, rsp",
        "mov rsi, {N}",
        "call generic_exception_handler",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        N = const N,
        options(noreturn)
    );
}

#[naked]
unsafe extern "C" fn db_asm() {
    core::arch::asm!(
        "push 0",
        push_all!(),
        "mov rdi, rsp",
        "call db_handler",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}

#[naked]
unsafe extern "C" fn nmi_asm() {
    core::arch::asm!(
        "push 0",
        push_all!(),
        "mov rdi, rsp",
        "call nmi_handler",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}

#[naked]
unsafe extern "C" fn bp_asm() {
    core::arch::asm!(
        "push 0",
        push_all!(),
        "mov rdi, rsp",
        "call bp_handler",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}

#[naked]
unsafe extern "C" fn page_fault_asm() {
    core::arch::asm!(
        push_all!(),
        "mov rdi, rsp",
        "mov rsi, cr2",
        "call page_fault_handler",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}

#[naked]
unsafe extern "C" fn timer_irq_asm() {
    core::arch::asm!(
        "push 0",
        push_all!(),
        "mov rdi, rsp",
        "call timer_irq_handler",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}

#[naked]
unsafe extern "C" fn generic_irq_asm_stub() {
    core::arch::asm!(
        "push 0",
        push_all!(),
        "mov rdi, rsp",
        "xor rsi, rsi",
        "call generic_irq_dispatch",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}
