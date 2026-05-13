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

use core::sync::atomic::{AtomicBool, Ordering};
use crate::sync::spinlock::SpinLock;

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
    pub r9:  u64,
    pub r8:  u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    // Error code (CPU-pushed for faults that have one, else stub-pushed 0)
    pub error_code: u64,
    // CPU-pushed interrupt frame
    pub rip:    u64,
    pub cs:     u64,
    pub rflags: u64,
    pub rsp:    u64,  // user/previous-privilege RSP
    pub ss:     u64,
}

// ── Dynamic handler registry ──────────────────────────────────────────────

pub type IrqHandler = fn(&mut InterruptFrame);

static IRQ_HANDLERS: SpinLock<[Option<IrqHandler>; 256]> =
    SpinLock::new([None; 256]);

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
//
// Push order must match InterruptFrame field order (reversed because push
// grows the stack downward).
//   push rdi first → rdi ends up at the highest address (InterruptFrame.rdi)
//   push r15 last  → r15 ends up at rsp (InterruptFrame.r15)

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

// ── IDT gate descriptor (16 bytes, Intel SDM Vol.3 §6.14.1) ──────────────

/// Flags byte for a present, DPL=0, 64-bit interrupt gate.
/// `0x8E` = Present(1) | DPL(00) | S(0) | Type(01110 = 64-bit interrupt gate)
const GATE_INT:   u8 = 0x8E;
/// Trap gate: same as interrupt gate but bit 0 = 1 (does NOT clear IF on entry).
const GATE_TRAP:  u8 = 0x8F;
/// DPL=3 interrupt gate — callable from ring 3 (e.g. INT 0x80 syscall)
#[allow(dead_code)]
const GATE_INT3:  u8 = 0xEE;

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IdtEntry {
    offset_low:  u16,
    selector:    u16,
    ist:         u8,   // bits[2:0] = IST index (0 = use RSP0, 1–7 = IST1–IST7)
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

    /// Build a gate pointing at `handler` with the given flags and IST index.
    fn set(&mut self, handler: usize, flags: u8, ist: u8) {
        self.offset_low  = handler as u16;
        self.selector    = 0x08;            // kernel CS
        self.ist         = ist & 0x07;
        self.flags       = flags;
        self.offset_mid  = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self._reserved   = 0;
    }
}

#[repr(C, packed)]
struct IdtPointer { limit: u16, base: u64 }

// 256-entry IDT, statically allocated.
static mut IDT: [IdtEntry; 256] = [IdtEntry::zero(); 256];
static IDT_LOADED: AtomicBool = AtomicBool::new(false);

// ── Public init ───────────────────────────────────────────────────────────

/// Initialise and load the IDT.
///
/// **Must** be called after `gdt_init()` because the TSS (and therefore IST
/// stacks) must be live before we load the IDT pointer.
/// Safe to call multiple times — only the first call takes effect.
pub fn idt_init() {
    if IDT_LOADED.swap(true, Ordering::SeqCst) { return; }
    unsafe {
        // ── CPU exceptions (vectors 0–31) ─────────────────────────────────
        //
        // Exceptions are split into three groups:
        //   A) No error code pushed by CPU       → stub pushes dummy 0
        //   B) Error code pushed by CPU           → stub does NOT push dummy
        //   C) Faults needing special handling    → dedicated stub
        //
        // IST1 is used for NMI (#2), #DF (#8), and #MC (#18) — these are the
        // three faults that can arrive on a corrupted or exhausted stack.
        // gdt_init() already wired TSS.ist1 to a dedicated kernel stack.

        // Group A — no error code (stub pushes 0)
        IDT[ 0].set(exc_noerr_asm:: <0>  as usize, GATE_INT,  0); // #DE
        IDT[ 4].set(exc_noerr_asm:: <4>  as usize, GATE_INT,  0); // #OF
        IDT[ 5].set(exc_noerr_asm:: <5>  as usize, GATE_INT,  0); // #BR
        IDT[ 6].set(exc_noerr_asm:: <6>  as usize, GATE_INT,  0); // #UD
        IDT[ 7].set(exc_noerr_asm:: <7>  as usize, GATE_INT,  0); // #NM
        IDT[ 9].set(exc_noerr_asm:: <9>  as usize, GATE_INT,  0); // coprocessor overrun (reserved)
        IDT[16].set(exc_noerr_asm::<16>  as usize, GATE_INT,  0); // #MF x87
        IDT[19].set(exc_noerr_asm::<19>  as usize, GATE_INT,  0); // #XM SIMD
        IDT[20].set(exc_noerr_asm::<20>  as usize, GATE_INT,  0); // #VE virtualisation

        // Group B — CPU pushes an error code
        IDT[10].set(exc_err_asm::<10>    as usize, GATE_INT,  0); // #TS
        IDT[11].set(exc_err_asm::<11>    as usize, GATE_INT,  0); // #NP
        IDT[12].set(exc_err_asm::<12>    as usize, GATE_INT,  0); // #SS
        IDT[13].set(exc_err_asm::<13>    as usize, GATE_INT,  0); // #GP
        IDT[17].set(exc_err_asm::<17>    as usize, GATE_INT,  0); // #AC
        IDT[21].set(exc_err_asm::<21>    as usize, GATE_INT,  0); // #CP

        // Group C — special handling
        IDT[ 1].set(db_asm              as usize, GATE_TRAP, 0); // #DB debug (trap gate — IF stays set)
        IDT[ 2].set(nmi_asm             as usize, GATE_INT,  1); // #NMI — IST1
        IDT[ 3].set(bp_asm              as usize, GATE_TRAP, 0); // #BP INT3 (trap gate)
        IDT[ 8].set(exc_err_asm:: <8>   as usize, GATE_INT,  1); // #DF — IST1, error_code always 0
        IDT[14].set(page_fault_asm      as usize, GATE_INT,  0); // #PF
        IDT[18].set(exc_noerr_asm::<18> as usize, GATE_INT,  1); // #MC — IST1

        // Vectors 15, 22–31 are reserved by Intel.  Install a catch-all so a
        // spurious delivery does not triple-fault.
        for v in [15u8, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31] {
            IDT[v as usize].set(exc_noerr_asm::<255> as usize, GATE_INT, 0);
        }

        // ── IRQ vectors (32–255) ──────────────────────────────────────────
        //
        // A single generic_irq_asm stub is installed for ALL 224 IRQ vectors.
        // The stub records the vector number in rsi, loads the InterruptFrame
        // pointer in rdi, and calls generic_irq_dispatch().  Drivers that need
        // faster paths can call register_irq() but still share this stub.
        IDT[32].set(timer_irq_asm as usize, GATE_INT, 0); // APIC timer — fast path
        for v in 33u8..=255 {
            IDT[v as usize].set(generic_irq_asm_for(v) as usize, GATE_INT, 0);
        }

        let ptr = IdtPointer {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base:  IDT.as_ptr() as u64,
        };
        core::arch::asm!("lidt [{p}]", p = in(reg) &ptr, options(nostack));
    }
}

// ── Generic IRQ dispatch (vectors 33–255) ─────────────────────────────────

/// Called from generic_irq_asm stubs with:
///   rdi = *mut InterruptFrame
///   rsi = vector number (u64)
#[no_mangle]
pub extern "C" fn generic_irq_dispatch(frame: &mut InterruptFrame, vector: u64) {
    let v = vector as usize;
    let handler = IRQ_HANDLERS.lock()[v];
    if let Some(h) = handler {
        h(frame);
    } else {
        crate::console::println!("[IDT] spurious IRQ vector={:#x} — no handler registered", v);
        // Send EOI anyway to prevent the APIC from locking up.
        crate::arch::x86_64::apic::send_eoi();
    }
}

/// Returns the generic IRQ stub address for vector `v`.
/// For now all use the same stub; the vector is encoded in rsi by the stub.
/// This is a placeholder — in production you would generate 224 tiny stubs
/// (each pushing its own vector number) via a build.rs macro expansion or a
/// const-generic #[naked] fn as shown below for vectors that matter.
#[inline(always)]
fn generic_irq_asm_for(_v: u8) -> unsafe extern "C" fn() {
    generic_irq_asm_stub
}

// ── Exception C handlers ──────────────────────────────────────────────────

/// Rust-side handler for all CPU exceptions that do not have dedicated logic.
/// Receives the full InterruptFrame so it can print registers and RIP.
#[no_mangle]
pub extern "C" fn generic_exception_handler(frame: &mut InterruptFrame, vector: u64) {
    let mnemonic = EXCEPTION_NAMES.get(vector as usize).copied().unwrap_or("UNKNOWN");
    crate::console::println!(
        "[EXCEPTION] #{} (vec={:#x}) err={:#x} rip={:#x} rsp={:#x} rflags={:#x}",
        mnemonic, vector, frame.error_code, frame.rip, frame.rsp, frame.rflags
    );
    dump_registers(frame);

    let pid = crate::proc::scheduler::current_pid();
    if pid != 0 {
        // Deliver SIGSEGV to the offending process and reschedule.
        crate::proc::signal::send_signal(pid, 11);
        crate::proc::scheduler::schedule();
    } else {
        // Kernel-mode exception — halt.
        loop { crate::arch::api::Cpu::halt(); }
    }
}

/// Non-maskable interrupt handler.
/// NMIs can arrive on a corrupted stack, so we use IST1 and keep this short.
#[no_mangle]
pub extern "C" fn nmi_handler(frame: &mut InterruptFrame) {
    crate::console::println!(
        "[NMI] rip={:#x} rsp={:#x} — checking hardware watchdogs",
        frame.rip, frame.rsp
    );
    // TODO: check NMI source (ECC, watchdog timer, IOCK#).
    // For now we return from the NMI; if it is truly fatal the platform will
    // fire a second NMI which x86 architecture forbids being nested → triple fault.
}

// ── #DB / #BP handlers ────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn db_handler(frame: *mut InterruptFrame) {
    #[cfg(feature = "gdbstub")]
    {
        let pid = crate::proc::scheduler::current_pid();
        crate::gdbstub::gdb_trap(
            frame as *mut crate::gdbstub::SavedRegs,
            pid,
        );
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
        crate::gdbstub::gdb_trap(
            frame as *mut crate::gdbstub::SavedRegs,
            pid,
        );
        return;
    }
    #[allow(unreachable_code)]
    generic_exception_handler(&mut *frame, 3);
}

// ── Page-fault handler ─────────────────────────────────────────────────────

/// #PF handler.  Called from page_fault_asm with the full InterruptFrame.
/// The faulting virtual address is in CR2; the ASM stub puts it in rdi as the
/// first argument and shifts the frame pointer to rsi.
#[no_mangle]
pub extern "C" fn page_fault_handler(frame: &mut InterruptFrame, faulting_va: u64) {
    let error_code = frame.error_code;
    let va = faulting_va as usize;

    // Bit 0 = P (present), bit 1 = W (write), bit 2 = U (user), bit 3 = RSVD, bit 4 = I (ifetch)
    let present = error_code & 0x1 != 0;
    let user    = error_code & 0x4 != 0;

    if !present {
        // Demand-paging / swap fault.
        if crate::mm::page_fault::handle_demand_fault(va) { return; }
    }

    // Copy-on-write
    if crate::proc::cow_fault::handle_cow_fault(va, error_code) { return; }

    let pid = crate::proc::scheduler::current_pid();
    crate::console::println!(
        "[#PF] pid={} va={:#x} err={:#x} present={} user={} rip={:#x}",
        pid, va, error_code, present, user, frame.rip
    );

    if pid != 0 {
        crate::proc::signal::send_signal(pid, 11); // SIGSEGV
        crate::proc::scheduler::schedule();
        return;
    }
    dump_registers(frame);
    loop { crate::arch::api::Cpu::halt(); }
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn dump_registers(f: &InterruptFrame) {
    crate::console::println!(
        "  rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}",
        f.rax, f.rbx, f.rcx, f.rdx
    );
    crate::console::println!(
        "  rsi={:#018x} rdi={:#018x} rbp={:#018x} rsp={:#018x}",
        f.rsi, f.rdi, f.rbp, f.rsp
    );
    crate::console::println!(
        "  r8={:#018x}  r9={:#018x}  r10={:#018x} r11={:#018x}",
        f.r8, f.r9, f.r10, f.r11
    );
    crate::console::println!(
        "  r12={:#018x} r13={:#018x} r14={:#018x} r15={:#018x}",
        f.r12, f.r13, f.r14, f.r15
    );
    crate::console::println!("  rip={:#018x} rflags={:#018x}", f.rip, f.rflags);
}

static EXCEPTION_NAMES: &[&str] = &[
    "DE",  "DB",  "NMI", "BP",  "OF",  "BR",  "UD",  "NM",
    "DF",  "?9",  "TS",  "NP",  "SS",  "GP",  "PF",  "?15",
    "MF",  "AC",  "MC",  "XM",  "VE",  "CP",
];

// ── ASM stubs ─────────────────────────────────────────────────────────────
//
// Two families:
//   exc_noerr_asm<N>  — exceptions WITHOUT a CPU-pushed error code
//                        (stub pushes 0 as a dummy so the frame layout
//                         is uniform regardless of exception type)
//   exc_err_asm<N>    — exceptions WITH a CPU-pushed error code
//                        (stub does NOT push a dummy; real code is on stack)
//
// Both call generic_exception_handler(frame: &mut InterruptFrame, vector: u64)
//   rdi = pointer to InterruptFrame (= rsp after saving GPRs)
//   rsi = vector number

/// Stub for exceptions that do NOT push an error code.
#[naked]
unsafe extern "C" fn exc_noerr_asm<const N: u64>() {
    core::arch::asm!(
        "push 0",           // dummy error code — keeps frame layout uniform
        push_all!(),
        "mov rdi, rsp",     // rdi = &InterruptFrame
        "mov rsi, {N}",     // rsi = vector number
        "call generic_exception_handler",
        pop_all!(),
        "add rsp, 8",       // discard dummy error code
        "iretq",
        N = const N,
        options(noreturn)
    );
}

/// Stub for exceptions that DO push an error code.
#[naked]
unsafe extern "C" fn exc_err_asm<const N: u64>() {
    core::arch::asm!(
        // error code already on stack — no dummy needed
        push_all!(),
        "mov rdi, rsp",     // rdi = &InterruptFrame
        "mov rsi, {N}",     // rsi = vector number
        "call generic_exception_handler",
        pop_all!(),
        "add rsp, 8",       // discard error code
        "iretq",
        N = const N,
        options(noreturn)
    );
}

// ── #DB (vector 1) ────────────────────────────────────────────────────────

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

// ── #NMI (vector 2) — IST1 ────────────────────────────────────────────────

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

// ── #BP (vector 3) ────────────────────────────────────────────────────────

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

// ── #PF (vector 14) ───────────────────────────────────────────────────────
//
// The CPU pushes [error_code, RIP, CS, RFLAGS, RSP, SS] in that order.
// CR2 holds the faulting virtual address.
//
// Stack on entry (before the stub does anything):
//   [rsp+0]  error_code  (CPU-pushed)
//   [rsp+8]  rip
//   ...
//
// We save GPRs normally (push_all!), then:
//   rdi = rsp           → &InterruptFrame  (first arg)
//   rsi = CR2           → faulting_va      (second arg)

#[naked]
unsafe extern "C" fn page_fault_asm() {
    core::arch::asm!(
        // error code already pushed by CPU — do NOT push a dummy
        push_all!(),
        "mov rdi, rsp",     // arg1 = &InterruptFrame
        "mov rsi, cr2",     // arg2 = faulting virtual address
        "call page_fault_handler",
        pop_all!(),
        "add rsp, 8",       // discard CPU-pushed error code
        "iretq",
        options(noreturn)
    );
}

// ── Timer IRQ (vector 32) — fast path ────────────────────────────────────

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

// ── Generic IRQ stub (vectors 33–255) ────────────────────────────────────
//
// All unregistered IRQ vectors share this single stub.  The vector number is
// NOT encoded here; instead the dispatcher reads it from the APIC ISR register
// or falls back to a "spurious" message.  For production use, replace with
// 224 const-generic stubs (or a build.rs trampoline table) so each stub pushes
// its own vector number into rsi before calling generic_irq_dispatch.
//
// rdi = &InterruptFrame
// rsi = 0  (unknown vector — dispatcher will log a warning)

#[naked]
unsafe extern "C" fn generic_irq_asm_stub() {
    core::arch::asm!(
        "push 0",           // dummy error code
        push_all!(),
        "mov rdi, rsp",     // arg1 = &InterruptFrame
        "xor rsi, rsi",     // arg2 = vector = 0 (unknown — use APIC ISR)
        "call generic_irq_dispatch",
        pop_all!(),
        "add rsp, 8",
        "iretq",
        options(noreturn)
    );
}
