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
//! ## IPI vectors (registered by apic::apic_init)
//!
//! | Vector | Name              |
//! |--------|-------------------|
//! | 0xF0   | TLB shootdown     |
//! | 0xF1   | Reschedule        |
//! | 0xF2   | Function call     |
//! | 0xFE   | Panic halt        |
//! | 0xFF   | Spurious (LAPIC)  |
//!
//! IPI vectors use the `generic_irq_asm<N>` const-generic stub so that
//! `generic_irq_dispatch` receives the correct vector in `rsi`.
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

const GATE_INT:  u8 = 0x8E; // Present | DPL=0 | 64-bit interrupt gate (IF cleared)
const GATE_TRAP: u8 = 0x8F; // Present | DPL=0 | 64-bit trap gate     (IF preserved)

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

    fn set(&mut self, handler: usize, flags: u8, ist: u8) {
        self.offset_low  = handler as u16;
        self.selector    = crate::arch::x86_64::gdt::SELECTOR_KERNEL_CS;
        self.ist         = ist & 0x07;
        self.flags       = flags;
        self.offset_mid  = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self._reserved   = 0;
    }
}

#[repr(C, packed)]
struct IdtPointer { limit: u16, base: u64 }

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
    if IDT_LOADED.swap(true, Ordering::SeqCst) { return; }
    unsafe {
        // ── Exceptions without CPU-pushed error code (stub pushes 0) ────────
        IDT[ 0].set(exc_noerr_asm:: <0>  as usize, GATE_INT,  0); // #DE
        IDT[ 4].set(exc_noerr_asm:: <4>  as usize, GATE_INT,  0); // #OF
        IDT[ 5].set(exc_noerr_asm:: <5>  as usize, GATE_INT,  0); // #BR
        IDT[ 6].set(exc_noerr_asm:: <6>  as usize, GATE_INT,  0); // #UD
        IDT[ 7].set(exc_noerr_asm:: <7>  as usize, GATE_INT,  0); // #NM
        IDT[ 9].set(exc_noerr_asm:: <9>  as usize, GATE_INT,  0); // legacy coproc
        IDT[16].set(exc_noerr_asm::<16>  as usize, GATE_INT,  0); // #MF
        IDT[19].set(exc_noerr_asm::<19>  as usize, GATE_INT,  0); // #XM
        IDT[20].set(exc_noerr_asm::<20>  as usize, GATE_INT,  0); // #VE

        // ── Exceptions with CPU-pushed error code ─────────────────────────
        IDT[10].set(exc_err_asm::<10>    as usize, GATE_INT,  0); // #TS
        IDT[11].set(exc_err_asm::<11>    as usize, GATE_INT,  0); // #NP
        IDT[12].set(exc_err_asm::<12>    as usize, GATE_INT,  0); // #SS
        IDT[13].set(exc_err_asm::<13>    as usize, GATE_INT,  0); // #GP
        IDT[17].set(exc_err_asm::<17>    as usize, GATE_INT,  0); // #AC
        IDT[21].set(exc_err_asm::<21>    as usize, GATE_INT,  0); // #CP

        // ── Special / IST-switched exceptions ───────────────────────────
        IDT[ 1].set(db_asm              as usize, GATE_TRAP, 0); // #DB  (trap gate)
        IDT[ 2].set(nmi_asm             as usize, GATE_INT,  1); // #NMI IST1
        IDT[ 3].set(bp_asm              as usize, GATE_TRAP, 0); // #BP  (trap gate)
        IDT[ 8].set(exc_err_asm:: <8>   as usize, GATE_INT,  1); // #DF  IST1
        IDT[14].set(page_fault_asm      as usize, GATE_INT,  0); // #PF
        IDT[18].set(exc_noerr_asm::<18> as usize, GATE_INT,  1); // #MC  IST1

        // Reserved vectors 15, 22–31 — catch-all prevents triple-fault.
        for v in [15u8, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31] {
            IDT[v as usize].set(exc_noerr_asm::<255> as usize, GATE_INT, 0);
        }

        // ── IRQ vectors 32–239: generic per-vector stubs ─────────────────
        // Each stub bakes N into `mov rsi, N` so generic_irq_dispatch
        // receives the correct vector number.  The IPI range (0xF0–0xFE)
        // benefits from this: apic::register_ipi_handlers() uses
        // register_irq() to install Rust closures into IRQ_HANDLERS[N].
        IDT[32].set(timer_irq_asm as usize, GATE_INT, 0); // APIC timer (fast path)
        IDT[ 33].set(generic_irq_asm::<  33> as usize, GATE_INT, 0);
        IDT[ 34].set(generic_irq_asm::<  34> as usize, GATE_INT, 0);
        IDT[ 35].set(generic_irq_asm::<  35> as usize, GATE_INT, 0);
        IDT[ 36].set(generic_irq_asm::<  36> as usize, GATE_INT, 0);
        IDT[ 37].set(generic_irq_asm::<  37> as usize, GATE_INT, 0);
        IDT[ 38].set(generic_irq_asm::<  38> as usize, GATE_INT, 0);
        IDT[ 39].set(generic_irq_asm::<  39> as usize, GATE_INT, 0);
        IDT[ 40].set(generic_irq_asm::<  40> as usize, GATE_INT, 0);
        IDT[ 41].set(generic_irq_asm::<  41> as usize, GATE_INT, 0);
        IDT[ 42].set(generic_irq_asm::<  42> as usize, GATE_INT, 0);
        IDT[ 43].set(generic_irq_asm::<  43> as usize, GATE_INT, 0);
        IDT[ 44].set(generic_irq_asm::<  44> as usize, GATE_INT, 0);
        IDT[ 45].set(generic_irq_asm::<  45> as usize, GATE_INT, 0);
        IDT[ 46].set(generic_irq_asm::<  46> as usize, GATE_INT, 0);
        IDT[ 47].set(generic_irq_asm::<  47> as usize, GATE_INT, 0);
        IDT[ 48].set(generic_irq_asm::<  48> as usize, GATE_INT, 0);
        IDT[ 49].set(generic_irq_asm::<  49> as usize, GATE_INT, 0);
        IDT[ 50].set(generic_irq_asm::<  50> as usize, GATE_INT, 0);
        IDT[ 51].set(generic_irq_asm::<  51> as usize, GATE_INT, 0);
        IDT[ 52].set(generic_irq_asm::<  52> as usize, GATE_INT, 0);
        IDT[ 53].set(generic_irq_asm::<  53> as usize, GATE_INT, 0);
        IDT[ 54].set(generic_irq_asm::<  54> as usize, GATE_INT, 0);
        IDT[ 55].set(generic_irq_asm::<  55> as usize, GATE_INT, 0);
        IDT[ 56].set(generic_irq_asm::<  56> as usize, GATE_INT, 0);
        IDT[ 57].set(generic_irq_asm::<  57> as usize, GATE_INT, 0);
        IDT[ 58].set(generic_irq_asm::<  58> as usize, GATE_INT, 0);
        IDT[ 59].set(generic_irq_asm::<  59> as usize, GATE_INT, 0);
        IDT[ 60].set(generic_irq_asm::<  60> as usize, GATE_INT, 0);
        IDT[ 61].set(generic_irq_asm::<  61> as usize, GATE_INT, 0);
        IDT[ 62].set(generic_irq_asm::<  62> as usize, GATE_INT, 0);
        IDT[ 63].set(generic_irq_asm::<  63> as usize, GATE_INT, 0);
        IDT[ 64].set(generic_irq_asm::<  64> as usize, GATE_INT, 0);
        IDT[ 65].set(generic_irq_asm::<  65> as usize, GATE_INT, 0);
        IDT[ 66].set(generic_irq_asm::<  66> as usize, GATE_INT, 0);
        IDT[ 67].set(generic_irq_asm::<  67> as usize, GATE_INT, 0);
        IDT[ 68].set(generic_irq_asm::<  68> as usize, GATE_INT, 0);
        IDT[ 69].set(generic_irq_asm::<  69> as usize, GATE_INT, 0);
        IDT[ 70].set(generic_irq_asm::<  70> as usize, GATE_INT, 0);
        IDT[ 71].set(generic_irq_asm::<  71> as usize, GATE_INT, 0);
        IDT[ 72].set(generic_irq_asm::<  72> as usize, GATE_INT, 0);
        IDT[ 73].set(generic_irq_asm::<  73> as usize, GATE_INT, 0);
        IDT[ 74].set(generic_irq_asm::<  74> as usize, GATE_INT, 0);
        IDT[ 75].set(generic_irq_asm::<  75> as usize, GATE_INT, 0);
        IDT[ 76].set(generic_irq_asm::<  76> as usize, GATE_INT, 0);
        IDT[ 77].set(generic_irq_asm::<  77> as usize, GATE_INT, 0);
        IDT[ 78].set(generic_irq_asm::<  78> as usize, GATE_INT, 0);
        IDT[ 79].set(generic_irq_asm::<  79> as usize, GATE_INT, 0);
        IDT[ 80].set(generic_irq_asm::<  80> as usize, GATE_INT, 0);
        IDT[ 81].set(generic_irq_asm::<  81> as usize, GATE_INT, 0);
        IDT[ 82].set(generic_irq_asm::<  82> as usize, GATE_INT, 0);
        IDT[ 83].set(generic_irq_asm::<  83> as usize, GATE_INT, 0);
        IDT[ 84].set(generic_irq_asm::<  84> as usize, GATE_INT, 0);
        IDT[ 85].set(generic_irq_asm::<  85> as usize, GATE_INT, 0);
        IDT[ 86].set(generic_irq_asm::<  86> as usize, GATE_INT, 0);
        IDT[ 87].set(generic_irq_asm::<  87> as usize, GATE_INT, 0);
        IDT[ 88].set(generic_irq_asm::<  88> as usize, GATE_INT, 0);
        IDT[ 89].set(generic_irq_asm::<  89> as usize, GATE_INT, 0);
        IDT[ 90].set(generic_irq_asm::<  90> as usize, GATE_INT, 0);
        IDT[ 91].set(generic_irq_asm::<  91> as usize, GATE_INT, 0);
        IDT[ 92].set(generic_irq_asm::<  92> as usize, GATE_INT, 0);
        IDT[ 93].set(generic_irq_asm::<  93> as usize, GATE_INT, 0);
        IDT[ 94].set(generic_irq_asm::<  94> as usize, GATE_INT, 0);
        IDT[ 95].set(generic_irq_asm::<  95> as usize, GATE_INT, 0);
        IDT[ 96].set(generic_irq_asm::<  96> as usize, GATE_INT, 0);
        IDT[ 97].set(generic_irq_asm::<  97> as usize, GATE_INT, 0);
        IDT[ 98].set(generic_irq_asm::<  98> as usize, GATE_INT, 0);
        IDT[ 99].set(generic_irq_asm::<  99> as usize, GATE_INT, 0);
        IDT[100].set(generic_irq_asm::< 100> as usize, GATE_INT, 0);
        IDT[101].set(generic_irq_asm::< 101> as usize, GATE_INT, 0);
        IDT[102].set(generic_irq_asm::< 102> as usize, GATE_INT, 0);
        IDT[103].set(generic_irq_asm::< 103> as usize, GATE_INT, 0);
        IDT[104].set(generic_irq_asm::< 104> as usize, GATE_INT, 0);
        IDT[105].set(generic_irq_asm::< 105> as usize, GATE_INT, 0);
        IDT[106].set(generic_irq_asm::< 106> as usize, GATE_INT, 0);
        IDT[107].set(generic_irq_asm::< 107> as usize, GATE_INT, 0);
        IDT[108].set(generic_irq_asm::< 108> as usize, GATE_INT, 0);
        IDT[109].set(generic_irq_asm::< 109> as usize, GATE_INT, 0);
        IDT[110].set(generic_irq_asm::< 110> as usize, GATE_INT, 0);
        IDT[111].set(generic_irq_asm::< 111> as usize, GATE_INT, 0);
        IDT[112].set(generic_irq_asm::< 112> as usize, GATE_INT, 0);
        IDT[113].set(generic_irq_asm::< 113> as usize, GATE_INT, 0);
        IDT[114].set(generic_irq_asm::< 114> as usize, GATE_INT, 0);
        IDT[115].set(generic_irq_asm::< 115> as usize, GATE_INT, 0);
        IDT[116].set(generic_irq_asm::< 116> as usize, GATE_INT, 0);
        IDT[117].set(generic_irq_asm::< 117> as usize, GATE_INT, 0);
        IDT[118].set(generic_irq_asm::< 118> as usize, GATE_INT, 0);
        IDT[119].set(generic_irq_asm::< 119> as usize, GATE_INT, 0);
        IDT[120].set(generic_irq_asm::< 120> as usize, GATE_INT, 0);
        IDT[121].set(generic_irq_asm::< 121> as usize, GATE_INT, 0);
        IDT[122].set(generic_irq_asm::< 122> as usize, GATE_INT, 0);
        IDT[123].set(generic_irq_asm::< 123> as usize, GATE_INT, 0);
        IDT[124].set(generic_irq_asm::< 124> as usize, GATE_INT, 0);
        IDT[125].set(generic_irq_asm::< 125> as usize, GATE_INT, 0);
        IDT[126].set(generic_irq_asm::< 126> as usize, GATE_INT, 0);
        IDT[127].set(generic_irq_asm::< 127> as usize, GATE_INT, 0);
        IDT[128].set(generic_irq_asm::< 128> as usize, GATE_INT, 0);
        IDT[129].set(generic_irq_asm::< 129> as usize, GATE_INT, 0);
        IDT[130].set(generic_irq_asm::< 130> as usize, GATE_INT, 0);
        IDT[131].set(generic_irq_asm::< 131> as usize, GATE_INT, 0);
        IDT[132].set(generic_irq_asm::< 132> as usize, GATE_INT, 0);
        IDT[133].set(generic_irq_asm::< 133> as usize, GATE_INT, 0);
        IDT[134].set(generic_irq_asm::< 134> as usize, GATE_INT, 0);
        IDT[135].set(generic_irq_asm::< 135> as usize, GATE_INT, 0);
        IDT[136].set(generic_irq_asm::< 136> as usize, GATE_INT, 0);
        IDT[137].set(generic_irq_asm::< 137> as usize, GATE_INT, 0);
        IDT[138].set(generic_irq_asm::< 138> as usize, GATE_INT, 0);
        IDT[139].set(generic_irq_asm::< 139> as usize, GATE_INT, 0);
        IDT[140].set(generic_irq_asm::< 140> as usize, GATE_INT, 0);
        IDT[141].set(generic_irq_asm::< 141> as usize, GATE_INT, 0);
        IDT[142].set(generic_irq_asm::< 142> as usize, GATE_INT, 0);
        IDT[143].set(generic_irq_asm::< 143> as usize, GATE_INT, 0);
        IDT[144].set(generic_irq_asm::< 144> as usize, GATE_INT, 0);
        IDT[145].set(generic_irq_asm::< 145> as usize, GATE_INT, 0);
        IDT[146].set(generic_irq_asm::< 146> as usize, GATE_INT, 0);
        IDT[147].set(generic_irq_asm::< 147> as usize, GATE_INT, 0);
        IDT[148].set(generic_irq_asm::< 148> as usize, GATE_INT, 0);
        IDT[149].set(generic_irq_asm::< 149> as usize, GATE_INT, 0);
        IDT[150].set(generic_irq_asm::< 150> as usize, GATE_INT, 0);
        IDT[151].set(generic_irq_asm::< 151> as usize, GATE_INT, 0);
        IDT[152].set(generic_irq_asm::< 152> as usize, GATE_INT, 0);
        IDT[153].set(generic_irq_asm::< 153> as usize, GATE_INT, 0);
        IDT[154].set(generic_irq_asm::< 154> as usize, GATE_INT, 0);
        IDT[155].set(generic_irq_asm::< 155> as usize, GATE_INT, 0);
        IDT[156].set(generic_irq_asm::< 156> as usize, GATE_INT, 0);
        IDT[157].set(generic_irq_asm::< 157> as usize, GATE_INT, 0);
        IDT[158].set(generic_irq_asm::< 158> as usize, GATE_INT, 0);
        IDT[159].set(generic_irq_asm::< 159> as usize, GATE_INT, 0);
        IDT[160].set(generic_irq_asm::< 160> as usize, GATE_INT, 0);
        IDT[161].set(generic_irq_asm::< 161> as usize, GATE_INT, 0);
        IDT[162].set(generic_irq_asm::< 162> as usize, GATE_INT, 0);
        IDT[163].set(generic_irq_asm::< 163> as usize, GATE_INT, 0);
        IDT[164].set(generic_irq_asm::< 164> as usize, GATE_INT, 0);
        IDT[165].set(generic_irq_asm::< 165> as usize, GATE_INT, 0);
        IDT[166].set(generic_irq_asm::< 166> as usize, GATE_INT, 0);
        IDT[167].set(generic_irq_asm::< 167> as usize, GATE_INT, 0);
        IDT[168].set(generic_irq_asm::< 168> as usize, GATE_INT, 0);
        IDT[169].set(generic_irq_asm::< 169> as usize, GATE_INT, 0);
        IDT[170].set(generic_irq_asm::< 170> as usize, GATE_INT, 0);
        IDT[171].set(generic_irq_asm::< 171> as usize, GATE_INT, 0);
        IDT[172].set(generic_irq_asm::< 172> as usize, GATE_INT, 0);
        IDT[173].set(generic_irq_asm::< 173> as usize, GATE_INT, 0);
        IDT[174].set(generic_irq_asm::< 174> as usize, GATE_INT, 0);
        IDT[175].set(generic_irq_asm::< 175> as usize, GATE_INT, 0);
        IDT[176].set(generic_irq_asm::< 176> as usize, GATE_INT, 0);
        IDT[177].set(generic_irq_asm::< 177> as usize, GATE_INT, 0);
        IDT[178].set(generic_irq_asm::< 178> as usize, GATE_INT, 0);
        IDT[179].set(generic_irq_asm::< 179> as usize, GATE_INT, 0);
        IDT[180].set(generic_irq_asm::< 180> as usize, GATE_INT, 0);
        IDT[181].set(generic_irq_asm::< 181> as usize, GATE_INT, 0);
        IDT[182].set(generic_irq_asm::< 182> as usize, GATE_INT, 0);
        IDT[183].set(generic_irq_asm::< 183> as usize, GATE_INT, 0);
        IDT[184].set(generic_irq_asm::< 184> as usize, GATE_INT, 0);
        IDT[185].set(generic_irq_asm::< 185> as usize, GATE_INT, 0);
        IDT[186].set(generic_irq_asm::< 186> as usize, GATE_INT, 0);
        IDT[187].set(generic_irq_asm::< 187> as usize, GATE_INT, 0);
        IDT[188].set(generic_irq_asm::< 188> as usize, GATE_INT, 0);
        IDT[189].set(generic_irq_asm::< 189> as usize, GATE_INT, 0);
        IDT[190].set(generic_irq_asm::< 190> as usize, GATE_INT, 0);
        IDT[191].set(generic_irq_asm::< 191> as usize, GATE_INT, 0);
        IDT[192].set(generic_irq_asm::< 192> as usize, GATE_INT, 0);
        IDT[193].set(generic_irq_asm::< 193> as usize, GATE_INT, 0);
        IDT[194].set(generic_irq_asm::< 194> as usize, GATE_INT, 0);
        IDT[195].set(generic_irq_asm::< 195> as usize, GATE_INT, 0);
        IDT[196].set(generic_irq_asm::< 196> as usize, GATE_INT, 0);
        IDT[197].set(generic_irq_asm::< 197> as usize, GATE_INT, 0);
        IDT[198].set(generic_irq_asm::< 198> as usize, GATE_INT, 0);
        IDT[199].set(generic_irq_asm::< 199> as usize, GATE_INT, 0);
        IDT[200].set(generic_irq_asm::< 200> as usize, GATE_INT, 0);
        IDT[201].set(generic_irq_asm::< 201> as usize, GATE_INT, 0);
        IDT[202].set(generic_irq_asm::< 202> as usize, GATE_INT, 0);
        IDT[203].set(generic_irq_asm::< 203> as usize, GATE_INT, 0);
        IDT[204].set(generic_irq_asm::< 204> as usize, GATE_INT, 0);
        IDT[205].set(generic_irq_asm::< 205> as usize, GATE_INT, 0);
        IDT[206].set(generic_irq_asm::< 206> as usize, GATE_INT, 0);
        IDT[207].set(generic_irq_asm::< 207> as usize, GATE_INT, 0);
        IDT[208].set(generic_irq_asm::< 208> as usize, GATE_INT, 0);
        IDT[209].set(generic_irq_asm::< 209> as usize, GATE_INT, 0);
        IDT[210].set(generic_irq_asm::< 210> as usize, GATE_INT, 0);
        IDT[211].set(generic_irq_asm::< 211> as usize, GATE_INT, 0);
        IDT[212].set(generic_irq_asm::< 212> as usize, GATE_INT, 0);
        IDT[213].set(generic_irq_asm::< 213> as usize, GATE_INT, 0);
        IDT[214].set(generic_irq_asm::< 214> as usize, GATE_INT, 0);
        IDT[215].set(generic_irq_asm::< 215> as usize, GATE_INT, 0);
        IDT[216].set(generic_irq_asm::< 216> as usize, GATE_INT, 0);
        IDT[217].set(generic_irq_asm::< 217> as usize, GATE_INT, 0);
        IDT[218].set(generic_irq_asm::< 218> as usize, GATE_INT, 0);
        IDT[219].set(generic_irq_asm::< 219> as usize, GATE_INT, 0);
        IDT[220].set(generic_irq_asm::< 220> as usize, GATE_INT, 0);
        IDT[221].set(generic_irq_asm::< 221> as usize, GATE_INT, 0);
        IDT[222].set(generic_irq_asm::< 222> as usize, GATE_INT, 0);
        IDT[223].set(generic_irq_asm::< 223> as usize, GATE_INT, 0);
        IDT[224].set(generic_irq_asm::< 224> as usize, GATE_INT, 0);
        IDT[225].set(generic_irq_asm::< 225> as usize, GATE_INT, 0);
        IDT[226].set(generic_irq_asm::< 226> as usize, GATE_INT, 0);
        IDT[227].set(generic_irq_asm::< 227> as usize, GATE_INT, 0);
        IDT[228].set(generic_irq_asm::< 228> as usize, GATE_INT, 0);
        IDT[229].set(generic_irq_asm::< 229> as usize, GATE_INT, 0);
        IDT[230].set(generic_irq_asm::< 230> as usize, GATE_INT, 0);
        IDT[231].set(generic_irq_asm::< 231> as usize, GATE_INT, 0);
        IDT[232].set(generic_irq_asm::< 232> as usize, GATE_INT, 0);
        IDT[233].set(generic_irq_asm::< 233> as usize, GATE_INT, 0);
        IDT[234].set(generic_irq_asm::< 234> as usize, GATE_INT, 0);
        IDT[235].set(generic_irq_asm::< 235> as usize, GATE_INT, 0);
        IDT[236].set(generic_irq_asm::< 236> as usize, GATE_INT, 0);
        IDT[237].set(generic_irq_asm::< 237> as usize, GATE_INT, 0);
        IDT[238].set(generic_irq_asm::< 238> as usize, GATE_INT, 0);
        IDT[239].set(generic_irq_asm::< 239> as usize, GATE_INT, 0);
        // IPI vectors 0xF0–0xFE — must pass correct N so dispatch works.
        IDT[0xF0].set(generic_irq_asm::<0xF0> as usize, GATE_INT, 0); // TLB shootdown
        IDT[0xF1].set(generic_irq_asm::<0xF1> as usize, GATE_INT, 0); // Reschedule
        IDT[0xF2].set(generic_irq_asm::<0xF2> as usize, GATE_INT, 0); // Func call
        IDT[0xF3].set(generic_irq_asm::<0xF3> as usize, GATE_INT, 0);
        IDT[0xF4].set(generic_irq_asm::<0xF4> as usize, GATE_INT, 0);
        IDT[0xF5].set(generic_irq_asm::<0xF5> as usize, GATE_INT, 0);
        IDT[0xF6].set(generic_irq_asm::<0xF6> as usize, GATE_INT, 0);
        IDT[0xF7].set(generic_irq_asm::<0xF7> as usize, GATE_INT, 0);
        IDT[0xF8].set(generic_irq_asm::<0xF8> as usize, GATE_INT, 0);
        IDT[0xF9].set(generic_irq_asm::<0xF9> as usize, GATE_INT, 0);
        IDT[0xFA].set(generic_irq_asm::<0xFA> as usize, GATE_INT, 0);
        IDT[0xFB].set(generic_irq_asm::<0xFB> as usize, GATE_INT, 0);
        IDT[0xFC].set(generic_irq_asm::<0xFC> as usize, GATE_INT, 0);
        IDT[0xFD].set(generic_irq_asm::<0xFD> as usize, GATE_INT, 0);
        IDT[0xFE].set(generic_irq_asm::<0xFE> as usize, GATE_INT, 0); // Panic halt
        IDT[0xFF].set(generic_irq_asm::<0xFF> as usize, GATE_INT, 0); // LAPIC spurious

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
            base:  IDT.as_ptr() as u64,
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
    let mnemonic = EXCEPTION_NAMES.get(vector as usize).copied().unwrap_or("UNKNOWN");
    crate::console::println!(
        "[EXCEPTION] #{} (vec={:#x}) err={:#x} rip={:#x} rsp={:#x} rflags={:#x}",
        mnemonic, vector, frame.error_code, frame.rip, frame.rsp, frame.rflags
    );
    dump_registers(frame);

    let pid = crate::proc::scheduler::current_pid();
    if pid != 0 {
        crate::proc::signal::send_signal(pid, 11);
        crate::proc::scheduler::schedule();
    } else {
        loop { crate::arch::api::Cpu::halt(); }
    }
}

#[no_mangle]
pub extern "C" fn nmi_handler(frame: &mut InterruptFrame) {
    crate::console::println!(
        "[NMI] rip={:#x} rsp={:#x}",
        frame.rip, frame.rsp
    );
    // TODO: inspect NMI source (ECC, watchdog, IOCK#).
}

// ── #DB handler — single-step (RFLAGS.TF) and hardware breakpoints/watchpoints
//
// Called for:
//   • Single-step: RFLAGS.TF was set by rsp_x86_64::step_set_tf()
//   • Hardware BP/watchpoint: DR0–DR3 triggered via DR7
//
// When the gdbstub feature is active:
//   1. Clear RFLAGS.TF from the *saved* frame so iretq does not re-arm it.
//   2. Clear DR6 (status register) so the next #DB isn't a false positive.
//   3. Notify the GDB session that the target has stopped.
//
// When gdbstub is not active fall through to generic_exception_handler.

const RFLAGS_TF: u64 = 1 << 8;

#[no_mangle]
pub unsafe extern "C" fn db_handler(frame: *mut InterruptFrame) {
    #[cfg(feature = "gdbstub")]
    {
        let f = &mut *frame;

        // 1. Clear TF in the saved RFLAGS so it is not re-armed after iretq.
        f.rflags &= !RFLAGS_TF;

        // 2. Clear DR6 (debug status) to avoid stale bits on the next #DB.
        //    We write zero directly rather than going through proc_debug so
        //    this works even before the GDB session is fully attached.
        core::arch::asm!("mov dr6, {z}", z = in(reg) 0u64, options(nostack, nomem));

        // 3. Hand control to the GDB stop-reply loop.
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

// ── #BP handler — INT3 / software breakpoint (0xCC)
//
// The CPU does NOT decrement RIP after a trap-gate #BP — RIP already points
// past the 0xCC byte.  We rewind by 1 so GDB sees the address of the
// breakpoint instruction itself (matching the address stored in SwBreakpointTable).

#[no_mangle]
pub unsafe extern "C" fn bp_handler(frame: *mut InterruptFrame) {
    #[cfg(feature = "gdbstub")]
    {
        let f = &mut *frame;

        // Rewind RIP by 1: GDB expects stop address == breakpoint address.
        f.rip = f.rip.saturating_sub(1);

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

#[no_mangle]
pub extern "C" fn page_fault_handler(frame: &mut InterruptFrame, faulting_va: u64) {
    let error_code = frame.error_code;
    let va = faulting_va as usize;
    let present = error_code & 0x1 != 0;
    let user    = error_code & 0x4 != 0;

    if !present {
        if crate::mm::page_fault::handle_demand_fault(va) { return; }
    }
    if crate::proc::cow_fault::handle_cow_fault(va, error_code) { return; }

    let pid = crate::proc::scheduler::current_pid();
    crate::console::println!(
        "[#PF] pid={} va={:#x} err={:#x} present={} user={} rip={:#x}",
        pid, va, error_code, present, user, frame.rip
    );
    if pid != 0 {
        crate::proc::signal::send_signal(pid, 11);
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
        "  r8 ={:#018x} r9 ={:#018x} r10={:#018x} r11={:#018x}",
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

/// Per-vector IRQ stub.  Encodes the vector number N as an immediate into
/// `rsi` so `generic_irq_dispatch` always receives the correct vector.
/// This replaces the old single `generic_irq_asm_stub` that passed rsi=0.
#[naked]
unsafe extern "C" fn generic_irq_asm<const N: u64>() {
    core::arch::asm!(
        "push 0",
        push_all!(),
        "mov rdi, rsp",
        "mov rsi, {N}",
        "call generic_irq_dispatch",
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
