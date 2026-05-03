//! Global Descriptor Table + Task State Segment.
//!
//! ## GDT layout
//!   [0] 0x00  null descriptor
//!   [1] 0x08  kernel code  DPL=0, L=1 (64-bit)
//!   [2] 0x10  kernel data  DPL=0
//!   [3] 0x18  user code    DPL=3, L=1  → SYSRET CS  = 0x1B (0x18|RPL3)
//!   [4] 0x20  user data    DPL=3       → SYSRET SS  = 0x23 (0x20|RPL3)
//!   [5] 0x28  TSS low  ┐  16-byte system descriptor
//!   [6] 0x30  TSS high ┘
//!
//! ## Segment selector arithmetic (matches syscall.rs STAR value)
//!   MSR_STAR = 0x001B_0008 << 32
//!     SYSCALL kernel CS = STAR[47:32]      = 0x08  → GDT[1]
//!     SYSRET  user   CS = STAR[63:48] | 3  = 0x1B  → GDT[3]+RPL3
//!     SYSRET  user   SS = STAR[63:48]+8|3  = 0x23  → GDT[4]+RPL3
//!
//! ## Per-CPU GSBASE struct
//!   offset 0: kernel RSP  (written by gdt_init; updated by scheduler)
//!   offset 8: user   RSP  (save slot used by syscall_asm_entry)
//!   syscall_asm_entry does: swapgs; mov [gs:8], rsp; mov rsp, [gs:0]
//!
//! ## TSS
//!   RSP0 = kernel stack top for ring-3 → ring-0 transitions via IDT
//!   (SYSCALL does NOT use RSP0; it uses gs:0. IDT entries do.)
//!
//! Call gdt_init() exactly once at boot, before idt_init() and syscall_setup().

use core::arch::asm;
use crate::mm::kstack::alloc_kstack;

// ── Descriptor encoding helpers ───────────────────────────────────────────

/// Pack a 64-bit code/data descriptor.
/// base and limit are ignored in 64-bit mode (except for FS/GS), so we zero them.
const fn code_desc(dpl: u8, long: bool) -> u64 {
    let mut d: u64 = 0;
    d |= 1 << 44;            // S=1 (code/data, not system)
    d |= 1 << 43;            // Executable
    d |= 1 << 47;            // Present
    d |= (dpl as u64 & 3) << 45; // DPL
    if long { d |= 1 << 53; } // L=1 → 64-bit code
    // G=0, D=0 required when L=1
    d
}

const fn data_desc(dpl: u8) -> u64 {
    let mut d: u64 = 0;
    d |= 1 << 44;            // S=1
    d |= 1 << 47;            // Present
    d |= (dpl as u64 & 3) << 45;
    d |= 1 << 41;            // Writable
    d
}

// ── TSS descriptor (16 bytes = two GDT slots) ─────────────────────────────

fn tss_desc(base: u64, limit: u32) -> (u64, u64) {
    let lo: u64 =
          ((base & 0x00FF_FFFF) << 16)
        | ((base & 0xFF00_0000) << 32)
        | ((limit as u64 & 0xFFFF))
        | ((limit as u64 & 0x000F_0000) << 32)
        | (0x89 << 40);  // Present, DPL=0, type=0x9 (64-bit available TSS)
    let hi: u64 = (base >> 32) & 0xFFFF_FFFF;
    (lo, hi)
}

// ── x86-64 TSS (only RSP0 and IST1 are used here) ─────────────────────────

#[repr(C, packed)]
struct Tss {
    _reserved0: u32,
    rsp0:       u64,   // ring-0 stack for IDT entries from ring 3
    rsp1:       u64,
    rsp2:       u64,
    _reserved1: u64,
    ist1:       u64,   // IST stack 1 (double-fault etc.)
    ist2:       u64,
    ist3:       u64,
    ist4:       u64,
    ist5:       u64,
    ist6:       u64,
    ist7:       u64,
    _reserved2: u64,
    _reserved3: u16,
    iomap_base: u16,   // = sizeof(TSS) → no IOPM
}

impl Tss {
    const fn zero() -> Self {
        Self {
            _reserved0: 0, rsp0: 0, rsp1: 0, rsp2: 0,
            _reserved1: 0, ist1: 0, ist2: 0, ist3: 0,
            ist4: 0, ist5: 0, ist6: 0, ist7: 0,
            _reserved2: 0, _reserved3: 0,
            iomap_base: core::mem::size_of::<Tss>() as u16,
        }
    }
}

// ── Per-CPU kernel/user RSP save area (pointed to by GSBASE) ──────────────

#[repr(C)]
pub struct PerCpu {
    pub kstack_rsp:   u64,  // gs:0  — kernel stack top for this task
    pub user_rsp_save: u64, // gs:8  — saved user RSP on syscall entry
}

// ── Statics ───────────────────────────────────────────────────────────────

static mut GDT: [u64; 7] = [0u64; 7];
static mut TSS: Tss = Tss::zero();
static mut PER_CPU: PerCpu = PerCpu { kstack_rsp: 0, user_rsp_save: 0 };

#[repr(C, packed)]
struct GdtPointer { limit: u16, base: u64 }

/// Initialise the GDT, TSS, and per-CPU GSBASE.
/// Must be called before idt_init() and syscall_setup().
pub fn gdt_init() {
    // Allocate the initial kernel stack (used by PID 0 / the boot task).
    let kstack_top = alloc_kstack();

    unsafe {
        // Fill GDT entries.
        GDT[0] = 0;                         // null
        GDT[1] = code_desc(0, true);        // 0x08 kernel CS
        GDT[2] = data_desc(0);              // 0x10 kernel DS
        GDT[3] = code_desc(3, true);        // 0x18 user CS  (SYSRET → 0x1B)
        GDT[4] = data_desc(3);              // 0x20 user DS  (SYSRET → 0x23)

        // TSS: RSP0 = kernel stack top for ring-3 IDT entries.
        TSS.rsp0 = kstack_top as u64;
        TSS.ist1 = kstack_top as u64; // double-fault stack
        let tss_base  = &TSS as *const Tss as u64;
        let tss_limit = (core::mem::size_of::<Tss>() - 1) as u32;
        let (lo, hi) = tss_desc(tss_base, tss_limit);
        GDT[5] = lo;
        GDT[6] = hi;

        // Load GDT.
        let ptr = GdtPointer {
            limit: (core::mem::size_of::<[u64; 7]>() - 1) as u16,
            base:  GDT.as_ptr() as u64,
        };
        asm!("lgdt [{p}]", p = in(reg) &ptr, options(nostack));

        // Reload segment registers.
        // CS must be loaded via a far return or far jmp — use retf trick.
        asm!(
            // Push new CS (0x08) and RIP of 2f onto the stack, then retfq.
            "push 0x08",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            // Reload data segments.
            "mov ax, 0x10",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            "xor ax, ax",
            "mov fs, ax",
            "mov gs, ax",
            options(nostack)
        );

        // Load TSS (selector 0x28, RPL=0).
        asm!("ltr ax", in("ax") 0x28u16, options(nostack));

        // Set up per-CPU struct and point GSBASE at it.
        PER_CPU.kstack_rsp   = kstack_top as u64;
        PER_CPU.user_rsp_save = 0;
        let pcpu_ptr = &PER_CPU as *const PerCpu as u64;
        // WRMSR(IA32_GS_BASE = 0xC000_0101)
        let lo = pcpu_ptr as u32;
        let hi = (pcpu_ptr >> 32) as u32;
        asm!("wrmsr", in("ecx") 0xC000_0101u32,
             in("eax") lo, in("edx") hi, options(nostack));
        // Also set KERNEL_GS_BASE (0xC000_0102) for swapgs.
        asm!("wrmsr", in("ecx") 0xC000_0102u32,
             in("eax") lo, in("edx") hi, options(nostack));
    }
}

/// Update RSP0 in the TSS and GS:0 for the incoming task.
/// Called by the scheduler on every context switch.
pub fn update_rsp0(kstack_top: usize) {
    unsafe {
        TSS.rsp0 = kstack_top as u64;
        PER_CPU.kstack_rsp = kstack_top as u64;
    }
}
