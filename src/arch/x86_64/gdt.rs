//! Global Descriptor Table + Task State Segment — x86-64 implementation.
//!
//! ## GDT layout (selectors are byte offsets)
//!
//! ```text
//!  Index  Selector   Descriptor
//!  ─────  ────────   ──────────────────────────────────────────────────────
//!    0    0x00       Null (required by architecture)
//!    1    0x08       Kernel code  DPL=0, L=1 (64-bit code segment)
//!    2    0x10       Kernel data  DPL=0, writable
//!    3    0x18       User code    DPL=3, L=1  → SYSRET target CS  (0x1B|RPL3)
//!    4    0x20       User data    DPL=3       → SYSRET target SS  (0x23|RPL3)
//!    5    0x28       TSS low  ─┐  16-byte (two-slot) system descriptor
//!    6    0x30       TSS high ─┘
//! ```
//!
//! ## Segment selector arithmetic
//!
//! `MSR_STAR = 0x001B_0008 << 32`
//! - SYSCALL kernel CS  = STAR\[47:32\]       = 0x08  → GDT\[1\]
//! - SYSRET  user   CS  = STAR\[63:48\] \| 3  = 0x1B  → GDT\[3\] + RPL3
//! - SYSRET  user   SS  = STAR\[63:48\]+8\|3  = 0x23  → GDT\[4\] + RPL3
//!
//! ## Task State Segment
//!
//! Each logical CPU has its own `PerCpuGdt` that bundles a 7-slot GDT and a
//! 64-bit TSS.  The TSS stores:
//!
//! | Field | Purpose |
//! |-------|---------|
//! | RSP0  | Ring-3 → ring-0 stack for IDT entries (updated by scheduler) |
//! | IST1  | Emergency stack for #NMI / #DF / #MC (never reused) |
//! | IST2  | (reserved for future watchdog / MCE extension) |
//!
//! ## Per-CPU GSBASE struct
//!
//! ```text
//!  gs:0   kstack_rsp    — kernel RSP for the current task (scheduler writes)
//!  gs:8   user_rsp_save — scratch slot written by syscall_asm_entry (swapgs)
//!  gs:16  cpu_id        — logical CPU id (read-only after init)
//!  gs:24  tss_rsp0_ptr  — &TSS.rsp0 fast-path for context_switch
//! ```
//!
//! ## SMP
//!
//! `gdt_init()` initialises the BSP's per-CPU GDT/TSS and writes the GDT
//! pointer to the AP trampoline shared-memory slot at physical 0x8FD0 so
//! that each AP can `lgdt` the same descriptor table.
//!
//! `init_ap(cpu_id)` is called from `ap_entry()` on each AP after paging is
//! enabled.  It allocates a fresh kernel stack for the AP, patches the AP's
//! TSS RSP0 and IST1, rebuilds the GDT slots, and loads them.
//!
//! ## Call order
//!
//! ```text
//!   BSP:  gdt_init()  →  idt_init()  →  syscall_setup()
//!   AP:   gdt::init_ap(cpu_id)  →  idt::load()  →  apic::ap_init_local()
//! ```

use crate::mm::kstack::alloc_kstack;
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

/// Present | DPL=0 | S=1 | Executable | L=1 (64-bit code).
const KCODE64: u64 = (1 << 47) | (1 << 44) | (1 << 43) | (1 << 53);
/// Present | DPL=0 | S=1 | Writable (data).
const KDATA: u64 = (1 << 47) | (1 << 44) | (1 << 41);
/// Present | DPL=3 | S=1 | Executable | L=1 (64-bit user code).
const UCODE64: u64 = (1 << 47) | (3 << 45) | (1 << 44) | (1 << 43) | (1 << 53);
/// Present | DPL=3 | S=1 | Writable (user data).
const UDATA: u64 = (1 << 47) | (3 << 45) | (1 << 44) | (1 << 41);

/// Kernel code segment selector (RPL=0).
pub const SELECTOR_KERNEL_CS: u16 = 0x08;
/// Kernel data segment selector (RPL=0).
pub const SELECTOR_KERNEL_DS: u16 = 0x10;
/// User code segment selector (RPL=3) — set on SYSRET.
pub const SELECTOR_USER_CS: u16 = 0x1B;
/// User data segment selector (RPL=3) — set on SYSRET.
pub const SELECTOR_USER_DS: u16 = 0x23;
/// TSS selector (RPL=0).
pub const SELECTOR_TSS: u16 = 0x28;

// The TSS must be 104 bytes and aligned to at least 4 bytes.
// `iomap_base` is set to sizeof(Tss) so there is no I/O permission bitmap;
// any I/O port access from ring 3 raises #GP.

#[repr(C, packed)]
struct Tss {
    _reserved0: u32,
    rsp0: u64, // ring-0 stack for IDT transitions from ring 3
    rsp1: u64, // (unused; would be ring-1 stack)
    rsp2: u64, // (unused; would be ring-2 stack)
    _reserved1: u64,
    ist1: u64, // IST1 — used by #NMI, #DF, #MC (idt.rs IST=1)
    ist2: u64, // IST2 — reserved for future watchdog use
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    _reserved2: u64,
    _reserved3: u16,
    iomap_base: u16, // offset to IOPM; = sizeof(Tss) disables IOPM
}

impl Tss {
    const fn zero() -> Self {
        Self {
            _reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            _reserved1: 0,
            ist1: 0,
            ist2: 0,
            ist3: 0,
            ist4: 0,
            ist5: 0,
            ist6: 0,
            ist7: 0,
            _reserved2: 0,
            _reserved3: 0,
            iomap_base: core::mem::size_of::<Tss>() as u16,
        }
    }
}

// Each logical CPU owns its own copy of the GDT and TSS so that RSP0/IST1
// updates are lock-free (no cross-CPU cache line bouncing on context switch).
// The GDT is 7 × 8 = 56 bytes; TSS is 104 bytes.

#[repr(C, align(16))]
struct PerCpuGdt {
    gdt: [u64; 7],
    tss: Tss,
    used: AtomicBool,
}

impl PerCpuGdt {
    const fn zero() -> Self {
        Self {
            gdt: [0u64; 7],
            tss: Tss::zero(),
            used: AtomicBool::new(false),
        }
    }
}

/// Maximum logical CPUs.  Must match `smp::MAX_CPUS`.
const MAX_CPUS: usize = 256;

static mut PER_CPU_GDT: [PerCpuGdt; MAX_CPUS] = [const { PerCpuGdt::zero() }; MAX_CPUS];

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct GdtPointer {
    pub limit: u16,
    pub base: u64,
}

// Pointed to by IA32_GS_BASE (MSR 0xC000_0101).
// KERNEL_GS_BASE (MSR 0xC000_0102) holds the same value so that `swapgs`
// inside syscall_asm_entry swaps in the kernel struct and `swapgs` on exit
// swaps it back out.
// Alignment: 64 bytes (one cache line) to avoid false sharing on SMP.

#[repr(C, align(64))]
pub struct PerCpu {
    /// gs:0  — kernel RSP for the running task; read by IDT ring-3 entries
    ///          via the TSS RSP0, and by syscall_asm_entry via GS directly.
    pub kstack_rsp: u64,
    /// gs:8  — user RSP scratch slot; written by `syscall_asm_entry` before
    ///          switching to the kernel stack.
    pub user_rsp_save: u64,
    /// gs:16 — logical CPU id (read-only after percpu_init).
    pub cpu_id: u32,
    pub _pad0: u32,
    /// gs:24 — pointer to TSS.rsp0; context_switch() writes the new task's
    ///          kernel stack top here for the fast path (avoids a full
    ///          gdt::update_rsp0() call on every switch).
    pub tss_rsp0_ptr: u64,
}

static mut PER_CPU_STRUCTS: [PerCpu; MAX_CPUS] = [const {
    PerCpu {
        kstack_rsp: 0,
        user_rsp_save: 0,
        cpu_id: 0,
        _pad0: 0,
        tss_rsp0_ptr: 0,
    }
}; MAX_CPUS];

static mut BSP_GDT_PTR: GdtPointer = GdtPointer { limit: 0, base: 0 };

/// Encode a 64-bit available TSS descriptor (two GDT slots).
/// Intel SDM Vol.3A §7.2.3, Table 3-2.
fn tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    // Low 64-bit word:
    //   [15: 0] limit[15:0]
    //   [31:16] base[15:0]
    //   [39:32] base[23:16]
    //   [43:40] type = 0b1001 (64-bit available TSS)
    //   [44]    S    = 0      (system descriptor)
    //   [46:45] DPL  = 0
    //   [47]    P    = 1      (present)
    //   [51:48] limit[19:16]
    //   [55]    G    = 0      (byte granularity)
    //   [63:56] base[31:24]
    let lo: u64 = (limit as u64 & 0x0000_FFFF)
        | ((base as u64 & 0x00FF_FFFF) << 16)
        | ((base as u64 & 0xFF00_0000) << 32)
        | ((limit as u64 & 0x000F_0000) << 32)
        | (0x89u64 << 40); // P=1, DPL=0, Type=0x9 (64-bit avail TSS)
                           // High 64-bit word:
                           //   [31:0] base[63:32]
                           //   [63:32] reserved (must be zero)
    let hi: u64 = (base >> 32) & 0xFFFF_FFFF;
    (lo, hi)
}

/// Fill the 7-slot GDT for a CPU whose TSS lives at `tss_ptr`.
unsafe fn fill_gdt(gdt: &mut [u64; 7], tss_ptr: *const Tss) {
    gdt[0] = 0; // null
    gdt[1] = KCODE64; // 0x08 kernel CS
    gdt[2] = KDATA; // 0x10 kernel DS
    gdt[3] = UCODE64; // 0x18 user CS
    gdt[4] = UDATA; // 0x20 user DS
    let tss_base = tss_ptr as u64;
    let tss_limit = (core::mem::size_of::<Tss>() - 1) as u32;
    let (lo, hi) = tss_descriptor(tss_base, tss_limit);
    gdt[5] = lo; // 0x28 TSS low
    gdt[6] = hi; // 0x30 TSS high
}

/// Load a GDT pointer + reload all segment registers + load TSS.
/// Must be called with a valid pointer to a GDT whose TSS is already set up.
unsafe fn load_gdt(ptr: &GdtPointer) {
    asm!("lgdt [{p}]", p = in(reg) ptr, options(nostack, readonly));

    // Reload CS via the far-return (retfq) trick — the only reliable way to
    // update CS in 64-bit mode without a real far jump target.
    asm!(
        "push {cs}",
        "lea {tmp}, [rip + 2f]",
        "push {tmp}",
        "retfq",
        "2:",
        cs  = in(reg) SELECTOR_KERNEL_CS as u64,
        tmp = out(reg) _,
        options(nostack),
    );

    // Reload data/stack segments.
    asm!(
        "mov {ds:x}, {kds}",
        "mov ds, {ds:x}",
        "mov es, {ds:x}",
        "mov ss, {ds:x}",
        "xor {z:e}, {z:e}",
        "mov fs, {z:x}",
        "mov gs, {z:x}",
        kds = const SELECTOR_KERNEL_DS as u64,
        ds  = out(reg) _,
        z   = out(reg) _,
        options(nostack),
    );

    // Load TSS (selector 0x28 = GDT[5]).
    asm!("ltr {sel:x}", sel = in(reg) SELECTOR_TSS, options(nostack));
}

/// Point IA32_GS_BASE and KERNEL_GS_BASE at `pcpu`.
unsafe fn set_gsbase(pcpu: *const PerCpu) {
    let addr = pcpu as u64;
    let lo = addr as u32;
    let hi = (addr >> 32) as u32;
    // IA32_GS_BASE — active GS base (used after `swapgs` or in kernel mode).
    asm!("wrmsr", in("ecx") 0xC000_0101u32,
         in("eax") lo, in("edx") hi, options(nostack));
    // KERNEL_GS_BASE — swapped in by `swapgs`; syscall_asm_entry uses this.
    asm!("wrmsr", in("ecx") 0xC000_0102u32,
         in("eax") lo, in("edx") hi, options(nostack));
}

/// Write the GDT pointer into the AP trampoline shared-memory region so that
/// `ap_boot.s` can `lgdt` it before jumping to 64-bit mode.
///
/// Layout (defined in ap_boot.s comments):
///   0x8FD0  GdtPointer  (10 bytes; two-slot pseudo-descriptor)
///   0x8FE8  u64         per-AP kernel stack pointer
///   0x8FF0  u32         PML4 physical address (written by paging.rs)
///   0x8FF8  u32         cpu_id (written by apic::start_ap)
unsafe fn write_trampoline_gdt(ptr: &GdtPointer) {
    const TRAMPOLINE_GDT_SLOT: usize = 0x8FD0;
    let dst = TRAMPOLINE_GDT_SLOT as *mut GdtPointer;
    core::ptr::write_volatile(dst, *ptr);
    core::sync::atomic::fence(Ordering::Release);
}

/// Initialise the BSP's GDT, TSS, PerCpu struct, and GSBASE.
///
/// Must be called **once** on the BSP, before `idt_init()` and
/// `syscall_setup()`.  Also publishes the GDT pointer to the AP trampoline
/// shared-memory region so APs can use the same table descriptor.
pub fn gdt_init() {
    let cpu_id: usize = 0; // BSP is always logical CPU 0.
    let kstack_top = alloc_kstack();

    // Allocate a dedicated IST1 emergency stack (8 KiB above the kernel stack).
    // This stack is ONLY used for #NMI / #DF / #MC; it must never be reused.
    let ist1_top = alloc_kstack();

    unsafe {
        let slot = &mut PER_CPU_GDT[cpu_id];
        slot.used.store(true, Ordering::Relaxed);

        // Patch TSS stacks.
        slot.tss.rsp0 = kstack_top as u64;
        slot.tss.ist1 = ist1_top as u64;
        slot.tss.ist2 = ist1_top as u64; // IST2 shares IST1 for now
        slot.tss.iomap_base = core::mem::size_of::<Tss>() as u16;

        // Build the 7 GDT entries.
        fill_gdt(&mut slot.gdt, &slot.tss as *const Tss);

        // Build the pseudo-descriptor.
        let ptr = GdtPointer {
            limit: (core::mem::size_of::<[u64; 7]>() - 1) as u16,
            base: slot.gdt.as_ptr() as u64,
        };
        BSP_GDT_PTR = ptr;

        // Load GDT + reload segment registers + LTR.
        load_gdt(&BSP_GDT_PTR);

        // Publish GDT pointer to AP trampoline shared page.
        write_trampoline_gdt(&BSP_GDT_PTR);

        // Init PerCpu struct.
        let pcpu = &mut PER_CPU_STRUCTS[cpu_id];
        pcpu.kstack_rsp = kstack_top as u64;
        pcpu.user_rsp_save = 0;
        pcpu.cpu_id = cpu_id as u32;
        pcpu.tss_rsp0_ptr = &slot.tss.rsp0 as *const u64 as u64;

        // Point GS_BASE at the per-CPU struct.
        set_gsbase(pcpu);
    }
}

/// Initialise a non-BSP (AP) CPU's GDT, TSS, PerCpu struct, and GSBASE.
///
/// Called from `ap_entry(cpu_id)` after the AP has paging enabled.
/// Unsafe because it writes per-CPU statics and executes privileged
/// instructions.
pub unsafe fn init_ap(cpu_id: u32) {
    let idx = cpu_id as usize;
    assert!(
        idx < MAX_CPUS,
        "gdt::init_ap: cpu_id {} exceeds MAX_CPUS",
        idx
    );

    let kstack_top = alloc_kstack();
    let ist1_top = alloc_kstack();

    let slot = &mut PER_CPU_GDT[idx];
    slot.used.store(true, Ordering::Relaxed);

    slot.tss.rsp0 = kstack_top as u64;
    slot.tss.ist1 = ist1_top as u64;
    slot.tss.ist2 = ist1_top as u64;
    slot.tss.iomap_base = core::mem::size_of::<Tss>() as u16;

    fill_gdt(&mut slot.gdt, &slot.tss as *const Tss);

    let ptr = GdtPointer {
        limit: (core::mem::size_of::<[u64; 7]>() - 1) as u16,
        base: slot.gdt.as_ptr() as u64,
    };
    load_gdt(&ptr);

    let pcpu = &mut PER_CPU_STRUCTS[idx];
    pcpu.kstack_rsp = kstack_top as u64;
    pcpu.user_rsp_save = 0;
    pcpu.cpu_id = cpu_id;
    pcpu.tss_rsp0_ptr = &slot.tss.rsp0 as *const u64 as u64;

    set_gsbase(pcpu);

    log::debug!(
        "gdt: AP {} online kstack={:#x} ist1={:#x}",
        cpu_id,
        kstack_top,
        ist1_top
    );
}

/// Write a new AP kernel stack pointer into the trampoline shared-memory slot
/// at 0x8FE8 before firing the SIPI for `cpu_id`.
///
/// Called by `apic::start_ap()` immediately before the IPI sequence.
pub fn write_trampoline_kstack(kstack_top: usize) {
    const SLOT: usize = 0x8FE8;
    unsafe {
        core::ptr::write_volatile(SLOT as *mut u64, kstack_top as u64);
        core::sync::atomic::fence(Ordering::Release);
    }
}

/// Update RSP0 in this CPU's TSS and the GS-visible kstack_rsp.
///
/// Called by the scheduler on every context switch to ensure that ring-3
/// interrupts land on the new task's kernel stack rather than the old one.
///
/// # Safety
/// Must be called with the correct `cpu_id` for the running CPU.
#[inline]
pub fn update_rsp0(cpu_id: u32, kstack_top: usize) {
    unsafe {
        let idx = cpu_id as usize;
        // Update TSS.rsp0 — used by the CPU on IDT entry from ring 3.
        PER_CPU_GDT[idx].tss.rsp0 = kstack_top as u64;
        // Update the GS-visible copy — used by syscall_asm_entry fast path.
        PER_CPU_STRUCTS[idx].kstack_rsp = kstack_top as u64;
    }
}

/// Read the current CPU's logical ID from GS:16.
///
/// Returns 0 if GSBASE has not yet been configured (early boot).
#[inline]
pub fn current_cpu_id() -> u32 {
    let id: u32;
    unsafe {
        asm!(
            "mov {0:e}, gs:[16]",
            out(reg) id,
            options(nostack, readonly, preserves_flags)
        );
    }
    id
}

/// Return a raw pointer to this CPU's `PerCpu` struct (via current cpu_id).
///
/// Used by hot paths (syscall entry, context switch) that need gs:0 without
/// a full GS segment dereference in Rust code.
#[inline]
pub fn current_percpu() -> *mut PerCpu {
    let id = current_cpu_id() as usize;
    unsafe { &mut PER_CPU_STRUCTS[id] as *mut PerCpu }
}

/// Return a reference to the BSP GDT pointer.
/// Called by `idt::load()` on APs to read the limit/base.
pub fn bsp_gdt_ptr() -> GdtPointer {
    unsafe { BSP_GDT_PTR }
}
