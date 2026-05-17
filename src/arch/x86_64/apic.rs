//! x86-64 Local APIC driver.
//!
//! Supports both xAPIC (MMIO) and x2APIC (MSR-based).  Mode is
//! auto-detected once per CPU at `enable_apic()` via CPUID leaf 1 ECX[21].
//!
//! ## Initialisation order
//!
//!   BSP: `gdt::gdt_init()` → `idt::idt_init()` → `apic::apic_init()`
//!   AP:  `gdt::init_ap()`  → `idt::load()`     → `apic::ap_init_local()`
//!
//! ## LAPIC register map (xAPIC byte offsets — 32-bit access only)
//!
//! | Offset | Name                      |
//! |--------|---------------------------|
//! | 0x020  | ID                        |
//! | 0x030  | Version                   |
//! | 0x080  | Task Priority (TPR)       |
//! | 0x0B0  | EOI                       |
//! | 0x0F0  | Spurious Vector (SVR)     |
//! | 0x300  | ICR low                   |
//! | 0x310  | ICR high                  |
//! | 0x320  | LVT Timer                 |
//! | 0x380  | Timer Initial Count       |
//! | 0x390  | Timer Current Count       |
//! | 0x3E0  | Timer Divide Config       |

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::arch::x86_64::mem_layout::{apic as ml, trampoline as tram, higher_half};

// ── Mode flag ─────────────────────────────────────────────────────────────────

static X2APIC_MODE: AtomicBool  = AtomicBool::new(false);
static LAPIC_PHYS:  AtomicU64   = AtomicU64::new(ml::LAPIC_PHYS_DEFAULT);

#[inline] fn x2apic() -> bool { X2APIC_MODE.load(Ordering::Relaxed) }

/// Override the LAPIC physical base (called from ACPI MADT parser).
pub fn set_lapic_base(phys: u64) { LAPIC_PHYS.store(phys, Ordering::Relaxed); }

// ── LAPIC MMIO virtual address ────────────────────────────────────────────────

#[inline]
fn lapic_virt() -> usize {
    higher_half::phys_to_virt(LAPIC_PHYS.load(Ordering::Relaxed))
}

// ── Low-level register access ─────────────────────────────────────────────────

#[inline]
unsafe fn lapic_read(offset: usize) -> u32 {
    if x2apic() {
        let msr = ml::X2APIC_MSR_BASE + (offset as u32 >> 4);
        let lo: u32;
        core::arch::asm!("rdmsr",
            in("ecx") msr, out("eax") lo, out("edx") _,
            options(nostack, preserves_flags));
        lo
    } else {
        core::ptr::read_volatile((lapic_virt() + offset) as *const u32)
    }
}

#[inline]
unsafe fn lapic_write(offset: usize, val: u32) {
    if x2apic() {
        let msr = ml::X2APIC_MSR_BASE + (offset as u32 >> 4);
        core::arch::asm!("wrmsr",
            in("ecx") msr, in("eax") val, in("edx") 0u32,
            options(nostack, preserves_flags));
    } else {
        core::ptr::write_volatile((lapic_virt() + offset) as *mut u32, val);
    }
}

/// Write the ICR.  x2APIC: single 64-bit wrmsr.  xAPIC: write hi then lo
/// (lo write triggers delivery, so hi must be stable first).
#[inline]
unsafe fn icr_write(hi: u32, lo: u32) {
    if x2apic() {
        let msr = ml::X2APIC_MSR_BASE + (ml::REG_ICR_LO as u32 >> 4);
        let v64 = ((hi as u64) << 32) | lo as u64;
        core::arch::asm!("wrmsr",
            in("ecx") msr,
            in("eax") v64 as u32,
            in("edx") (v64 >> 32) as u32,
            options(nostack, preserves_flags));
    } else {
        lapic_write(ml::REG_ICR_HI, hi);
        lapic_write(ml::REG_ICR_LO, lo);
    }
}

/// Spin until xAPIC ICR delivery-status bit clears (no-op for x2APIC).
#[inline]
unsafe fn icr_wait_idle() {
    if !x2apic() {
        while lapic_read(ml::REG_ICR_LO) & ml::ICR_DELIVERY_PENDING != 0 {
            core::hint::spin_loop();
        }
    }
}

// ── APIC enable ───────────────────────────────────────────────────────────────

/// Detect and enable x2APIC (if supported) or xAPIC on the calling CPU.
/// Safe to call on BSP and each AP independently.
unsafe fn enable_apic() {
    // CPUID leaf 1, ECX[21] = x2APIC support.
    let ecx: u32;
    core::arch::asm!("cpuid",
        inout("eax") 1u32 => _,
        out("ecx") ecx,
        out("ebx") _, out("edx") _,
        options(nostack, preserves_flags));
    let has_x2 = (ecx >> 21) & 1 != 0;

    // Read IA32_APIC_BASE (MSR 0x1B).
    let (base_lo, base_hi): (u32, u32);
    core::arch::asm!("rdmsr",
        in("ecx") ml::MSR_IA32_APIC_BASE,
        out("eax") base_lo, out("edx") base_hi,
        options(nostack, preserves_flags));
    let mut base = (base_lo as u64) | ((base_hi as u64) << 32);

    if has_x2 {
        base |= ml::MSR_APIC_GLOBAL_EN as u64 | ml::MSR_X2APIC_ENABLE as u64;
        X2APIC_MODE.store(true, Ordering::Relaxed);
    } else {
        base |= ml::MSR_APIC_GLOBAL_EN as u64;
        // Record actual MMIO base from MSR (firmware may relocate it).
        let phys = base & ml::MSR_APIC_BASE_MASK;
        LAPIC_PHYS.store(phys, Ordering::Relaxed);
    }

    core::arch::asm!("wrmsr",
        in("ecx") ml::MSR_IA32_APIC_BASE,
        in("eax") base as u32,
        in("edx") (base >> 32) as u32,
        options(nostack, preserves_flags));
}

/// Common LAPIC setup run on every CPU after `enable_apic()`.
unsafe fn local_apic_setup() {
    // Accept all interrupt priorities.
    lapic_write(ml::REG_TPR, 0);
    // Mask thermal, perf, LINT0/1, error LVTs to avoid spurious faults.
    for off in [
        ml::REG_THERMAL_LVT,
        ml::REG_PERF_LVT,
        ml::REG_LINT0_LVT,
        ml::REG_LINT1_LVT,
        ml::REG_ERROR_LVT,
    ] {
        lapic_write(off, ml::LVT_MASKED);
    }
    // Spurious Vector Register: software-enable LAPIC + spurious vector.
    lapic_write(ml::REG_SPURIOUS,
        ml::SPURIOUS_ENABLE | ml::SPURIOUS_VECTOR as u32);
    // Timer: divide-by-16, periodic, vector 32 (~1 ms at 100 MHz bus clock).
    // Calibrate properly in time::calibrate_lapic_timer() later.
    lapic_write(ml::REG_TIMER_DCR, 0x3);  // divide by 16
    lapic_write(ml::REG_TIMER_LVT, (1 << 17) | crate::smp::ipi::APIC_TIMER_VECTOR as u32);
    lapic_write(ml::REG_TIMER_ICR, 100_000);
}

// ── Public init entrypoints ───────────────────────────────────────────────────

/// BSP initialisation.  Call after `gdt_init()` and `idt_init()`.
pub fn apic_init() {
    unsafe {
        enable_apic();
        local_apic_setup();
    }
    register_ipi_handlers();
    log::info!("apic: BSP id={:#x} mode={}",
        lapic_id(), if x2apic() { "x2APIC" } else { "xAPIC" });
}

/// Per-AP initialisation.  Called from `ap_entry()` after GDT+IDT are live.
pub unsafe fn ap_init_local() {
    enable_apic();
    local_apic_setup();
}

// ── EOI ───────────────────────────────────────────────────────────────────────

/// Signal end-of-interrupt to the LAPIC.  Must be called before returning
/// from any LAPIC-sourced interrupt handler (timer, IPI, etc.).
#[inline]
pub fn send_eoi() {
    unsafe { lapic_write(ml::REG_EOI, 0); }
}

// ── LAPIC ID ──────────────────────────────────────────────────────────────────

/// Return the calling CPU's APIC ID.
#[inline]
pub fn lapic_id() -> u32 {
    unsafe {
        if x2apic() {
            lapic_read(ml::REG_ID)      // x2APIC: full 32-bit APIC ID
        } else {
            lapic_read(ml::REG_ID) >> 24 // xAPIC: ID in bits [31:24]
        }
    }
}

// ── IPI send ──────────────────────────────────────────────────────────────────

/// Send a fixed-mode IPI to `apic_id` on `vector`.
/// Called by `smp::ipi::send()` after the pending bit has been set.
pub fn send_ipi(apic_id: u32, vector: u8) {
    unsafe {
        icr_wait_idle();
        icr_write(
            apic_id,
            ml::ICR_DELIVERY_FIXED
                | ml::ICR_LEVEL_ASSERT
                | vector as u32,
        );
        icr_wait_idle();
    }
}

// ── AP bring-up ───────────────────────────────────────────────────────────────

extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end:   u8;
}

/// Copy the trampoline into the low page, fill BSP-supplied slots, then
/// fire INIT–SIPI–SIPI for every non-BSP CPU in the topology table.
///
/// Called from `smp::init()` (x86_64 path) after `acpi::init()` has
/// registered all CPUs via `smp::register_cpu()`.
pub fn start_all_aps() {
    let tram_page = (ml::TRAMPOLINE_PHYS >> 12) as u8;
    let tram_base = ml::TRAMPOLINE_PHYS;

    // ── 1. Copy trampoline code into physical 0x8000 (direct-map) ─────────
    unsafe {
        let src  = &ap_trampoline_start as *const u8;
        let end  = &ap_trampoline_end   as *const u8;
        let len  = end as usize - src as usize;
        let dst  = higher_half::phys_to_virt(tram_base) as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
    }

    // ── 2. Write the kernel PML4 PA into the trampoline slot ─────────────
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, preserves_flags));
        let slot = higher_half::phys_to_virt(tram_base + tram::GDT_PTR_OFFSET as u64 - 0x20)
                   as *mut u64;  // PML4 slot = TRAMPOLINE_PHYS + 0xFF0
        let pml4_slot = higher_half::phys_to_virt(
            tram_base + tram::PML4_OFFSET as u64) as *mut u64;
        let _ = slot;
        core::ptr::write_volatile(pml4_slot, cr3 & !0xFFFu64);
    }

    // ── 3. Write the BSP's GDTR into the trampoline GDT-ptr slot ─────────
    unsafe {
        let gdt_slot = higher_half::phys_to_virt(
            tram_base + tram::GDT_PTR_OFFSET as u64) as *mut u8;
        core::arch::asm!("sgdt [{p}]", p = in(reg) gdt_slot, options(nostack));
    }

    // ── 4. Global INIT deassert, then assert ──────────────────────────────
    unsafe {
        icr_wait_idle();
        // Deassert to ensure clean state.
        icr_write(0,
            ml::ICR_DELIVERY_INIT
            | ml::ICR_LEVEL_DEASSERT
            | ml::ICR_TRIGGER_LEVEL
            | (3 << 18))  // all-including-self shorthand
        ;
        icr_wait_idle();
    }
    busy_wait_us(10_000);  // 10 ms

    unsafe {
        icr_wait_idle();
        icr_write(0,
            ml::ICR_DELIVERY_INIT
            | ml::ICR_LEVEL_ASSERT
            | ml::ICR_TRIGGER_LEVEL
            | (3 << 18))  // all-except-self shorthand
        ;
        icr_wait_idle();
    }
    busy_wait_us(10_000);

    // ── 5. Per-AP stack allocation + SIPI×2 ───────────────────────────────
    let total = crate::smp::num_cpus();
    for cpu_id in 0..total {
        let info = match crate::smp::cpu_info(cpu_id) {
            Some(i) if !i.is_bsp => i,
            _ => continue,
        };

        let stack_top = allocate_ap_stack(cpu_id);

        unsafe {
            let stack_slot = higher_half::phys_to_virt(
                tram_base + tram::KSTACK_OFFSET as u64) as *mut u64;
            let cpuid_slot = higher_half::phys_to_virt(
                tram_base + tram::CPU_ID_OFFSET as u64) as *mut u32;
            core::ptr::write_volatile(stack_slot, stack_top);
            core::ptr::write_volatile(cpuid_slot, cpu_id);
        }

        // Full fence — AP must see stack/cpu_id before it reads them.
        core::sync::atomic::fence(Ordering::SeqCst);

        unsafe {
            send_sipi(info.hw_id, tram_page);
            busy_wait_us(200);
            send_sipi(info.hw_id, tram_page);  // second SIPI per MP spec §B.4
            busy_wait_us(200);
        }

        log::debug!("apic: SIPI → apic_id={} cpu={}", info.hw_id, cpu_id);
    }
}

unsafe fn send_sipi(apic_id: u32, page: u8) {
    icr_wait_idle();
    icr_write(
        apic_id,
        ml::ICR_DELIVERY_SIPI | ml::ICR_LEVEL_ASSERT | page as u32,
    );
    icr_wait_idle();
}

/// Allocate `AP_STACK_PAGES` physically contiguous pages and return the
/// virtual address of the top (stacks grow downward).
fn allocate_ap_stack(_cpu_id: u32) -> u64 {
    const AP_STACK_PAGES: usize = 16;  // 64 KiB
    let phys = crate::mm::pmm::alloc_pages(AP_STACK_PAGES)
        .expect("apic: AP stack allocation failed");
    let virt = higher_half::phys_to_virt(phys as u64);
    (virt + AP_STACK_PAGES * 0x1000) as u64
}

// ── IPI vector registration ───────────────────────────────────────────────────

/// Wire IPI vectors 0xF0/0xF1/0xF2/0xFE into the IDT.
/// Each handler: set pending bit (already done by sender), call
/// `ipi::dispatch()` to drain all pending bits, then EOI.
fn register_ipi_handlers() {
    use crate::arch::x86_64::idt;
    use crate::smp::ipi;

    idt::register_irq(ipi::IPI_TLB_SHOOTDOWN, |_f| {
        ipi::dispatch(crate::smp::percpu::current_cpu_id());
        send_eoi();
    });
    idt::register_irq(ipi::IPI_RESCHEDULE, |_f| {
        ipi::dispatch(crate::smp::percpu::current_cpu_id());
        send_eoi();
    });
    idt::register_irq(ipi::IPI_FUNC_CALL, |_f| {
        ipi::dispatch(crate::smp::percpu::current_cpu_id());
        send_eoi();
    });
    idt::register_irq(ipi::IPI_PANIC_HALT, |_f| {
        ipi::dispatch(crate::smp::percpu::current_cpu_id());
        send_eoi();  // unreachable if PanicHalt fires, kept for correctness
    });
}

// ── Micro-delay (TSC busy-spin, pre-calibration) ──────────────────────────────

#[inline]
fn busy_wait_us(us: u64) {
    // Conservative: assumes >= 1 GHz TSC at boot.
    // Replace with `time::busy_spin_ns(us * 1000)` once TSC is calibrated.
    const CYCLES_PER_US: u64 = 1_000;
    let end = rdtsc().wrapping_add(us * CYCLES_PER_US);
    while rdtsc().wrapping_sub(end) as i64 > 0 {
        core::hint::spin_loop();
    }
}

#[inline]
fn rdtsc() -> u64 {
    let lo: u32; let hi: u32;
    unsafe {
        core::arch::asm!("rdtsc",
            out("eax") lo, out("edx") hi,
            options(nostack, preserves_flags));
    }
    (hi as u64) << 32 | lo as u64
}

// ── APIC timer vector constant (used by local_apic_setup) ────────────────────
pub mod ipi {
    /// Vector 32 = APIC timer (IDT slot 32, same as IRQ0 in PIC-free mode).
    pub const APIC_TIMER_VECTOR: u8 = 32;
}
