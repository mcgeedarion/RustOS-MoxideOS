//! x86-64 Local APIC driver.
//!
//! Supports both xAPIC (MMIO) and x2APIC (MSR-based).  Mode is
//! auto-detected once per CPU at `enable_apic()` via CPUID leaf 1 ECX[21].
//!
//! ## Initialisation order
//!
//!   BSP: `gdt::gdt_init()` → `idt::idt_init()` → `time::init()` →
//!        `apic::apic_init()` → `apic::calibrate_lapic_timer()`
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

static X2APIC_MODE: AtomicBool  = AtomicBool::new(false);
static LAPIC_PHYS:  AtomicU64   = AtomicU64::new(ml::LAPIC_PHYS_DEFAULT);

/// Calibrated APIC timer ticks per millisecond (set by calibrate_lapic_timer).
static APIC_TICKS_PER_MS: AtomicU64 = AtomicU64::new(0);

#[inline] fn x2apic() -> bool { X2APIC_MODE.load(Ordering::Relaxed) }

/// Override the LAPIC physical base (called from ACPI MADT parser).
pub fn set_lapic_base(phys: u64) { LAPIC_PHYS.store(phys, Ordering::Relaxed); }

#[inline]
fn lapic_virt() -> usize {
    higher_half::phys_to_virt(LAPIC_PHYS.load(Ordering::Relaxed))
}

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
/// The APIC timer LVT is left MASKED here; `calibrate_lapic_timer()` on the
/// BSP (and `ap_init_local()` on APs after calibration is complete) will
/// unmask it with the correct ICR.
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
    // Timer: divide-by-16, MASKED until calibrate_lapic_timer() runs.
    lapic_write(ml::REG_TIMER_DCR, 0x3);  // divide by 16
    lapic_write(ml::REG_TIMER_LVT, ml::LVT_MASKED);
    lapic_write(ml::REG_TIMER_ICR, 0);
}

/// BSP initialisation.  Call after `gdt_init()`, `idt_init()`, and
/// critically **after** `time::init()` so that `busy_wait_us()` is accurate.
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
/// Reuses the BSP-calibrated APIC_TICKS_PER_MS to arm the timer directly.
pub unsafe fn ap_init_local() {
    enable_apic();
    local_apic_setup();
    // Arm timer using BSP-calibrated value if available.
    let ticks_per_ms = APIC_TICKS_PER_MS.load(Ordering::Relaxed);
    if ticks_per_ms > 0 {
        arm_periodic_1ms(ticks_per_ms);
    }
}

/// Calibrate the APIC bus clock and arm the periodic 1 ms timer.
///
/// Strategy (in priority order):
///   1. TSC window  — if `time::tsc` was calibrated (invariant TSC present).
///   2. HPET window — if HPET is initialised.
///   3. PIT window  — 8253 channel 2, always available on x86.
///
/// Must be called on the BSP after `apic_init()` and `time::init()`.
/// Unmasks the APIC timer LVT on completion.
pub fn calibrate_lapic_timer() {
    let ticks_per_ms = unsafe { measure_apic_ticks_per_ms() };
    APIC_TICKS_PER_MS.store(ticks_per_ms, Ordering::SeqCst);
    unsafe { arm_periodic_1ms(ticks_per_ms); }
    log::info!("apic: timer calibrated — {} ticks/ms (ICR={})",
        ticks_per_ms, ticks_per_ms);
}

/// Measure how many APIC bus ticks elapse in 10 ms, return ticks/ms.
unsafe fn measure_apic_ticks_per_ms() -> u64 {
    const DIVIDE_BY: u64 = 16; // must match REG_TIMER_DCR = 0x3
    const WINDOW_MS: u64 = 10;

    // Set APIC timer to count-down from max with divider, no interrupt.
    lapic_write(ml::REG_TIMER_DCR, 0x3);         // divide by 16
    lapic_write(ml::REG_TIMER_LVT, ml::LVT_MASKED);
    lapic_write(ml::REG_TIMER_ICR, 0xFFFF_FFFF);

    // Gate over WINDOW_MS using the best available reference.
    let elapsed_apic = measure_with_best_reference(WINDOW_MS);

    // Stop the count-down.
    lapic_write(ml::REG_TIMER_ICR, 0);

    // elapsed_apic = ticks elapsed in WINDOW_MS ms.
    // ticks_per_ms = elapsed_apic / WINDOW_MS
    let ticks_per_ms = (elapsed_apic / WINDOW_MS).max(1);
    ticks_per_ms
}

/// Spin for `window_ms` milliseconds using TSC → HPET → PIT in that order.
/// Returns the number of APIC timer ticks that elapsed.
unsafe fn measure_with_best_reference(window_ms: u64) -> u64 {
    use crate::time;

    let start_apic = lapic_read(ml::REG_TIMER_CCR) as u64;

    let tsc_freq = time::tsc::freq_hz();
    if tsc_freq > 0 {
        let tsc_ticks = tsc_freq / 1000 * window_ms;
        let t0 = rdtsc();
        while rdtsc().wrapping_sub(t0) < tsc_ticks {
            core::hint::spin_loop();
        }
        let end_apic = lapic_read(ml::REG_TIMER_CCR) as u64;
        return start_apic.saturating_sub(end_apic); // counts down
    }

    if time::hpet::is_ready() {
        let t0_ns = time::hpet::read_ns();
        let target_ns = window_ms * 1_000_000;
        while time::hpet::read_ns().wrapping_sub(t0_ns) < target_ns {
            core::hint::spin_loop();
        }
        let end_apic = lapic_read(ml::REG_TIMER_CCR) as u64;
        return start_apic.saturating_sub(end_apic);
    }

    // PIT channel 2, mode 0 (one-shot), 11932 counts ≈ 10 ms.
    // We fire one PIT window per window_ms / 10 iteration (or one if ≤ 10 ms).
    pit_wait_ms(window_ms);
    let end_apic = lapic_read(ml::REG_TIMER_CCR) as u64;
    start_apic.saturating_sub(end_apic)
}

/// Busy-spin for `ms` milliseconds using the 8253 PIT channel 2.
/// Does not require the heap, TSC, or HPET.
unsafe fn pit_wait_ms(ms: u64) {
    const PIT_HZ: u64 = 1_193_182;
    // Max PIT one-shot count = 65535 ≈ 54.9 ms.  Split into 10 ms chunks.
    const CHUNK_MS:    u64 = 10;
    const CHUNK_COUNT: u16 = 11932; // PIT counts for ~10 ms

    let full_chunks = ms / CHUNK_MS;
    let remainder   = ms % CHUNK_MS;

    for _ in 0..full_chunks {
        pit_oneshot(CHUNK_COUNT);
    }
    if remainder > 0 {
        let counts = (remainder * PIT_HZ / 1000) as u16;
        pit_oneshot(counts.max(1));
    }
}

/// Program PIT channel 2 mode 0 and wait for OUT to go high.
unsafe fn pit_oneshot(count: u16) {
    // Disable gate, configure channel 2 mode 0.
    let mut v: u8 = inb(0x61) & 0xFE; // gate off
    outb(0x61, v & 0xFD);             // speaker off
    outb(0x43, 0xB0);                 // channel 2, mode 0, binary
    outb(0x42, (count & 0xFF) as u8);
    outb(0x42, (count >> 8) as u8);
    // Start count: set gate bit.
    v = inb(0x61) | 0x01;
    outb(0x61, v);
    // Wait for OUT2 (bit 5 of port 0x61) to go high.
    while inb(0x61) & 0x20 == 0 {
        core::hint::spin_loop();
    }
    // Gate off to stop.
    outb(0x61, inb(0x61) & 0xFE);
}

/// Arm the APIC periodic timer for a 1 ms period.
/// Unmasks the LVT timer vector.
unsafe fn arm_periodic_1ms(ticks_per_ms: u64) {
    let icr = (ticks_per_ms as u32).max(1);
    lapic_write(ml::REG_TIMER_DCR, 0x3); // divide by 16
    lapic_write(ml::REG_TIMER_ICR, icr);
    // Enable periodic mode (bit 17) + vector, unmask.
    lapic_write(ml::REG_TIMER_LVT,
        (1 << 17) | crate::smp::ipi::APIC_TIMER_VECTOR as u32);
}

/// Signal end-of-interrupt to the LAPIC.  Must be called before returning
/// from any LAPIC-sourced interrupt handler (timer, IPI, etc.).
#[inline]
pub fn send_eoi() {
    unsafe { lapic_write(ml::REG_EOI, 0); }
}

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

extern "C" {
    static ap_trampoline_start: u8;
    static ap_trampoline_end:   u8;
}

/// Copy the trampoline into the low page, fill BSP-supplied slots, then
/// fire INIT–SIPI–SIPI for every non-BSP CPU in the topology table.
///
/// Called from `smp::init()` (x86_64 path) after `acpi::init()` has
/// registered all CPUs via `smp::register_cpu()`.
/// Must be called AFTER `calibrate_lapic_timer()` so `busy_wait_us()` is
/// accurate.
pub fn start_all_aps() {
    let tram_page = (ml::TRAMPOLINE_PHYS >> 12) as u8;
    let tram_base = ml::TRAMPOLINE_PHYS;

    unsafe {
        let src  = &ap_trampoline_start as *const u8;
        let end  = &ap_trampoline_end   as *const u8;
        let len  = end as usize - src as usize;
        let dst  = higher_half::phys_to_virt(tram_base) as *mut u8;
        core::ptr::copy_nonoverlapping(src, dst, len);
    }

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

    unsafe {
        let gdt_slot = higher_half::phys_to_virt(
            tram_base + tram::GDT_PTR_OFFSET as u64) as *mut u8;
        core::arch::asm!("sgdt [{p}]", p = in(reg) gdt_slot, options(nostack));
    }

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
    busy_wait_us(10_000);  // 10 ms — now calibrated

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

/// Spin for `us` microseconds.
///
/// Uses the TSC multiplier from `time::tsc` if available (accurate on any
/// CPU speed).  Falls back to a PIT-based spin if the TSC has not been
/// calibrated yet (e.g. very early in boot before `time::init()`).
pub fn busy_wait_us(us: u64) {
    let freq = crate::time::tsc::freq_hz();
    if freq > 0 {
        // TSC path: exact regardless of CPU frequency.
        let tsc_ticks = freq / 1_000_000 * us;
        let t0 = rdtsc();
        while rdtsc().wrapping_sub(t0) < tsc_ticks {
            core::hint::spin_loop();
        }
    } else {
        // PIT path: no TSC yet — use PIT channel 2 (safe at any point).
        let ms = (us + 999) / 1000; // round up to ms
        unsafe { pit_wait_ms(ms.max(1)); }
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

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nostack));
    val
}

#[inline]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack));
}

pub mod ipi {
    /// Vector 32 = APIC timer (IDT slot 32, same as IRQ0 in PIC-free mode).
    pub const APIC_TIMER_VECTOR: u8 = 32;
}
