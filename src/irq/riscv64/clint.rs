//! RISC-V CLINT (Core Local INTerruptor) driver.
//!
//! The CLINT provides two facilities per hart:
//!   - **MSIP**   — machine-mode software interrupt (inter-processor interrupt)
//!   - **MTIMECMP** / **MTIME** — memory-mapped 64-bit timer
//!
//! ## Memory map (relative to CLINT base; QEMU virt default 0x0200_0000)
//!
//! ```text
//!  Offset                       Size  Description
//!  ─────────────────────────────────────────────────────────────────────
//!  0x0000 + hart*4              4     MSIP register (bit 0 = pending)
//!  0x4000 + hart*8              8     MTIMECMP for hart N
//!  0xBFF8                       8     MTIME (shared, read-only for S-mode)
//! ```
//!
//! ## Timer workflow
//!
//! OpenSBI exposes MTIME and MTIMECMP to S-mode via the SBI Timer extension
//! (EID 0x54494D45).  On QEMU this works perfectly.  On bare-metal designs
//! that skip SBI, the driver writes MTIMECMP directly via the MMIO base.
//!
//! The public API always prefers the SBI path and falls back to direct MMIO
//! when `USE_SBI_TIMER` is `false` (set by calling `set_use_sbi(false)` from
//! the FDT walker if the platform has no SBI runtime).
//!
//! ## MSIP (software IPI)
//!
//! Each hart's MSIP register is a 1-bit latch.  Writing 1 raises a pending
//! machine-mode software interrupt; writing 0 clears it.  S-mode code uses
//! this to send IPIs by calling into SBI `SEND_IPI` **or** by writing the
//! CLINT MSIP register directly when SBI is absent.
//!
//! ## kswapd / tick integration
//!
//! `clint::handle_timer_irq()` is called from the trap handler on every
//! timer interrupt.  It:
//!   1. Re-arms the next timer deadline (TIMECMP += interval_ticks).
//!   2. Calls `crate::mm::swap::kswapd_tick(16)` for background reclaim.
//!   3. Calls `crate::proc::scheduler::tick()` for preemptive scheduling.
//!   4. Calls `drm::vblank_tick_head(0)` to advance the simulated vblank.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

/// QEMU virt machine CLINT MMIO base (also the default on many SiFive boards).
pub const DEFAULT_BASE: usize = 0x0200_0000;

/// MTIME offset from CLINT base.
const MTIME_OFFSET: usize = 0x0000_BFF8;
/// MTIMECMP base offset; add `hart * 8` for the correct hart.
const MTIMECMP_OFFSET: usize = 0x0000_4000;
/// MSIP base offset; add `hart * 4`.
const MSIP_OFFSET: usize = 0x0000_0000;

/// Maximum number of harts this driver supports.
const MAX_HARTS: usize = 8;

/// SBI Timer extension ID ("TIME" in ASCII = 0x54494D45).
const SBI_EXT_TIMER: usize = 0x54494D45;
const SBI_TIMER_SET_TIMER: usize = 0;

/// SBI IPI extension ID.
const SBI_EXT_IPI: usize = 0x00735049;
const SBI_IPI_SEND: usize = 0;

/// Default tick interval in CLINT cycles (~10 ms at a 10 MHz timebase).
pub const DEFAULT_INTERVAL_TICKS: u64 = 100_000;

/// CLINT MMIO base address (physical = kernel-virtual for identity map).
static CLINT_BASE: AtomicUsize = AtomicUsize::new(DEFAULT_BASE);

/// Timer tick interval in CLINT cycles.
static INTERVAL: AtomicU64 = AtomicU64::new(DEFAULT_INTERVAL_TICKS);

/// Whether to use SBI ecall for timer programming (default: yes).
static USE_SBI_TIMER: AtomicBool = AtomicBool::new(true);

/// Global tick counter (incremented every `handle_timer_irq` call).
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Registered per-tick hook (called after scheduler + kswapd work).
static TICK_HOOK: Mutex<Option<fn()>> = Mutex::new(None);

#[inline]
unsafe fn read64(addr: usize) -> u64 {
    core::ptr::read_volatile(addr as *const u64)
}

#[inline]
unsafe fn write64(addr: usize, val: u64) {
    core::ptr::write_volatile(addr as *mut u64, val);
}

#[inline]
unsafe fn write32(addr: usize, val: u32) {
    core::ptr::write_volatile(addr as *mut u32, val);
}

/// Issue an SBI ecall.  Returns (error, value).
#[inline]
unsafe fn sbi_call(ext: usize, fid: usize, a0: usize, a1: usize, a2: usize) -> (isize, usize) {
    let error: isize;
    let value: usize;
    core::arch::asm!(
        "ecall",
        inlateout("a0") a0    => error,
        inlateout("a1") a1    => value,
        in("a2")         a2,
        in("a6")         fid,
        in("a7")         ext,
        options(nostack),
    );
    (error, value)
}

/// Override the CLINT MMIO base (called from FDT walker or board init).
///
/// Default is `DEFAULT_BASE` (0x0200_0000).
pub fn set_base(base: usize) {
    CLINT_BASE.store(base, Ordering::Relaxed);
}

/// Return the current CLINT MMIO base.
#[inline]
pub fn base() -> usize {
    CLINT_BASE.load(Ordering::Relaxed)
}

/// Configure the timer tick interval in CLINT cycles.
///
/// At a 10 MHz timebase, 10 ms = 100_000 cycles (the default).
pub fn set_interval(ticks: u64) {
    INTERVAL.store(ticks.max(1), Ordering::Relaxed);
}

/// Select whether the SBI Timer extension (EID 0x54494D45) is used to
/// program MTIMECMP.  Set to `false` on platforms without an SBI runtime.
pub fn set_use_sbi(sbi: bool) {
    USE_SBI_TIMER.store(sbi, Ordering::Relaxed);
}

/// Register a callback invoked on every timer tick (after scheduler work).
///
/// Only one hook can be registered at a time; a second call replaces the
/// previous hook.
pub fn register_tick_hook(f: fn()) {
    *TICK_HOOK.lock() = Some(f);
}

/// Return the total number of timer ticks since `init()`.
#[inline]
pub fn tick_count() -> u64 {
    TICK_COUNT.load(Ordering::Relaxed)
}

/// Initialise the CLINT timer for the BSP (hart 0).
///
/// Arms the first timer interrupt at `now + INTERVAL` ticks.
/// Call this once from `kernel_main` after FDT initialisation.
pub fn init() {
    let interval = INTERVAL.load(Ordering::Relaxed);
    let now = mtime();
    set_timecmp(0, now.wrapping_add(interval));
    // Enable the supervisor timer interrupt bit in sie.
    unsafe {
        // sie.STIE = bit 5
        core::arch::asm!("csrs sie, {}", in(reg) 1usize << 5, options(nostack));
    }
    crate::println!(
        "clint: init OK (base {:#x}, interval {} cycles)",
        CLINT_BASE.load(Ordering::Relaxed),
        interval
    );
}

/// Read the current MTIME counter.
///
/// On RV64 this is a single 64-bit read.  On RV32 we do the high/low dance
/// to avoid a torn read when the low word rolls over.
#[cfg(target_arch = "riscv64")]
pub fn mtime() -> u64 {
    let base = CLINT_BASE.load(Ordering::Relaxed);
    unsafe { read64(base + MTIME_OFFSET) }
}

#[cfg(not(target_arch = "riscv64"))]
pub fn mtime() -> u64 {
    // x86_64 / aarch64 stub — return TSC-like value.
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32;
        let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
        (hi as u64) << 32 | lo as u64
    }
    #[cfg(not(target_arch = "x86_64"))]
    0u64
}

/// Program the MTIMECMP register for `hart`, using SBI if available.
pub fn set_timecmp(hart: usize, deadline: u64) {
    if hart >= MAX_HARTS {
        return;
    }
    if USE_SBI_TIMER.load(Ordering::Relaxed) {
        unsafe {
            sbi_call(
                SBI_EXT_TIMER,
                SBI_TIMER_SET_TIMER,
                deadline as usize,
                (deadline >> 32) as usize,
                0,
            );
        }
    } else {
        let base = CLINT_BASE.load(Ordering::Relaxed);
        unsafe {
            write64(base + MTIMECMP_OFFSET + hart * 8, deadline);
        }
    }
}

/// Read the MTIMECMP for `hart` directly from MMIO (bypass SBI).
/// Returns 0 on non-RISC-V targets.
pub fn timecmp(hart: usize) -> u64 {
    if hart >= MAX_HARTS {
        return 0;
    }
    let base = CLINT_BASE.load(Ordering::Relaxed);
    #[cfg(target_arch = "riscv64")]
    unsafe {
        read64(base + MTIMECMP_OFFSET + hart * 8)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        let _ = base;
        0u64
    }
}

/// Number of CLINT cycles remaining until the next timer interrupt on `hart`.
pub fn ticks_until_irq(hart: usize) -> u64 {
    let cmp = timecmp(hart);
    let now = mtime();
    cmp.saturating_sub(now)
}

/// Called from the supervisor trap handler on every timer interrupt
/// (scause = 0x8000_0000_0000_0005 on RV64).
///
/// Re-arms the timer, runs kswapd, ticks the scheduler, and advances vblank.
pub fn handle_timer_irq() {
    let interval = INTERVAL.load(Ordering::Relaxed);
    let hart: usize;
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("mv {}, tp", out(reg) hart, options(nostack, nomem));
    }
    #[cfg(not(target_arch = "riscv64"))]
    let hart = 0usize;

    // Re-arm: next deadline = current TIMECMP + interval (avoids drift).
    let next = timecmp(hart).wrapping_add(interval);
    set_timecmp(hart, next);

    // Increment global tick counter.
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);

    // kswapd: proactive memory reclaim (background, bounded to 16 pages/tick).
    crate::mm::swap::kswapd_tick(16);

    // Scheduler preemption tick.
    crate::proc::scheduler::tick();

    // Simulated vblank for DRM/KMS (head 0).
    crate::drivers::drm::vblank_tick_head(0);

    // User-registered hook.
    if let Some(f) = *TICK_HOOK.lock() {
        f();
    }
}

/// Send a software IPI to `target_hart`.
///
/// Uses SBI `SEND_IPI` ecall when SBI is available; falls back to direct
/// MSIP MMIO write otherwise.
pub fn send_ipi(target_hart: usize) {
    if target_hart >= MAX_HARTS {
        return;
    }
    if USE_SBI_TIMER.load(Ordering::Relaxed) {
        // SBI IPI: a0 = hart_mask, a1 = hart_mask_base
        let mask = 1usize << target_hart;
        unsafe {
            sbi_call(SBI_EXT_IPI, SBI_IPI_SEND, mask, 0, 0);
        }
    } else {
        let base = CLINT_BASE.load(Ordering::Relaxed);
        unsafe {
            write32(base + MSIP_OFFSET + target_hart * 4, 1);
        }
    }
}

/// Clear the MSIP latch for `hart` (call from the IPI handler after
/// processing).
pub fn clear_ipi(hart: usize) {
    if hart >= MAX_HARTS {
        return;
    }
    let base = CLINT_BASE.load(Ordering::Relaxed);
    unsafe {
        write32(base + MSIP_OFFSET + hart * 4, 0);
    }
}

/// Read the raw MSIP register for `hart` (bit 0 = pending).
pub fn msip(hart: usize) -> u32 {
    if hart >= MAX_HARTS {
        return 0;
    }
    let base = CLINT_BASE.load(Ordering::Relaxed);
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::ptr::read_volatile((base + MSIP_OFFSET + hart * 4) as *const u32)
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        let _ = base;
        0u32
    }
}

/// Spin for at least `us` microseconds using MTIME.
///
/// `timebase_hz` is the CLINT timebase frequency in Hz (e.g. 10_000_000 for
/// the QEMU virt machine).  Pass 0 to use the default of 10 MHz.
pub fn delay_us(us: u64, timebase_hz: u64) {
    let hz = if timebase_hz == 0 {
        10_000_000
    } else {
        timebase_hz
    };
    let ticks = (us * hz) / 1_000_000;
    let start = mtime();
    while mtime().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
}

/// Spin for at least `ms` milliseconds.
pub fn delay_ms(ms: u64, timebase_hz: u64) {
    delay_us(ms * 1_000, timebase_hz);
}

/// Print CLINT status to the kernel log.
pub fn print_status() {
    let base = CLINT_BASE.load(Ordering::Relaxed);
    let interval = INTERVAL.load(Ordering::Relaxed);
    let use_sbi = USE_SBI_TIMER.load(Ordering::Relaxed);
    let ticks = TICK_COUNT.load(Ordering::Relaxed);
    let now = mtime();
    crate::println!(
        "clint: base={:#x} interval={} sbi={} ticks={} mtime={}",
        base,
        interval,
        use_sbi,
        ticks,
        now
    );
}
