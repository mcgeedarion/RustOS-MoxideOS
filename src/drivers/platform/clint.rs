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
//! when `USE_SBI_TIMER` is `false`.
//!
//! ## MSIP (software IPI)
//!
//! Each hart's MSIP register is a 1-bit latch.  Writing 1 raises a pending
//! machine-mode software interrupt; writing 0 clears it.
//!
//! ## kswapd / tick integration
//!
//! `clint::handle_timer_irq()` is called from the trap handler on every
//! timer interrupt.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;

pub const DEFAULT_BASE: usize = 0x0200_0000;
const MTIME_OFFSET:    usize = 0x0000_BFF8;
const MTIMECMP_OFFSET: usize = 0x0000_4000;
const MSIP_OFFSET:     usize = 0x0000_0000;
const MAX_HARTS: usize = 8;
const SBI_EXT_TIMER: usize = 0x54494D45;
const SBI_TIMER_SET_TIMER: usize = 0;
const SBI_EXT_IPI: usize = 0x00735049;
const SBI_IPI_SEND: usize = 0;
pub const DEFAULT_INTERVAL_TICKS: u64 = 100_000;

static CLINT_BASE: AtomicUsize = AtomicUsize::new(DEFAULT_BASE);
static INTERVAL: AtomicU64 = AtomicU64::new(DEFAULT_INTERVAL_TICKS);
static USE_SBI_TIMER: AtomicBool = AtomicBool::new(true);
static TICK_COUNT: AtomicU64 = AtomicU64::new(0);
static TICK_HOOK: Mutex<Option<fn()>> = Mutex::new(None);

#[inline]
unsafe fn read64(addr: usize) -> u64 { core::ptr::read_volatile(addr as *const u64) }
#[inline]
unsafe fn write64(addr: usize, val: u64) { core::ptr::write_volatile(addr as *mut u64, val); }
#[inline]
unsafe fn write32(addr: usize, val: u32) { core::ptr::write_volatile(addr as *mut u32, val); }

#[inline]
unsafe fn sbi_call(ext: usize, fid: usize, a0: usize, a1: usize, a2: usize) -> (isize, usize) {
    let error: isize; let value: usize;
    core::arch::asm!(
        "ecall",
        inlateout("a0") a0 => error, inlateout("a1") a1 => value,
        in("a2") a2, in("a6") fid, in("a7") ext, options(nostack),
    );
    (error, value)
}

pub fn set_base(base: usize) { CLINT_BASE.store(base, Ordering::Relaxed); }
pub fn base() -> usize { CLINT_BASE.load(Ordering::Relaxed) }
pub fn set_interval(ticks: u64) { INTERVAL.store(ticks.max(1), Ordering::Relaxed); }
pub fn set_use_sbi(sbi: bool) { USE_SBI_TIMER.store(sbi, Ordering::Relaxed); }
pub fn register_tick_hook(f: fn()) { *TICK_HOOK.lock() = Some(f); }
pub fn tick_count() -> u64 { TICK_COUNT.load(Ordering::Relaxed) }

pub fn init() {
    let interval = INTERVAL.load(Ordering::Relaxed);
    let now = mtime();
    set_timecmp(0, now.wrapping_add(interval));
    unsafe { core::arch::asm!("csrs sie, {}", in(reg) 1usize << 5, options(nostack)); }
    crate::println!("clint: init OK (base {:#x}, interval {} cycles)",
        CLINT_BASE.load(Ordering::Relaxed), interval);
}

#[cfg(target_arch = "riscv64")]
pub fn mtime() -> u64 {
    let base = CLINT_BASE.load(Ordering::Relaxed);
    unsafe { read64(base + MTIME_OFFSET) }
}
#[cfg(not(target_arch = "riscv64"))]
pub fn mtime() -> u64 {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let lo: u32; let hi: u32;
        core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nostack, nomem));
        (hi as u64) << 32 | lo as u64
    }
    #[cfg(not(target_arch = "x86_64"))]
    0u64
}

pub fn set_timecmp(hart: usize, deadline: u64) {
    if hart >= MAX_HARTS { return; }
    if USE_SBI_TIMER.load(Ordering::Relaxed) {
        unsafe { sbi_call(SBI_EXT_TIMER, SBI_TIMER_SET_TIMER, deadline as usize, (deadline >> 32) as usize, 0); }
    } else {
        let base = CLINT_BASE.load(Ordering::Relaxed);
        unsafe { write64(base + MTIMECMP_OFFSET + hart * 8, deadline); }
    }
}

pub fn timecmp(hart: usize) -> u64 {
    if hart >= MAX_HARTS { return 0; }
    let base = CLINT_BASE.load(Ordering::Relaxed);
    #[cfg(target_arch = "riscv64")]
    unsafe { read64(base + MTIMECMP_OFFSET + hart * 8) }
    #[cfg(not(target_arch = "riscv64"))]
    { let _ = base; 0u64 }
}

pub fn ticks_until_irq(hart: usize) -> u64 { timecmp(hart).saturating_sub(mtime()) }

pub fn handle_timer_irq() {
    let interval = INTERVAL.load(Ordering::Relaxed);
    let hart: usize;
    #[cfg(target_arch = "riscv64")]
    unsafe { core::arch::asm!("mv {}, tp", out(reg) hart, options(nostack, nomem)); }
    #[cfg(not(target_arch = "riscv64"))]
    let hart = 0usize;
    let next = timecmp(hart).wrapping_add(interval);
    set_timecmp(hart, next);
    TICK_COUNT.fetch_add(1, Ordering::Relaxed);
    crate::mm::swap::kswapd_tick(16);
    crate::proc::scheduler::tick();
    crate::drivers::gpu::drm::vblank_tick_head(0);
    if let Some(f) = *TICK_HOOK.lock() { f(); }
}

pub fn send_ipi(target_hart: usize) {
    if target_hart >= MAX_HARTS { return; }
    if USE_SBI_TIMER.load(Ordering::Relaxed) {
        let mask = 1usize << target_hart;
        unsafe { sbi_call(SBI_EXT_IPI, SBI_IPI_SEND, mask, 0, 0); }
    } else {
        let base = CLINT_BASE.load(Ordering::Relaxed);
        unsafe { write32(base + MSIP_OFFSET + target_hart * 4, 1); }
    }
}

pub fn clear_ipi(hart: usize) {
    if hart >= MAX_HARTS { return; }
    let base = CLINT_BASE.load(Ordering::Relaxed);
    unsafe { write32(base + MSIP_OFFSET + hart * 4, 0); }
}

pub fn msip(hart: usize) -> u32 {
    if hart >= MAX_HARTS { return 0; }
    let base = CLINT_BASE.load(Ordering::Relaxed);
    #[cfg(target_arch = "riscv64")]
    unsafe { core::ptr::read_volatile((base + MSIP_OFFSET + hart * 4) as *const u32) }
    #[cfg(not(target_arch = "riscv64"))]
    { let _ = base; 0u32 }
}

pub fn delay_us(us: u64, timebase_hz: u64) {
    let hz = if timebase_hz == 0 { 10_000_000 } else { timebase_hz };
    let ticks = (us * hz) / 1_000_000;
    let start = mtime();
    while mtime().wrapping_sub(start) < ticks { core::hint::spin_loop(); }
}
pub fn delay_ms(ms: u64, timebase_hz: u64) { delay_us(ms * 1_000, timebase_hz); }

pub fn print_status() {
    crate::println!("clint: base={:#x} interval={} sbi={} ticks={} mtime={}",
        CLINT_BASE.load(Ordering::Relaxed), INTERVAL.load(Ordering::Relaxed),
        USE_SBI_TIMER.load(Ordering::Relaxed), TICK_COUNT.load(Ordering::Relaxed), mtime());
}
