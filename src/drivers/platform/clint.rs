//! RISC-V CLINT (Core Local INTerruptor) driver.
//!
//! The CLINT provides two facilities per hart:
//!   - **MSIP**   — machine-mode software interrupt (inter-processor interrupt)
//!   - **MTIMECMP** / **MTIME** — memory-mapped 64-bit timer
//!
//! ## Memory map (relative to CLINT base; QEMU virt = 0x200_0000)
//!
//!   +0x0000  msip[0..N]      4 B each   (write 1 to pend MIP.MSIP on hart N)
//!   +0x4000  mtimecmp[0..N]  8 B each   (deadline; timer fires when mtime >= mtimecmp)
//!   +0xBFF8  mtime           8 B         (global read-only monotonic counter)
//!
//! ## Usage model
//!   The kernel boots with M-mode SBI firmware (OpenSBI) handling the raw
//!   timer interrupt.  This driver is used in two scenarios:
//!
//!   1. **Direct M-mode** (no SBI): set `CLINT_BASE` and call `init()`,
//!      then use `set_timer` / `clear_timer` and `send_ipi` / `clear_ipi`
//!      directly from M-mode trap handlers.
//!
//!   2. **S-mode under OpenSBI**: use the SBI timer extension instead;
//!      this driver provides `read_mtime()` via MMIO for wall-clock reads.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

// ─────────────────────────────────────────────────────────────────────────────
// Base address
// ─────────────────────────────────────────────────────────────────────────────

/// Physical base of the CLINT.  0x200_0000 on QEMU virt.
pub const CLINT_BASE: usize = 0x0200_0000;

/// Maximum number of harts the driver tracks.
pub const MAX_HARTS: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// Register address helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
const fn msip_addr(hart: usize) -> usize {
    CLINT_BASE + hart * 4
}

#[inline]
const fn mtimecmp_addr(hart: usize) -> usize {
    CLINT_BASE + 0x4000 + hart * 8
}

const MTIME_ADDR: usize = CLINT_BASE + 0xBFF8;

// ─────────────────────────────────────────────────────────────────────────────
// Low-level I/O
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
unsafe fn read64(addr: usize) -> u64 {
    // 64-bit MMIO reads must be done as two 32-bit halves on RV32;
    // on RV64 a single LD is fine.  We use two volatile u32 reads for
    // maximum portability across RV32/RV64.
    let lo = read_volatile(addr as *const u32) as u64;
    let hi = read_volatile((addr + 4) as *const u32) as u64;
    lo | (hi << 32)
}

#[inline]
unsafe fn write64(addr: usize, val: u64) {
    write_volatile(addr as *mut u32,         (val & 0xFFFF_FFFF) as u32);
    write_volatile((addr + 4) as *mut u32,   (val >> 32) as u32);
}

// ─────────────────────────────────────────────────────────────────────────────
// Monotonic tick tracking (S-mode accessible copy)
// ─────────────────────────────────────────────────────────────────────────────

/// Shadow copy of the last observed mtime value, updated by `tick()`.
/// Allows S-mode code to read a reasonably fresh mtime without an MMIO
/// access on every syscall.
static MTIME_SHADOW: AtomicU64 = AtomicU64::new(0);

/// Tick frequency in Hz (set by `init`; default 10 MHz for QEMU virt).
static TICK_HZ: AtomicU64 = AtomicU64::new(10_000_000);

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Initialise the CLINT driver for `num_harts` harts.
///
/// - Disarms all mtimecmp registers (set to u64::MAX).
/// - Clears all MSIP bits.
/// - Records `tick_hz` for future deadline calculations.
pub fn init(num_harts: usize, tick_hz: u64) {
    let n = num_harts.min(MAX_HARTS);
    TICK_HZ.store(tick_hz, Ordering::Relaxed);
    for h in 0..n {
        unsafe {
            write_volatile(msip_addr(h) as *mut u32, 0);
            write64(mtimecmp_addr(h), u64::MAX);
        }
    }
}

/// Read the global `mtime` counter (raw ticks).
#[inline]
pub fn read_mtime() -> u64 {
    let v = unsafe { read64(MTIME_ADDR) };
    MTIME_SHADOW.store(v, Ordering::Relaxed);
    v
}

/// Return the last cached mtime without an MMIO read.
#[inline]
pub fn mtime_cached() -> u64 {
    MTIME_SHADOW.load(Ordering::Relaxed)
}

/// Return tick frequency (Hz).
#[inline]
pub fn tick_hz() -> u64 {
    TICK_HZ.load(Ordering::Relaxed)
}

/// Schedule a timer interrupt for `hart` at `deadline` ticks.
/// Call from M-mode timer setup or from an SBI ecall shim.
pub fn set_timer(hart: usize, deadline: u64) {
    if hart >= MAX_HARTS { return; }
    unsafe { write64(mtimecmp_addr(hart), deadline); }
}

/// Set the timer `delta_ns` nanoseconds from now for `hart`.
pub fn set_timer_ns(hart: usize, delta_ns: u64) {
    let hz  = TICK_HZ.load(Ordering::Relaxed);
    let now = read_mtime();
    let delta_ticks = delta_ns * hz / 1_000_000_000;
    set_timer(hart, now.saturating_add(delta_ticks));
}

/// Set the timer `delta_us` microseconds from now for `hart`.
pub fn set_timer_us(hart: usize, delta_us: u64) {
    let hz  = TICK_HZ.load(Ordering::Relaxed);
    let now = read_mtime();
    let delta_ticks = delta_us * hz / 1_000_000;
    set_timer(hart, now.saturating_add(delta_ticks));
}

/// Disarm the timer for `hart` (set mtimecmp to u64::MAX).
pub fn clear_timer(hart: usize) {
    if hart >= MAX_HARTS { return; }
    unsafe { write64(mtimecmp_addr(hart), u64::MAX); }
}

/// Send a software IPI to `hart` by setting its MSIP bit.
pub fn send_ipi(hart: usize) {
    if hart >= MAX_HARTS { return; }
    unsafe { write_volatile(msip_addr(hart) as *mut u32, 1); }
}

/// Clear the pending software IPI on `hart`.
pub fn clear_ipi(hart: usize) {
    if hart >= MAX_HARTS { return; }
    unsafe { write_volatile(msip_addr(hart) as *mut u32, 0); }
}

/// Returns true if hart `hart` has a pending MSIP.
pub fn ipi_pending(hart: usize) -> bool {
    if hart >= MAX_HARTS { return false; }
    unsafe { read_volatile(msip_addr(hart) as *const u32) & 1 != 0 }
}

/// Called from the M-mode timer ISR: refresh shadow, reschedule for next
/// quantum, and notify the scheduler.
///
/// `quantum_us` — desired timer quantum in microseconds (e.g. 1000 = 1 ms).
pub fn tick(hart: usize, quantum_us: u64) {
    let now = read_mtime(); // also refreshes MTIME_SHADOW
    set_timer_us(hart, quantum_us);
    crate::sched::timer_tick(now);
}

/// Convert a raw mtime tick count to nanoseconds.
#[inline]
pub fn ticks_to_ns(ticks: u64) -> u64 {
    let hz = TICK_HZ.load(Ordering::Relaxed);
    if hz == 0 { return 0; }
    ticks * 1_000_000_000 / hz
}

/// Convert nanoseconds to mtime ticks.
#[inline]
pub fn ns_to_ticks(ns: u64) -> u64 {
    let hz = TICK_HZ.load(Ordering::Relaxed);
    ns * hz / 1_000_000_000
}

// ─────────────────────────────────────────────────────────────────────────────
// SBI timer shim (S-mode ecall handler)
// ─────────────────────────────────────────────────────────────────────────────

/// Handle `stime_value` from an SBI SET_TIMER ecall (EID=0, FID=0).
/// Writes directly to mtimecmp[hart] and clears any pending timer interrupt.
pub fn sbi_set_timer(hart: usize, stime_value: u64) {
    set_timer(hart, stime_value);
    // Clear any stale pending timer interrupt by also clearing sstatus.STIP
    // if the new deadline is in the future.
    let now = unsafe { read64(MTIME_ADDR) };
    if stime_value > now {
        // Clear timer-pending bit via CSR: clear mip.STIP (M-mode only).
        // On real hardware this is done differently; under QEMU writing
        // mtimecmp > mtime is sufficient to de-assert the interrupt line.
        unsafe {
            core::arch::asm!("csrc mip, {}", in(reg) 1u64 << 5);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Timestamp counter (for clock_gettime / RDTIME)
// ─────────────────────────────────────────────────────────────────────────────

/// Kernel wall-clock: seconds and nanoseconds since boot.
#[derive(Clone, Copy, Debug, Default)]
pub struct Timespec {
    pub sec:  u64,
    pub nsec: u32,
}

/// Convert current mtime to a `Timespec` relative to boot.
pub fn now() -> Timespec {
    let ticks = read_mtime();
    let ns    = ticks_to_ns(ticks);
    Timespec { sec: ns / 1_000_000_000, nsec: (ns % 1_000_000_000) as u32 }
}

/// Monotonic nanosecond counter (wraps at u64::MAX ~= 584 years @ 1 GHz).
pub fn monotonic_ns() -> u64 {
    ticks_to_ns(read_mtime())
}
