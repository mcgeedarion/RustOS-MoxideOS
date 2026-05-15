//! RISC-V CLINT `mtime` clocksource.
//!
//! The CLINT (Core Local Interruptor) provides a 64-bit memory-mapped
//! `mtime` register that increments at a platform-defined frequency
//! (typically 10 MHz for QEMU virt, or as defined in the FDT/DTS
//! `timebase-frequency` property).
//!
//! ## Register layout (base from DTS / FDT `clint` node)
//!
//!   base + 0x0000   msip[0..N]    per-hart software interrupt pending
//!   base + 0x4000   mtimecmp[0..N] per-hart compare register
//!   base + 0xBFF8   mtime          global monotonic counter
//!
//! ## QEMU virt defaults
//!
//!   CLINT base:          0x0200_0000
//!   timebase-frequency:  10_000_000 Hz  (10 MHz)

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const MTIME_OFFSET: usize = 0xBFF8;
const MTIMECMP_BASE: usize = 0x4000;

static CLINT_BASE: AtomicU64 = AtomicU64::new(0x0200_0000); // QEMU default
static TIMEBASE_HZ: AtomicU64 = AtomicU64::new(10_000_000); // 10 MHz default
static CLINT_READY: AtomicBool = AtomicBool::new(false);

/// Initialise CLINT clocksource.  `base` and `freq_hz` come from the FDT.
/// Falls back to QEMU defaults if called with zeros.
pub fn init() -> bool {
    CLINT_READY.store(true, Ordering::SeqCst);
    true
}

/// Configure with FDT-provided base address and timebase frequency.
pub fn configure(base: u64, freq_hz: u64) {
    if base != 0 {
        CLINT_BASE.store(base, Ordering::SeqCst);
    }
    if freq_hz != 0 {
        TIMEBASE_HZ.store(freq_hz, Ordering::SeqCst);
    }
}

/// Read the `mtime` counter.
#[inline]
pub fn read_mtime() -> u64 {
    let base = CLINT_BASE.load(Ordering::Relaxed);
    unsafe { core::ptr::read_volatile((base as usize + MTIME_OFFSET) as *const u64) }
}

/// Convert `mtime` ticks to nanoseconds.
pub fn ticks_to_ns(ticks: u64) -> u64 {
    let hz = TIMEBASE_HZ.load(Ordering::Relaxed);
    // ns = ticks * 1_000_000_000 / hz
    // Use 128-bit to avoid overflow at high tick values.
    (ticks as u128 * 1_000_000_000 / hz as u128) as u64
}

/// Read current time as nanoseconds since boot.
pub fn read_ns() -> u64 {
    ticks_to_ns(read_mtime())
}

/// Program `mtimecmp` for hart `hartid` to fire an interrupt `ns_from_now` ns later.
pub fn set_next_event(hartid: usize, ns_from_now: u64) {
    let base = CLINT_BASE.load(Ordering::Relaxed);
    let hz = TIMEBASE_HZ.load(Ordering::Relaxed);
    let now = read_mtime();
    let delta_ticks = (ns_from_now as u128 * hz as u128 / 1_000_000_000) as u64;
    let cmp = now.wrapping_add(delta_ticks);
    let addr = (base as usize + MTIMECMP_BASE + hartid * 8) as *mut u64;
    unsafe {
        core::ptr::write_volatile(addr, cmp);
    }
}

/// Return the timebase frequency (from FDT or default).
pub fn freq_hz() -> u64 {
    TIMEBASE_HZ.load(Ordering::Relaxed)
}
