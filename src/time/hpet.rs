//! HPET (High Precision Event Timer) clocksource and one-shot comparator.
//!
//! HPET provides a 64-bit up-counter running at a fixed frequency
//! (typically 14.318 MHz or higher).  It is the fallback clocksource on
//! x86_64 when the TSC is not invariant.
//!
//! ## Discovery
//!
//! The HPET base address is found in the ACPI HPET table (signature `"HPET"`).
//! `init()` reads the ACPI HPET table via `crate::firmware::acpi::find_table`,
//! maps the MMIO region, and reads the capabilities register to obtain the
//! clock period in femtoseconds (HPET spec § 2.3.7).
//!
//! ## MMIO register layout (offset from base)
//!
//!   0x000  GCAP_ID     — capabilities & ID (clock period in bits [63:32])
//!   0x010  GEN_CONF    — general configuration (bit 0 = ENABLE_CNF)
//!   0x020  GINTR_STA   — general interrupt status
//!   0x0F0  MAIN_CNT    — main counter value (64-bit)
//!   0x100  T0_CONF     — timer 0 config/capability
//!   0x108  T0_CMP      — timer 0 comparator

use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

// HPET MMIO register offsets.
const GCAP_ID:   usize = 0x000;
const GEN_CONF:  usize = 0x010;
const MAIN_CNT:  usize = 0x0F0;
const T0_CONF:   usize = 0x100;
const T0_CMP:    usize = 0x108;

static HPET_BASE:     AtomicU64  = AtomicU64::new(0);
static HPET_PERIOD_FS: AtomicU64 = AtomicU64::new(0); // femtoseconds per tick
static HPET_READY:    AtomicBool = AtomicBool::new(false);

/// Initialise HPET.  Returns `true` if successfully mapped and enabled.
pub fn init() -> bool {
    let base = match acpi_hpet_base() {
        Some(b) => b,
        None    => return false,
    };
    HPET_BASE.store(base, Ordering::SeqCst);

    let caps = mmio_read64(base, GCAP_ID);
    let period_fs = caps >> 32;
    if period_fs == 0 || period_fs > 100_000_000 { return false; }
    HPET_PERIOD_FS.store(period_fs, Ordering::SeqCst);

    let conf = mmio_read64(base, GEN_CONF);
    mmio_write64(base, GEN_CONF, conf | 1);

    HPET_READY.store(true, Ordering::SeqCst);
    true
}

/// Returns `true` if HPET has been successfully initialised.
#[inline]
pub fn is_ready() -> bool {
    HPET_READY.load(Ordering::Relaxed)
}

/// Read the main counter and convert to nanoseconds.
pub fn read_ns() -> u64 {
    if !HPET_READY.load(Ordering::Relaxed) { return 0; }
    let base    = HPET_BASE.load(Ordering::Relaxed);
    let ticks   = mmio_read64(base, MAIN_CNT);
    let period  = HPET_PERIOD_FS.load(Ordering::Relaxed);
    ticks.saturating_mul(period) / 1_000_000
}

/// Program timer 0 as a one-shot comparator to fire `ns_from_now` ns later.
/// The caller should have set up the interrupt vector beforehand.
pub fn set_oneshot(ns_from_now: u64) {
    if !HPET_READY.load(Ordering::Relaxed) { return; }
    let base   = HPET_BASE.load(Ordering::Relaxed);
    let period = HPET_PERIOD_FS.load(Ordering::Relaxed);
    let now    = mmio_read64(base, MAIN_CNT);
    let ticks  = ns_from_now.saturating_mul(1_000_000) / period;
    let t0conf = mmio_read64(base, T0_CONF);
    mmio_write64(base, T0_CONF, t0conf & !(1 << 3) | (1 << 2));
    mmio_write64(base, T0_CMP,  now.wrapping_add(ticks));
}

fn acpi_hpet_base() -> Option<u64> {
    let table = crate::firmware::acpi::find_table(b"HPET")?;
    if table.len() < 52 { return None; }
    let addr_bytes: [u8; 8] = table[44..52].try_into().ok()?;
    let addr = u64::from_le_bytes(addr_bytes);
    if addr == 0 { None } else { Some(addr) }
}

fn mmio_read64(base: u64, offset: usize) -> u64 {
    unsafe { core::ptr::read_volatile((base as usize + offset) as *const u64) }
}
fn mmio_write64(base: u64, offset: usize, val: u64) {
    unsafe { core::ptr::write_volatile((base as usize + offset) as *mut u64, val) }
}
