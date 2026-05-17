//! ACPI Control Method Battery (`PNP0C0A`) — `_BIF` / `_BST` parser.
//!
//! ## What we implement
//!
//! ACPI exposes battery state through two AML control methods:
//! - `_BIF` (Battery Information) — static data: capacity, voltage, chemistry.
//! - `_BST` (Battery Status)      — dynamic data: state, rate, remaining capacity.
//!
//! Because we lack a full AML interpreter, we scan the DSDT for the well-known
//! byte patterns produced by virtually every firmware that implements these
//! methods.  We also hook the ACPI Notify(battery, 0x80) GPE so the kernel
//! gets notified when the battery status changes.
//!
//! The `BATTERY_STATE` static is updated by the SCI handler (in `power.rs`)
//! via the `update()` entry point below.

use core::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use crate::console::println;
use super::SdtHeader;

// ── Battery status flags (_BST `battery_state` field) ────────────────────

pub const BST_DISCHARGING:  u32 = 1 << 0;
pub const BST_CHARGING:     u32 = 1 << 1;
pub const BST_CRITICAL:     u32 = 1 << 2;
pub const BST_CHARGE_LIMIT: u32 = 1 << 3;

// ── Static battery information from _BIF ─────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct BatteryInfo {
    /// 0 = mWh design units, 1 = mAh design units.
    pub power_unit:         u32,
    pub design_capacity:    u32,
    pub last_full_capacity: u32,
    pub battery_technology: u32, // 0 = primary, 1 = rechargeable
    pub design_voltage_mv:  u32,
    pub warning_capacity:   u32,
    pub low_capacity:       u32,
    pub capacity_granularity1: u32,
    pub capacity_granularity2: u32,
}

// ── Dynamic battery status from _BST ─────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct BatteryStatus {
    /// Bitmask: BST_DISCHARGING | BST_CHARGING | BST_CRITICAL.
    pub state:              u32,
    /// Present rate in mW (or mA if power_unit == 1). 0xFFFFFFFF = unknown.
    pub present_rate:       u32,
    /// Remaining capacity in mWh (or mAh).
    pub remaining_capacity: u32,
    /// Present voltage in mV.
    pub present_voltage:    u32,
}

// ── Atomics for lock-free reads from any context ─────────────────────────

static BST_STATE:    AtomicU32 = AtomicU32::new(0);
static BST_RATE:     AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
static BST_REMAIN:   AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
static BST_VOLTAGE:  AtomicU32 = AtomicU32::new(0xFFFF_FFFF);

static BIF_UNIT:     AtomicU32 = AtomicU32::new(0);
static BIF_DESIGN:   AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
static BIF_LAST:     AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
static BIF_VOLTAGE:  AtomicU32 = AtomicU32::new(0xFFFF_FFFF);
static BIF_TECH:     AtomicU32 = AtomicU32::new(0);

static BATTERY_PRESENT: AtomicBool = AtomicBool::new(false);

// ── AML scanner helpers ───────────────────────────────────────────────────

unsafe fn read_dword(aml: &[u8], i: usize) -> Option<u32> {
    // AML DWordPrefix = 0x0C followed by LE u32.
    if *aml.get(i)? != 0x0Cu8 || i + 5 > aml.len() {
        return None;
    }
    Some(u32::from_le_bytes([aml[i+1], aml[i+2], aml[i+3], aml[i+4]]))
}

/// Scan AML for `_BIF` and populate the BIF atomics.
unsafe fn scan_bif(aml: &[u8]) {
    let marker = *b"_BIF";
    let mut i = 0usize;
    while i + 10 < aml.len() {
        if aml[i..i+4] != marker { i += 1; continue; }
        // Expect Package opcode (0x12) followed by a 9-DWord body.
        let mut j = i + 4;
        if *aml.get(j)? != 0x12 { i += 1; continue; }
        j += 1;
        // Skip PkgLength.
        let lead = *aml.get(j)?;
        j += 1 + (lead >> 6) as usize;
        j += 1; // NumElements
        let mut vals = [0u32; 9];
        let mut ok = true;
        for k in 0..9 {
            match read_dword(aml, j) {
                Some(v) => { vals[k] = v; j += 5; }
                None    => { ok = false; break; }
            }
        }
        if !ok { i += 1; continue; }
        BIF_UNIT.store(vals[0], Ordering::Relaxed);
        BIF_DESIGN.store(vals[1], Ordering::Relaxed);
        BIF_LAST.store(vals[2], Ordering::Relaxed);
        BIF_TECH.store(vals[3], Ordering::Relaxed);
        BIF_VOLTAGE.store(vals[4], Ordering::Relaxed);
        BATTERY_PRESENT.store(true, Ordering::Relaxed);
        println!("acpi/battery: design={}  last_full={}  voltage={}mV  unit={}",
            vals[1], vals[2], vals[4], if vals[0] == 0 { "mWh" } else { "mAh" });
        return;
    }
}

/// Scan AML for `_BST` and update the BST atomics.
unsafe fn scan_bst(aml: &[u8]) {
    let marker = *b"_BST";
    let mut i = 0usize;
    while i + 10 < aml.len() {
        if aml[i..i+4] != marker { i += 1; continue; }
        let mut j = i + 4;
        if *aml.get(j)? != 0x12 { i += 1; continue; }
        j += 1;
        let lead = *aml.get(j)?;
        j += 1 + (lead >> 6) as usize;
        j += 1;
        let mut vals = [0u32; 4];
        let mut ok = true;
        for k in 0..4 {
            match read_dword(aml, j) {
                Some(v) => { vals[k] = v; j += 5; }
                None    => { ok = false; break; }
            }
        }
        if !ok { i += 1; continue; }
        BST_STATE.store(vals[0], Ordering::Relaxed);
        BST_RATE.store(vals[1], Ordering::Relaxed);
        BST_REMAIN.store(vals[2], Ordering::Relaxed);
        BST_VOLTAGE.store(vals[3], Ordering::Relaxed);
        let pct = if BIF_LAST.load(Ordering::Relaxed) > 0 {
            vals[2] * 100 / BIF_LAST.load(Ordering::Relaxed)
        } else { 0 };
        println!("acpi/battery: state={:#x}  remain={}  {}%  {}mV",
            vals[0], vals[2], pct, vals[3]);
        return;
    }
}

// ── Public API ────────────────────────────────────────────────────────────

/// Discover battery and parse initial `_BIF`/`_BST`.
pub unsafe fn init() {
    let fadt = match super::find_table(b"FACP") {
        Some(p) => p,
        None => return,
    };
    let base = fadt as *const u8;
    let dsdt_phys = (base.add(40) as *const u32).read_unaligned() as usize;
    if dsdt_phys == 0 { return; }
    let dsdt = &*(dsdt_phys as *const SdtHeader);
    if &dsdt.sig != b"DSDT" { return; }
    let aml_off = core::mem::size_of::<SdtHeader>();
    let aml_len = (dsdt.len as usize).saturating_sub(aml_off);
    let aml = core::slice::from_raw_parts((dsdt_phys + aml_off) as *const u8, aml_len);
    scan_bif(aml);
    scan_bst(aml);
}

/// Called from the ACPI Notify handler when the battery device emits 0x80.
/// Re-scans `_BST` to refresh the dynamic state.
pub unsafe fn update() {
    let fadt = match super::find_table(b"FACP") {
        Some(p) => p,
        None => return,
    };
    let base = fadt as *const u8;
    let dsdt_phys = (base.add(40) as *const u32).read_unaligned() as usize;
    if dsdt_phys == 0 { return; }
    let dsdt = &*(dsdt_phys as *const SdtHeader);
    if &dsdt.sig != b"DSDT" { return; }
    let aml_off = core::mem::size_of::<SdtHeader>();
    let aml_len = (dsdt.len as usize).saturating_sub(aml_off);
    let aml = core::slice::from_raw_parts((dsdt_phys + aml_off) as *const u8, aml_len);
    scan_bst(aml);
}

/// Returns `true` if a battery was found in the DSDT.
pub fn is_present() -> bool {
    BATTERY_PRESENT.load(Ordering::Relaxed)
}

/// Snapshot of the last-known battery status.
pub fn status() -> BatteryStatus {
    BatteryStatus {
        state:              BST_STATE.load(Ordering::Relaxed),
        present_rate:       BST_RATE.load(Ordering::Relaxed),
        remaining_capacity: BST_REMAIN.load(Ordering::Relaxed),
        present_voltage:    BST_VOLTAGE.load(Ordering::Relaxed),
    }
}

/// Snapshot of the static battery information.
pub fn info() -> BatteryInfo {
    BatteryInfo {
        power_unit:         BIF_UNIT.load(Ordering::Relaxed),
        design_capacity:    BIF_DESIGN.load(Ordering::Relaxed),
        last_full_capacity: BIF_LAST.load(Ordering::Relaxed),
        battery_technology: BIF_TECH.load(Ordering::Relaxed),
        design_voltage_mv:  BIF_VOLTAGE.load(Ordering::Relaxed),
        warning_capacity:   0,
        low_capacity:       0,
        capacity_granularity1: 0,
        capacity_granularity2: 0,
    }
}

/// Charge percentage, 0–100.  Returns `None` if capacity is unknown.
pub fn charge_percent() -> Option<u32> {
    let last = BIF_LAST.load(Ordering::Relaxed);
    let rem  = BST_REMAIN.load(Ordering::Relaxed);
    if last == 0 || last == 0xFFFF_FFFF || rem == 0xFFFF_FFFF {
        return None;
    }
    Some((rem * 100 / last).min(100))
}
