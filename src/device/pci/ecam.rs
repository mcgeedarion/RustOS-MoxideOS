//! ECAM (Enhanced Configuration Access Mechanism) MMIO helpers.
//!
//! Address formula:
//!   addr = ecam_base | (bus<<20) | (dev<<15) | (fn<<12) | offset
//!
//! `set_base` must be called exactly once at boot, before any cfg_read/write.

use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

static ECAM_BASE: Mutex<u64> = Mutex::new(0);

/// Initialise the ECAM base from the ACPI MCFG table or device-tree.
///
/// # Safety
/// Caller guarantees `base` maps a valid ECAM region.
pub fn set_base(base: u64) {
    *ECAM_BASE.lock() = base;
}

#[inline]
fn addr(bus: u8, dev: u8, func: u8, off: u16) -> usize {
    let base = *ECAM_BASE.lock() as usize;
    base | ((bus as usize) << 20)
        | ((dev as usize) << 15)
        | ((func as usize) << 12)
        | (off as usize)
}

#[inline]
pub fn cfg_read32(bus: u8, dev: u8, func: u8, off: u16) -> u32 {
    unsafe { read_volatile(addr(bus, dev, func, off) as *const u32) }
}

#[inline]
pub fn cfg_read16(bus: u8, dev: u8, func: u8, off: u16) -> u16 {
    unsafe { read_volatile(addr(bus, dev, func, off) as *const u16) }
}

#[inline]
pub fn cfg_read8(bus: u8, dev: u8, func: u8, off: u16) -> u8 {
    unsafe { read_volatile(addr(bus, dev, func, off) as *const u8) }
}

#[inline]
pub fn cfg_write32(bus: u8, dev: u8, func: u8, off: u16, val: u32) {
    unsafe { write_volatile(addr(bus, dev, func, off) as *mut u32, val) }
}

#[inline]
pub fn cfg_write16(bus: u8, dev: u8, func: u8, off: u16, val: u16) {
    unsafe { write_volatile(addr(bus, dev, func, off) as *mut u16, val) }
}
