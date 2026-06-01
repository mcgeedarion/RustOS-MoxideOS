//! PCIe ECAM (Enhanced Configuration Access Mechanism) for AArch64.
//!
//! On AArch64 systems (QEMU virt, Raspberry Pi 4, etc.) the PCIe config space
//! is memory-mapped via ECAM rather than accessed through I/O ports.  The base
//! address is read from the ACPI MCFG table or the device tree; it is stored
//! in `ECAM_BASE` during early init.
//!
//! ## Config space address formula
//!
//!   phys = ecam_base
//!         | (bus  << 20)
//!         | (dev  << 15)
//!         | (fun  << 12)
//!         | (off  & !3)

#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Physical base address of the ECAM window.  Set by `ecam_init()`.
static ECAM_BASE: AtomicUsize = AtomicUsize::new(0);

/// Register the ECAM base address (called from ACPI MCFG or DTB parsing).
pub fn ecam_init(base: usize) {
    ECAM_BASE.store(base, Ordering::Relaxed);
}

#[inline]
fn cfg_addr(bus: u8, dev: u8, fun: u8, off: u16) -> *mut u32 {
    let base = ECAM_BASE.load(Ordering::Relaxed);
    let offset = ((bus  as usize) << 20)
               | ((dev  as usize) << 15)
               | ((fun  as usize) << 12)
               | ((off  as usize) & !0x3);
    (base + offset) as *mut u32
}

/// Read a 32-bit config register.
///
/// Returns `0xffff_ffff` ("all ones") if ECAM base is not yet set.
#[inline]
pub unsafe fn read32(bus: u8, dev: u8, fun: u8, off: u16) -> u32 {
    if ECAM_BASE.load(Ordering::Relaxed) == 0 {
        return 0xffff_ffff;
    }
    read_volatile(cfg_addr(bus, dev, fun, off))
}

/// Write a 32-bit config register.
#[inline]
pub unsafe fn write32(bus: u8, dev: u8, fun: u8, off: u16, val: u32) {
    if ECAM_BASE.load(Ordering::Relaxed) == 0 {
        return;
    }
    write_volatile(cfg_addr(bus, dev, fun, off), val);
}

/// Read a 16-bit config register.
#[inline]
pub unsafe fn read16(bus: u8, dev: u8, fun: u8, off: u16) -> u16 {
    let word = read32(bus, dev, fun, off & !2);
    if off & 2 != 0 { (word >> 16) as u16 } else { word as u16 }
}

/// Read an 8-bit config register.
#[inline]
pub unsafe fn read8(bus: u8, dev: u8, fun: u8, off: u16) -> u8 {
    let word = read32(bus, dev, fun, off & !3);
    (word >> ((off & 3) * 8)) as u8
}

/// Vendor/Device ID pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciId {
    pub vendor: u16,
    pub device: u16,
}

/// Enumerate every function on every bus and call `f` for each present device.
///
/// Stops scanning a device's functions after function 0 if the multi-function
/// bit (header type bit 7) is not set.
pub unsafe fn enumerate(mut f: impl FnMut(u8, u8, u8, PciId, u8, u8)) {
    if ECAM_BASE.load(Ordering::Relaxed) == 0 {
        return;
    }
    for bus in 0u8..=255 {
        for dev in 0u8..32 {
            let id0 = read32(bus, dev, 0, 0x00);
            if id0 == 0xffff_ffff { continue; }

            let hdr = read8(bus, dev, 0, 0x0e);
            let max_fun: u8 = if hdr & 0x80 != 0 { 8 } else { 1 };

            for fun in 0..max_fun {
                let id_reg = read32(bus, dev, fun, 0x00);
                if id_reg == 0xffff_ffff { continue; }
                let class_reg = read32(bus, dev, fun, 0x08);
                let class  = (class_reg >> 24) as u8;
                let subclass = (class_reg >> 16) as u8;
                let id = PciId {
                    vendor: id_reg as u16,
                    device: (id_reg >> 16) as u16,
                };
                f(bus, dev, fun, id, class, subclass);
            }
        }
    }
}
