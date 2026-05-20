//! MSI-X vector configuration.
//!
//! Configures a single MSI-X table entry for a device that has the
//! MSI-X capability (`d.msix_cap != 0`).
//!
//! This module is intentionally separate from the enumerator so that
//! drivers can call `msix_configure` without pulling in scanning logic.

use super::PciDevice;
use super::ecam::{cfg_read16, cfg_read32, cfg_write16};
use core::ptr::write_volatile;

/// Enable MSI-X on `d` and program vector `vec_idx` to deliver
/// interrupt `vector` to the local APIC identified by `lapic_id`.
///
/// Only BAR0-based MSI-X tables are supported (BIR == 0).
/// If `d.msix_cap == 0` or the table resides in another BAR, this
/// function returns without modifying hardware.
pub fn msix_configure(
    d:        &PciDevice,
    vec_idx:  usize,
    lapic_id: u32,
    vector:   u8,
    _data:    u32,
) {
    if d.msix_cap == 0 {
        return;
    }
    let cap = d.msix_cap as u16;

    // MSI-X table BIR and byte offset within that BAR.
    let table_dw = cfg_read32(d.bus, d.dev, d.func, cap + 4);
    let bir      = (table_dw & 0x7) as u8;
    let offset   = (table_dw & !0x7) as usize;

    // Resolve BAR — only BAR0 supported for now.
    if bir != 0 {
        return;
    }
    let table_base = d.bar0 as usize + offset;

    // Each entry: [addr_lo(4), addr_hi(4), data(4), ctrl(4)] = 16 bytes.
    let entry = (table_base + vec_idx * 16) as *mut u32;
    unsafe {
        let addr = 0xFEE0_0000u32 | (lapic_id << 12);
        write_volatile(entry,           addr);
        write_volatile(entry.add(1),    0);             // addr_hi
        write_volatile(entry.add(2),    vector as u32); // data
        write_volatile(entry.add(3),    0);             // ctrl: unmask
    }

    // Set the MSI-X Enable bit in the Message Control register.
    let mc = cfg_read16(d.bus, d.dev, d.func, cap + 2);
    cfg_write16(d.bus, d.dev, d.func, cap + 2, mc | 0x8000);
}
