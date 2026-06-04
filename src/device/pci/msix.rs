//! MSI-X vector configuration.
//!
//! Configures MSI-X table entries for any device that has the MSI-X
//! capability (`d.msix_cap != 0`).  The table BAR is resolved via the
//! BIR field in the MSI-X capability, so all six BARs are supported.

use super::PciDevice;
use super::ecam::{cfg_read16, cfg_read32, cfg_write16};
use core::ptr::write_volatile;

/// Enable MSI-X on `d` and program vector `vec_idx` to deliver
/// interrupt `vector` to the local APIC identified by `lapic_id`.
///
/// The table BAR is resolved from the BIR field in the capability
/// structure, so any of BAR0–BAR5 is supported.
///
/// Returns without modifying hardware if:
///   - `d.msix_cap == 0` (device has no MSI-X capability), or
///   - the resolved BAR is 0 (not decoded / I/O BAR).
pub fn msix_configure(
    d:        &PciDevice,
    vec_idx:  usize,
    lapic_id: u32,
    vector:   u8,
) {
    if d.msix_cap == 0 {
        return;
    }
    let cap = d.msix_cap as u16;

    // Capability +4: [2:0] = BIR, [31:3] = table offset within that BAR.
    let table_dw = cfg_read32(d.bus, d.dev, d.func, cap + 4);
    let bir      = (table_dw & 0x7) as usize;
    let offset   = (table_dw & !0x7u32) as usize;

    // Resolve the BAR.  If it decoded as 0 (e.g. I/O BAR or absent) bail.
    if bir >= 6 {
        return;
    }
    let bar = d.bars[bir];
    if bar == 0 {
        return;
    }

    let table_base = bar as usize + offset;

    // Each MSI-X table entry: [addr_lo(4B), addr_hi(4B), data(4B), ctrl(4B)].
    let entry = (table_base + vec_idx * 16) as *mut u32;
    unsafe {
        // x86 MSI address: 0xFEE_XXXXX where bits [19:12] = destination APIC ID.
        let addr = 0xFEE0_0000u32 | (lapic_id << 12);
        write_volatile(entry,        addr);             // addr_lo
        write_volatile(entry.add(1), 0);               // addr_hi
        write_volatile(entry.add(2), vector as u32);   // data (vector number)
        write_volatile(entry.add(3), 0);               // ctrl: bit 0 = mask; 0 = unmasked
    }

    // Message Control register (cap + 2):
    //   bit 15 = MSI-X Enable
    //   bit 14 = Function Mask (mask all vectors) — clear this
    let mc = cfg_read16(d.bus, d.dev, d.func, cap + 2);
    cfg_write16(d.bus, d.dev, d.func, cap + 2,
        (mc & !0x4000) | 0x8000);
}
