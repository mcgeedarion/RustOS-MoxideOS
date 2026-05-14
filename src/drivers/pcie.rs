//! PCIe bus enumerator — Phase 1 (ECAM + MSI-X).
//!
//! ## PCI configuration space access
//!   Legacy (CAM): two I/O ports (0xCF8 / 0xCFC).
//!   Modern  (ECAM): MMIO, base from MCFG ACPI table.
//!
//! ## Device discovery
//!   Bus 0-255 × Device 0-31 × Function 0-7.
//!   Header type 0 = endpoint, type 1 = bridge.
//!
//! ## MSI-X
//!   Locate cap, map Table BAR + PBA BAR, unmask vectors.

use crate::mm::PhysAddr;
use alloc::vec::Vec;

// ── Legacy CAM ports ─────────────────────────────────────────────────────
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA:    u16 = 0xCFC;

pub fn cam_read32(bus: u8, dev: u8, func: u8, off: u8) -> u32 {
    let addr = 0x8000_0000u32
        | ((bus  as u32) << 16)
        | ((dev  as u32) << 11)
        | ((func as u32) <<  8)
        | ((off  as u32) & 0xFC);
    unsafe {
        crate::arch::x86_64::port::outl(PCI_CONFIG_ADDRESS, addr);
        crate::arch::x86_64::port::inl(PCI_CONFIG_DATA)
    }
}

pub fn cam_write32(bus: u8, dev: u8, func: u8, off: u8, val: u32) {
    let addr = 0x8000_0000u32
        | ((bus  as u32) << 16)
        | ((dev  as u32) << 11)
        | ((func as u32) <<  8)
        | ((off  as u32) & 0xFC);
    unsafe {
        crate::arch::x86_64::port::outl(PCI_CONFIG_ADDRESS, addr);
        crate::arch::x86_64::port::outl(PCI_CONFIG_DATA, val);
    }
}

// ── ECAM MMIO ─────────────────────────────────────────────────────────────
static mut ECAM_BASE: Option<PhysAddr> = None;

pub fn init_ecam(base: PhysAddr) {
    unsafe { ECAM_BASE = Some(base); }
}

fn ecam_addr(bus: u8, dev: u8, func: u8, off: u16) -> *mut u32 {
    let base = unsafe { ECAM_BASE.expect("ECAM not initialised") };
    let offset = ((bus  as usize) << 20)
               | ((dev  as usize) << 15)
               | ((func as usize) << 12)
               | (off   as usize);
    (base.0 as usize + offset) as *mut u32
}

pub fn ecam_read32(bus: u8, dev: u8, func: u8, off: u16) -> u32 {
    unsafe { ecam_addr(bus, dev, func, off).read_volatile() }
}

pub fn ecam_write32(bus: u8, dev: u8, func: u8, off: u16, val: u32) {
    unsafe { ecam_addr(bus, dev, func, off).write_volatile(val) }
}

// ── Device descriptor ─────────────────────────────────────────────────────
#[derive(Debug, Clone)]
pub struct PciDevice {
    pub bus:      u8,
    pub dev:      u8,
    pub func:     u8,
    pub vendor:   u16,
    pub device:   u16,
    pub class:    u8,
    pub subclass: u8,
    pub prog_if:  u8,
    pub bars:     [u64; 6],
    pub irq_line: u8,
}

impl PciDevice {
    fn read32(&self, off: u16) -> u32 {
        if unsafe { ECAM_BASE.is_some() } {
            ecam_read32(self.bus, self.dev, self.func, off)
        } else {
            cam_read32(self.bus, self.dev, self.func, off as u8)
        }
    }

    fn write32(&self, off: u16, val: u32) {
        if unsafe { ECAM_BASE.is_some() } {
            ecam_write32(self.bus, self.dev, self.func, off, val)
        } else {
            cam_write32(self.bus, self.dev, self.func, off as u8, val)
        }
    }

    pub fn enable_bus_master(&self) {
        let cmd = self.read32(0x04);
        self.write32(0x04, cmd | (1 << 2));
    }

    pub fn enable_mmio(&self) {
        let cmd = self.read32(0x04);
        self.write32(0x04, cmd | (1 << 1));
    }
}

// ── BAR decoding ──────────────────────────────────────────────────────────
fn decode_bars(bus: u8, dev: u8, func: u8) -> [u64; 6] {
    let mut bars = [0u64; 6];
    let read = |off: u16| -> u32 {
        if unsafe { ECAM_BASE.is_some() } {
            ecam_read32(bus, dev, func, off)
        } else {
            cam_read32(bus, dev, func, off as u8)
        }
    };
    let write = |off: u16, val: u32| {
        if unsafe { ECAM_BASE.is_some() } {
            ecam_write32(bus, dev, func, off, val)
        } else {
            cam_write32(bus, dev, func, off as u8, val)
        }
    };

    let mut i = 0usize;
    while i < 6 {
        let off = (0x10 + i * 4) as u16;
        let bar = read(off);
        if bar == 0 { i += 1; continue; }

        if bar & 1 == 0 {
            // memory BAR
            let bar_type = (bar >> 1) & 3;
            if bar_type == 2 && i + 1 < 6 {
                // 64-bit
                let hi = read((0x10 + (i + 1) * 4) as u16);
                write(off, 0xFFFF_FFFF);
                write((0x10 + (i + 1) * 4) as u16, 0xFFFF_FFFF);
                let lo_sz = read(off);
                let hi_sz = read((0x10 + (i + 1) * 4) as u16);
                write(off, bar);
                write((0x10 + (i + 1) * 4) as u16, hi);
                let size = (!(((hi_sz as u64) << 32) | (lo_sz as u64 & 0xFFFF_FFF0)) + 1) as u64;
                bars[i] = ((bar as u64 & 0xFFFF_FFF0) | ((hi as u64) << 32)) | (size << 32);
                i += 2;
                continue;
            } else {
                write(off, 0xFFFF_FFFF);
                let sz = read(off);
                write(off, bar);
                bars[i] = (bar as u64 & 0xFFFF_FFF0) | (((!(sz & 0xFFFF_FFF0) + 1) as u64) << 32);
            }
        } else {
            // I/O BAR
            bars[i] = (bar as u64 & 0xFFFC) | ((((!(bar & 0xFFFC) + 1) & 0xFFFF) as u64) << 32);
        }
        i += 1;
    }
    bars
}

// ── Bus enumeration ───────────────────────────────────────────────────────
pub fn enumerate() -> Vec<PciDevice> {
    let mut devices = Vec::new();
    for bus in 0u8..=255 {
        for dev in 0u8..32 {
            for func in 0u8..8 {
                let vd = if unsafe { ECAM_BASE.is_some() } {
                    ecam_read32(bus, dev, func, 0x00)
                } else {
                    cam_read32(bus, dev, func, 0x00)
                };
                if vd == 0xFFFF_FFFF || (vd & 0xFFFF) == 0xFFFF { continue; }

                let class_rev = if unsafe { ECAM_BASE.is_some() } {
                    ecam_read32(bus, dev, func, 0x08)
                } else {
                    cam_read32(bus, dev, func, 0x08)
                };
                let irq = if unsafe { ECAM_BASE.is_some() } {
                    ecam_read32(bus, dev, func, 0x3C)
                } else {
                    cam_read32(bus, dev, func, 0x3C)
                };

                devices.push(PciDevice {
                    bus, dev, func,
                    vendor:   (vd & 0xFFFF) as u16,
                    device:   (vd >> 16) as u16,
                    class:    (class_rev >> 24) as u8,
                    subclass: (class_rev >> 16) as u8,
                    prog_if:  (class_rev >>  8) as u8,
                    bars:     decode_bars(bus, dev, func),
                    irq_line: (irq & 0xFF) as u8,
                });

                // single-function check
                let hdr = if unsafe { ECAM_BASE.is_some() } {
                    ecam_read32(bus, dev, func, 0x0C)
                } else {
                    cam_read32(bus, dev, func, 0x0C)
                };
                if func == 0 && (hdr >> 16) & 0x80 == 0 { break; }
            }
        }
    }
    devices
}

// ── MSI-X ─────────────────────────────────────────────────────────────────
pub struct MsixTable {
    pub table_bar:  usize,
    pub table_off:  u32,
    pub pba_bar:    usize,
    pub pba_off:    u32,
    pub num_vecs:   u16,
    pub table_base: *mut u32,
}

impl MsixTable {
    pub unsafe fn configure(&mut self, vec_idx: u16, apic_id: u8, vector: u8) {
        let entry = self.table_base.add((vec_idx as usize) * 4);
        // Address: 0xFEE0_0000 | (APIC_ID << 12)
        entry.add(0).write_volatile(0xFEE0_0000 | ((apic_id as u32) << 12));
        entry.add(1).write_volatile(0);
        // Data: fixed delivery, edge, vector
        entry.add(2).write_volatile(vector as u32);
        // Unmask
        entry.add(3).write_volatile(0);
    }

    pub unsafe fn enable_global(dev: &PciDevice) {
        // Find MSI-X cap
        let mut cap_ptr = (cam_read32(dev.bus, dev.dev, dev.func, 0x34) & 0xFF) as u8;
        while cap_ptr != 0 {
            let cap = cam_read32(dev.bus, dev.dev, dev.func, cap_ptr);
            if (cap & 0xFF) == 0x11 {
                // MSI-X cap found — set Enable bit
                let msg_ctrl = ((cap >> 16) | 0x8000) & 0xFFFF_u32;
                cam_write32(dev.bus, dev.dev, dev.func, cap_ptr + 2,
                            (cam_read32(dev.bus, dev.dev, dev.func, cap_ptr + 2) & 0xFFFF)
                            | (msg_ctrl << 16));
                return;
            }
            cap_ptr = ((cap >> 8) & 0xFF) as u8;
        }
    }
}
