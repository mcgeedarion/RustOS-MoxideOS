//! x86_64 PCI bus enumerator — Type-1 (I/O port) configuration space access.
//!
//! `pci::init()` performs a full bus/device/function scan and populates
//! `PCI_DEVICES`.  All subsequent drivers call `pci::find_device()` or
//! `pci::find_class()` rather than performing their own config-space walks.
//!
//! ## Config-space I/O ports
//!   0xCF8  CONFIG_ADDRESS (write)  — [31]=enable, [23:16]=bus, [15:11]=dev,
//!                                    [10:8]=func, [7:2]=reg, [1:0]=0
//!   0xCFC  CONFIG_DATA   (r/w)     — 32-bit aligned register data
//!
//! ## Scan order
//!   bus 0..=255 → device 0..31 → function 0..7
//!   Single-function devices (header-type bit 7 = 0) skip functions 1–7.

use core::sync::atomic::{AtomicU32, Ordering};

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA:    u16 = 0xCFC;

/// PCI mass-storage, SATA, AHCI 1.0  (class=0x01, sub=0x06, prog_if=0x01)
pub const PCI_CLASS_STORAGE_AHCI: (u8, u8, u8) = (0x01, 0x06, 0x01);
/// PCI mass-storage, NVMe            (class=0x01, sub=0x08, prog_if=0x02)
pub const PCI_CLASS_STORAGE_NVME: (u8, u8, u8) = (0x01, 0x08, 0x02);
/// PCI network, Ethernet             (class=0x02, sub=0x00)
pub const PCI_CLASS_NETWORK_ETH:  (u8, u8)     = (0x02, 0x00);

#[inline]
fn config_addr(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    0x8000_0000
        | ((bus  as u32) << 16)
        | ((dev  as u32) << 11)
        | ((func as u32) <<  8)
        | ((offset & 0xFC) as u32)
}

pub fn config_read_u32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    unsafe {
        x86::io::outl(CONFIG_ADDRESS, config_addr(bus, dev, func, offset));
        x86::io::inl(CONFIG_DATA)
    }
}

pub fn config_read_u16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let v = config_read_u32(bus, dev, func, offset & 0xFC);
    ((v >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

pub fn config_read_u8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let v = config_read_u32(bus, dev, func, offset & 0xFC);
    ((v >> ((offset & 3) * 8)) & 0xFF) as u8
}

pub fn config_write_u32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    unsafe {
        x86::io::outl(CONFIG_ADDRESS, config_addr(bus, dev, func, offset));
        x86::io::outl(CONFIG_DATA, val);
    }
}

const MAX_DEVICES: usize = 256;

#[derive(Copy, Clone, Debug, Default)]
pub struct PciDevice {
    pub bus:      u8,
    pub dev:      u8,
    pub func:     u8,
    pub vendor:   u16,
    pub device:   u16,
    pub class:    u8,
    pub subclass: u8,
    pub prog_if:  u8,
    pub irq_line: u8,
    pub irq_pin:  u8,
}

impl PciDevice {
    /// Read a 32-bit BAR, decode it as a 64-bit MMIO address (handles 64-bit BARs).
    /// Returns `None` if the BAR is I/O space or zero.
    pub fn bar_mmio(&self, bar_index: u8) -> Option<u64> {
        let offset = 0x10 + bar_index * 4;
        let lo = config_read_u32(self.bus, self.dev, self.func, offset);
        if lo & 1 != 0 { return None; } // I/O BAR
        let base_lo = (lo & !0xF) as u64;
        if base_lo == 0 { return None; }
        // Type field bits [2:1]: 0x2 = 64-bit BAR
        if (lo >> 1) & 3 == 2 {
            let hi = config_read_u32(self.bus, self.dev, self.func, offset + 4) as u64;
            Some(base_lo | (hi << 32))
        } else {
            Some(base_lo)
        }
    }

    /// Enable bus-mastering and MMIO decoding for this device.
    pub fn enable(&self) {
        let cmd = config_read_u16(self.bus, self.dev, self.func, 0x04);
        // bit 1 = Memory Space Enable, bit 2 = Bus Master Enable
        config_write_u32(self.bus, self.dev, self.func, 0x04,
            (cmd as u32) | 0x06);
    }
}

static mut PCI_DEVICES: [PciDevice; MAX_DEVICES] = [PciDevice {
    bus: 0, dev: 0, func: 0,
    vendor: 0, device: 0,
    class: 0, subclass: 0, prog_if: 0,
    irq_line: 0, irq_pin: 0,
}; MAX_DEVICES];
static PCI_COUNT: AtomicU32 = AtomicU32::new(0);

fn register_device(d: PciDevice) {
    let idx = PCI_COUNT.fetch_add(1, Ordering::Relaxed) as usize;
    if idx < MAX_DEVICES {
        unsafe { PCI_DEVICES[idx] = d; }
    }
}

/// Find a device by vendor + device ID.
pub fn find_device(vendor: u16, device_id: u16) -> Option<PciDevice> {
    let n = PCI_COUNT.load(Ordering::Relaxed) as usize;
    unsafe { PCI_DEVICES[..n].iter().find(|d| d.vendor == vendor && d.device == device_id).copied() }
}

/// Find the first device matching (class, subclass).
pub fn find_class(class: u8, subclass: u8) -> Option<PciDevice> {
    let n = PCI_COUNT.load(Ordering::Relaxed) as usize;
    unsafe { PCI_DEVICES[..n].iter().find(|d| d.class == class && d.subclass == subclass).copied() }
}

/// Find the first device matching (class, subclass, prog_if).
/// Use this for NVMe (0x01, 0x08, 0x02) and AHCI (0x01, 0x06, 0x01).
pub fn find_class_progif(class: u8, subclass: u8, prog_if: u8) -> Option<PciDevice> {
    let n = PCI_COUNT.load(Ordering::Relaxed) as usize;
    unsafe {
        PCI_DEVICES[..n].iter().find(|d|
            d.class == class && d.subclass == subclass && d.prog_if == prog_if
        ).copied()
    }
}

/// Iterate all discovered devices.
pub fn for_each(mut f: impl FnMut(PciDevice)) {
    let n = PCI_COUNT.load(Ordering::Relaxed) as usize;
    unsafe { PCI_DEVICES[..n].iter().copied().for_each(&mut f); }
}

/// Find device by (class, subclass, prog_if) — thin alias used by kernel_main.
pub fn find_device_by_class(tuple: (u8, u8, u8)) -> Option<PciDevice> {
    find_class_progif(tuple.0, tuple.1, tuple.2)
}

pub fn init() {
    let mut count = 0u32;

    'bus: for bus in 0u8..=255 {
        for dev in 0u8..32 {
            for func in 0u8..8 {
                let dword0 = config_read_u32(bus, dev, func, 0x00);
                let vendor  = (dword0 & 0xFFFF) as u16;
                if vendor == 0xFFFF {
                    if func == 0 { continue; }
                    else         { continue; }
                }
                let device_id = (dword0 >> 16) as u16;

                let dword2  = config_read_u32(bus, dev, func, 0x08);
                let prog_if = ((dword2 >>  8) & 0xFF) as u8;
                let subclass= ((dword2 >> 16) & 0xFF) as u8;
                let class   = ((dword2 >> 24) & 0xFF) as u8;

                let dword15 = config_read_u32(bus, dev, func, 0x3C);
                let irq_line= (dword15 & 0xFF) as u8;
                let irq_pin = ((dword15 >> 8) & 0xFF) as u8;

                register_device(PciDevice { bus, dev, func, vendor, device: device_id,
                                            class, subclass, prog_if, irq_line, irq_pin });
                count += 1;

                crate::println!(
                    "pci: {:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}/{:02x}/{:02x} irq {}",
                    bus, dev, func, vendor, device_id, class, subclass, prog_if, irq_line
                );

                if func == 0 {
                    let hdr = config_read_u8(bus, dev, func, 0x0E);
                    if hdr & 0x80 == 0 { break; }
                }
            }
        }
        if bus == 255 { break 'bus; }
    }

    crate::println!("pci: enumerated {} function(s)", count);
}
