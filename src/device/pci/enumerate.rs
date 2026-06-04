//! Full PCI bus scan.
//!
//! Iterates bus 0..=255, device 0..=31, function 0..=7 via ECAM and
//! populates the global `DEVICES` registry in `super`.
//!
//! Called exclusively from `PciBus::enumerate()`; not part of the public API.

use super::{
    DEVICES, PciDevice,
    PCI_VENDOR, PCI_DEVICE, PCI_COMMAND, PCI_STATUS,
    PCI_CLASS, PCI_HDR_TYPE, PCI_BAR0, PCI_CAP_PTR,
    CMD_BUS_MASTER, CMD_MEM_SPACE, STATUS_CAP_LIST, CAP_MSIX,
};
use super::ecam::{cfg_read8, cfg_read16, cfg_read32, cfg_write16};

pub fn scan_all() {
    let mut devs = DEVICES.lock();
    devs.clear();

    for bus in 0u8..=255 {
        for dev in 0u8..32 {
            for func in 0u8..8 {
                let vid = cfg_read16(bus, dev, func, PCI_VENDOR);
                if vid == 0xFFFF {
                    continue;
                }

                let did   = cfg_read16(bus, dev, func, PCI_DEVICE);
                let class = cfg_read16(bus, dev, func, PCI_CLASS);
                let hdr   = cfg_read8 (bus, dev, func, PCI_HDR_TYPE);

                // Decode all 6 BARs (config offsets 0x10–0x24).
                // A 64-bit BAR occupies two consecutive slots; we advance
                // the index by 2 and leave the upper slot as 0.
                let mut bars = [0u64; 6];
                let mut i = 0usize;
                while i < 6 {
                    let off = PCI_BAR0 + (i as u16) * 4;
                    let raw = cfg_read32(bus, dev, func, off);
                    if raw & 0x1 != 0 {
                        // I/O-space BAR — not useful for MMIO drivers.
                        bars[i] = 0;
                        i += 1;
                        continue;
                    }
                    let is_64bit = (raw & 0x6) == 0x4;
                    let lo = (raw & !0xFu32) as u64;
                    if is_64bit && i + 1 < 6 {
                        let hi = cfg_read32(bus, dev, func, off + 4) as u64;
                        bars[i]     = lo | (hi << 32);
                        bars[i + 1] = 0; // upper half consumed
                        i += 2;
                    } else {
                        bars[i] = lo;
                        i += 1;
                    }
                }

                // Enable bus-master + memory-space decode.
                let cmd = cfg_read16(bus, dev, func, PCI_COMMAND);
                cfg_write16(bus, dev, func, PCI_COMMAND,
                    cmd | CMD_BUS_MASTER | CMD_MEM_SPACE);

                // Walk capability list; locate MSI-X (0x11).
                let mut msix_cap = 0u8;
                let status = cfg_read16(bus, dev, func, PCI_STATUS);
                if status & STATUS_CAP_LIST != 0 {
                    let mut ptr = cfg_read8(bus, dev, func, PCI_CAP_PTR) & !3;
                    for _ in 0..48 {
                        if ptr == 0 { break; }
                        let cap_id = cfg_read8(bus, dev, func, ptr as u16);
                        if cap_id == CAP_MSIX {
                            msix_cap = ptr;
                            break;
                        }
                        ptr = cfg_read8(bus, dev, func, ptr as u16 + 1);
                    }
                }

                devs.push(PciDevice {
                    bus, dev, func,
                    vendor: vid, device: did, class,
                    bars, msix_cap,
                });

                // Single-function device — skip remaining functions.
                if hdr & 0x80 == 0 && func == 0 {
                    break;
                }
            }
        }
    }
}
