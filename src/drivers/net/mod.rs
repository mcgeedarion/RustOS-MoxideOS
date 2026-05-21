//! Network interface drivers.
//!
//! ## Modules
//!   e1000e           — Intel e1000e Gigabit Ethernet (takes BAR0 MMIO u64)
//!   nic              — NIC abstraction layer (send / recv / mac / stats)
//!   virtio_net       — VirtIO network device (PCIe, x86_64; takes BAR0 I/O port u16)
//!   virtio_net_mmio  — VirtIO network device (MMIO, RISC-V virt machine)
//!   virtio_blk       — VirtIO block stubs
//!
//! ## Boot entry-point
//!
//! `kernel_main` calls `crate::drivers::nic::init()` which resolves here.
//! On x86_64 we scan PCI_DEVICES for a known NIC, extract the correct BAR,
//! and call the driver's existing `init(raw)` function directly — no probe()
//! wrapper needed in the individual drivers.
//!
//! BAR layout per driver:
//!   e1000e      — BAR0 is a 64-bit MMIO region  → passed as u64
//!   virtio-net  — BAR0 is a legacy I/O port BAR → low 16 bits (mask ~0x3) as u16
//!
//! Priority order (first match wins):
//!   1. Intel e1000e   (0x8086:0x10D3 / 0x10F6 / 0x150C)
//!   2. virtio-net PCI (0x1AF4:0x1000 legacy | 0x1041 transitional)
//!   3. virtio-net MMIO (RISC-V only)

pub mod e1000e;
pub mod nic;
pub mod virtio_blk;
pub mod virtio_net;
pub mod virtio_net_mmio;

// ── PCI IDs ──────────────────────────────────────────────────────────────────

const VENDOR_INTEL:       u16 = 0x8086;
const DEV_E1000E_82574L:  u16 = 0x10D3;
const DEV_E1000E_82574L2: u16 = 0x10F6;
const DEV_E1000E_82583V:  u16 = 0x150C;

const VENDOR_VIRTIO:      u16 = 0x1AF4;
const DEV_VIRTIO_NET_LEG: u16 = 0x1000;   // legacy (virtio 0.9)
const DEV_VIRTIO_NET_T:   u16 = 0x1041;   // transitional (virtio 1.x)

/// Probe and initialise the first available NIC.
///
/// Called once from `kernel_main` after `pci::init()` (x86_64) or
/// `fdt_phase2()` (RISC-V).  Safe to call before the scheduler is running.
pub fn init() {
    // ── x86_64: PCI scan + inline BAR extraction ──────────────────────────────
    #[cfg(target_arch = "x86_64")]
    {
        use crate::device::pci;

        // 1. Intel e1000e — BAR0 is a 64-bit MMIO BAR.
        //    PCI spec: bits[2:1] == 0b10 for 64-bit; base = bar0 & !0xF
        //    combined with bar1 as the high 32 bits.
        let e1000e_ids = [DEV_E1000E_82574L, DEV_E1000E_82574L2, DEV_E1000E_82583V];
        for &dev_id in &e1000e_ids {
            if let Some(dev) = pci::find(VENDOR_INTEL, dev_id) {
                let bar0 = dev.bar[0];
                let bar1 = dev.bar[1];
                // BAR0 low bits: bit0=0 (MMIO), bits[2:1]=10 (64-bit)
                let mmio_base: u64 = ((bar1 as u64) << 32) | ((bar0 as u64) & !0xF);
                crate::serial_println!(
                    "[nic] Intel e1000e {:04x}:{:04x} at {:02x}:{:02x}.{} BAR0={:#x}",
                    VENDOR_INTEL, dev_id, dev.bus, dev.dev, dev.func, mmio_base
                );
                crate::drivers::net::e1000e::init(mmio_base);
                return;
            }
        }

        // 2. virtio-net — BAR0 is a legacy I/O port BAR.
        //    PCI spec: bit0=1 (I/O); base = bar0 & !0x3
        let vnet_ids = [DEV_VIRTIO_NET_LEG, DEV_VIRTIO_NET_T];
        for &dev_id in &vnet_ids {
            if let Some(dev) = pci::find(VENDOR_VIRTIO, dev_id) {
                let iobase: u16 = (dev.bar[0] & !0x3) as u16;
                crate::serial_println!(
                    "[nic] virtio-net {:04x}:{:04x} at {:02x}:{:02x}.{} iobase={:#x}",
                    VENDOR_VIRTIO, dev_id, dev.bus, dev.dev, dev.func, iobase
                );
                crate::drivers::net::virtio_net::init(iobase);
                return;
            }
        }

        crate::serial_println!("[nic] no supported NIC found on PCI bus");
    }

    // ── RISC-V: virtio-net MMIO (base already found by fdt_phase2) ───────────
    #[cfg(target_arch = "riscv64")]
    {
        crate::drivers::net::virtio_net_mmio::init();
        if crate::drivers::net::virtio_net_mmio::is_initialised() {
            crate::serial_println!("[nic] virtio-net MMIO initialised");
        } else {
            crate::serial_println!("[nic] no virtio-net MMIO device found");
        }
    }
}
