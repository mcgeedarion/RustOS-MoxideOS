//! Network interface drivers.
//!
//! ## Modules
//!   e1000e           — Intel e1000e Gigabit Ethernet
//!   nic              — NIC abstraction layer (send / recv / mac / stats)
//!   virtio_net       — VirtIO network device (PCIe, x86_64)
//!   virtio_net_mmio  — VirtIO network device (MMIO, RISC-V virt machine)
//!   virtio_blk       — VirtIO block stubs (kept here for historical reasons)
//!
//! ## Boot entry-point
//!
//! `kernel_main` calls `crate::drivers::nic::init()` which resolves to this
//! module's `init()` function.  On x86_64 we walk `PCI_DEVICES` looking for a
//! known NIC PCI ID and hand the `PciDevice` to the matching driver.  On
//! RISC-V the virtio-net MMIO device was already probed by `fdt_phase2`; we
//! just tell `virtio_net_mmio` to finish its initialisation here.
//!
//! Priority order (first match wins):
//!   1. Intel e1000e   (vendor 0x8086, device 0x10D3)  — real / QEMU `-nic e1000e`
//!   2. virtio-net PCI (vendor 0x1AF4, device 0x1000)  — QEMU `-nic virtio`
//!   3. virtio-net MMIO                                 — RISC-V virt machine

pub mod e1000e;
pub mod nic;
pub mod virtio_blk;
pub mod virtio_net;
pub mod virtio_net_mmio;

// Known PCI IDs for supported NICs.
const VENDOR_INTEL:     u16 = 0x8086;
const DEV_E1000E:       u16 = 0x10D3;

const VENDOR_VIRTIO:    u16 = 0x1AF4;
const DEV_VIRTIO_NET:   u16 = 0x1000;   // legacy virtio-net
const DEV_VIRTIO_NET_T: u16 = 0x1041;   // transitional virtio-net (virtio 1.x)

/// Probe and initialise the first available NIC.
///
/// Called once from `kernel_main` after `pci::init()` (x86_64) or
/// `fdt_phase2()` (RISC-V).  Safe to call before the scheduler is running
/// because all drivers use spin-based init paths.
pub fn init() {
    // ── x86_64: PCI device scan ───────────────────────────────────────────────
    #[cfg(target_arch = "x86_64")]
    {
        // 1. Intel e1000e
        if let Some(dev) = crate::device::pci::find(VENDOR_INTEL, DEV_E1000E) {
            crate::serial_println!("[nic] found Intel e1000e at {:02x}:{:02x}.{}", dev.bus, dev.dev, dev.func);
            crate::drivers::net::e1000e::probe(&dev);
            return;
        }

        // 2. virtio-net (legacy PCI ID)
        if let Some(dev) = crate::device::pci::find(VENDOR_VIRTIO, DEV_VIRTIO_NET) {
            crate::serial_println!("[nic] found virtio-net (legacy) at {:02x}:{:02x}.{}", dev.bus, dev.dev, dev.func);
            crate::drivers::net::virtio_net::probe(&dev);
            return;
        }

        // 3. virtio-net (transitional / virtio 1.x PCI ID)
        if let Some(dev) = crate::device::pci::find(VENDOR_VIRTIO, DEV_VIRTIO_NET_T) {
            crate::serial_println!("[nic] found virtio-net (1.x) at {:02x}:{:02x}.{}", dev.bus, dev.dev, dev.func);
            crate::drivers::net::virtio_net::probe(&dev);
            return;
        }

        crate::serial_println!("[nic] no supported NIC found on PCI bus");
    }

    // ── RISC-V: virtio-net MMIO (probed by fdt_phase2; finish init here) ─────
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
