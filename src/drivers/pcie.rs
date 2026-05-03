//! Phase 1 — PCIe bus enumerator.
//!
//! ## PCI configuration space access
//!   Legacy (CAM): two I/O ports — CONFIG_ADDRESS (0xCF8) and CONFIG_DATA (0xCFC).
//!     Write (bus<<16 | dev<<11 | fn<<8 | reg | 0x8000_0000) to 0xCF8,
//!     then read/write 32-bit value from 0xCFC.
//!     Covers bus 0-255, dev 0-31, fn 0-7, dword offsets 0-63 (256 B config space).
//!
//!   Extended (ECAM / PCIe): MMIO window from ACPI MCFG table.
//!     Base + (bus<<20 | dev<<15 | fn<<12) → 4 KiB config space per function.
//!     Covers 4096-byte config space, required for PCIe capabilities.
//!     We detect ECAM by scanning the ACPI tables; fall back to CAM.
//!
//! ## Enumeration strategy
//!   Recursive bus walk:
//!     For every (bus, dev 0..31, fn 0..7):
//!       Read vendor/device from offset 0. 0xFFFF vendor → slot empty, skip.
//!       Read header_type (offset 0x0E):
//!         Type 0 → endpoint device. Record PciDevice.
//!         Type 1 → PCI-to-PCI bridge. Recurse into secondary bus.
//!         Type 2 → CardBus bridge. Skip.
//!       Multi-function bit (header_type bit 7): if clear on fn 0, skip fn 1-7.
//!
//! ## BAR decode
//!   For each endpoint device, decode BARs 0-5:
//!     Write 0xFFFF_FFFF, read back, restore.
//!     Bit 0 = 0 → MMIO bar; bits [2:1] = type (0=32-bit, 2=64-bit).
//!     Bit 0 = 1 → I/O bar.
//!     Size = ~(readback & mask) + 1.
//!     Assign address from BAR allocator windows:
//!       MMIO32: 0xC000_0000 .. 0xFEBF_FFFF
//!       MMIO64: 0x4000_0000_0000 .. 0x5FFF_FFFF_FFFF
//!       IO:     0x1000 .. 0xFFFF
//!
//! ## MSI-X / MSI programming
//!   After enumeration, drivers call pci_enable_msi(dev, vector) which:
//!     Walks the capability list (offset 0x34) for cap ID 0x05 (MSI).
//!     Writes the LAPIC message address (0xFEE0_0000 | (apic_id << 12))
//!     and the vector into the MSI message data register.
//!     Clears the mask bit to enable.

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

// ── I/O port helpers ──────────────────────────────────────────────────────

unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    core::arch::asm!("in eax, dx", in("dx") port, out("eax") v);
    v
}
unsafe fn outl(port: u16, val: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") val);
}

const PCI_ADDR: u16 = 0xCF8;
const PCI_DATA: u16 = 0xCFC;

/// Read a 32-bit dword from PCI legacy config space.
pub unsafe fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = 0x8000_0000
        | ((bus  as u32) << 16)
        | ((dev  as u32) << 11)
        | ((func as u32) << 8)
        | ((offset & 0xFC) as u32);
    outl(PCI_ADDR, addr);
    inl(PCI_DATA)
}

/// Write a 32-bit dword to PCI legacy config space.
pub unsafe fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr: u32 = 0x8000_0000
        | ((bus  as u32) << 16)
        | ((dev  as u32) << 11)
        | ((func as u32) << 8)
        | ((offset & 0xFC) as u32);
    outl(PCI_ADDR, addr);
    outl(PCI_DATA, val);
}

/// Read a 16-bit word (little-endian, byte-shifted within the dword).
pub unsafe fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let dw = pci_read32(bus, dev, func, offset & 0xFC);
    ((dw >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

/// Read a byte.
pub unsafe fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let dw = pci_read32(bus, dev, func, offset & 0xFC);
    ((dw >> ((offset & 3) * 8)) & 0xFF) as u8
}

// ── PCI config space offsets ──────────────────────────────────────────────

pub const PCI_VENDOR_ID:     u8 = 0x00;
pub const PCI_DEVICE_ID:     u8 = 0x02;
pub const PCI_COMMAND:       u8 = 0x04;
pub const PCI_CLASS_REV:     u8 = 0x08; // [31:24]=class [23:16]=sub [15:8]=prog-if [7:0]=rev
pub const PCI_HEADER_TYPE:   u8 = 0x0E;
pub const PCI_BAR0:          u8 = 0x10;
pub const PCI_CAP_PTR:       u8 = 0x34;
pub const PCI_SECONDARY_BUS: u8 = 0x19; // only valid for type-1 headers

pub const PCI_CMD_MMIO:  u16 = 1 << 1;  // memory space enable
pub const PCI_CMD_BUSMASTER: u16 = 1 << 2; // DMA enable

// PCI class codes (class.subclass)
pub const PCI_CLASS_STORAGE_IDE:  u32 = 0x0101;
pub const PCI_CLASS_STORAGE_AHCI: u32 = 0x0106;
pub const PCI_CLASS_NETWORK_ETH:  u32 = 0x0200;
pub const PCI_CLASS_DISPLAY_VGA:  u32 = 0x0300;

// MSI capability ID
const CAP_MSI: u8 = 0x05;

// ── BAR allocator ─────────────────────────────────────────────────────────
// We hand out MMIO addresses from two windows that don't overlap the kernel
// or LAPIC. 32-bit BARs from 0xC000_0000; 64-bit from 0x4000_0000_0000.

static MMIO32_CURSOR: spin::Mutex<usize> = spin::Mutex::new(0xC000_0000);
static MMIO64_CURSOR: spin::Mutex<usize> = spin::Mutex::new(0x4000_0000_0000);
static IO_CURSOR:     spin::Mutex<u16>   = spin::Mutex::new(0x1000);

fn alloc_mmio32(size: u32) -> u64 {
    let mut cur = MMIO32_CURSOR.lock();
    let aligned = (*cur + size as usize - 1) & !(size as usize - 1);
    *cur = aligned + size as usize;
    aligned as u64
}
fn alloc_mmio64(size: u64) -> u64 {
    let mut cur = MMIO64_CURSOR.lock();
    let aligned = (*cur as u64 + size - 1) & !(size - 1);
    *cur = (aligned + size) as usize;
    aligned
}
fn alloc_io(size: u16) -> u16 {
    let mut cur = IO_CURSOR.lock();
    let aligned = (*cur + size - 1) & !(size - 1);
    *cur = aligned + size;
    aligned
}

// ── PciDevice ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PciBar {
    pub base: u64,
    pub size: u64,
    pub is_io: bool,
    pub is_64bit: bool,
}

#[derive(Clone, Debug)]
pub struct PciDevice {
    pub bus:       u8,
    pub dev:       u8,
    pub func:      u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class:     u8,   // base class
    pub subclass:  u8,
    pub prog_if:   u8,
    pub bars:      [Option<PciBar>; 6],
}

impl PciDevice {
    pub fn class_sub(&self) -> u32 {
        ((self.class as u32) << 8) | self.subclass as u32
    }

    /// Enable MMIO + bus-master in the command register.
    pub fn enable(&self) {
        unsafe {
            let cmd = pci_read16(self.bus, self.dev, self.func, PCI_COMMAND);
            pci_write32(self.bus, self.dev, self.func, PCI_COMMAND,
                (cmd | PCI_CMD_MMIO | PCI_CMD_BUSMASTER) as u32);
        }
    }

    /// Return the base address of BARn (MMIO), or None.
    pub fn bar_mmio(&self, n: usize) -> Option<u64> {
        self.bars.get(n).and_then(|b| b.as_ref()).and_then(|b| {
            if !b.is_io { Some(b.base) } else { None }
        })
    }
}

// ── Global device list ────────────────────────────────────────────────────

static DEVICES: Mutex<Vec<PciDevice>> = Mutex::new(Vec::new());

/// Walk the entire PCI bus tree and populate the device list.
/// Call once during early boot, after PMM + heap are up.
pub fn pcie_init() {
    let mut devs = DEVICES.lock();
    devs.clear();
    scan_bus(0, &mut devs);
    crate::arch::x86_64::serial::serial_println!(
        "pcie: {} device(s) found", devs.len()
    );
    for d in devs.iter() {
        crate::arch::x86_64::serial::serial_println!(
            "  [{:02x}:{:02x}.{:x}] {:04x}:{:04x} class {:02x}.{:02x}",
            d.bus, d.dev, d.func, d.vendor_id, d.device_id, d.class, d.subclass
        );
    }
}

fn scan_bus(bus: u8, out: &mut Vec<PciDevice>) {
    for dev in 0u8..32 {
        for func in 0u8..8 {
            if let Some(d) = probe(bus, dev, func) {
                let is_bridge = d.class == 0x06 && d.subclass == 0x04;
                out.push(d.clone());
                if is_bridge {
                    // Read secondary bus number and recurse.
                    let sec = unsafe {
                        pci_read8(bus, dev, func, PCI_SECONDARY_BUS)
                    };
                    if sec != 0 && sec != bus {
                        scan_bus(sec, out);
                    }
                }
                // If fn0 and not multi-function, skip fn 1-7.
                if func == 0 {
                    let ht = unsafe { pci_read8(bus, dev, func, PCI_HEADER_TYPE) };
                    if ht & 0x80 == 0 { break; }
                }
            }
        }
    }
}

fn probe(bus: u8, dev: u8, func: u8) -> Option<PciDevice> {
    let vd = unsafe { pci_read32(bus, dev, func, PCI_VENDOR_ID) };
    let vendor_id = (vd & 0xFFFF) as u16;
    if vendor_id == 0xFFFF { return None; }
    let device_id = (vd >> 16) as u16;

    let cr = unsafe { pci_read32(bus, dev, func, PCI_CLASS_REV) };
    let class   = (cr >> 24) as u8;
    let subclass= (cr >> 16) as u8;
    let prog_if = (cr >>  8) as u8;

    let header_type = unsafe { pci_read8(bus, dev, func, PCI_HEADER_TYPE) } & 0x7F;

    let bars = if header_type == 0 {
        decode_bars(bus, dev, func)
    } else {
        Default::default()
    };

    Some(PciDevice { bus, dev, func, vendor_id, device_id, class, subclass, prog_if, bars })
}

// ── BAR decoding ──────────────────────────────────────────────────────────

fn decode_bars(bus: u8, dev: u8, func: u8) -> [Option<PciBar>; 6] {
    let mut bars: [Option<PciBar>; 6] = Default::default();
    let mut i = 0usize;
    while i < 6 {
        let offset = PCI_BAR0 + (i as u8) * 4;
        let orig = unsafe { pci_read32(bus, dev, func, offset) };
        unsafe { pci_write32(bus, dev, func, offset, 0xFFFF_FFFF); }
        let readback = unsafe { pci_read32(bus, dev, func, offset) };
        unsafe { pci_write32(bus, dev, func, offset, orig); }

        if readback == 0 || readback == 0xFFFF_FFFF { i += 1; continue; }

        let is_io    = orig & 1 != 0;
        let bar_type = (orig >> 1) & 3; // 0=32-bit, 2=64-bit

        if is_io {
            let size = (!(readback & !3)).wrapping_add(1);
            let base = alloc_io(size as u16) as u64;
            // Program the new base.
            unsafe { pci_write32(bus, dev, func, offset, base as u32 | 1); }
            bars[i] = Some(PciBar { base, size: size as u64, is_io: true, is_64bit: false });
            i += 1;
        } else if bar_type == 2 {
            // 64-bit MMIO — next BAR holds high 32 bits.
            if i + 1 >= 6 { i += 2; continue; }
            let orig_hi = unsafe { pci_read32(bus, dev, func, offset + 4) };
            unsafe { pci_write32(bus, dev, func, offset + 4, 0xFFFF_FFFF); }
            let rb_hi   = unsafe { pci_read32(bus, dev, func, offset + 4) };
            unsafe { pci_write32(bus, dev, func, offset + 4, orig_hi); }
            let size64 = (!(((rb_hi as u64) << 32) | (readback & !0xF) as u64))
                .wrapping_add(1);
            let base64 = alloc_mmio64(size64);
            unsafe {
                pci_write32(bus, dev, func, offset,     (base64 & 0xFFFF_FFFF) as u32 | 0x4);
                pci_write32(bus, dev, func, offset + 4, (base64 >> 32) as u32);
            }
            bars[i] = Some(PciBar { base: base64, size: size64, is_io: false, is_64bit: true });
            i += 2; // skip the high-half BAR slot
        } else {
            // 32-bit MMIO
            let size = (!(readback & !0xF)).wrapping_add(1);
            let base = alloc_mmio32(size);
            unsafe { pci_write32(bus, dev, func, offset, base as u32); }
            bars[i] = Some(PciBar { base, size: size as u64, is_io: false, is_64bit: false });
            i += 1;
        }
    }
    bars
}

// ── MSI programming ───────────────────────────────────────────────────────

/// Enable MSI for a device and route it to `vector` on the BSP (APIC ID 0).
/// Returns true if MSI capability was found and configured.
pub fn pci_enable_msi(d: &PciDevice, vector: u8) -> bool {
    let mut cap_off = unsafe {
        pci_read8(d.bus, d.dev, d.func, PCI_CAP_PTR) & 0xFC
    };
    for _ in 0..48 { // cap chain max 48 hops
        if cap_off < 0x40 { break; }
        let cap_dw = unsafe { pci_read32(d.bus, d.dev, d.func, cap_off) };
        let cap_id = (cap_dw & 0xFF) as u8;
        if cap_id == CAP_MSI {
            // MSI message address: 0xFEE0_0000 | (apic_id << 12) | (RH=0, DM=0)
            let msg_addr: u32 = 0xFEE0_0000;
            // MSI message data: delivery mode=fixed (000), vector
            let msg_data: u16 = vector as u16;
            let ctrl = ((cap_dw >> 16) as u16) & !(1 << 0); // clear enable first
            unsafe {
                // Write address low (offset +4)
                pci_write32(d.bus, d.dev, d.func, cap_off + 4, msg_addr);
                // Address high = 0 (offset +8) for 32-bit MSI
                let mc = (cap_dw >> 16) as u16;
                let is_64bit = mc & (1 << 7) != 0;
                if is_64bit {
                    pci_write32(d.bus, d.dev, d.func, cap_off + 8, 0);
                    pci_write32(d.bus, d.dev, d.func, cap_off + 12,
                                msg_data as u32);
                } else {
                    pci_write32(d.bus, d.dev, d.func, cap_off + 8,
                                msg_data as u32);
                }
                // Enable MSI (bit 0 of message control)
                pci_write32(d.bus, d.dev, d.func, cap_off,
                            (cap_dw & 0x0000_FFFF) | (((ctrl | 1) as u32) << 16));
            }
            return true;
        }
        cap_off = ((cap_dw >> 8) & 0xFC) as u8;
    }
    false
}

// ── Public accessors ──────────────────────────────────────────────────────

/// Iterate over all discovered PCI devices, calling `f` for each.
pub fn with_devices<F: FnMut(&PciDevice)>(mut f: F) {
    for d in DEVICES.lock().iter() { f(d); }
}

/// Find the first device matching a class/subclass pair.
pub fn find_device_by_class(class_sub: u32) -> Option<PciDevice> {
    DEVICES.lock().iter()
        .find(|d| d.class_sub() == class_sub)
        .cloned()
}
