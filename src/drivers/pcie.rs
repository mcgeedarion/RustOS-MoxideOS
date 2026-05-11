//! PCIe bus enumerator — Phase 1 (ECAM + MSI-X).
//!
//! ## PCI configuration space access
//!   Legacy (CAM): two I/O ports — CONFIG_ADDRESS (0xCF8) and CONFIG_DATA (0xCFC).
//!     Write (bus<<16 | dev<<11 | fn<<8 | reg | 0x8000_0000) to 0xCF8,
//!     then read/write 32-bit value from 0xCFC.
//!     Covers bus 0-255, dev 0-31, fn 0-7, dword offsets 0-63 (256 B config space).
//!
//!   Extended (ECAM / PCIe): MMIO window from ACPI MCFG table.
//!     Base + (bus<<20 | dev<<15 | fn<<12) → 4 KiB config space per function.
//!     Covers 4096-byte config space, required for PCIe capabilities (offsets > 0xFF).
//!     Call ecam_set_base() from your ACPI init path before pcie_init().
//!     Map the window (ecam_base..ecam_base+256 MiB) as UC before any reads.
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
//!     BAR preservation: if firmware already set a non-zero base, keep it.
//!     Otherwise allocate from our windows:
//!       MMIO32: 0xC000_0000 .. 0xFEBF_FFFF
//!       MMIO64: 0x4000_0000_0000 .. 0x5FFF_FFFF_FFFF
//!       IO:     0x1000 .. 0xFFFF
//!
//! ## Interrupt programming
//!   For every new driver, try in this order:
//!     1. MSI-X (cap 0x11):  pci_enable_msix(&dev, apic_id, vector, entry_idx)
//!     2. MSI   (cap 0x05):  pci_enable_msi_ex(&dev, apic_id, vector)
//!     3. INTx fallback:     use ACPI _PRT routing
//!
//! ## MCFG parsing note
//!   MCFG signature: "MCFG"
//!   Header: standard 36-byte ACPI header + 8 reserved bytes.
//!   Entries start at offset 44 (0x2C), 16 bytes each:
//!     [+0x00] base_address (u64)   ← pass to ecam_set_base for segment 0
//!     [+0x08] pci_segment  (u16)   ← use entry where segment == 0
//!     [+0x0A] start_bus    (u8)
//!     [+0x0B] end_bus      (u8)
//!     [+0x0C] reserved     (u32)

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};

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

pub unsafe fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = 0x8000_0000
        | ((bus  as u32) << 16)
        | ((dev  as u32) << 11)
        | ((func as u32) << 8)
        | ((offset & 0xFC) as u32);
    outl(PCI_ADDR, addr);
    inl(PCI_DATA)
}

pub unsafe fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr: u32 = 0x8000_0000
        | ((bus  as u32) << 16)
        | ((dev  as u32) << 11)
        | ((func as u32) << 8)
        | ((offset & 0xFC) as u32);
    outl(PCI_ADDR, addr);
    outl(PCI_DATA, val);
}

pub unsafe fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let dw = pci_read32(bus, dev, func, offset & 0xFC);
    ((dw >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

pub unsafe fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let dw = pci_read32(bus, dev, func, offset & 0xFC);
    ((dw >> ((offset & 3) * 8)) & 0xFF) as u8
}

// ── ECAM ──────────────────────────────────────────────────────────────────

static ECAM_BASE: AtomicU64 = AtomicU64::new(0);

pub fn ecam_set_base(base: u64) {
    ECAM_BASE.store(base, Ordering::Release);
}

#[inline]
fn ecam_ptr(bus: u8, dev: u8, func: u8) -> *mut u8 {
    let base   = ECAM_BASE.load(Ordering::Acquire);
    let offset = ((bus as u64) << 20) | ((dev as u64) << 15) | ((func as u64) << 12);
    (base + offset) as *mut u8
}

pub unsafe fn config_read32(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    if ECAM_BASE.load(Ordering::Relaxed) != 0 {
        core::ptr::read_volatile(ecam_ptr(bus, dev, func).add(offset as usize) as *mut u32)
    } else {
        pci_read32(bus, dev, func, offset as u8)
    }
}

pub unsafe fn config_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    if ECAM_BASE.load(Ordering::Relaxed) != 0 {
        core::ptr::write_volatile(ecam_ptr(bus, dev, func).add(offset as usize) as *mut u32, val);
    } else {
        pci_write32(bus, dev, func, offset as u8, val);
    }
}

pub unsafe fn config_read16(bus: u8, dev: u8, func: u8, offset: u16) -> u16 {
    let dw = config_read32(bus, dev, func, offset & !3);
    ((dw >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

pub unsafe fn config_read8(bus: u8, dev: u8, func: u8, offset: u16) -> u8 {
    let dw = config_read32(bus, dev, func, offset & !3);
    ((dw >> ((offset & 3) * 8)) & 0xFF) as u8
}

// ── PCI config space offsets ──────────────────────────────────────────────

pub const PCI_VENDOR_ID:     u8 = 0x00;
pub const PCI_DEVICE_ID:     u8 = 0x02;
pub const PCI_COMMAND:       u8 = 0x04;
pub const PCI_CLASS_REV:     u8 = 0x08;
pub const PCI_HEADER_TYPE:   u8 = 0x0E;
pub const PCI_BAR0:          u8 = 0x10;
pub const PCI_CAP_PTR:       u8 = 0x34;
pub const PCI_SECONDARY_BUS: u8 = 0x19;

pub const PCI_CMD_MMIO:      u16 = 1 << 1;
pub const PCI_CMD_BUSMASTER: u16 = 1 << 2;
pub const PCI_CMD_IOSPACE:   u16 = 1 << 0; // I/O space enable

pub const PCI_CLASS_STORAGE_IDE:  u32 = 0x0101;
pub const PCI_CLASS_STORAGE_AHCI: u32 = 0x0106;
pub const PCI_CLASS_STORAGE_NVME: u32 = 0x0108;
pub const PCI_CLASS_NETWORK_ETH:  u32 = 0x0200;
pub const PCI_CLASS_DISPLAY_VGA:  u32 = 0x0300;

const CAP_MSI:  u8 = 0x05;
const CAP_MSIX: u8 = 0x11;

// ── BAR allocator ─────────────────────────────────────────────────────────

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
    pub base:    u64,
    pub size:    u64,
    pub is_io:   bool,
    pub is_64bit: bool,
}

#[derive(Clone, Debug)]
pub struct PciDevice {
    pub bus:       u8,
    pub dev:       u8,
    pub func:      u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class:     u8,
    pub subclass:  u8,
    pub prog_if:   u8,
    pub bars:      [Option<PciBar>; 6],
}

impl PciDevice {
    pub fn class_sub(&self) -> u32 {
        ((self.class as u32) << 8) | self.subclass as u32
    }

    /// Enable MMIO + bus-master + I/O space in the command register.
    pub fn enable(&self) {
        unsafe {
            let cmd = config_read16(self.bus, self.dev, self.func, PCI_COMMAND as u16);
            config_write32(
                self.bus, self.dev, self.func, PCI_COMMAND as u16,
                (cmd | PCI_CMD_MMIO | PCI_CMD_BUSMASTER | PCI_CMD_IOSPACE) as u32,
            );
        }
    }

    /// Return the MMIO base address of BARn, or None if it is an I/O BAR or unset.
    pub fn bar_mmio(&self, n: usize) -> Option<u64> {
        self.bars.get(n).and_then(|b| b.as_ref()).and_then(|b| {
            if !b.is_io { Some(b.base) } else { None }
        })
    }

    /// Return the I/O port base of BARn, or None if it is an MMIO BAR or unset.
    ///
    /// Used by legacy virtio drivers (BAR0 = I/O port space).
    pub fn bar_io(&self, n: usize) -> Option<u64> {
        self.bars.get(n).and_then(|b| b.as_ref()).and_then(|b| {
            if b.is_io { Some(b.base) } else { None }
        })
    }
}

// ── Global device list ────────────────────────────────────────────────────

static DEVICES: Mutex<Vec<PciDevice>> = Mutex::new(Vec::new());

pub fn pcie_init() {
    let mut devs = DEVICES.lock();
    devs.clear();
    scan_bus(0, &mut devs);
    let ecam_active = ECAM_BASE.load(Ordering::Relaxed) != 0;
    crate::arch::x86_64::serial::serial_println!(
        "pcie: {} device(s) found ({})",
        devs.len(),
        if ecam_active { "ECAM" } else { "CAM fallback" }
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
                    let sec = unsafe {
                        config_read8(bus, dev, func, PCI_SECONDARY_BUS as u16)
                    };
                    if sec != 0 && sec != bus {
                        scan_bus(sec, out);
                    }
                }
                if func == 0 {
                    let ht = unsafe { config_read8(bus, dev, func, PCI_HEADER_TYPE as u16) };
                    if ht & 0x80 == 0 { break; }
                }
            }
        }
    }
}

fn probe(bus: u8, dev: u8, func: u8) -> Option<PciDevice> {
    let vd = unsafe { config_read32(bus, dev, func, PCI_VENDOR_ID as u16) };
    let vendor_id = (vd & 0xFFFF) as u16;
    if vendor_id == 0xFFFF { return None; }
    let device_id = (vd >> 16) as u16;

    let cr = unsafe { config_read32(bus, dev, func, PCI_CLASS_REV as u16) };
    let class    = (cr >> 24) as u8;
    let subclass = (cr >> 16) as u8;
    let prog_if  = (cr >>  8) as u8;

    let header_type = unsafe { config_read8(bus, dev, func, PCI_HEADER_TYPE as u16) } & 0x7F;

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
        let offset = (PCI_BAR0 as u16) + (i as u16) * 4;
        let orig = unsafe { config_read32(bus, dev, func, offset) };

        unsafe { config_write32(bus, dev, func, offset, 0xFFFF_FFFF); }
        let readback = unsafe { config_read32(bus, dev, func, offset) };
        unsafe { config_write32(bus, dev, func, offset, orig); }

        if readback == 0 || readback == 0xFFFF_FFFF { i += 1; continue; }

        let is_io    = orig & 1 != 0;
        let bar_type = (orig >> 1) & 3;

        if is_io {
            let size = (!(readback & !3u32)).wrapping_add(1);
            let existing = (orig & !3) as u64;
            let base = if existing != 0 {
                existing
            } else {
                let b = alloc_io(size as u16) as u64;
                unsafe { config_write32(bus, dev, func, offset, b as u32 | 1); }
                b
            };
            bars[i] = Some(PciBar { base, size: size as u64, is_io: true, is_64bit: false });
            i += 1;

        } else if bar_type == 2 {
            if i + 1 >= 6 { i += 2; continue; }
            let offset_hi = offset + 4;
            let orig_hi = unsafe { config_read32(bus, dev, func, offset_hi) };

            unsafe { config_write32(bus, dev, func, offset_hi, 0xFFFF_FFFF); }
            let rb_hi = unsafe { config_read32(bus, dev, func, offset_hi) };
            unsafe { config_write32(bus, dev, func, offset_hi, orig_hi); }

            let size64 = (!(((rb_hi as u64) << 32) | (readback & !0xF) as u64))
                .wrapping_add(1);

            let existing64 = ((orig_hi as u64) << 32) | (orig & !0xF) as u64;
            let base64 = if existing64 != 0 {
                existing64
            } else {
                let b = alloc_mmio64(size64);
                unsafe {
                    config_write32(bus, dev, func, offset,    (b & 0xFFFF_FFFF) as u32 | 0x4);
                    config_write32(bus, dev, func, offset_hi, (b >> 32) as u32);
                }
                b
            };
            bars[i] = Some(PciBar { base: base64, size: size64, is_io: false, is_64bit: true });
            i += 2;

        } else {
            let size = (!(readback & !0xF)).wrapping_add(1);
            let existing = (orig & !0xF) as u64;
            let base = if existing != 0 {
                existing
            } else {
                let b = alloc_mmio32(size);
                unsafe { config_write32(bus, dev, func, offset, b as u32); }
                b
            };
            bars[i] = Some(PciBar { base, size: size as u64, is_io: false, is_64bit: false });
            i += 1;
        }
    }
    bars
}

// ── MSI programming ───────────────────────────────────────────────────────

/// Enable MSI (cap 0x05) for a device.
///
/// ## Fix: MSI Multi Message Enable field
///
/// The MSI Message Control register bits [6:4] select how many vectors the
/// device is granted (MME).  The old code wrote `(mc & !0) | 1`, where
/// `!0u16 == 0xFFFF` is an identity mask, so it left the MME field unchanged
/// at whatever firmware had set.  If firmware set MME > 0 (multiple vectors)
/// and the device had also set the corresponding MMC bits, the device might
/// use a different vector than `vector` for some interrupts.
///
/// The fix clears MME (bits [6:4]) to `000` before setting the MSI Enable
/// bit, requesting exactly 1 vector.  This matches what Linux does:
///   mc = (mc & ~PCI_MSI_FLAGS_QSIZE) | PCI_MSI_FLAGS_ENABLE;
pub fn pci_enable_msi_ex(d: &PciDevice, apic_id: u8, vector: u8) -> bool {
    let mut cap_off = unsafe {
        config_read8(d.bus, d.dev, d.func, PCI_CAP_PTR as u16) & 0xFC
    } as u16;

    for _ in 0..48 {
        if cap_off < 0x40 { break; }
        let cap_dw = unsafe { config_read32(d.bus, d.dev, d.func, cap_off) };
        let cap_id = (cap_dw & 0xFF) as u8;

        if cap_id == CAP_MSI {
            let msg_addr: u32 = 0xFEE0_0000 | ((apic_id as u32) << 12);
            let msg_data: u16 = vector as u16;
            let mc            = (cap_dw >> 16) as u16;
            let is_64bit      = mc & (1 << 7) != 0;
            unsafe {
                config_write32(d.bus, d.dev, d.func, cap_off + 4, msg_addr);
                if is_64bit {
                    config_write32(d.bus, d.dev, d.func, cap_off + 8,  0);
                    config_write32(d.bus, d.dev, d.func, cap_off + 12, msg_data as u32);
                } else {
                    config_write32(d.bus, d.dev, d.func, cap_off + 8,  msg_data as u32);
                }
                // Clear MME (bits [6:4]) to request 1 vector; set Enable (bit 0).
                // Old code: `(mc & !0) | 1` left MME bits unchanged (identity mask).
                let mc_new = (mc & !0x0070u16) | 1u16;
                config_write32(
                    d.bus, d.dev, d.func, cap_off,
                    (cap_dw & 0x0000_FFFF) | ((mc_new as u32) << 16),
                );
            }
            return true;
        }
        cap_off = ((cap_dw >> 8) & 0xFC) as u16;
    }
    false
}

/// Backwards-compatible wrapper — routes to BSP (APIC ID 0).
pub fn pci_enable_msi(d: &PciDevice, vector: u8) -> bool {
    pci_enable_msi_ex(d, 0, vector)
}

// ── MSI-X programming (cap 0x11) ─────────────────────────────────────────

pub fn pci_enable_msix(d: &PciDevice, apic_id: u8, vector: u8, msix_entry: u16) -> bool {
    let mut cap_off = unsafe {
        config_read8(d.bus, d.dev, d.func, PCI_CAP_PTR as u16) & 0xFC
    } as u16;

    for _ in 0..48 {
        if cap_off < 0x40 { break; }
        let cap_dw = unsafe { config_read32(d.bus, d.dev, d.func, cap_off) };
        let cap_id = (cap_dw & 0xFF) as u8;

        if cap_id == CAP_MSIX {
            let table_dw  = unsafe { config_read32(d.bus, d.dev, d.func, cap_off + 4) };
            let bir        = (table_dw & 0x7) as usize;
            let tbl_offset = (table_dw & !0x7) as u64;

            let bar_base = match d.bar_mmio(bir) {
                Some(b) => b,
                None    => return false,
            };

            let entry_va = (bar_base + tbl_offset + msix_entry as u64 * 16) as *mut u32;

            let msg_addr_lo: u32 = 0xFEE0_0000 | ((apic_id as u32) << 12);
            let msg_data: u32    = vector as u32;

            unsafe {
                // Mask the entry before modifying it.
                let ctrl_ptr = entry_va.add(3);
                core::ptr::write_volatile(ctrl_ptr,
                    core::ptr::read_volatile(ctrl_ptr) | 1);

                core::ptr::write_volatile(entry_va.add(0), msg_addr_lo);
                core::ptr::write_volatile(entry_va.add(1), 0u32);
                core::ptr::write_volatile(entry_va.add(2), msg_data);

                // Unmask.
                core::ptr::write_volatile(entry_va.add(3),
                    core::ptr::read_volatile(entry_va.add(3)) & !1);
            }

            // Enable MSI-X (bit 15), clear function mask (bit 14).
            let mc   = (cap_dw >> 16) as u16;
            let ctrl = (mc | (1 << 15)) & !(1 << 14);
            unsafe {
                config_write32(d.bus, d.dev, d.func, cap_off,
                    (cap_dw & 0x0000_FFFF) | ((ctrl as u32) << 16));
            }
            return true;
        }

        cap_off = ((cap_dw >> 8) & 0xFC) as u16;
    }
    false
}

// ── Public accessors ──────────────────────────────────────────────────────

pub fn with_devices<F: FnMut(&PciDevice)>(mut f: F) {
    for d in DEVICES.lock().iter() { f(d); }
}

pub fn find_device_by_class(class_sub: u32) -> Option<PciDevice> {
    DEVICES.lock().iter()
        .find(|d| d.class_sub() == class_sub)
        .cloned()
}

pub fn find_device_by_id(vendor: u16, device: u16) -> Option<PciDevice> {
    DEVICES.lock().iter()
        .find(|d| d.vendor_id == vendor && d.device_id == device)
        .cloned()
}

pub fn find_all_devices_by_id(vendor: u16, device: u16) -> Vec<PciDevice> {
    DEVICES.lock().iter()
        .filter(|d| d.vendor_id == vendor && d.device_id == device)
        .cloned()
        .collect()
}
