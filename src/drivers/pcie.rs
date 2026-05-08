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

/// Read a 32-bit dword from PCI legacy CAM config space.
pub unsafe fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = 0x8000_0000
        | ((bus  as u32) << 16)
        | ((dev  as u32) << 11)
        | ((func as u32) << 8)
        | ((offset & 0xFC) as u32);
    outl(PCI_ADDR, addr);
    inl(PCI_DATA)
}

/// Write a 32-bit dword to PCI legacy CAM config space.
pub unsafe fn pci_write32(bus: u8, dev: u8, func: u8, offset: u8, val: u32) {
    let addr: u32 = 0x8000_0000
        | ((bus  as u32) << 16)
        | ((dev  as u32) << 11)
        | ((func as u32) << 8)
        | ((offset & 0xFC) as u32);
    outl(PCI_ADDR, addr);
    outl(PCI_DATA, val);
}

/// Read a 16-bit word via CAM.
pub unsafe fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let dw = pci_read32(bus, dev, func, offset & 0xFC);
    ((dw >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

/// Read a byte via CAM.
pub unsafe fn pci_read8(bus: u8, dev: u8, func: u8, offset: u8) -> u8 {
    let dw = pci_read32(bus, dev, func, offset & 0xFC);
    ((dw >> ((offset & 3) * 8)) & 0xFF) as u8
}

// ── ECAM — Enhanced Configuration Access Mechanism ────────────────────────
//
// Physical base address of the ECAM MMIO window (PCI segment 0, bus 0 base).
// 0 means ECAM unavailable; all config_* functions fall back to CAM.
// Set by ecam_set_base() after parsing the ACPI MCFG table.

static ECAM_BASE: AtomicU64 = AtomicU64::new(0);

/// Store the ECAM MMIO base from MCFG.  Call before pcie_init().
/// Typical value on QEMU/OVMF: 0xB000_0000.
pub fn ecam_set_base(base: u64) {
    ECAM_BASE.store(base, Ordering::Release);
}

/// Raw pointer to the start of a function's 4 KiB ECAM config space.
#[inline]
fn ecam_ptr(bus: u8, dev: u8, func: u8) -> *mut u8 {
    let base   = ECAM_BASE.load(Ordering::Acquire);
    let offset = ((bus as u64) << 20) | ((dev as u64) << 15) | ((func as u64) << 12);
    (base + offset) as *mut u8
}

/// Read a 32-bit dword — ECAM if available, CAM otherwise.
/// ECAM supports the full 12-bit (0x000–0xFFC) PCIe config space.
pub unsafe fn config_read32(bus: u8, dev: u8, func: u8, offset: u16) -> u32 {
    if ECAM_BASE.load(Ordering::Relaxed) != 0 {
        core::ptr::read_volatile(ecam_ptr(bus, dev, func).add(offset as usize) as *mut u32)
    } else {
        pci_read32(bus, dev, func, offset as u8)
    }
}

/// Write a 32-bit dword — ECAM if available, CAM otherwise.
pub unsafe fn config_write32(bus: u8, dev: u8, func: u8, offset: u16, val: u32) {
    if ECAM_BASE.load(Ordering::Relaxed) != 0 {
        core::ptr::write_volatile(ecam_ptr(bus, dev, func).add(offset as usize) as *mut u32, val);
    } else {
        pci_write32(bus, dev, func, offset as u8, val);
    }
}

/// Read a 16-bit word via ECAM/CAM.
pub unsafe fn config_read16(bus: u8, dev: u8, func: u8, offset: u16) -> u16 {
    let dw = config_read32(bus, dev, func, offset & !3);
    ((dw >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

/// Read a byte via ECAM/CAM.
pub unsafe fn config_read8(bus: u8, dev: u8, func: u8, offset: u16) -> u8 {
    let dw = config_read32(bus, dev, func, offset & !3);
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

pub const PCI_CMD_MMIO:      u16 = 1 << 1; // memory space enable
pub const PCI_CMD_BUSMASTER: u16 = 1 << 2; // DMA enable

// PCI class codes (class.subclass)
pub const PCI_CLASS_STORAGE_IDE:  u32 = 0x0101;
pub const PCI_CLASS_STORAGE_AHCI: u32 = 0x0106;
pub const PCI_CLASS_STORAGE_NVME: u32 = 0x0108;
pub const PCI_CLASS_NETWORK_ETH:  u32 = 0x0200;
pub const PCI_CLASS_DISPLAY_VGA:  u32 = 0x0300;

// Capability IDs
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

    /// Enable MMIO + bus-master in the command register.
    pub fn enable(&self) {
        unsafe {
            let cmd = config_read16(self.bus, self.dev, self.func, PCI_COMMAND as u16);
            config_write32(self.bus, self.dev, self.func, PCI_COMMAND as u16,
                (cmd | PCI_CMD_MMIO | PCI_CMD_BUSMASTER) as u32);
        }
    }

    /// Return the MMIO base address of BARn, or None.
    pub fn bar_mmio(&self, n: usize) -> Option<u64> {
        self.bars.get(n).and_then(|b| b.as_ref()).and_then(|b| {
            if !b.is_io { Some(b.base) } else { None }
        })
    }
}

// ── Global device list ────────────────────────────────────────────────────

static DEVICES: Mutex<Vec<PciDevice>> = Mutex::new(Vec::new());

/// Walk the entire PCI bus tree and populate the device list.
/// Call once during early boot, after PMM + heap are up and ECAM is mapped.
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
    let class   = (cr >> 24) as u8;
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

// ── BAR decoding (with firmware preservation) ─────────────────────────────
//
// If firmware already assigned a non-zero base address to a BAR, we keep it.
// Only allocate from our windows when the firmware left the base at zero.
// This prevents collisions with HPET, LAPIC, IOAPIC, and other firmware MMIO.

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

/// Enable MSI (cap 0x05) for a device, routing `vector` to `apic_id`.
/// Pass apic_id=0 for BSP-only interrupt routing.
/// Returns true if MSI capability was found and configured.
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
            let mc           = (cap_dw >> 16) as u16;
            let is_64bit      = mc & (1 << 7) != 0;
            unsafe {
                config_write32(d.bus, d.dev, d.func, cap_off + 4, msg_addr);
                if is_64bit {
                    config_write32(d.bus, d.dev, d.func, cap_off + 8,  0);
                    config_write32(d.bus, d.dev, d.func, cap_off + 12, msg_data as u32);
                } else {
                    config_write32(d.bus, d.dev, d.func, cap_off + 8, msg_data as u32);
                }
                config_write32(d.bus, d.dev, d.func, cap_off,
                    (cap_dw & 0x0000_FFFF) | ((((mc & !0) | 1) as u32) << 16));
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
//
// MSI-X uses an MMIO table (pointed to by a BAR + offset) instead of a single
// config-space register.  Each 16-byte entry in the table:
//   [0x00] msg_addr_lo  (u32)
//   [0x04] msg_addr_hi  (u32)
//   [0x08] msg_data     (u32)
//   [0x0C] vector_ctrl  (u32)  bit 0 = per-vector mask
//
// The MSI-X capability structure (at cap_off in config space):
//   [+0x00] cap_id (0x11), next_cap, message_control
//       mc bits[10:0] = table_size - 1; bit[14] = function mask; bit[15] = enable
//   [+0x04] table_offset_and_bir
//       bits[2:0] = BIR (which BAR holds the table)
//       bits[31:3] = table offset (8-byte aligned)
//   [+0x08] pba_offset_and_bir (Pending Bit Array — not used here)
//
// Prerequisites before calling:
//   - dev.enable() must have been called (MMIO + bus-master bits set).
//   - The BAR that holds the MSI-X table must be mapped as UC in the kernel
//     page tables.  Map bar_base..bar_base+bar_size as UC before calling.
//
// For multi-vector devices, call in a loop:
//   for (entry, vec) in (0..).zip(MY_VECTORS) { pci_enable_msix(&dev, apic_id, vec, entry); }

/// Enable MSI-X, programming table entry `msix_entry` to fire `vector` on `apic_id`.
/// Returns true if the MSI-X capability was found and the entry was programmed.
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

            // Pointer to the 16-byte MSI-X table entry.
            // Assumes the BAR's MMIO is mapped (identity or at bar_base).
            let entry_va = (bar_base + tbl_offset + msix_entry as u64 * 16) as *mut u32;

            let msg_addr_lo: u32 = 0xFEE0_0000 | ((apic_id as u32) << 12);
            let msg_data: u32    = vector as u32; // fixed delivery, edge trigger

            unsafe {
                // Mask before writing (vector_ctrl bit 0 = 1).
                let ctrl_ptr = entry_va.add(3);
                core::ptr::write_volatile(ctrl_ptr,
                    core::ptr::read_volatile(ctrl_ptr) | 1);

                core::ptr::write_volatile(entry_va.add(0), msg_addr_lo);
                core::ptr::write_volatile(entry_va.add(1), 0u32); // addr hi = 0
                core::ptr::write_volatile(entry_va.add(2), msg_data);

                // Unmask (clear bit 0 of vector_ctrl).
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

/// Iterate over all discovered PCI devices, calling `f` for each.
pub fn with_devices<F: FnMut(&PciDevice)>(mut f: F) {
    for d in DEVICES.lock().iter() { f(d); }
}

/// Find the first device matching a class/subclass pair.
/// Common values: PCI_CLASS_STORAGE_NVME (0x0108), PCI_CLASS_NETWORK_ETH (0x0200).
pub fn find_device_by_class(class_sub: u32) -> Option<PciDevice> {
    DEVICES.lock().iter()
        .find(|d| d.class_sub() == class_sub)
        .cloned()
}

/// Find the first device matching a specific vendor + device ID.
///
/// Common IDs:
///   Intel NVMe:         (0x8086, 0x0953)
///   Intel e1000e NIC:   (0x8086, 0x10D3)
///   Intel igb NIC:      (0x8086, 0x10C9)
///   Realtek r8169 NIC:  (0x10EC, 0x8169)
///   AMD NVMe (FCH):     (0x1022, 0x7901)
///   AMD GPU (Navi):     (0x1002, 0x731F)
///   virtio-net:         (0x1AF4, 0x1000)
///   virtio-blk:         (0x1AF4, 0x1001)
pub fn find_device_by_id(vendor: u16, device: u16) -> Option<PciDevice> {
    DEVICES.lock().iter()
        .find(|d| d.vendor_id == vendor && d.device_id == device)
        .cloned()
}

/// Find all devices matching a vendor + device ID.
/// Use for multi-port NICs, multiple NVMe controllers, etc.
pub fn find_all_devices_by_id(vendor: u16, device: u16) -> Vec<PciDevice> {
    DEVICES.lock().iter()
        .filter(|d| d.vendor_id == vendor && d.device_id == device)
        .cloned()
        .collect()
}
