//! Intel e1000e Gigabit Ethernet driver.
//!
//! ## Supported PCI IDs
//!   0x8086 / 0x10D3  — 82574L (most common QEMU e1000e target)
//!   0x8086 / 0x10EA  — 82577LM
//!   0x8086 / 0x10EB  — 82577LC
//!   0x8086 / 0x10EF  — 82579LM
//!
//! ## Register map (BAR0 MMIO)
//!   All offsets are relative to BAR0.  Access with read32/write32.
//!
//!   CTRL    0x0000  Device Control
//!   STATUS  0x0008  Device Status
//!   RCTL    0x0100  Receive Control
//!   TCTL    0x0400  Transmit Control
//!   RDBAL   0x2800  RX Descriptor Base Low
//!   RDBAH   0x2804  RX Descriptor Base High
//!   RDLEN   0x2808  RX Descriptor Ring Length (bytes)
//!   RDH     0x2810  RX Descriptor Head
//!   RDT     0x2818  RX Descriptor Tail
//!   TDBAL   0x3800  TX Descriptor Base Low
//!   TDBAH   0x3804  TX Descriptor Base High
//!   TDLEN   0x3808  TX Descriptor Ring Length (bytes)
//!   TDH     0x3810  TX Descriptor Head
//!   TDT     0x3818  TX Descriptor Tail
//!   RAL0    0x5400  Receive Address Low  (bytes 0-3 of MAC)
//!   RAH0    0x5404  Receive Address High (bytes 4-5 + AV bit)
//!   ICR     0x00C0  Interrupt Cause Read (clears on read)
//!   IMS     0x00D0  Interrupt Mask Set
//!   IMC     0x00D8  Interrupt Mask Clear
//!
//! ## Initialization sequence (e1000e_probe)
//!   1. PCIe: find_device_by_id (try all four IDs above)
//!   2. BAR0 MMIO, dev.enable()
//!   3. MSI-X entry 0 → E1000E_IRQ_VECTOR; fallback MSI; fallback polled
//!   4. Software reset (CTRL.RST, wait cleared)
//!   5. Read MAC from RAL0/RAH0
//!   6. Allocate 16-entry RX descriptor ring + 2 KiB buffers
//!   7. Program RDBAL/RDBAH/RDLEN/RDH/RDT; enable RCTL
//!   8. Allocate 16-entry TX descriptor ring + 2 KiB buffers
//!   9. Program TDBAL/TDBAH/TDLEN/TDH/TDT; enable TCTL
//!  10. Enable RXT0 interrupt (IMS bit 7)
//!  11. Register with nic::register_nic()
//!
//! ## Wiring in kernel_main
//!   ```rust
//!   e1000e::e1000e_probe();
//!   idt.set_handler(e1000e::E1000E_IRQ_VECTOR, e1000e_irq_stub);
//!   // naked stub calls e1000e::e1000e_irq()
//!   ```

use crate::drivers::pcie::{find_device_by_id, pci_enable_msix, pci_enable_msi_ex};
use crate::drivers::nic::{register_nic, NicDevice};
use crate::mm::pmm;
use spin::Mutex;

// ── IRQ vector ───────────────────────────────────────────────────────────

pub const E1000E_IRQ_VECTOR: u8 = 0x33;

// ── PCI IDs ──────────────────────────────────────────────────────────────

const VENDOR: u16 = 0x8086;
const DEVIDS: [u16; 4] = [0x10D3, 0x10EA, 0x10EB, 0x10EF];

// ── Register offsets ─────────────────────────────────────────────────────

const REG_CTRL:  u32 = 0x0000;
const REG_STATUS: u32 = 0x0008;
const REG_ICR:   u32 = 0x00C0;
const REG_IMS:   u32 = 0x00D0;
const REG_IMC:   u32 = 0x00D8;
const REG_RCTL:  u32 = 0x0100;
const REG_TCTL:  u32 = 0x0400;
const REG_RDBAL: u32 = 0x2800;
const REG_RDBAH: u32 = 0x2804;
const REG_RDLEN: u32 = 0x2808;
const REG_RDH:   u32 = 0x2810;
const REG_RDT:   u32 = 0x2818;
const REG_TDBAL: u32 = 0x3800;
const REG_TDBAH: u32 = 0x3804;
const REG_TDLEN: u32 = 0x3808;
const REG_TDH:   u32 = 0x3810;
const REG_TDT:   u32 = 0x3818;
const REG_RAL0:  u32 = 0x5400;
const REG_RAH0:  u32 = 0x5404;

// ── CTRL bits ─────────────────────────────────────────────────────────────

const CTRL_RST:        u32 = 1 << 26; // software reset
const CTRL_SLU:        u32 = 1 << 6;  // set link up
const CTRL_ASDE:       u32 = 1 << 5;  // auto-speed detection enable

// ── RCTL bits ────────────────────────────────────────────────────────────

const RCTL_EN:         u32 = 1 << 1;  // receiver enable
const RCTL_BAM:        u32 = 1 << 15; // broadcast accept
const RCTL_BSIZE_2K:   u32 = 0 << 16; // buffer size 2048 (BSIZE=00, BSEX=0)
const RCTL_SECRC:      u32 = 1 << 26; // strip CRC

// ── TCTL bits ────────────────────────────────────────────────────────────

const TCTL_EN:         u32 = 1 << 1;  // transmit enable
const TCTL_PSP:        u32 = 1 << 3;  // pad short packets
const TCTL_CT_SHIFT:   u32 = 4;       // collision threshold (set to 0x10)
const TCTL_COLD_SHIFT: u32 = 12;      // collision distance (set to 0x40)

// ── Interrupt bits (ICR/IMS) ─────────────────────────────────────────────

const ICR_RXT0:  u32 = 1 << 7; // RX timer interrupt (frame received)
const ICR_TXDW:  u32 = 1 << 0; // TX descriptor written-back

// ── Descriptor formats ───────────────────────────────────────────────────

/// Legacy RX descriptor (16 bytes).
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct RxDesc {
    addr:     u64, // buffer address
    length:   u16,
    checksum: u16,
    status:   u8,  // bit 0 = DD (descriptor done), bit 1 = EOP
    errors:   u8,
    special:  u16,
}

/// Legacy TX descriptor (16 bytes).
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct TxDesc {
    addr:    u64,
    length:  u16,
    cso:     u8,
    cmd:     u8,  // bit 0 = EOP, bit 1 = IFCS (insert FCS), bit 3 = RS (report status)
    status:  u8,  // bit 0 = DD
    css:     u8,
    special: u16,
}

const TX_CMD_EOP:  u8 = 1 << 0;
const TX_CMD_IFCS: u8 = 1 << 1;
const TX_CMD_RS:   u8 = 1 << 3;
const RX_STATUS_DD:  u8 = 1 << 0;
const TX_STATUS_DD:  u8 = 1 << 0;

// ── Ring size ────────────────────────────────────────────────────────────

const RING_SIZE:   usize = 16;
const RX_BUF_SIZE: usize = 2048;
const TX_BUF_SIZE: usize = 2048;

// ── Device state ─────────────────────────────────────────────────────────

struct E1000eDev {
    bar0:    u64,
    mac:     [u8; 6],
    rx_ring: *mut RxDesc,
    tx_ring: *mut TxDesc,
    rx_bufs: [*mut u8; RING_SIZE],
    tx_bufs: [*mut u8; RING_SIZE],
    rx_tail: usize,
    tx_tail: usize,
}

unsafe impl Send for E1000eDev {}

static DEV: Mutex<Option<E1000eDev>> = Mutex::new(None);

// ── Register helpers ─────────────────────────────────────────────────────

#[inline]
unsafe fn read32(bar0: u64, reg: u32) -> u32 {
    core::ptr::read_volatile((bar0 + reg as u64) as *const u32)
}
#[inline]
unsafe fn write32(bar0: u64, reg: u32, val: u32) {
    core::ptr::write_volatile((bar0 + reg as u64) as *mut u32, val);
}

// ── Probe ────────────────────────────────────────────────────────────────

/// Probe the e1000e controller.  Tries all known device IDs.
/// Call after pcie_init(); safe to call if no e1000e is present (returns false).
pub fn e1000e_probe() -> bool {
    let dev = DEVIDS.iter()
        .find_map(|&id| find_device_by_id(VENDOR, id));

    let dev = match dev {
        Some(d) => d,
        None => {
            crate::arch::x86_64::serial::serial_println!("e1000e: no device found");
            return false;
        }
    };

    let bar0 = match dev.bar_mmio(0) {
        Some(b) => b,
        None => {
            crate::arch::x86_64::serial::serial_println!("e1000e: BAR0 not MMIO");
            return false;
        }
    };

    dev.enable();

    let irq_mode = if pci_enable_msix(&dev, 0, E1000E_IRQ_VECTOR, 0) {
        "MSI-X"
    } else if pci_enable_msi_ex(&dev, 0, E1000E_IRQ_VECTOR) {
        "MSI"
    } else {
        "polled"
    };

    crate::arch::x86_64::serial::serial_println!(
        "e1000e: {:04x}:{:04x} BAR0={:#x} irq={}",
        dev.vendor_id, dev.device_id, bar0, irq_mode
    );

    unsafe { init(bar0) };
    true
}

unsafe fn init(bar0: u64) {
    // ── 1. Software reset ──────────────────────────────────────────────
    write32(bar0, REG_CTRL, read32(bar0, REG_CTRL) | CTRL_RST);
    // Spec says wait ≥ 1 µs; spin a few thousand PAUSEs.
    for _ in 0..10_000 {
        core::arch::asm!("pause", options(nomem, nostack));
        if read32(bar0, REG_CTRL) & CTRL_RST == 0 { break; }
    }

    // Disable all interrupts during setup.
    write32(bar0, REG_IMC, 0xFFFF_FFFF);

    // Set link up, auto-speed.
    let ctrl = read32(bar0, REG_CTRL);
    write32(bar0, REG_CTRL, (ctrl | CTRL_SLU | CTRL_ASDE) & !CTRL_RST);

    // ── 2. Read MAC from RAL0/RAH0 ────────────────────────────────────
    let ral = read32(bar0, REG_RAL0);
    let rah = read32(bar0, REG_RAH0);
    let mac = [
        (ral & 0xFF) as u8,
        ((ral >> 8)  & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8)  & 0xFF) as u8,
    ];
    crate::arch::x86_64::serial::serial_println!(
        "e1000e: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );

    // ── 3. RX ring ────────────────────────────────────────────────────
    // Allocate descriptor ring (RING_SIZE * 16 bytes) from PMM.
    // Each descriptor is 16 bytes; RING_SIZE=16 → 256 bytes total, fits in one page.
    let rx_ring_pa = pmm::alloc_page().expect("e1000e: rx ring alloc");
    core::ptr::write_bytes(rx_ring_pa as *mut u8, 0, 4096);
    let rx_ring = rx_ring_pa as *mut RxDesc;

    let mut rx_bufs = [core::ptr::null_mut::<u8>(); RING_SIZE];
    for (i, buf_ref) in rx_bufs.iter_mut().enumerate() {
        let buf_pa = pmm::alloc_page().expect("e1000e: rx buf alloc") as *mut u8;
        core::ptr::write_bytes(buf_pa, 0, 4096);
        *buf_ref = buf_pa;
        let desc = &mut *rx_ring.add(i);
        desc.addr   = buf_pa as u64;
        desc.status = 0;
    }

    write32(bar0, REG_RDBAL, (rx_ring_pa & 0xFFFF_FFFF) as u32);
    write32(bar0, REG_RDBAH, (rx_ring_pa >> 32) as u32);
    write32(bar0, REG_RDLEN, (RING_SIZE * core::mem::size_of::<RxDesc>()) as u32);
    write32(bar0, REG_RDH,   0);
    write32(bar0, REG_RDT,   (RING_SIZE - 1) as u32); // give all but head to HW

    let rctl = RCTL_EN | RCTL_BAM | RCTL_BSIZE_2K | RCTL_SECRC;
    write32(bar0, REG_RCTL, rctl);

    // ── 4. TX ring ────────────────────────────────────────────────────
    let tx_ring_pa = pmm::alloc_page().expect("e1000e: tx ring alloc");
    core::ptr::write_bytes(tx_ring_pa as *mut u8, 0, 4096);
    let tx_ring = tx_ring_pa as *mut TxDesc;

    let mut tx_bufs = [core::ptr::null_mut::<u8>(); RING_SIZE];
    for (i, buf_ref) in tx_bufs.iter_mut().enumerate() {
        let buf_pa = pmm::alloc_page().expect("e1000e: tx buf alloc") as *mut u8;
        core::ptr::write_bytes(buf_pa, 0, 4096);
        *buf_ref = buf_pa;
        // Pre-fill addr; length/cmd filled at transmit time.
        let desc = &mut *tx_ring.add(i);
        desc.addr   = buf_pa as u64;
        desc.status = TX_STATUS_DD; // mark all slots as done initially
    }

    write32(bar0, REG_TDBAL, (tx_ring_pa & 0xFFFF_FFFF) as u32);
    write32(bar0, REG_TDBAH, (tx_ring_pa >> 32) as u32);
    write32(bar0, REG_TDLEN, (RING_SIZE * core::mem::size_of::<TxDesc>()) as u32);
    write32(bar0, REG_TDH,   0);
    write32(bar0, REG_TDT,   0);

    let tctl: u32 = TCTL_EN | TCTL_PSP
        | (0x10 << TCTL_CT_SHIFT)
        | (0x40 << TCTL_COLD_SHIFT);
    write32(bar0, REG_TCTL, tctl);

    // ── 5. Enable RX interrupt (RXT0) ────────────────────────────────
    write32(bar0, REG_IMS, ICR_RXT0);

    // ── 6. Register with NIC abstraction layer ────────────────────────
    let state = E1000eDev {
        bar0, mac,
        rx_ring, tx_ring,
        rx_bufs, tx_bufs,
        rx_tail: RING_SIZE - 1,
        tx_tail: 0,
    };
    *DEV.lock() = Some(state);

    // Set our MAC in the ethernet layer.
    crate::net::eth::set_mac(mac);

    register_nic(NicDevice {
        send_frame: e1000e_send_frame,
        rx_poll:    e1000e_rx_poll,
        mac,
    });

    crate::arch::x86_64::serial::serial_println!("e1000e: ready");
}

// ── TX ────────────────────────────────────────────────────────────────────

fn e1000e_send_frame(frame: &[u8]) -> bool {
    if frame.len() > TX_BUF_SIZE {
        crate::arch::x86_64::serial::serial_println!(
            "e1000e: frame too large ({} bytes)", frame.len()
        );
        return false;
    }

    let mut guard = DEV.lock();
    let Some(dev) = guard.as_mut() else { return false; };

    // Wait for the slot to be free (TX_STATUS_DD set by hardware).
    let tail = dev.tx_tail;
    let desc = unsafe { &mut *dev.tx_ring.add(tail) };

    // Spin briefly if HW hasn't finished with this slot yet.
    for _ in 0..100_000 {
        if desc.status & TX_STATUS_DD != 0 { break; }
        unsafe { core::arch::asm!("pause", options(nomem, nostack)); }
    }
    if desc.status & TX_STATUS_DD == 0 {
        crate::arch::x86_64::serial::serial_println!("e1000e: TX ring full");
        return false;
    }

    // Copy frame into pre-allocated bounce buffer.
    unsafe {
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(), dev.tx_bufs[tail], frame.len()
        );
    }

    desc.length  = frame.len() as u16;
    desc.cmd     = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
    desc.status  = 0; // clear DD — hardware owns this descriptor now
    desc.cso     = 0;
    desc.css     = 0;
    desc.special = 0;

    dev.tx_tail = (tail + 1) % RING_SIZE;
    unsafe { write32(dev.bar0, REG_TDT, dev.tx_tail as u32); }
    true
}

// ── RX ────────────────────────────────────────────────────────────────────

fn e1000e_rx_poll() {
    let mut guard = DEV.lock();
    let Some(dev) = guard.as_mut() else { return; };

    loop {
        // The next descriptor to check is rx_tail + 1 (hardware writes
        // completed descriptors ahead of the tail pointer we gave it).
        let next = (dev.rx_tail + 1) % RING_SIZE;
        let desc = unsafe { &mut *dev.rx_ring.add(next) };

        if desc.status & RX_STATUS_DD == 0 {
            break; // no more completed descriptors
        }

        let len = desc.length as usize;
        if len > 0 && len <= RX_BUF_SIZE {
            let frame = unsafe {
                core::slice::from_raw_parts(dev.rx_bufs[next], len)
            };
            crate::net::eth::receive_frame(frame);
        }

        // Return descriptor to hardware: clear status, keep buffer addr.
        desc.status = 0;
        desc.length = 0;

        // Advance our tail and tell the hardware it can reuse this slot.
        dev.rx_tail = next;
        unsafe { write32(dev.bar0, REG_RDT, dev.rx_tail as u32); }
    }
}

// ── IRQ handler ───────────────────────────────────────────────────────────

/// Call from the naked IDT stub at E1000E_IRQ_VECTOR.
pub fn e1000e_irq() {
    let guard = DEV.lock();
    let Some(dev) = guard.as_ref() else { return; };
    // Read ICR to acknowledge and identify the cause.
    let icr = unsafe { read32(dev.bar0, REG_ICR) };
    drop(guard);

    if icr & ICR_RXT0 != 0 {
        e1000e_rx_poll();
    }
    // TX writeback (ICR_TXDW) is handled opportunistically in send_frame.
}

/// Return this NIC's MAC address.
pub fn mac_address() -> [u8; 6] {
    DEV.lock().as_ref().map(|d| d.mac).unwrap_or([0u8; 6])
}

/// True if the device was found and initialised.
pub fn is_present() -> bool {
    DEV.lock().is_some()
}
