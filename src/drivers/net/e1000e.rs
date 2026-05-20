//! Intel e1000e Gigabit Ethernet driver.
//!
//! ## Supported PCI IDs
//!   0x8086 / 0x10D3  — 82574L (most common QEMU e1000e target)
//!   0x8086 / 0x10EA  — 82577LM
//!   0x8086 / 0x10EB  — 82577LC
//!   0x8086 / 0x10EF  — 82579LM
//!
//! ## Register map (BAR0 MMIO)
//!   CTRL    0x0000  RCTL    0x0100  TCTL    0x0400
//!   ICR     0x00C0  IMS     0x00D0  IMC     0x00D8
//!   RDBAL   0x2800  RDBAH   0x2804  RDLEN   0x2808
//!   RDH     0x2810  RDT     0x2818
//!   TDBAL   0x3800  TDBAH   0x3804  TDLEN   0x3808
//!   TDH     0x3810  TDT     0x3818
//!   RAL0    0x5400  RAH0    0x5404

use crate::drivers::net::nic::{register_nic, NicDevice};
use crate::drivers::platform::pcie::{enumerate, pci_enable_msix, pci_enable_msi_ex};
use crate::mm::pmm;
use spin::Mutex;

pub const E1000E_IRQ_VECTOR: u8 = 0x33;

const VENDOR: u16 = 0x8086;
const DEVIDS: [u16; 4] = [0x10D3, 0x10EA, 0x10EB, 0x10EF];

const REG_CTRL:  u32 = 0x0000; const REG_STATUS: u32 = 0x0008;
const REG_ICR:   u32 = 0x00C0; const REG_IMS:   u32 = 0x00D0; const REG_IMC: u32 = 0x00D8;
const REG_RCTL:  u32 = 0x0100; const REG_TCTL:  u32 = 0x0400;
const REG_RDBAL: u32 = 0x2800; const REG_RDBAH: u32 = 0x2804;
const REG_RDLEN: u32 = 0x2808; const REG_RDH:   u32 = 0x2810; const REG_RDT: u32 = 0x2818;
const REG_TDBAL: u32 = 0x3800; const REG_TDBAH: u32 = 0x3804;
const REG_TDLEN: u32 = 0x3808; const REG_TDH:   u32 = 0x3810; const REG_TDT: u32 = 0x3818;
const REG_RAL0:  u32 = 0x5400; const REG_RAH0:  u32 = 0x5404;

const CTRL_RST: u32 = 1 << 26; const CTRL_SLU: u32 = 1 << 6; const CTRL_ASDE: u32 = 1 << 5;
const RCTL_EN: u32 = 1 << 1; const RCTL_BAM: u32 = 1 << 15;
const RCTL_BSIZE_2K: u32 = 0 << 16; const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1; const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT_SHIFT: u32 = 4; const TCTL_COLD_SHIFT: u32 = 12;
const ICR_RXT0: u32 = 1 << 7;

#[repr(C, align(16))] #[derive(Clone, Copy, Default)]
struct RxDesc { addr: u64, length: u16, checksum: u16, status: u8, errors: u8, special: u16 }
#[repr(C, align(16))] #[derive(Clone, Copy, Default)]
struct TxDesc { addr: u64, length: u16, cso: u8, cmd: u8, status: u8, css: u8, special: u16 }

const TX_CMD_EOP: u8 = 1 << 0; const TX_CMD_IFCS: u8 = 1 << 1; const TX_CMD_RS: u8 = 1 << 3;
const RX_STATUS_DD: u8 = 1 << 0; const TX_STATUS_DD: u8 = 1 << 0;
const RING_SIZE: usize = 16; const RX_BUF_SIZE: usize = 2048; const TX_BUF_SIZE: usize = 2048;

struct E1000eDev {
    bar0: u64, mac: [u8; 6],
    rx_ring: *mut RxDesc, tx_ring: *mut TxDesc,
    rx_bufs: [*mut u8; RING_SIZE], tx_bufs: [*mut u8; RING_SIZE],
    rx_tail: usize, tx_tail: usize,
}
unsafe impl Send for E1000eDev {}
static DEV: Mutex<Option<E1000eDev>> = Mutex::new(None);

#[inline] unsafe fn read32(bar0: u64, reg: u32) -> u32 { core::ptr::read_volatile((bar0 + reg as u64) as *const u32) }
#[inline] unsafe fn write32(bar0: u64, reg: u32, val: u32) { core::ptr::write_volatile((bar0 + reg as u64) as *mut u32, val); }

pub fn e1000e_probe() -> bool {
    let pci_dev = enumerate().into_iter().find(|d| d.vendor == VENDOR && DEVIDS.contains(&d.device));
    let pci_dev = match pci_dev { Some(d) => d, None => { crate::println!("e1000e: no device found"); return false; } };
    let bar0 = match pci_dev.bar_mmio(0) { Some(b) => b, None => { crate::println!("e1000e: BAR0 not MMIO"); return false; } };
    pci_dev.enable();
    let irq_mode = if pci_enable_msix(&pci_dev, 0, E1000E_IRQ_VECTOR, 0) { "MSI-X" }
        else if pci_enable_msi_ex(&pci_dev, 0, E1000E_IRQ_VECTOR) { "MSI" } else { "polled" };
    crate::println!("e1000e: {:04x}:{:04x} BAR0={:#x} irq={}", pci_dev.vendor, pci_dev.device, bar0, irq_mode);
    unsafe { init(bar0) }; true
}

unsafe fn init(bar0: u64) {
    write32(bar0, REG_CTRL, read32(bar0, REG_CTRL) | CTRL_RST);
    for _ in 0..10_000 { core::arch::asm!("pause", options(nomem, nostack)); if read32(bar0, REG_CTRL) & CTRL_RST == 0 { break; } }
    write32(bar0, REG_IMC, 0xFFFF_FFFF);
    let ctrl = read32(bar0, REG_CTRL);
    write32(bar0, REG_CTRL, (ctrl | CTRL_SLU | CTRL_ASDE) & !CTRL_RST);
    let ral = read32(bar0, REG_RAL0); let rah = read32(bar0, REG_RAH0);
    let mac = [(ral & 0xFF) as u8, ((ral >> 8) & 0xFF) as u8, ((ral >> 16) & 0xFF) as u8,
               ((ral >> 24) & 0xFF) as u8, (rah & 0xFF) as u8, ((rah >> 8) & 0xFF) as u8];
    crate::println!("e1000e: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    let rx_ring_pa = pmm::alloc_page().expect("e1000e: rx ring alloc");
    core::ptr::write_bytes(rx_ring_pa as *mut u8, 0, 4096);
    let rx_ring = rx_ring_pa as *mut RxDesc;
    let mut rx_bufs = [core::ptr::null_mut::<u8>(); RING_SIZE];
    for (i, buf_ref) in rx_bufs.iter_mut().enumerate() {
        let buf_pa = pmm::alloc_page().expect("e1000e: rx buf alloc") as *mut u8;
        core::ptr::write_bytes(buf_pa, 0, 4096); *buf_ref = buf_pa;
        let desc = &mut *rx_ring.add(i); desc.addr = buf_pa as u64; desc.status = 0;
    }
    write32(bar0, REG_RDBAL, (rx_ring_pa & 0xFFFF_FFFF) as u32);
    write32(bar0, REG_RDBAH, (rx_ring_pa >> 32) as u32);
    write32(bar0, REG_RDLEN, (RING_SIZE * core::mem::size_of::<RxDesc>()) as u32);
    write32(bar0, REG_RDH, 0); write32(bar0, REG_RDT, (RING_SIZE - 1) as u32);
    write32(bar0, REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2K | RCTL_SECRC);
    let tx_ring_pa = pmm::alloc_page().expect("e1000e: tx ring alloc");
    core::ptr::write_bytes(tx_ring_pa as *mut u8, 0, 4096);
    let tx_ring = tx_ring_pa as *mut TxDesc;
    let mut tx_bufs = [core::ptr::null_mut::<u8>(); RING_SIZE];
    for (i, buf_ref) in tx_bufs.iter_mut().enumerate() {
        let buf_pa = pmm::alloc_page().expect("e1000e: tx buf alloc") as *mut u8;
        core::ptr::write_bytes(buf_pa, 0, 4096); *buf_ref = buf_pa;
        let desc = &mut *tx_ring.add(i); desc.addr = buf_pa as u64; desc.status = TX_STATUS_DD;
    }
    write32(bar0, REG_TDBAL, (tx_ring_pa & 0xFFFF_FFFF) as u32);
    write32(bar0, REG_TDBAH, (tx_ring_pa >> 32) as u32);
    write32(bar0, REG_TDLEN, (RING_SIZE * core::mem::size_of::<TxDesc>()) as u32);
    write32(bar0, REG_TDH, 0); write32(bar0, REG_TDT, 0);
    write32(bar0, REG_TCTL, TCTL_EN | TCTL_PSP | (0x10 << TCTL_CT_SHIFT) | (0x40 << TCTL_COLD_SHIFT));
    write32(bar0, REG_IMS, ICR_RXT0);
    *DEV.lock() = Some(E1000eDev { bar0, mac, rx_ring, tx_ring, rx_bufs, tx_bufs, rx_tail: RING_SIZE - 1, tx_tail: 0 });
    crate::net::eth::set_mac(mac);
    register_nic(NicDevice { send_frame: e1000e_send_frame, rx_poll: e1000e_rx_poll, mac });
    crate::println!("e1000e: ready");
}

fn e1000e_send_frame(frame: &[u8]) -> bool {
    if frame.len() > TX_BUF_SIZE { return false; }
    let mut guard = DEV.lock(); let Some(dev) = guard.as_mut() else { return false; };
    let tail = dev.tx_tail; let desc = unsafe { &mut *dev.tx_ring.add(tail) };
    for _ in 0..100_000 { if desc.status & TX_STATUS_DD != 0 { break; } unsafe { core::arch::asm!("pause", options(nomem, nostack)); } }
    if desc.status & TX_STATUS_DD == 0 { return false; }
    unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), dev.tx_bufs[tail], frame.len()); }
    desc.length = frame.len() as u16; desc.cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
    desc.status = 0; desc.cso = 0; desc.css = 0; desc.special = 0;
    dev.tx_tail = (tail + 1) % RING_SIZE;
    unsafe { write32(dev.bar0, REG_TDT, dev.tx_tail as u32); }
    true
}

fn e1000e_rx_poll() {
    let mut guard = DEV.lock(); let Some(dev) = guard.as_mut() else { return; };
    loop {
        let next = (dev.rx_tail + 1) % RING_SIZE;
        let desc = unsafe { &mut *dev.rx_ring.add(next) };
        if desc.status & RX_STATUS_DD == 0 { break; }
        let len = desc.length as usize;
        if len > 0 && len <= RX_BUF_SIZE {
            let frame = unsafe { core::slice::from_raw_parts(dev.rx_bufs[next], len) };
            crate::net::eth::receive_frame(frame);
        }
        desc.status = 0; desc.length = 0;
        dev.rx_tail = next;
        unsafe { write32(dev.bar0, REG_RDT, dev.rx_tail as u32); }
    }
}

pub fn e1000e_irq() {
    let guard = DEV.lock(); let Some(dev) = guard.as_ref() else { return; };
    let icr = unsafe { read32(dev.bar0, REG_ICR) }; drop(guard);
    if icr & ICR_RXT0 != 0 { e1000e_rx_poll(); }
}

pub fn mac_address() -> [u8; 6] { DEV.lock().as_ref().map(|d| d.mac).unwrap_or([0u8; 6]) }
pub fn is_present() -> bool { DEV.lock().is_some() }
