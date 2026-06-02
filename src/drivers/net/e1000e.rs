//! Intel e1000e / 82574L gigabit Ethernet driver.
//!
//! ## Scope
//!   - PCI BAR0 MMIO initialisation
//!   - RX/TX descriptor rings (legacy format)
//!   - Link up / MAC address readout
//!   - Interrupt moderation (optional, polling works without it)
//!   - Public API compatible with `nic.rs`
//!
//! ## Supported devices
//!   - 8086:10D3  82574L
//!   - 8086:10F6  82574L low-profile
//!   - 8086:150C  82583V (same register model)
//!
//! The driver is intentionally simple: one RX ring, one TX ring, all memory
//! allocated from the PMM and identity-mapped.  The `send` path is blocking
//! (spins until the NIC sets DD); the `recv` path polls the next RX desc.

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

use crate::drivers::net::nic::{MacAddr, NicStats};

pub const VENDOR_INTEL: u16 = 0x8086;
pub const DEV_82574L:   u16 = 0x10D3;
pub const DEV_82574L2:  u16 = 0x10F6;
pub const DEV_82583V:   u16 = 0x150C;

const CTRL:      usize = 0x0000;
const STATUS:    usize = 0x0008;
const EERD:      usize = 0x0014;
const CTRL_EXT:  usize = 0x0018;
const IMS:       usize = 0x00D0;
const IMC:       usize = 0x00D8;
const RCTL:      usize = 0x0100;
const TCTL:      usize = 0x0400;
const TIPG:      usize = 0x0410;

const RDBAL:     usize = 0x2800;
const RDBAH:     usize = 0x2804;
const RDLEN:     usize = 0x2808;
const RDH:       usize = 0x2810;
const RDT:       usize = 0x2818;

const TDBAL:     usize = 0x3800;
const TDBAH:     usize = 0x3804;
const TDLEN:     usize = 0x3808;
const TDH:       usize = 0x3810;
const TDT:       usize = 0x3818;

const RAL0:      usize = 0x5400;
const RAH0:      usize = 0x5404;

const ICR:       usize = 0x00C0;

// CTRL bits
const CTRL_RST:  u32 = 1 << 26;
const CTRL_SLU:  u32 = 1 << 6;
const CTRL_ASDE: u32 = 1 << 5;

// RCTL bits
const RCTL_EN:       u32 = 1 << 1;
const RCTL_BAM:      u32 = 1 << 15;
const RCTL_SECRC:    u32 = 1 << 26;
const RCTL_SZ_2048:  u32 = 0 << 16;

// TCTL bits
const TCTL_EN:       u32 = 1 << 1;
const TCTL_PSP:      u32 = 1 << 3;
const TCTL_CT_SHIFT: u32 = 4;
const TCTL_COLD_SHIFT:u32 = 12;

// RX/TX ring sizes
const RX_DESC_COUNT: usize = 256;
const TX_DESC_COUNT: usize = 256;
const RX_BUF_SIZE:   usize = 2048;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct RxDesc {
    addr:   u64,
    len:    u16,
    csum:   u16,
    status: u8,
    errors: u8,
    special:u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct TxDesc {
    addr:   u64,
    len:    u16,
    cso:    u8,
    cmd:    u8,
    status: u8,
    css:    u8,
    special:u16,
}

const RXD_STAT_DD: u8 = 1 << 0;
const TXD_CMD_EOP: u8 = 1 << 0;
const TXD_CMD_IFCS:u8 = 1 << 1;
const TXD_CMD_RS:  u8 = 1 << 3;
const TXD_STAT_DD: u8 = 1 << 0;

struct E1000e {
    mmio:        usize,
    rx_descs:    *mut RxDesc,
    tx_descs:    *mut TxDesc,
    rx_bufs:     Vec<u64>,
    tx_bufs:     Vec<u64>,
    rx_tail:     usize,
    tx_tail:     usize,
    mac:         MacAddr,
    stats:       NicStats,
}

unsafe impl Send for E1000e {}
unsafe impl Sync for E1000e {}

static NIC: Mutex<Option<E1000e>> = Mutex::new(None);

pub fn init(mmio_base: u64) {
    unsafe { _init(mmio_base as usize); }
}

pub fn is_initialised() -> bool {
    NIC.lock().is_some()
}

pub fn mac() -> Option<MacAddr> {
    NIC.lock().as_ref().map(|n| n.mac)
}

pub fn stats() -> Option<NicStats> {
    NIC.lock().as_ref().map(|n| n.stats)
}

pub fn send(frame: &[u8]) -> Result<(), &'static str> {
    unsafe { _send(frame) }
}

pub fn recv(out: &mut [u8]) -> Option<usize> {
    unsafe { _recv(out) }
}

unsafe fn _init(mmio: usize) {
    // Global reset.
    write32(mmio, CTRL, read32(mmio, CTRL) | CTRL_RST);
    for _ in 0..1_000_000 { core::hint::spin_loop(); }

    // Disable interrupts for polling mode.
    write32(mmio, IMC, 0xFFFF_FFFF);
    let _ = read32(mmio, ICR);

    // Allocate RX ring + buffers.
    let rx_descs_phys = alloc_dma(core::mem::size_of::<RxDesc>() * RX_DESC_COUNT, 4096).unwrap();
    let rx_descs = rx_descs_phys as *mut RxDesc;
    let mut rx_bufs = Vec::with_capacity(RX_DESC_COUNT);
    for i in 0..RX_DESC_COUNT {
        let buf = alloc_dma(RX_BUF_SIZE, 2048).unwrap();
        rx_bufs.push(buf);
        (*rx_descs.add(i)) = RxDesc { addr: buf, ..Default::default() };
    }

    // Allocate TX ring + buffers.
    let tx_descs_phys = alloc_dma(core::mem::size_of::<TxDesc>() * TX_DESC_COUNT, 4096).unwrap();
    let tx_descs = tx_descs_phys as *mut TxDesc;
    let mut tx_bufs = Vec::with_capacity(TX_DESC_COUNT);
    for i in 0..TX_DESC_COUNT {
        let buf = alloc_dma(2048, 2048).unwrap();
        tx_bufs.push(buf);
        (*tx_descs.add(i)) = TxDesc { status: TXD_STAT_DD, ..Default::default() };
    }

    // Program RX ring.
    write32(mmio, RDBAL, rx_descs_phys as u32);
    write32(mmio, RDBAH, (rx_descs_phys >> 32) as u32);
    write32(mmio, RDLEN, (RX_DESC_COUNT * core::mem::size_of::<RxDesc>()) as u32);
    write32(mmio, RDH, 0);
    write32(mmio, RDT, (RX_DESC_COUNT - 1) as u32);

    // Program TX ring.
    write32(mmio, TDBAL, tx_descs_phys as u32);
    write32(mmio, TDBAH, (tx_descs_phys >> 32) as u32);
    write32(mmio, TDLEN, (TX_DESC_COUNT * core::mem::size_of::<TxDesc>()) as u32);
    write32(mmio, TDH, 0);
    write32(mmio, TDT, 0);

    // Bring link up.
    write32(mmio, CTRL, read32(mmio, CTRL) | CTRL_SLU | CTRL_ASDE);

    // Receive control: enable, broadcast accept, strip CRC, 2048-byte buffers.
    write32(mmio, RCTL, RCTL_EN | RCTL_BAM | RCTL_SECRC | RCTL_SZ_2048);

    // Transmit control.
    let tctl = TCTL_EN | TCTL_PSP | (0x10 << TCTL_CT_SHIFT) | (0x40 << TCTL_COLD_SHIFT);
    write32(mmio, TCTL, tctl);
    write32(mmio, TIPG, 10 | (8 << 10) | (6 << 20));

    let mac = read_mac(mmio);
    *NIC.lock() = Some(E1000e {
        mmio,
        rx_descs,
        tx_descs,
        rx_bufs,
        tx_bufs,
        rx_tail: RX_DESC_COUNT - 1,
        tx_tail: 0,
        mac,
        stats: NicStats::default(),
    });
}

unsafe fn _send(frame: &[u8]) -> Result<(), &'static str> {
    let mut nic_g = NIC.lock();
    let nic = nic_g.as_mut().ok_or("e1000e not initialised")?;
    if frame.len() > 2048 { return Err("frame too large"); }

    let idx = nic.tx_tail;
    let desc = &mut *nic.tx_descs.add(idx);

    // Wait until NIC owns no longer.
    for _ in 0..5_000_000 {
        if desc.status & TXD_STAT_DD != 0 { break; }
        core::hint::spin_loop();
    }
    if desc.status & TXD_STAT_DD == 0 { return Err("tx timeout"); }

    core::ptr::copy_nonoverlapping(frame.as_ptr(), nic.tx_bufs[idx] as *mut u8, frame.len());
    *desc = TxDesc {
        addr: nic.tx_bufs[idx],
        len: frame.len() as u16,
        cmd: TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS,
        status: 0,
        ..Default::default()
    };

    nic.tx_tail = (idx + 1) % TX_DESC_COUNT;
    write32(nic.mmio, TDT, nic.tx_tail as u32);
    nic.stats.tx_packets += 1;
    nic.stats.tx_bytes += frame.len() as u64;
    Ok(())
}

unsafe fn _recv(out: &mut [u8]) -> Option<usize> {
    let mut nic_g = NIC.lock();
    let nic = nic_g.as_mut()?;

    let idx = (nic.rx_tail + 1) % RX_DESC_COUNT;
    let desc = &mut *nic.rx_descs.add(idx);
    if desc.status & RXD_STAT_DD == 0 {
        return None;
    }

    let len = desc.len as usize;
    let n = out.len().min(len);
    core::ptr::copy_nonoverlapping(nic.rx_bufs[idx] as *const u8, out.as_mut_ptr(), n);

    // Hand descriptor back to NIC.
    desc.status = 0;
    nic.rx_tail = idx;
    write32(nic.mmio, RDT, idx as u32);

    nic.stats.rx_packets += 1;
    nic.stats.rx_bytes += len as u64;
    Some(n)
}

unsafe fn read_mac(mmio: usize) -> MacAddr {
    let ral = read32(mmio, RAL0);
    let rah = read32(mmio, RAH0);
    MacAddr([
        (ral & 0xFF) as u8,
        ((ral >> 8) & 0xFF) as u8,
        ((ral >> 16) & 0xFF) as u8,
        ((ral >> 24) & 0xFF) as u8,
        (rah & 0xFF) as u8,
        ((rah >> 8) & 0xFF) as u8,
    ])
}

#[inline]
unsafe fn read32(base: usize, off: usize) -> u32 {
    read_volatile((base + off) as *const u32)
}

#[inline]
unsafe fn write32(base: usize, off: usize, val: u32) {
    write_volatile((base + off) as *mut u32, val);
}

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}
