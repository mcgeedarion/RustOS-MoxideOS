//! Intel e1000e Gigabit Ethernet driver.
//!
//! Supports the 82574L (PCI device 0x10D3) used by QEMU `-device e1000e`.
//!
//! ## Architecture
//!   - 16-entry TX descriptor ring
//!   - 16-entry RX descriptor ring (legacy descriptors)
//!   - DMA buffers allocated from PMM
//!   - Synchronous TX (spin on TXD.DD); interrupt-free RX poll

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;
use super::nic::NetworkDevice;

// ---------------------------------------------------------------------------
// Register offsets
// ---------------------------------------------------------------------------

const E1000_CTRL:   usize = 0x0000;
const E1000_STATUS: usize = 0x0008;
const E1000_EERD:   usize = 0x0014;
const E1000_ICR:    usize = 0x00C0;
const E1000_IMS:    usize = 0x00D0;
const E1000_IMC:    usize = 0x00D8;
const E1000_RCTL:   usize = 0x0100;
const E1000_TCTL:   usize = 0x0400;
const E1000_TIPG:   usize = 0x0410;
const E1000_RDBAL:  usize = 0x2800;
const E1000_RDBAH:  usize = 0x2804;
const E1000_RDLEN:  usize = 0x2808;
const E1000_RDH:    usize = 0x2810;
const E1000_RDT:    usize = 0x2818;
const E1000_TDBAL:  usize = 0x3800;
const E1000_TDBAH:  usize = 0x3804;
const E1000_TDLEN:  usize = 0x3808;
const E1000_TDH:    usize = 0x3810;
const E1000_TDT:    usize = 0x3818;
const E1000_RAL:    usize = 0x5400;
const E1000_RAH:    usize = 0x5404;

// CTRL bits
const CTRL_RST:   u32 = 1 << 26;
const CTRL_SLU:   u32 = 1 <<  6; // Set Link Up
const CTRL_ASDE:  u32 = 1 <<  5; // Auto-Speed Detection Enable

// RCTL bits
const RCTL_EN:    u32 = 1 <<  1;
const RCTL_BAM:   u32 = 1 << 15; // Broadcast Accept
const RCTL_BSIZE: u32 = 0 << 16; // 2048 B buffer
const RCTL_SECRC: u32 = 1 << 26; // Strip CRC

// TCTL bits
const TCTL_EN:    u32 = 1 <<  1;
const TCTL_PSP:   u32 = 1 <<  3; // Pad Short Packets
const TCTL_CT:    u32 = 0x0F << 4;
const TCTL_COLD:  u32 = 0x40 << 12;

// TX descriptor status
const TXD_STA_DD: u8 = 1 <<  0; // Descriptor Done
const TXD_CMD_EOP:u8 = 1 <<  0; // End of Packet
const TXD_CMD_RS: u8 = 1 <<  3; // Report Status
const TXD_CMD_IFCS:u8 = 1 << 1; // Insert FCS

// RX descriptor status
const RXD_STA_DD: u8 = 1 <<  0;
const RXD_STA_EOP:u8 = 1 <<  1;

// Ring sizes
const TX_RING: usize = 16;
const RX_RING: usize = 16;
const BUF_SZ:  usize = 2048;

// ---------------------------------------------------------------------------
// Descriptor layouts
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct TxDesc {
    addr:    u64,
    length:  u16,
    cso:     u8,
    cmd:     u8,
    status:  u8,
    css:     u8,
    special: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct RxDesc {
    addr:    u64,
    length:  u16,
    checksum:u16,
    status:  u8,
    errors:  u8,
    special: u16,
}

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

pub struct E1000e {
    bar0:    u64,
    mac:     [u8; 6],
    tx_ring: u64, // physical address of TX descriptor ring
    rx_ring: u64,
    tx_bufs: [u64; TX_RING],
    rx_bufs: [u64; RX_RING],
    tx_tail: usize,
    rx_tail: usize,
}

impl E1000e {
    /// Initialise the e1000e at MMIO base `bar0`.
    pub fn new(bar0: u64) -> Option<Self> {
        unsafe { Self::init(bar0) }
    }

    unsafe fn init(bar0: u64) -> Option<Self> {
        // Reset.
        reg_write(bar0, E1000_CTRL, reg_read(bar0, E1000_CTRL) | CTRL_RST);
        for _ in 0..100_000 { core::hint::spin_loop(); }

        // Mask all interrupts.
        reg_write(bar0, E1000_IMC, 0xFFFF_FFFF);

        // Read MAC from RAL/RAH.
        let ral = reg_read(bar0, E1000_RAL);
        let rah = reg_read(bar0, E1000_RAH);
        let mac = [
            (ral & 0xFF) as u8,
            ((ral >> 8)  & 0xFF) as u8,
            ((ral >> 16) & 0xFF) as u8,
            ((ral >> 24) & 0xFF) as u8,
            (rah & 0xFF) as u8,
            ((rah >> 8)  & 0xFF) as u8,
        ];

        // Allocate TX ring + buffers.
        let tx_ring = alloc_dma(TX_RING * 16, 16)?;
        core::ptr::write_bytes(tx_ring as *mut u8, 0, TX_RING * 16);
        let mut tx_bufs = [0u64; TX_RING];
        for i in 0..TX_RING {
            let buf = alloc_dma(BUF_SZ, BUF_SZ)?;
            tx_bufs[i] = buf;
            let desc = &mut *((tx_ring as usize + i * 16) as *mut TxDesc);
            desc.addr = buf;
        }

        // Allocate RX ring + buffers.
        let rx_ring = alloc_dma(RX_RING * 16, 16)?;
        core::ptr::write_bytes(rx_ring as *mut u8, 0, RX_RING * 16);
        let mut rx_bufs = [0u64; RX_RING];
        for i in 0..RX_RING {
            let buf = alloc_dma(BUF_SZ, BUF_SZ)?;
            rx_bufs[i] = buf;
            let desc = &mut *((rx_ring as usize + i * 16) as *mut RxDesc);
            desc.addr = buf;
        }

        // Program TX ring.
        reg_write(bar0, E1000_TDBAL, (tx_ring & 0xFFFF_FFFF) as u32);
        reg_write(bar0, E1000_TDBAH, (tx_ring >> 32) as u32);
        reg_write(bar0, E1000_TDLEN, (TX_RING * 16) as u32);
        reg_write(bar0, E1000_TDH,   0);
        reg_write(bar0, E1000_TDT,   0);
        reg_write(bar0, E1000_TCTL,  TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);
        reg_write(bar0, E1000_TIPG,  0x00602006);

        // Program RX ring.
        reg_write(bar0, E1000_RDBAL, (rx_ring & 0xFFFF_FFFF) as u32);
        reg_write(bar0, E1000_RDBAH, (rx_ring >> 32) as u32);
        reg_write(bar0, E1000_RDLEN, (RX_RING * 16) as u32);
        reg_write(bar0, E1000_RDH,   0);
        reg_write(bar0, E1000_RDT,   (RX_RING as u32) - 1);
        reg_write(bar0, E1000_RCTL,  RCTL_EN | RCTL_BAM | RCTL_BSIZE | RCTL_SECRC);

        // Bring link up.
        reg_write(bar0, E1000_CTRL,
            reg_read(bar0, E1000_CTRL) | CTRL_SLU | CTRL_ASDE);

        Some(E1000e { bar0, mac, tx_ring, rx_ring, tx_bufs, rx_bufs,
                      tx_tail: 0, rx_tail: 0 })
    }
}

impl NetworkDevice for E1000e {
    fn send(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.len() > BUF_SZ { return Err("frame too large"); }
        unsafe {
            let buf = self.tx_bufs[self.tx_tail];
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buf as *mut u8, frame.len());
            let desc = &mut *((self.tx_ring as usize + self.tx_tail * 16) as *mut TxDesc);
            desc.length = frame.len() as u16;
            desc.cmd    = TXD_CMD_EOP | TXD_CMD_RS | TXD_CMD_IFCS;
            desc.status = 0;
            self.tx_tail = (self.tx_tail + 1) % TX_RING;
            reg_write(self.bar0, E1000_TDT, self.tx_tail as u32);
            // Spin until TXD.DD set.
            let prev = (self.tx_tail + TX_RING - 1) % TX_RING;
            let dp = &*((self.tx_ring as usize + prev * 16) as *const TxDesc);
            for _ in 0..1_000_000 {
                if dp.status & TXD_STA_DD != 0 { return Ok(()); }
                core::hint::spin_loop();
            }
        }
        Err("e1000e tx timeout")
    }

    fn recv(&mut self, buf: &mut [u8]) -> Option<usize> {
        unsafe {
            let next = (self.rx_tail + 1) % RX_RING;
            let desc = &mut *((self.rx_ring as usize + next * 16) as *mut RxDesc);
            if desc.status & RXD_STA_DD == 0 { return None; }
            if desc.status & RXD_STA_EOP == 0 { desc.status = 0; return None; }
            let len = desc.length as usize;
            let src = self.rx_bufs[next] as *const u8;
            let n = len.min(buf.len());
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);
            desc.status = 0;
            self.rx_tail = next;
            reg_write(self.bar0, E1000_RDT, self.rx_tail as u32);
            Some(n)
        }
    }

    fn mac(&self)  -> [u8; 6]      { self.mac }
    fn name(&self) -> &'static str { "e1000e" }

    fn link_up(&self) -> bool {
        reg_read(self.bar0, E1000_STATUS) & 0x2 != 0
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline]
fn reg_read(base: u64, off: usize) -> u32 {
    unsafe { read_volatile((base as usize + off) as *const u32) }
}

#[inline]
fn reg_write(base: u64, off: usize, val: u32) {
    unsafe { write_volatile((base as usize + off) as *mut u32, val); }
}

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}

// ---------------------------------------------------------------------------
// Global singleton for systems with one e1000e
// ---------------------------------------------------------------------------

static DEVICE: Mutex<Option<E1000e>> = Mutex::new(None);

pub fn init(bar0: u64) -> bool {
    if let Some(dev) = E1000e::new(bar0) {
        *DEVICE.lock() = Some(dev);
        true
    } else { false }
}

pub fn send_frame(frame: &[u8]) -> Result<(), &'static str> {
    DEVICE.lock().as_mut().ok_or("e1000e not initialised")?.send(frame)
}

pub fn recv_frame(buf: &mut [u8]) -> Option<usize> {
    DEVICE.lock().as_mut()?.recv(buf)
}

pub fn mac_addr() -> Option<[u8; 6]> {
    DEVICE.lock().as_ref().map(|d| d.mac)
}
