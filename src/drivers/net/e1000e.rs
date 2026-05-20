//! Intel e1000e Gigabit Ethernet driver.
//!
//! Supports the 82574L / 82579LM / I217 family as exposed by QEMU `-device e1000`.
//!
//! ## Architecture
//!   - 16-entry TX descriptor ring (legacy format, single buffer per descriptor)
//!   - 16-entry RX descriptor ring (legacy format)
//!   - MMIO via BAR0 (memory-mapped, 128 KiB)
//!   - No interrupt support yet; TX/RX are polled
//!
//! ## Usage
//!   ```
//!   let nic = e1000e::E1000e::new(bar0_phys).unwrap();
//!   crate::drivers::nic::register(Box::new(nic));
//!   ```

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

use super::nic::NetworkDevice;

// ---------------------------------------------------------------------------
// Register offsets
// ---------------------------------------------------------------------------

const E1000_CTRL:    usize = 0x0000;
const E1000_STATUS:  usize = 0x0008;
const E1000_CTRL_EXT:usize = 0x0018;
const E1000_RCTL:    usize = 0x0100;
const E1000_TCTL:    usize = 0x0400;
const E1000_TIPG:    usize = 0x0410;
const E1000_RDBAL:   usize = 0x2800;
const E1000_RDBAH:   usize = 0x2804;
const E1000_RDLEN:   usize = 0x2808;
const E1000_RDH:     usize = 0x2810;
const E1000_RDT:     usize = 0x2818;
const E1000_TDBAL:   usize = 0x3800;
const E1000_TDBAH:   usize = 0x3804;
const E1000_TDLEN:   usize = 0x3808;
const E1000_TDH:     usize = 0x3810;
const E1000_TDT:     usize = 0x3818;
const E1000_RAL:     usize = 0x5400;
const E1000_RAH:     usize = 0x5404;
const E1000_MTA:     usize = 0x5200; // Multicast table (128 x u32)

// CTRL bits
const CTRL_RST:      u32 = 1 << 26;
const CTRL_SLU:      u32 = 1 << 6;  // Set Link Up
const CTRL_ASDE:     u32 = 1 << 5;  // Auto-Speed Detection

// RCTL bits
const RCTL_EN:       u32 = 1 << 1;
const RCTL_BAM:      u32 = 1 << 15; // Broadcast Accept
const RCTL_BSIZE_2K: u32 = 0 << 16; // Buffer size 2048
const RCTL_SECRC:    u32 = 1 << 26; // Strip Ethernet CRC

// TCTL bits
const TCTL_EN:       u32 = 1 << 1;
const TCTL_PSP:      u32 = 1 << 3;  // Pad Short Packets
const TCTL_CT:       u32 = 0x0F << 4;
const TCTL_COLD:     u32 = 0x3F << 12;

// TX descriptor CMD bits
const TX_CMD_EOP:    u8  = 1 << 0; // End Of Packet
const TX_CMD_IFCS:   u8  = 1 << 1; // Insert FCS
const TX_CMD_RS:     u8  = 1 << 3; // Report Status

// TX descriptor status
const TX_STA_DD:     u8  = 1 << 0; // Descriptor Done

// RX descriptor status
const RX_STA_DD:     u8  = 1 << 0; // Descriptor Done
const RX_STA_EOP:    u8  = 1 << 1; // End Of Packet

const RING_SIZE: usize = 16;
const BUF_SIZE:  usize = 2048;

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
    bar0:     u64,
    mac:      [u8; 6],
    tx_ring:  u64, // physical addr
    rx_ring:  u64, // physical addr
    tx_bufs:  [u64; RING_SIZE],
    rx_bufs:  [u64; RING_SIZE],
    tx_tail:  usize,
    rx_tail:  usize,
}

impl E1000e {
    /// Initialise from BAR0 physical address.  Returns None on failure.
    pub fn new(bar0_phys: u64) -> Option<Self> {
        unsafe { Self::_new(bar0_phys) }
    }

    unsafe fn _new(bar0: u64) -> Option<Self> {
        // Reset.
        let ctrl = mmio_r(bar0, E1000_CTRL);
        mmio_w(bar0, E1000_CTRL, ctrl | CTRL_RST);
        for _ in 0..100_000 { core::hint::spin_loop(); }

        // Set Link Up + Auto-Speed.
        mmio_w(bar0, E1000_CTRL, CTRL_SLU | CTRL_ASDE);

        // Clear multicast table.
        for i in 0..128usize {
            mmio_w(bar0, E1000_MTA + i * 4, 0);
        }

        // Read MAC from RAL/RAH.
        let ral = mmio_r(bar0, E1000_RAL);
        let rah = mmio_r(bar0, E1000_RAH);
        let mac = [
            (ral & 0xFF) as u8, ((ral >> 8) & 0xFF) as u8,
            ((ral >> 16) & 0xFF) as u8, ((ral >> 24) & 0xFF) as u8,
            (rah & 0xFF) as u8, ((rah >> 8) & 0xFF) as u8,
        ];

        // Allocate rings.
        let tx_ring = alloc_dma(RING_SIZE * 16, 16)?;
        let rx_ring = alloc_dma(RING_SIZE * 16, 16)?;
        let mut tx_bufs = [0u64; RING_SIZE];
        let mut rx_bufs = [0u64; RING_SIZE];

        // Set up TX buffers and descriptors.
        for i in 0..RING_SIZE {
            tx_bufs[i] = alloc_dma(BUF_SIZE, 16)?;
            let desc = (tx_ring as usize + i * 16) as *mut TxDesc;
            (*desc).addr = tx_bufs[i];
            (*desc).status = TX_STA_DD; // mark as done so first use works
        }

        // Set up RX buffers and descriptors.
        for i in 0..RING_SIZE {
            rx_bufs[i] = alloc_dma(BUF_SIZE, 16)?;
            let desc = (rx_ring as usize + i * 16) as *mut RxDesc;
            (*desc).addr = rx_bufs[i];
        }

        // Program TX ring.
        mmio_w(bar0, E1000_TDBAL, (tx_ring & 0xFFFF_FFFF) as u32);
        mmio_w(bar0, E1000_TDBAH, (tx_ring >> 32) as u32);
        mmio_w(bar0, E1000_TDLEN, (RING_SIZE * 16) as u32);
        mmio_w(bar0, E1000_TDH, 0);
        mmio_w(bar0, E1000_TDT, 0);
        mmio_w(bar0, E1000_TCTL, TCTL_EN | TCTL_PSP | TCTL_CT | TCTL_COLD);
        mmio_w(bar0, E1000_TIPG, 0x00602006); // standard IPG

        // Program RX ring.
        mmio_w(bar0, E1000_RDBAL, (rx_ring & 0xFFFF_FFFF) as u32);
        mmio_w(bar0, E1000_RDBAH, (rx_ring >> 32) as u32);
        mmio_w(bar0, E1000_RDLEN, (RING_SIZE * 16) as u32);
        mmio_w(bar0, E1000_RDH, 0);
        mmio_w(bar0, E1000_RDT, (RING_SIZE - 1) as u32);
        mmio_w(bar0, E1000_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2K | RCTL_SECRC);

        Some(E1000e { bar0, mac, tx_ring, rx_ring, tx_bufs, rx_bufs,
            tx_tail: 0, rx_tail: 0 })
    }
}

impl NetworkDevice for E1000e {
    fn send(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.len() > BUF_SIZE { return Err("frame too large"); }
        let desc = unsafe {
            &mut *((self.tx_ring as usize + self.tx_tail * 16) as *mut TxDesc)
        };
        // Wait until descriptor is free.
        let mut spin = 0;
        while desc.status & TX_STA_DD == 0 {
            core::hint::spin_loop();
            spin += 1;
            if spin > 1_000_000 { return Err("tx timeout"); }
        }
        unsafe {
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(),
                self.tx_bufs[self.tx_tail] as *mut u8,
                frame.len(),
            );
        }
        desc.length = frame.len() as u16;
        desc.cmd    = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
        desc.status = 0;
        self.tx_tail = (self.tx_tail + 1) % RING_SIZE;
        unsafe { mmio_w(self.bar0, E1000_TDT, self.tx_tail as u32); }
        Ok(())
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        let desc = unsafe {
            &mut *((self.rx_ring as usize + self.rx_tail * 16) as *mut RxDesc)
        };
        if desc.status & RX_STA_DD == 0 { return None; }
        if desc.status & RX_STA_EOP == 0 { desc.status = 0; return None; } // multi-buf: discard
        let len = desc.length as usize;
        let frame = unsafe {
            core::slice::from_raw_parts(self.rx_bufs[self.rx_tail] as *const u8, len)
        }.to_vec();
        desc.status = 0;
        self.rx_tail = (self.rx_tail + 1) % RING_SIZE;
        unsafe { mmio_w(self.bar0, E1000_RDT, ((self.rx_tail + RING_SIZE - 1) % RING_SIZE) as u32); }
        Some(frame)
    }

    fn mac(&self) -> [u8; 6] { self.mac }

    fn link_up(&self) -> bool {
        unsafe { mmio_r(self.bar0, E1000_STATUS) & 0x2 != 0 }
    }
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

#[inline]
unsafe fn mmio_r(base: u64, off: usize) -> u32 {
    read_volatile((base as usize + off) as *const u32)
}

#[inline]
unsafe fn mmio_w(base: u64, off: usize, val: u32) {
    write_volatile((base as usize + off) as *mut u32, val);
}

fn alloc_dma(size: usize, _align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages(pages)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}
