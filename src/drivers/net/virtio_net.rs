//! virtio-net driver (PCI transport, legacy and modern).
//!
//! Implements the virtio-net device using two virtqueues:
//!   - Queue 0: RX (device → driver)
//!   - Queue 1: TX (driver → device)
//!
//! Each TX/RX descriptor chain is:
//!   [virtio_net_hdr (12 B)] + [payload buffer]
//!
//! The driver is synchronous (no interrupts); TX/RX are polled.

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

use super::nic::NetworkDevice;

// ---------------------------------------------------------------------------
// virtio-net header
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VirtioNetHdr {
    flags:       u8,
    gso_type:    u8,
    hdr_len:     u16,
    gso_size:    u16,
    csum_start:  u16,
    csum_offset: u16,
    num_buffers: u16,
}

const HDR_SIZE: usize = core::mem::size_of::<VirtioNetHdr>();

// ---------------------------------------------------------------------------
// virtqueue constants
// ---------------------------------------------------------------------------

const VRING_SIZE:    usize = 64;
const BUF_SIZE:      usize = 1526; // max Ethernet frame + virtio header

// Descriptor flags
const VRING_DESC_F_NEXT:  u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

// ---------------------------------------------------------------------------
// virtqueue layout (split virtqueue, legacy)
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VringDesc {
    addr:  u64,
    len:   u32,
    flags: u16,
    next:  u16,
}

#[repr(C, packed)]
struct VringAvail {
    flags: u16,
    idx:   u16,
    ring:  [u16; VRING_SIZE],
}

#[repr(C, packed)]
struct VringUsedElem {
    id:  u32,
    len: u32,
}

#[repr(C, packed)]
struct VringUsed {
    flags: u16,
    idx:   u16,
    ring:  [VringUsedElem; VRING_SIZE],
}

// ---------------------------------------------------------------------------
// PCI / MMIO register layout (legacy virtio 0.9.5)
// ---------------------------------------------------------------------------

const VIRTIO_PCI_HOST_FEATURES: u16 = 0;
const VIRTIO_PCI_GUEST_FEATURES:u16 = 4;
const VIRTIO_PCI_QUEUE_PFN:     u16 = 8;
const VIRTIO_PCI_QUEUE_SIZE:    u16 = 12;
const VIRTIO_PCI_QUEUE_SEL:     u16 = 14;
const VIRTIO_PCI_QUEUE_NOTIFY:  u16 = 16;
const VIRTIO_PCI_STATUS:        u16 = 18;
const VIRTIO_PCI_ISR:           u16 = 19;

const VIRTIO_STATUS_ACK:        u8  = 1;
const VIRTIO_STATUS_DRIVER:     u8  = 2;
const VIRTIO_STATUS_DRIVER_OK:  u8  = 4;
const VIRTIO_STATUS_FEATURES_OK:u8  = 8;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct Queue {
    desc:    u64, // physical addr of descriptor table
    avail:   u64, // physical addr of available ring
    used:    u64, // physical addr of used ring
    bufs:    [u64; VRING_SIZE], // physical addrs of data buffers
    avail_idx: u16,
    used_idx:  u16,
}

pub struct VirtioNet {
    iobase: u16,  // PCI I/O BAR base (legacy)
    mac:    [u8; 6],
    rx:     Queue,
    tx:     Queue,
}

impl VirtioNet {
    pub fn new(iobase: u16) -> Option<Self> {
        unsafe { Self::_new(iobase) }
    }

    unsafe fn _new(io: u16) -> Option<Self> {
        use core::arch::x86_64::{_rdtsc};

        // Reset device.
        outb(io + VIRTIO_PCI_STATUS, 0);
        // Acknowledge + Driver.
        outb(io + VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);

        // Negotiate features: accept MAC + CSUM (bit 1) if offered.
        let host_feat = inl(io + VIRTIO_PCI_HOST_FEATURES);
        outl(io + VIRTIO_PCI_GUEST_FEATURES, host_feat & 0x0000_FFFF);
        outb(io + VIRTIO_PCI_STATUS,
            VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);

        // Read MAC from config space (starts at offset 20 for legacy).
        let mac_base = io + 20;
        let mac = [
            inb(mac_base), inb(mac_base+1), inb(mac_base+2),
            inb(mac_base+3), inb(mac_base+4), inb(mac_base+5),
        ];

        // Allocate queues.
        let rx = alloc_queue(io, 0)?;
        let tx = alloc_queue(io, 1)?;

        // Pre-fill RX descriptors.
        let mut rxq = rx;
        for i in 0..VRING_SIZE {
            let buf = alloc_dma(BUF_SIZE)?;
            rxq.bufs[i] = buf;
            let desc = (rxq.desc as usize + i * 16) as *mut VringDesc;
            (*desc) = VringDesc { addr: buf, len: BUF_SIZE as u32,
                flags: VRING_DESC_F_WRITE, next: 0 };
            let avail = &mut *(rxq.avail as *mut VringAvail);
            avail.ring[i] = i as u16;
        }
        {
            let avail = &mut *(rxq.avail as *mut VringAvail);
            avail.idx = VRING_SIZE as u16;
            rxq.avail_idx = VRING_SIZE as u16;
        }
        outw(io + VIRTIO_PCI_QUEUE_NOTIFY, 0);

        outb(io + VIRTIO_PCI_STATUS,
            VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER |
            VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

        Some(VirtioNet { iobase: io, mac, rx: rxq, tx })
    }
}

impl NetworkDevice for VirtioNet {
    fn send(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        let total = HDR_SIZE + frame.len();
        if total > BUF_SIZE { return Err("frame too large"); }
        let idx = (self.tx.avail_idx as usize) % VRING_SIZE;
        let buf_phys = if self.tx.bufs[idx] == 0 {
            let p = alloc_dma(BUF_SIZE).ok_or("tx alloc fail")?;
            self.tx.bufs[idx] = p;
            p
        } else {
            self.tx.bufs[idx]
        };
        unsafe {
            // Write virtio_net_hdr.
            core::ptr::write_bytes(buf_phys as *mut u8, 0, HDR_SIZE);
            // Copy frame payload.
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(), (buf_phys as usize + HDR_SIZE) as *mut u8, frame.len());
            // Set up descriptor.
            let desc = (self.tx.desc as usize + idx * 16) as *mut VringDesc;
            *desc = VringDesc { addr: buf_phys, len: total as u32, flags: 0, next: 0 };
            // Update available ring.
            let avail = &mut *(self.tx.avail as *mut VringAvail);
            avail.ring[self.tx.avail_idx as usize % VRING_SIZE] = idx as u16;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);
            self.tx.avail_idx = avail.idx;
        }
        // Kick queue 1.
        unsafe { outw(self.iobase + VIRTIO_PCI_QUEUE_NOTIFY, 1); }
        Ok(())
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        let used = unsafe { &*(self.rx.used as *const VringUsed) };
        if used.idx == self.rx.used_idx { return None; }
        let elem = unsafe {
            &*(self.rx.used as *const VringUsed)
        };
        let entry = &elem.ring[self.rx.used_idx as usize % VRING_SIZE];
        let buf_idx = entry.id as usize % VRING_SIZE;
        let total   = entry.len as usize;
        if total <= HDR_SIZE { self.rx.used_idx = self.rx.used_idx.wrapping_add(1); return None; }
        let payload_len = total - HDR_SIZE;
        let frame = unsafe {
            core::slice::from_raw_parts(
                (self.rx.bufs[buf_idx] as usize + HDR_SIZE) as *const u8,
                payload_len,
            )
        }.to_vec();
        // Recycle descriptor.
        unsafe {
            let avail = &mut *(self.rx.avail as *mut VringAvail);
            avail.ring[self.rx.avail_idx as usize % VRING_SIZE] = buf_idx as u16;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);
            self.rx.avail_idx = avail.idx;
            outw(self.iobase + VIRTIO_PCI_QUEUE_NOTIFY, 0);
        }
        self.rx.used_idx = self.rx.used_idx.wrapping_add(1);
        Some(frame)
    }

    fn mac(&self) -> [u8; 6] { self.mac }
}

// ---------------------------------------------------------------------------
// Queue allocation helper
// ---------------------------------------------------------------------------

unsafe fn alloc_queue(io: u16, queue_idx: u16) -> Option<Queue> {
    outw(io + VIRTIO_PCI_QUEUE_SEL, queue_idx);
    let size = inw(io + VIRTIO_PCI_QUEUE_SIZE) as usize;
    if size == 0 { return None; }
    let size = size.min(VRING_SIZE);

    // virtqueue alignment: desc table 16-byte, avail 2-byte, used 4-byte.
    let desc_bytes  = size * 16;
    let avail_bytes = 4 + size * 2;
    let used_off    = ((desc_bytes + avail_bytes + 3) / 4096 + 1) * 4096;
    let total       = used_off + 4 + size * 8;
    let pages       = (total + 4095) / 4096;

    let phys = alloc_dma(pages * 4096)?;
    core::ptr::write_bytes(phys as *mut u8, 0, pages * 4096);

    let desc_phys  = phys;
    let avail_phys = phys + desc_bytes as u64;
    let used_phys  = phys + used_off as u64;

    // Tell device about queue.
    outl(io + VIRTIO_PCI_QUEUE_PFN, (phys / 4096) as u32);

    Some(Queue {
        desc: desc_phys, avail: avail_phys, used: used_phys,
        bufs: [0u64; VRING_SIZE], avail_idx: 0, used_idx: 0,
    })
}

fn alloc_dma(size: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages(pages)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}

// ---------------------------------------------------------------------------
// x86 port I/O helpers
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack));
}
#[cfg(target_arch = "x86_64")]
unsafe fn outw(port: u16, val: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack));
}
#[cfg(target_arch = "x86_64")]
unsafe fn outl(port: u16, val: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack));
}
#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack));
    v
}
#[cfg(target_arch = "x86_64")]
unsafe fn inw(port: u16) -> u16 {
    let v: u16;
    core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack));
    v
}
#[cfg(target_arch = "x86_64")]
unsafe fn inl(port: u16) -> u32 {
    let v: u32;
    core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack));
    v
}

// RISC-V stubs
#[cfg(not(target_arch = "x86_64"))]
unsafe fn outb(_: u16, _: u8) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn outw(_: u16, _: u16) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn outl(_: u16, _: u32) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn inb(_: u16) -> u8 { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn inw(_: u16) -> u16 { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn inl(_: u16) -> u32 { 0 }
