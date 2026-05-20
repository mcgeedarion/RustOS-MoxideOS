//! virtio-net MMIO transport driver (RISC-V / ARM).
//!
//! Uses the virtio MMIO transport (as exposed by QEMU `-device virtio-net-device`).
//! Register layout follows virtio spec 1.1, section 4.2.
//!
//! Queue layout is identical to the PCI driver (virtio_net.rs):
//!   Queue 0 = RX, Queue 1 = TX
//!   Each chain: [virtio_net_hdr (12 B)][payload]

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};

use super::nic::NetworkDevice;

// ---------------------------------------------------------------------------
// MMIO register offsets (virtio spec 1.1 s4.2.2)
// ---------------------------------------------------------------------------

const MMIO_MAGIC:           usize = 0x000;
const MMIO_VERSION:         usize = 0x004;
const MMIO_DEVICE_ID:       usize = 0x008;
const MMIO_VENDOR_ID:       usize = 0x00C;
const MMIO_HOST_FEATURES:   usize = 0x010;
const MMIO_HOST_FEAT_SEL:   usize = 0x014;
const MMIO_GUEST_FEATURES:  usize = 0x020;
const MMIO_GUEST_FEAT_SEL:  usize = 0x024;
const MMIO_GUEST_PAGE_SHIFT:usize = 0x028;
const MMIO_QUEUE_SEL:       usize = 0x030;
const MMIO_QUEUE_NUM_MAX:   usize = 0x034;
const MMIO_QUEUE_NUM:       usize = 0x038;
const MMIO_QUEUE_ALIGN:     usize = 0x03C;
const MMIO_QUEUE_PFN:       usize = 0x040;
const MMIO_QUEUE_NOTIFY:    usize = 0x050;
const MMIO_INTERRUPT_STATUS:usize = 0x060;
const MMIO_INTERRUPT_ACK:   usize = 0x064;
const MMIO_STATUS:          usize = 0x070;
const MMIO_CONFIG:          usize = 0x100; // device-specific config

const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"
const DEVICE_NET:   u32 = 1;

const STATUS_ACK:        u32 = 1;
const STATUS_DRIVER:     u32 = 2;
const STATUS_DRIVER_OK:  u32 = 4;
const STATUS_FEAT_OK:    u32 = 8;
const STATUS_FAILED:     u32 = 0x80;

const VRING_SIZE:  usize = 64;
const BUF_SIZE:    usize = 1526;
const HDR_SIZE:    usize = 12;
const PAGE_SIZE:   u32   = 4096;

// Descriptor flags
const DESC_F_NEXT:  u16 = 1;
const DESC_F_WRITE: u16 = 2;

// ---------------------------------------------------------------------------
// Shared vring types (same as virtio_net.rs)
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VringDesc { addr: u64, len: u32, flags: u16, next: u16 }

#[repr(C, packed)]
struct VringAvail { flags: u16, idx: u16, ring: [u16; VRING_SIZE] }

#[repr(C, packed)]
struct VringUsedElem { id: u32, len: u32 }

#[repr(C, packed)]
struct VringUsed { flags: u16, idx: u16, ring: [VringUsedElem; VRING_SIZE] }

#[repr(C, packed)]
#[derive(Default)]
struct VirtioNetHdr {
    flags: u8, gso_type: u8, hdr_len: u16,
    gso_size: u16, csum_start: u16, csum_offset: u16, num_buffers: u16,
}

// ---------------------------------------------------------------------------
// Queue state
// ---------------------------------------------------------------------------

struct Queue {
    desc:       u64,
    avail:      u64,
    used:       u64,
    bufs:       [u64; VRING_SIZE],
    avail_idx:  u16,
    used_idx:   u16,
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

pub struct VirtioNetMmio {
    base:  u64,
    mac:   [u8; 6],
    rx:    Queue,
    tx:    Queue,
}

impl VirtioNetMmio {
    /// Probe and initialise a virtio-net MMIO device at `base_phys`.
    pub fn new(base_phys: u64) -> Option<Self> {
        unsafe { Self::_new(base_phys) }
    }

    unsafe fn _new(base: u64) -> Option<Self> {
        let magic = mmio_r(base, MMIO_MAGIC);
        if magic != VIRTIO_MAGIC { return None; }
        let dev_id = mmio_r(base, MMIO_DEVICE_ID);
        if dev_id != DEVICE_NET { return None; }

        // Reset.
        mmio_w(base, MMIO_STATUS, 0);
        // Ack + Driver.
        mmio_w(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER);

        // Negotiate features (accept everything for now).
        mmio_w(base, MMIO_HOST_FEAT_SEL, 0);
        let feat = mmio_r(base, MMIO_HOST_FEATURES);
        mmio_w(base, MMIO_GUEST_FEAT_SEL, 0);
        mmio_w(base, MMIO_GUEST_FEATURES, feat & 0x0000_FFFF);
        mmio_w(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK);

        // Read MAC from config space (+0x100).
        let mac = [
            mmio_r8(base, MMIO_CONFIG),
            mmio_r8(base, MMIO_CONFIG + 1),
            mmio_r8(base, MMIO_CONFIG + 2),
            mmio_r8(base, MMIO_CONFIG + 3),
            mmio_r8(base, MMIO_CONFIG + 4),
            mmio_r8(base, MMIO_CONFIG + 5),
        ];

        mmio_w(base, MMIO_GUEST_PAGE_SHIFT, 12); // 4 KiB pages

        let rx = setup_queue(base, 0)?;
        let tx = setup_queue(base, 1)?;

        // Pre-fill RX ring.
        let mut rxq = rx;
        for i in 0..VRING_SIZE {
            let buf = alloc_dma(BUF_SIZE)?;
            rxq.bufs[i] = buf;
            let desc = (rxq.desc as usize + i * 16) as *mut VringDesc;
            *desc = VringDesc { addr: buf, len: BUF_SIZE as u32,
                flags: DESC_F_WRITE, next: 0 };
            let avail = &mut *(rxq.avail as *mut VringAvail);
            avail.ring[i] = i as u16;
        }
        {
            let avail = &mut *(rxq.avail as *mut VringAvail);
            avail.idx = VRING_SIZE as u16;
            rxq.avail_idx = VRING_SIZE as u16;
        }
        mmio_w(base, MMIO_QUEUE_NOTIFY, 0);

        mmio_w(base, MMIO_STATUS,
            STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK | STATUS_DRIVER_OK);

        Some(VirtioNetMmio { base, mac, rx: rxq, tx })
    }
}

impl NetworkDevice for VirtioNetMmio {
    fn send(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        let total = HDR_SIZE + frame.len();
        if total > BUF_SIZE { return Err("frame too large"); }
        let idx = self.tx.avail_idx as usize % VRING_SIZE;
        let buf = if self.tx.bufs[idx] == 0 {
            let p = alloc_dma(BUF_SIZE).ok_or("tx alloc")?;
            self.tx.bufs[idx] = p;
            p
        } else { self.tx.bufs[idx] };
        unsafe {
            core::ptr::write_bytes(buf as *mut u8, 0, HDR_SIZE);
            core::ptr::copy_nonoverlapping(
                frame.as_ptr(), (buf as usize + HDR_SIZE) as *mut u8, frame.len());
            let desc = (self.tx.desc as usize + idx * 16) as *mut VringDesc;
            *desc = VringDesc { addr: buf, len: total as u32, flags: 0, next: 0 };
            let avail = &mut *(self.tx.avail as *mut VringAvail);
            avail.ring[self.tx.avail_idx as usize % VRING_SIZE] = idx as u16;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);
            self.tx.avail_idx = avail.idx;
        }
        unsafe { mmio_w(self.base, MMIO_QUEUE_NOTIFY, 1); }
        Ok(())
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        let used = unsafe { &*(self.rx.used as *const VringUsed) };
        if used.idx == self.rx.used_idx { return None; }
        let entry = &used.ring[self.rx.used_idx as usize % VRING_SIZE];
        let buf_idx = entry.id as usize % VRING_SIZE;
        let total   = entry.len as usize;
        if total <= HDR_SIZE {
            self.rx.used_idx = self.rx.used_idx.wrapping_add(1);
            return None;
        }
        let frame = unsafe {
            core::slice::from_raw_parts(
                (self.rx.bufs[buf_idx] as usize + HDR_SIZE) as *const u8,
                total - HDR_SIZE,
            )
        }.to_vec();
        unsafe {
            let avail = &mut *(self.rx.avail as *mut VringAvail);
            avail.ring[self.rx.avail_idx as usize % VRING_SIZE] = buf_idx as u16;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);
            self.rx.avail_idx = avail.idx;
            mmio_w(self.base, MMIO_QUEUE_NOTIFY, 0);
        }
        self.rx.used_idx = self.rx.used_idx.wrapping_add(1);
        Some(frame)
    }

    fn mac(&self) -> [u8; 6] { self.mac }
}

// ---------------------------------------------------------------------------
// Queue setup
// ---------------------------------------------------------------------------

unsafe fn setup_queue(base: u64, idx: u32) -> Option<Queue> {
    mmio_w(base, MMIO_QUEUE_SEL, idx);
    let max = mmio_r(base, MMIO_QUEUE_NUM_MAX) as usize;
    if max == 0 { return None; }
    let size = max.min(VRING_SIZE);
    mmio_w(base, MMIO_QUEUE_NUM, size as u32);
    mmio_w(base, MMIO_QUEUE_ALIGN, PAGE_SIZE);

    let desc_bytes  = size * 16;
    let avail_bytes = 4 + size * 2;
    let used_off    = (desc_bytes + avail_bytes + 4095) / 4096 * 4096;
    let total       = used_off + 4 + size * 8;
    let pages       = (total + 4095) / 4096;

    let phys = alloc_dma(pages * 4096)?;
    core::ptr::write_bytes(phys as *mut u8, 0, pages * 4096);

    mmio_w(base, MMIO_QUEUE_PFN, (phys / PAGE_SIZE as u64) as u32);

    Some(Queue {
        desc:      phys,
        avail:     phys + desc_bytes as u64,
        used:      phys + used_off as u64,
        bufs:      [0u64; VRING_SIZE],
        avail_idx: 0,
        used_idx:  0,
    })
}

fn alloc_dma(size: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages(pages)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

#[inline] unsafe fn mmio_r(base: u64, off: usize) -> u32 {
    read_volatile((base as usize + off) as *const u32)
}
#[inline] unsafe fn mmio_w(base: u64, off: usize, val: u32) {
    write_volatile((base as usize + off) as *mut u32, val);
}
#[inline] unsafe fn mmio_r8(base: u64, off: usize) -> u8 {
    read_volatile((base as usize + off) as *const u8)
}
