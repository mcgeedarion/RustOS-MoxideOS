//! virtio-net PCI driver (modern / legacy).
//!
//! Implements a minimal virtio-net device on top of the PCI transport.
//! Uses two virtqueues: RX (queue 0) and TX (queue 1).
//!
//! ## Limitations
//! - Single RX/TX queue pair
//! - No multi-buffer scatter/gather (one descriptor per packet)
//! - Header-only feature negotiation (VIRTIO_NET_F_MAC)

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

// ---------------------------------------------------------------------------
// PCI config-space / BAR0 offsets (legacy virtio)
// ---------------------------------------------------------------------------

const VIRTIO_PCI_DEVFEAT:  usize = 0x00; // Device (host) features
const VIRTIO_PCI_GUESTFEAT:usize = 0x04; // Driver (guest) features
const VIRTIO_PCI_QADDR:    usize = 0x08; // Queue PFN (legacy, 4096-page units)
const VIRTIO_PCI_QSIZE:    usize = 0x0C; // Queue size
const VIRTIO_PCI_QSEL:     usize = 0x0E; // Queue select
const VIRTIO_PCI_QNOTIFY:  usize = 0x10; // Queue notify
const VIRTIO_PCI_STATUS:   usize = 0x12; // Device status
const VIRTIO_PCI_ISR:      usize = 0x13; // ISR status
const VIRTIO_PCI_CFGOFF:   usize = 0x14; // Device-specific config (MAC etc.)

// Device status bits
const VIRTIO_STATUS_ACK:    u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FEATURES_OK: u8 = 8;
const VIRTIO_STATUS_FAILED: u8 = 128;

// Feature bits
const VIRTIO_NET_F_MAC: u32 = 1 << 5;

// Virtqueue ring sizes
const VRING_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Vring descriptors
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VringDesc {
    addr:  u64,
    len:   u32,
    flags: u16,
    next:  u16,
}

const VRING_DESC_F_NEXT:  u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VringAvail {
    flags: u16,
    idx:   u16,
    ring:  [u16; VRING_SIZE],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VringUsedElem {
    id:  u32,
    len: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct VringUsed {
    flags: u16,
    idx:   u16,
    ring:  [VringUsedElem; VRING_SIZE],
}

// Net header (10 bytes, prepended to every TX packet)
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

// ---------------------------------------------------------------------------
// Queue state
// ---------------------------------------------------------------------------

struct VirtQueue {
    desc_phys:  u64,
    avail_phys: u64,
    used_phys:  u64,
    bufs:       [u64; VRING_SIZE],
    last_used:  u16,
    next_desc:  usize,
}

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct VirtioNet {
    iobase: u64,   // BAR0 I/O or MMIO base
    mac:    [u8; 6],
    rxq:    VirtQueue,
    txq:    VirtQueue,
}

static DEVICE: Mutex<Option<VirtioNet>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

pub fn init(bar0: u64) {
    unsafe { _init(bar0); }
}

pub fn send(frame: &[u8]) -> Result<(), &'static str> {
    let mut dev = DEVICE.lock();
    let d = dev.as_mut().ok_or("virtio-net not init")?;
    unsafe { _send(d, frame) }
}

pub fn recv(buf: &mut [u8]) -> Option<usize> {
    let mut dev = DEVICE.lock();
    let d = dev.as_mut()?;
    unsafe { _recv(d, buf) }
}

pub fn mac() -> Option<[u8; 6]> {
    DEVICE.lock().as_ref().map(|d| d.mac)
}

// ---------------------------------------------------------------------------
// Init internals
// ---------------------------------------------------------------------------

unsafe fn _init(base: u64) {
    // Reset device.
    cfg_write8(base, VIRTIO_PCI_STATUS, 0);
    cfg_write8(base, VIRTIO_PCI_STATUS, VIRTIO_STATUS_ACK);
    cfg_write8(base, VIRTIO_PCI_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER);

    // Negotiate VIRTIO_NET_F_MAC only.
    let feat = cfg_read32(base, VIRTIO_PCI_DEVFEAT);
    let neg  = feat & VIRTIO_NET_F_MAC;
    cfg_write32(base, VIRTIO_PCI_GUESTFEAT, neg);
    cfg_write8(base, VIRTIO_PCI_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER | VIRTIO_STATUS_FEATURES_OK);

    // Read MAC from device config.
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = cfg_read8(base, VIRTIO_PCI_CFGOFF + i);
    }

    let rxq = setup_queue(base, 0);
    let txq = setup_queue(base, 1);

    // Finalise.
    cfg_write8(base, VIRTIO_PCI_STATUS,
        VIRTIO_STATUS_ACK | VIRTIO_STATUS_DRIVER |
        VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);

    let mut rxq = rxq;
    // Pre-fill RX descriptors.
    for i in 0..VRING_SIZE {
        let buf = alloc_dma(2048, 16).expect("rx buf");
        rxq.bufs[i] = buf;
        let desc = &mut *((rxq.desc_phys as usize + i * 16) as *mut VringDesc);
        desc.addr  = buf;
        desc.len   = 2048;
        desc.flags = VRING_DESC_F_WRITE;
        desc.next  = 0;
        let avail = &mut *(rxq.avail_phys as *mut VringAvail);
        avail.ring[i] = i as u16;
        avail.idx = avail.idx.wrapping_add(1);
    }
    // Notify RX queue.
    cfg_write16(base, VIRTIO_PCI_QNOTIFY, 0);

    *DEVICE.lock() = Some(VirtioNet { iobase: base, mac, rxq, txq });
}

unsafe fn setup_queue(base: u64, qidx: u16) -> VirtQueue {
    cfg_write16(base, VIRTIO_PCI_QSEL, qidx);
    let size = cfg_read16(base, VIRTIO_PCI_QSIZE) as usize;
    let size = size.min(VRING_SIZE);

    let desc_sz  = size * 16;
    let avail_sz = 6 + size * 2;
    let used_sz  = 6 + size * 8;
    let total    = desc_sz + avail_sz + 4096 + used_sz; // pessimistic alignment

    let phys = alloc_dma(total, 4096).expect("vring alloc");
    let desc_phys  = phys;
    let avail_phys = phys + desc_sz as u64;
    let used_phys  = (avail_phys + avail_sz as u64 + 4095) & !4095;

    core::ptr::write_bytes(phys as *mut u8, 0, total);

    // Register with device (legacy: PFN in 4096-byte pages).
    cfg_write32(base, VIRTIO_PCI_QADDR, (phys / 4096) as u32);

    VirtQueue {
        desc_phys, avail_phys, used_phys,
        bufs: [0u64; VRING_SIZE],
        last_used: 0,
        next_desc: 0,
    }
}

unsafe fn _send(d: &mut VirtioNet, frame: &[u8]) -> Result<(), &'static str> {
    let hdr_sz = core::mem::size_of::<VirtioNetHdr>();
    let total  = hdr_sz + frame.len();
    if total > 2048 { return Err("frame too large"); }

    let i  = d.txq.next_desc % VRING_SIZE;
    let i2 = (i + 1) % VRING_SIZE;

    // Alloc / reuse buffer.
    if d.txq.bufs[i] == 0 {
        d.txq.bufs[i] = alloc_dma(2048, 16).ok_or("oom")?;
    }
    let buf = d.txq.bufs[i] as *mut u8;

    // Write header.
    core::ptr::write_bytes(buf, 0, hdr_sz);
    // Write frame.
    core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.add(hdr_sz), frame.len());

    // Descriptor 0: header.
    let d0 = &mut *((d.txq.desc_phys as usize + i * 16) as *mut VringDesc);
    d0.addr  = d.txq.bufs[i];
    d0.len   = total as u32;
    d0.flags = 0;
    d0.next  = 0;

    let avail = &mut *(d.txq.avail_phys as *mut VringAvail);
    avail.ring[(avail.idx as usize) % VRING_SIZE] = i as u16;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    avail.idx = avail.idx.wrapping_add(1);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

    cfg_write16(d.iobase, VIRTIO_PCI_QNOTIFY, 1);
    d.txq.next_desc += 1;
    Ok(())
}

unsafe fn _recv(d: &mut VirtioNet, buf: &mut [u8]) -> Option<usize> {
    let used = &*(d.rxq.used_phys as *const VringUsed);
    let used_idx = read_volatile(&used.idx);
    if used_idx == d.rxq.last_used { return None; }

    let elem = &used.ring[(d.rxq.last_used as usize) % VRING_SIZE];
    let desc_idx = elem.id as usize;
    let len = elem.len as usize;
    let hdr_sz = core::mem::size_of::<VirtioNetHdr>();
    let payload = len.saturating_sub(hdr_sz);
    let src = (d.rxq.bufs[desc_idx] as usize + hdr_sz) as *const u8;
    let n = payload.min(buf.len());
    core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);

    d.rxq.last_used = d.rxq.last_used.wrapping_add(1);

    // Recycle descriptor into available ring.
    let avail = &mut *(d.rxq.avail_phys as *mut VringAvail);
    avail.ring[(avail.idx as usize) % VRING_SIZE] = desc_idx as u16;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    avail.idx = avail.idx.wrapping_add(1);
    cfg_write16(d.iobase, VIRTIO_PCI_QNOTIFY, 0);

    Some(n)
}

// ---------------------------------------------------------------------------
// MMIO helpers (legacy virtio uses I/O port; we use MMIO BAR)
// ---------------------------------------------------------------------------

#[inline] unsafe fn cfg_read8(b: u64, o: usize)  -> u8  { read_volatile((b as usize+o) as *const u8) }
#[inline] unsafe fn cfg_read16(b: u64, o: usize) -> u16 { read_volatile((b as usize+o) as *const u16) }
#[inline] unsafe fn cfg_read32(b: u64, o: usize) -> u32 { read_volatile((b as usize+o) as *const u32) }
#[inline] unsafe fn cfg_write8(b: u64, o: usize, v: u8)  { write_volatile((b as usize+o) as *mut u8,  v) }
#[inline] unsafe fn cfg_write16(b: u64, o: usize, v: u16){ write_volatile((b as usize+o) as *mut u16, v) }
#[inline] unsafe fn cfg_write32(b: u64, o: usize, v: u32){ write_volatile((b as usize+o) as *mut u32, v) }

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}
