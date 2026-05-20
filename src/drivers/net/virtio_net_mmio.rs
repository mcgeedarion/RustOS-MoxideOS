//! virtio-net MMIO transport driver (device-tree / QEMU -device virtio-net-device).
//!
//! Implements virtio-net over the MMIO transport (as opposed to PCI).
//! Used on RISC-V QEMU virt machines where virtio devices appear at
//! fixed MMIO addresses enumerated from the device-tree.
//!
//! ## MMIO register map (base + offset)
//!   +0x000  MagicValue      R    0x74726976 ("virt")
//!   +0x004  Version         R    1 (legacy) or 2 (modern)
//!   +0x008  DeviceID        R    1 = net
//!   +0x00C  VendorID        R    0x554D4551
//!   +0x010  DeviceFeatures  R
//!   +0x014  DeviceFeaturesSel W
//!   +0x020  DriverFeatures  W
//!   +0x024  DriverFeaturesSel W
//!   +0x030  QueueSel        W
//!   +0x034  QueueNumMax     R
//!   +0x038  QueueNum        W
//!   +0x044  QueueReady      RW   (modern)
//!   +0x050  QueueNotify     W
//!   +0x060  InterruptStatus R
//!   +0x064  InterruptACK    W
//!   +0x070  Status          RW
//!   +0x080  QueueDescLow    W
//!   +0x084  QueueDescHigh   W
//!   +0x090  QueueDriverLow  W   (AvailLow)
//!   +0x094  QueueDriverHigh W
//!   +0x0A0  QueueDeviceLow  W   (UsedLow)
//!   +0x0A4  QueueDeviceHigh W
//!   +0x100  Config          RW  (device-specific)

extern crate alloc;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

// ---------------------------------------------------------------------------
// Register offsets
// ---------------------------------------------------------------------------

const MMIO_MAGIC:          usize = 0x000;
const MMIO_VERSION:        usize = 0x004;
const MMIO_DEVICE_ID:      usize = 0x008;
const MMIO_DEV_FEATURES:   usize = 0x010;
const MMIO_DEV_FEAT_SEL:   usize = 0x014;
const MMIO_DRV_FEATURES:   usize = 0x020;
const MMIO_DRV_FEAT_SEL:   usize = 0x024;
const MMIO_QUEUE_SEL:      usize = 0x030;
const MMIO_QUEUE_NUM_MAX:  usize = 0x034;
const MMIO_QUEUE_NUM:      usize = 0x038;
const MMIO_QUEUE_READY:    usize = 0x044;
const MMIO_QUEUE_NOTIFY:   usize = 0x050;
const MMIO_IRQ_STATUS:     usize = 0x060;
const MMIO_IRQ_ACK:        usize = 0x064;
const MMIO_STATUS:         usize = 0x070;
const MMIO_QUEUE_DESC_LO:  usize = 0x080;
const MMIO_QUEUE_DESC_HI:  usize = 0x084;
const MMIO_QUEUE_DRV_LO:   usize = 0x090;
const MMIO_QUEUE_DRV_HI:   usize = 0x094;
const MMIO_QUEUE_DEV_LO:   usize = 0x0A0;
const MMIO_QUEUE_DEV_HI:   usize = 0x0A4;
const MMIO_CONFIG:         usize = 0x100;

const VIRTIO_MAGIC: u32 = 0x74726976;

// Status bits
const STATUS_ACK:        u32 = 1;
const STATUS_DRIVER:     u32 = 2;
const STATUS_DRIVER_OK:  u32 = 4;
const STATUS_FEAT_OK:    u32 = 8;
const STATUS_FAILED:     u32 = 128;

// Feature bits
const NET_F_MAC: u32 = 1 << 5;

// Ring sizes
const VRING_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// vring structures (same layout as virtio_net.rs)
// ---------------------------------------------------------------------------

#[repr(C, packed)] #[derive(Clone, Copy, Default)]
struct Desc  { addr: u64, len: u32, flags: u16, next: u16 }
#[repr(C, packed)] #[derive(Clone, Copy, Default)]
struct Avail { flags: u16, idx: u16, ring: [u16; VRING_SIZE] }
#[repr(C, packed)] #[derive(Clone, Copy)]
struct UsedElem { id: u32, len: u32 }
#[repr(C, packed)] #[derive(Clone, Copy)]
struct Used  { flags: u16, idx: u16, ring: [UsedElem; VRING_SIZE] }

#[repr(C, packed)] #[derive(Clone, Copy, Default)]
struct NetHdr {
    flags: u8, gso_type: u8, hdr_len: u16,
    gso_size: u16, csum_start: u16, csum_offset: u16, num_buffers: u16,
}

const DESC_F_WRITE: u16 = 2;

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct Queue {
    desc_phys:  u64,
    avail_phys: u64,
    used_phys:  u64,
    bufs:       [u64; VRING_SIZE],
    last_used:  u16,
    next_avail: u16,
}

struct VirtioNetMmio {
    base:  u64,
    mac:   [u8; 6],
    rxq:   Queue,
    txq:   Queue,
}

static DEV: Mutex<Option<VirtioNetMmio>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Probe and initialise a virtio-net MMIO device at `base`.
/// Returns true on success.
pub fn init(base: u64) -> bool {
    unsafe { _init(base) }
}

pub fn send(frame: &[u8]) -> Result<(), &'static str> {
    let mut g = DEV.lock();
    let d = g.as_mut().ok_or("not init")?;
    unsafe { _send(d, frame) }
}

pub fn recv(buf: &mut [u8]) -> Option<usize> {
    let mut g = DEV.lock();
    unsafe { _recv(g.as_mut()?, buf) }
}

pub fn mac() -> Option<[u8; 6]> {
    DEV.lock().as_ref().map(|d| d.mac)
}

pub fn is_present() -> bool { DEV.lock().is_some() }

/// Acknowledge and clear the interrupt (call from IRQ handler).
pub fn irq_ack(base: u64) {
    let status = unsafe { mmio_r(base, MMIO_IRQ_STATUS) };
    unsafe { mmio_w(base, MMIO_IRQ_ACK, status); }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

unsafe fn _init(base: u64) -> bool {
    if mmio_r(base, MMIO_MAGIC)     != VIRTIO_MAGIC { return false; }
    if mmio_r(base, MMIO_DEVICE_ID) != 1            { return false; }

    // Reset.
    mmio_w(base, MMIO_STATUS, 0);
    mmio_w(base, MMIO_STATUS, STATUS_ACK);
    mmio_w(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER);

    // Negotiate features (MAC only).
    mmio_w(base, MMIO_DEV_FEAT_SEL, 0);
    let feat = mmio_r(base, MMIO_DEV_FEATURES) & NET_F_MAC;
    mmio_w(base, MMIO_DRV_FEAT_SEL, 0);
    mmio_w(base, MMIO_DRV_FEATURES, feat);
    mmio_w(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK);
    if mmio_r(base, MMIO_STATUS) & STATUS_FEAT_OK == 0 { return false; }

    // Read MAC from config space.
    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = read_volatile((base as usize + MMIO_CONFIG + i) as *const u8);
    }

    let rxq = setup_queue(base, 0);
    let txq = setup_queue(base, 1);
    let mut rxq = rxq;

    // Pre-fill RX descriptors.
    for i in 0..VRING_SIZE {
        let buf = alloc_dma(2048, 16)?;
        rxq.bufs[i] = buf;
        let d = &mut *((rxq.desc_phys as usize + i * 16) as *mut Desc);
        d.addr = buf; d.len = 2048; d.flags = DESC_F_WRITE; d.next = 0;
        let avail = &mut *(rxq.avail_phys as *mut Avail);
        avail.ring[i] = i as u16;
        avail.idx = avail.idx.wrapping_add(1);
    }
    mmio_w(base, MMIO_QUEUE_NOTIFY, 0);

    mmio_w(base, MMIO_STATUS,
        STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK | STATUS_DRIVER_OK);

    *DEV.lock() = Some(VirtioNetMmio { base, mac, rxq, txq });
    true
}

unsafe fn setup_queue(base: u64, qidx: u32) -> Queue {
    mmio_w(base, MMIO_QUEUE_SEL, qidx);
    let max = mmio_r(base, MMIO_QUEUE_NUM_MAX) as usize;
    let sz  = max.min(VRING_SIZE);
    mmio_w(base, MMIO_QUEUE_NUM, sz as u32);

    let desc_sz  = sz * 16;
    let avail_sz = 6 + sz * 2;
    let total    = desc_sz + avail_sz + 4096 + 6 + sz * 8;
    let phys = alloc_dma(total, 4096).expect("vring");
    core::ptr::write_bytes(phys as *mut u8, 0, total);

    let desc_phys  = phys;
    let avail_phys = phys + desc_sz as u64;
    let used_phys  = (avail_phys + avail_sz as u64 + 4095) & !4095;

    mmio_w(base, MMIO_QUEUE_DESC_LO,  (desc_phys  & 0xFFFF_FFFF) as u32);
    mmio_w(base, MMIO_QUEUE_DESC_HI,  (desc_phys  >> 32) as u32);
    mmio_w(base, MMIO_QUEUE_DRV_LO,   (avail_phys & 0xFFFF_FFFF) as u32);
    mmio_w(base, MMIO_QUEUE_DRV_HI,   (avail_phys >> 32) as u32);
    mmio_w(base, MMIO_QUEUE_DEV_LO,   (used_phys  & 0xFFFF_FFFF) as u32);
    mmio_w(base, MMIO_QUEUE_DEV_HI,   (used_phys  >> 32) as u32);
    mmio_w(base, MMIO_QUEUE_READY, 1);

    Queue { desc_phys, avail_phys, used_phys,
            bufs: [0u64; VRING_SIZE], last_used: 0, next_avail: 0 }
}

unsafe fn _send(d: &mut VirtioNetMmio, frame: &[u8]) -> Result<(), &'static str> {
    let hdr_sz = core::mem::size_of::<NetHdr>();
    if hdr_sz + frame.len() > 2048 { return Err("too large"); }
    let i = d.txq.next_avail as usize % VRING_SIZE;
    if d.txq.bufs[i] == 0 { d.txq.bufs[i] = alloc_dma(2048, 16).ok_or("oom")?; }
    let buf = d.txq.bufs[i] as *mut u8;
    core::ptr::write_bytes(buf, 0, hdr_sz);
    core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.add(hdr_sz), frame.len());
    let desc = &mut *((d.txq.desc_phys as usize + i * 16) as *mut Desc);
    desc.addr = d.txq.bufs[i]; desc.len = (hdr_sz + frame.len()) as u32;
    desc.flags = 0; desc.next = 0;
    let avail = &mut *(d.txq.avail_phys as *mut Avail);
    avail.ring[(avail.idx as usize) % VRING_SIZE] = i as u16;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    avail.idx = avail.idx.wrapping_add(1);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    mmio_w(d.base, MMIO_QUEUE_NOTIFY, 1);
    d.txq.next_avail = d.txq.next_avail.wrapping_add(1);
    Ok(())
}

unsafe fn _recv(d: &mut VirtioNetMmio, buf: &mut [u8]) -> Option<usize> {
    let used = &*(d.rxq.used_phys as *const Used);
    if read_volatile(&used.idx) == d.rxq.last_used { return None; }
    let elem = &used.ring[(d.rxq.last_used as usize) % VRING_SIZE];
    let len = elem.len as usize;
    let hdr_sz = core::mem::size_of::<NetHdr>();
    let payload = len.saturating_sub(hdr_sz);
    let src = (d.rxq.bufs[elem.id as usize] as usize + hdr_sz) as *const u8;
    let n = payload.min(buf.len());
    core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);
    d.rxq.last_used = d.rxq.last_used.wrapping_add(1);
    let avail = &mut *(d.rxq.avail_phys as *mut Avail);
    avail.ring[(avail.idx as usize) % VRING_SIZE] = elem.id as u16;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    avail.idx = avail.idx.wrapping_add(1);
    mmio_w(d.base, MMIO_QUEUE_NOTIFY, 0);
    Some(n)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline] unsafe fn mmio_r(b: u64, o: usize) -> u32 { read_volatile((b as usize+o) as *const u32) }
#[inline] unsafe fn mmio_w(b: u64, o: usize, v: u32) { write_volatile((b as usize+o) as *mut u32, v); }

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}
