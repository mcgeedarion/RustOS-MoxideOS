//! virtio-input device driver.
//!
//! Handles virtio-input devices (keyboard, mouse, tablet …) exposed by
//! QEMU via `-device virtio-keyboard-device` or `-device virtio-mouse-device`.
//! Events are forwarded into the evdev queue.
//!
//! ## Virtqueues
//!   Queue 0 (eventq): device → driver, 64-entry, 8-byte events
//!   Queue 1 (statusq): driver → device, status updates (unused here)

extern crate alloc;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;
use super::evdev::{self, InputEvent, EventType};

// ---------------------------------------------------------------------------
// MMIO register offsets (virtio-mmio transport)
// ---------------------------------------------------------------------------

const MMIO_MAGIC:        usize = 0x000;
const MMIO_VERSION:      usize = 0x004;
const MMIO_DEVICE_ID:    usize = 0x008;
const MMIO_DEV_FEATURES: usize = 0x010;
const MMIO_DEV_FEAT_SEL: usize = 0x014;
const MMIO_DRV_FEATURES: usize = 0x020;
const MMIO_DRV_FEAT_SEL: usize = 0x024;
const MMIO_QUEUE_SEL:    usize = 0x030;
const MMIO_QUEUE_NUM_MAX:usize = 0x034;
const MMIO_QUEUE_NUM:    usize = 0x038;
const MMIO_QUEUE_READY:  usize = 0x044;
const MMIO_QUEUE_NOTIFY: usize = 0x050;
const MMIO_IRQ_STATUS:   usize = 0x060;
const MMIO_IRQ_ACK:      usize = 0x064;
const MMIO_STATUS:       usize = 0x070;
const MMIO_QUEUE_DESC_LO:usize = 0x080;
const MMIO_QUEUE_DESC_HI:usize = 0x084;
const MMIO_QUEUE_DRV_LO: usize = 0x090;
const MMIO_QUEUE_DRV_HI: usize = 0x094;
const MMIO_QUEUE_DEV_LO: usize = 0x0A0;
const MMIO_QUEUE_DEV_HI: usize = 0x0A4;

const VIRTIO_MAGIC:   u32 = 0x74726976;
const DEVICE_ID_INPUT:u32 = 18;

const STATUS_ACK:       u32 = 1;
const STATUS_DRIVER:    u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEAT_OK:   u32 = 8;

const VRING_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// vring
// ---------------------------------------------------------------------------

#[repr(C, packed)] #[derive(Clone, Copy, Default)]
struct Desc  { addr: u64, len: u32, flags: u16, next: u16 }
#[repr(C, packed)] #[derive(Clone, Copy, Default)]
struct Avail { flags: u16, idx: u16, ring: [u16; VRING_SIZE] }
#[repr(C, packed)] #[derive(Clone, Copy)]
struct UsedElem { id: u32, len: u32 }
#[repr(C, packed)] #[derive(Clone, Copy)]
struct Used  { flags: u16, idx: u16, ring: [UsedElem; VRING_SIZE] }

const DESC_F_WRITE: u16 = 2;

// virtio_input_event
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct VirtioInputEvent {
    ev_type: u16,
    code:    u16,
    value:   u32,
}

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------

struct VirtioInput {
    base:       u64,
    desc_phys:  u64,
    avail_phys: u64,
    used_phys:  u64,
    bufs:       [u64; VRING_SIZE],
    last_used:  u16,
}

static DEV: Mutex<Option<VirtioInput>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Probe and initialise a virtio-input MMIO device at `base`.
pub fn init(base: u64) -> bool {
    unsafe { _init(base) }
}

/// Poll for new input events and push them into the evdev queue.
/// Call this from the device IRQ handler or a polling loop.
pub fn poll() {
    let mut g = DEV.lock();
    let d = match g.as_mut() { Some(d) => d, None => return };
    unsafe { _poll(d); }
}

/// Acknowledge device interrupt.
pub fn irq_ack(base: u64) {
    let s = unsafe { mmio_r(base, MMIO_IRQ_STATUS) };
    unsafe { mmio_w(base, MMIO_IRQ_ACK, s); }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

unsafe fn _init(base: u64) -> bool {
    if mmio_r(base, MMIO_MAGIC)     != VIRTIO_MAGIC    { return false; }
    if mmio_r(base, MMIO_DEVICE_ID) != DEVICE_ID_INPUT { return false; }

    mmio_w(base, MMIO_STATUS, 0);
    mmio_w(base, MMIO_STATUS, STATUS_ACK);
    mmio_w(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER);

    mmio_w(base, MMIO_DEV_FEAT_SEL, 0);
    mmio_w(base, MMIO_DRV_FEAT_SEL, 0);
    mmio_w(base, MMIO_DRV_FEATURES, 0);
    mmio_w(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK);
    if mmio_r(base, MMIO_STATUS) & STATUS_FEAT_OK == 0 { return false; }

    // Set up eventq (queue 0).
    mmio_w(base, MMIO_QUEUE_SEL, 0);
    let sz = mmio_r(base, MMIO_QUEUE_NUM_MAX) as usize;
    let sz = sz.min(VRING_SIZE);
    mmio_w(base, MMIO_QUEUE_NUM, sz as u32);

    let desc_sz  = sz * 16;
    let avail_sz = 6 + sz * 2;
    let total    = desc_sz + avail_sz + 4096 + 6 + sz * 8;
    let phys = match alloc_dma(total, 4096) { Some(p) => p, None => return false };
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

    let mut bufs = [0u64; VRING_SIZE];
    // Pre-fill descriptors with event buffers.
    for i in 0..sz {
        let buf = match alloc_dma(8, 8) { Some(b) => b, None => break };
        bufs[i] = buf;
        let desc = &mut *((desc_phys as usize + i * 16) as *mut Desc);
        desc.addr = buf; desc.len = 8; desc.flags = DESC_F_WRITE; desc.next = 0;
        let avail = &mut *(avail_phys as *mut Avail);
        avail.ring[i] = i as u16;
        avail.idx = avail.idx.wrapping_add(1);
    }
    mmio_w(base, MMIO_QUEUE_NOTIFY, 0);

    mmio_w(base, MMIO_STATUS,
        STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK | STATUS_DRIVER_OK);

    *DEV.lock() = Some(VirtioInput {
        base, desc_phys, avail_phys, used_phys, bufs, last_used: 0,
    });
    true
}

unsafe fn _poll(d: &mut VirtioInput) {
    let used = &*(d.used_phys as *const Used);
    loop {
        let used_idx = read_volatile(&used.idx);
        if used_idx == d.last_used { break; }
        let elem = &used.ring[(d.last_used as usize) % VRING_SIZE];
        let buf  = d.bufs[elem.id as usize] as *const VirtioInputEvent;
        let ev   = &*buf;
        d.last_used = d.last_used.wrapping_add(1);

        // Translate to evdev.
        let ev_type = match ev.ev_type {
            1 => EventType::Key,
            2 => EventType::Relative,
            3 => EventType::Absolute,
            0 => EventType::Sync,
            _ => EventType::Misc,
        };
        evdev::push(InputEvent { ev_type, code: ev.code, value: ev.value as i32 });

        // Recycle descriptor.
        let avail = &mut *(d.avail_phys as *mut Avail);
        avail.ring[(avail.idx as usize) % VRING_SIZE] = elem.id as u16;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        avail.idx = avail.idx.wrapping_add(1);
    }
    mmio_w(d.base, MMIO_QUEUE_NOTIFY, 0);
}

#[inline] unsafe fn mmio_r(b: u64, o: usize) -> u32 { read_volatile((b as usize+o) as *const u32) }
#[inline] unsafe fn mmio_w(b: u64, o: usize, v: u32) { write_volatile((b as usize+o) as *mut u32, v); }

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}
