//! Virtio-input driver (virtio device ID 18).
//!
//! Provides keyboard, mouse and tablet input for QEMU virtio-input devices.
//! Uses two virtqueues:
//!   - VQ 0 (eventq): device → driver — input events
//!   - VQ 1 (statusq): driver → device — LED/feedback status
//!
//! ## Event format (matches Linux virtio_input_event)
//!   type  u16
//!   code  u16
//!   value u32

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

use crate::drivers::input::evdev::{self, InputEvent};

// ---------------------------------------------------------------------------
// Virtio MMIO register offsets
// ---------------------------------------------------------------------------

const MMIO_MAGIC:        usize = 0x000;
const MMIO_VERSION:      usize = 0x004;
const MMIO_DEVICE_ID:    usize = 0x008;
const MMIO_VENDOR_ID:    usize = 0x00C;
const MMIO_DEV_FEAT:     usize = 0x010;
const MMIO_DEV_FEATSEL:  usize = 0x014;
const MMIO_DRV_FEAT:     usize = 0x020;
const MMIO_DRV_FEATSEL:  usize = 0x024;
const MMIO_QUEUE_SEL:    usize = 0x030;
const MMIO_QUEUE_NUMMAX: usize = 0x034;
const MMIO_QUEUE_NUM:    usize = 0x038;
const MMIO_QUEUE_ALIGN:  usize = 0x03C;
const MMIO_QUEUE_PFN:    usize = 0x040;
const MMIO_QUEUE_READY:  usize = 0x044;
const MMIO_QUEUE_NOTIFY: usize = 0x050;
const MMIO_INT_STATUS:   usize = 0x060;
const MMIO_INT_ACK:      usize = 0x064;
const MMIO_STATUS:       usize = 0x070;
const MMIO_CONFIG:       usize = 0x100;

const STATUS_ACK:    u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_OK:     u32 = 4;
const STATUS_FEAT_OK:u32 = 8;

const DEVICE_ID_INPUT: u32 = 18;
const MAGIC_VALUE:     u32 = 0x7472_6976;

const QSZ: usize = 64;

// ---------------------------------------------------------------------------
// Virtqueue structures
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct Desc {
    addr:  u64,
    len:   u32,
    flags: u16,
    next:  u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Avail {
    flags: u16,
    idx:   u16,
    ring:  [u16; QSZ],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct UsedElem {
    id:  u32,
    len: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Used {
    flags: u16,
    idx:   u16,
    ring:  [UsedElem; QSZ],
}

const DESC_F_WRITE: u16 = 2;

// Each event buffer is 8 bytes (type u16 + code u16 + value u32).
const EVT_SIZE: usize = 8;

struct Vq {
    desc:      *mut Desc,
    avail:     *mut Avail,
    used:      *mut Used,
    bufs:      Vec<u64>,
    last_used: u16,
}

// ---------------------------------------------------------------------------
// Per-device state
// ---------------------------------------------------------------------------

struct VirtioInput {
    base:  usize,
    eventq: Vq,
}

unsafe impl Send for VirtioInput {}
unsafe impl Sync for VirtioInput {}

static DEVS: Mutex<Vec<VirtioInput>> = Mutex::new(Vec::new());

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialise one virtio-input MMIO device at `mmio_base`.
pub fn init(mmio_base: u64) {
    unsafe { _init(mmio_base as usize); }
}

/// Poll all registered virtio-input devices for new events.
/// Call from the main loop or timer tick.
pub fn poll() {
    unsafe { _poll(); }
}

/// Returns true if at least one device has been registered.
pub fn is_initialised() -> bool {
    !DEVS.lock().is_empty()
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

unsafe fn _init(base: usize) {
    if read32(base, MMIO_MAGIC) != MAGIC_VALUE { return; }
    if read32(base, MMIO_DEVICE_ID) != DEVICE_ID_INPUT { return; }

    write32(base, MMIO_STATUS, 0);
    write32(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER);

    // No special features needed.
    write32(base, MMIO_DEV_FEATSEL, 0);
    write32(base, MMIO_DRV_FEATSEL, 0);
    write32(base, MMIO_DRV_FEAT, 0);
    write32(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK);

    let eventq = setup_queue(base, 0);
    // statusq (queue 1) is optional; skip for now.

    write32(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK | STATUS_OK);

    let mut dev = VirtioInput { base, eventq };
    refill_eventq(&mut dev.eventq, base);
    DEVS.lock().push(dev);
}

// ---------------------------------------------------------------------------
// Polling
// ---------------------------------------------------------------------------

unsafe fn _poll() {
    let mut devs = DEVS.lock();
    for dev in devs.iter_mut() {
        loop {
            let used = pop_used(&mut dev.eventq);
            let elem = match used { Some(e) => e, None => break };

            let buf_phys = dev.eventq.bufs[elem.id as usize % dev.eventq.bufs.len()];
            let raw = core::slice::from_raw_parts(buf_phys as *const u8, EVT_SIZE);
            let ev_type  = u16::from_le_bytes([raw[0], raw[1]]);
            let ev_code  = u16::from_le_bytes([raw[2], raw[3]]);
            let ev_value = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as i32;

            let ns = crate::drivers::platform::clint::monotonic_ns();
            evdev::push(InputEvent {
                time_sec:  (ns / 1_000_000_000) as u32,
                time_usec: ((ns % 1_000_000_000) / 1_000) as u32,
                r#type:    ev_type,
                code:      ev_code,
                value:     ev_value,
            });

            // Hand descriptor back.
            recycle_desc(&mut dev.eventq, elem.id as u16, dev.base);
        }
    }
}

// ---------------------------------------------------------------------------
// Virtqueue helpers
// ---------------------------------------------------------------------------

unsafe fn setup_queue(base: usize, q: u32) -> Vq {
    write32(base, MMIO_QUEUE_SEL, q);
    let qmax = read32(base, MMIO_QUEUE_NUMMAX) as usize;
    let qsz  = QSZ.min(qmax);
    write32(base, MMIO_QUEUE_NUM, qsz as u32);
    write32(base, MMIO_QUEUE_ALIGN, 4096);

    let desc_bytes  = qsz * core::mem::size_of::<Desc>();
    let avail_bytes = core::mem::size_of::<Avail>();
    let used_bytes  = core::mem::size_of::<Used>();
    let total = align_up(desc_bytes + avail_bytes, 4096) + align_up(used_bytes, 4096);
    let phys = alloc_dma(total, 4096).unwrap();
    core::ptr::write_bytes(phys as *mut u8, 0, total);

    write32(base, MMIO_QUEUE_PFN, (phys >> 12) as u32);
    write32(base, MMIO_QUEUE_READY, 1);

    let desc  = phys as *mut Desc;
    let avail = (phys as usize + desc_bytes) as *mut Avail;
    let used  = (phys as usize + align_up(desc_bytes + avail_bytes, 4096)) as *mut Used;

    let mut bufs = Vec::with_capacity(qsz);
    for _ in 0..qsz { bufs.push(alloc_dma(EVT_SIZE, 8).unwrap()); }

    Vq { desc, avail, used, bufs, last_used: 0 }
}

unsafe fn refill_eventq(q: &mut Vq, base: usize) {
    for i in 0..q.bufs.len() as u16 {
        recycle_desc(q, i, base);
    }
}

unsafe fn recycle_desc(q: &mut Vq, idx: u16, base: usize) {
    let d = &mut *q.desc.add(idx as usize);
    d.addr  = q.bufs[idx as usize % q.bufs.len()];
    d.len   = EVT_SIZE as u32;
    d.flags = DESC_F_WRITE;
    d.next  = 0;
    // Add to avail ring.
    let a = &mut *q.avail;
    let slot = (a.idx as usize) % q.bufs.len();
    a.ring[slot] = idx;
    a.idx = a.idx.wrapping_add(1);
    // Notify.
    write32(base, MMIO_QUEUE_NOTIFY, 0);
}

unsafe fn pop_used(q: &mut Vq) -> Option<UsedElem> {
    let u = &*q.used;
    if q.last_used == u.idx { return None; }
    let elem = u.ring[(q.last_used as usize) % q.bufs.len()];
    q.last_used = q.last_used.wrapping_add(1);
    Some(elem)
}

#[inline]
fn align_up(x: usize, a: usize) -> usize { (x + a - 1) & !(a - 1) }

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size.max(4096) + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}

#[inline]
unsafe fn read32(base: usize, off: usize) -> u32 {
    read_volatile((base + off) as *const u32)
}

#[inline]
unsafe fn write32(base: usize, off: usize, val: u32) {
    write_volatile((base + off) as *mut u32, val);
}
