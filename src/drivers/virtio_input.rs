//! VirtIO input driver (virtio-1.2 §5.8).
//!
//! ## Spec references
//!   VirtIO 1.2 §5.8 — input device
//!   Linux kernel drivers/virtio/virtio_input.c
//!
//! ## Overview
//! The virtio-input device exposes two virtqueues:
//!   eventq (0) — device posts input events (struct virtio_input_event)
//!   statusq (1) — driver can post LED/haptic requests (unused here)
//!
//! We pre-fill eventq with RX buffers (one per slot), drain in the IRQ
//! handler, and forward each event to evdev::push_event().
//!
//! ## Public API
//!   virtio_input_probe()           — PCIe discovery + init
//!   virtio_input_irq()             — call from IDT at VIRTIO_INPUT_VECTOR
//!   VIRTIO_INPUT_VECTOR            — MSI-X / MSI vector constant

use crate::drivers::pcie::{find_device_by_id, pci_enable_msix, pci_enable_msi_ex};
use crate::drivers::evdev::{push_event, EventType, InputEvent};
use crate::mm::pmm;
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

// ── IRQ vector ───────────────────────────────────────────────────────────────

/// MSI-X entry 0 — eventq completions.
pub const VIRTIO_INPUT_VECTOR: u8 = 0x30;

// ── PCI IDs ──────────────────────────────────────────────────────────────────

const VENDOR_VIRTIO:   u16 = 0x1AF4;
const DEV_INPUT:       u16 = 0x1052;

// ── virtio_input_event (§5.8.6) ──────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtInputEvent {
    typ:   u16,
    code:  u16,
    value: u32,
}

// ── Split virtqueue (minimal, event-queue only) ───────────────────────────────

const QUEUE_SIZE: usize = 64;
const EVENT_SIZE: usize = core::mem::size_of::<VirtInputEvent>();  // 8 bytes

#[repr(C)]
struct VirtDesc {
    addr:  u64,
    len:   u32,
    flags: u16,
    next:  u16,
}

#[repr(C)]
struct VirtAvail {
    flags: u16,
    idx:   u16,
    ring:  [u16; QUEUE_SIZE],
}

#[repr(C)]
struct VirtUsedElem { id: u32, len: u32 }

#[repr(C)]
struct VirtUsed {
    flags: u16,
    idx:   u16,
    ring:  [VirtUsedElem; QUEUE_SIZE],
}

struct Eventq {
    desc:      *mut VirtDesc,
    avail:     *mut VirtAvail,
    used:      *mut VirtUsed,
    bufs:      [*mut VirtInputEvent; QUEUE_SIZE],
    free_head: usize,
    last_used: u16,
}

unsafe impl Send for Eventq {}
unsafe impl Sync for Eventq {}

impl Eventq {
    const fn zeroed() -> Self {
        Self {
            desc: core::ptr::null_mut(),
            avail: core::ptr::null_mut(),
            used: core::ptr::null_mut(),
            bufs: [core::ptr::null_mut(); QUEUE_SIZE],
            free_head: 0,
            last_used: 0,
        }
    }

    /// Allocate rings and return (desc_pa, avail_pa, used_pa).
    unsafe fn alloc(&mut self) -> (u64, u64, u64) {
        let desc_bytes  = core::mem::size_of::<VirtDesc>() * QUEUE_SIZE;
        let avail_bytes = core::mem::size_of::<VirtAvail>();

        let desc_page = alloc_page_zeroed();
        let avail_page = alloc_page_zeroed();
        let used_page  = alloc_page_zeroed();

        self.desc  = desc_page  as *mut VirtDesc;
        self.avail = avail_page as *mut VirtAvail;
        self.used  = used_page  as *mut VirtUsed;

        for i in 0..QUEUE_SIZE - 1 {
            (*self.desc.add(i)).next = (i + 1) as u16;
        }
        self.free_head = 0;
        let _ = (desc_bytes, avail_bytes);

        (desc_page as u64, avail_page as u64, used_page as u64)
    }

    /// Post a write-only (device-writable) event buffer.
    unsafe fn post_buf(&mut self, buf: *mut VirtInputEvent) {
        let idx = self.free_head;
        self.free_head = (*self.desc.add(idx)).next as usize;
        let d = &mut *self.desc.add(idx);
        d.addr  = buf as u64;
        d.len   = EVENT_SIZE as u32;
        d.flags = 2; // VRING_DESC_F_WRITE
        d.next  = 0;
        self.bufs[idx] = buf;

        let avail = &mut *self.avail;
        let slot  = avail.idx as usize & (QUEUE_SIZE - 1);
        avail.ring[slot] = idx as u16;
        fence(Ordering::Release);
        avail.idx = avail.idx.wrapping_add(1);
    }

    /// Drain used ring.  Calls f(event) for each completed entry,
    /// then recycles the buffer.
    unsafe fn drain(&mut self, mut f: impl FnMut(VirtInputEvent)) {
        fence(Ordering::Acquire);
        while self.last_used != (*self.used).idx {
            let slot = self.last_used as usize & (QUEUE_SIZE - 1);
            let elem = (*self.used).ring[slot];
            let ev   = *self.bufs[elem.id as usize];
            f(ev);
            // Recycle.
            (*self.desc.add(elem.id as usize)).next = self.free_head as u16;
            self.free_head = elem.id as usize;
            self.post_buf(self.bufs[elem.id as usize]);
            self.last_used = self.last_used.wrapping_add(1);
        }
    }
}

fn alloc_page_zeroed() -> usize {
    let p = pmm::alloc_page().expect("virtio_input: out of memory");
    unsafe { core::ptr::write_bytes(p as *mut u8, 0, 4096); }
    p
}

// ── Modern CommonCfg MMIO offsets (BAR1) ─────────────────────────────────────
// (same layout as virtio_net/virtio_blk)

const VCFG_DEVICE_STATUS:     usize = 0x14;
const VCFG_QUEUE_SELECT:      usize = 0x16;
const VCFG_QUEUE_SIZE:        usize = 0x18;
const VCFG_QUEUE_ENABLE:      usize = 0x1C;
const VCFG_QUEUE_NOTIFY_OFF:  usize = 0x1E;
const VCFG_QUEUE_DESC_LO:     usize = 0x20;
const VCFG_QUEUE_DESC_HI:     usize = 0x24;
const VCFG_QUEUE_AVAIL_LO:    usize = 0x28;
const VCFG_QUEUE_AVAIL_HI:    usize = 0x2C;
const VCFG_QUEUE_USED_LO:     usize = 0x30;
const VCFG_QUEUE_USED_HI:     usize = 0x34;

const STATUS_ACK:         u8 = 0x01;
const STATUS_DRIVER:      u8 = 0x02;
const STATUS_DRIVER_OK:   u8 = 0x04;
const STATUS_FEATURES_OK: u8 = 0x08;

// ── Device state ─────────────────────────────────────────────────────────────

struct Dev {
    cfg_base:     usize,
    notify_base:  usize,
    notify_mult:  u32,
    eventq:       Eventq,
}

unsafe impl Send for Dev {}
unsafe impl Sync for Dev {}

static DEV: Mutex<Option<Dev>> = Mutex::new(None);

// ── Probe ─────────────────────────────────────────────────────────────────────

/// Locate virtio-input via PCIe and initialise.
/// Call after pcie_init() from kernel_main.
pub fn virtio_input_probe() -> bool {
    let dev = match find_device_by_id(VENDOR_VIRTIO, DEV_INPUT) {
        Some(d) => d,
        None    => { log!("virtio_input: no device"); return false; }
    };
    dev.enable();

    if !pci_enable_msix(&dev, 0, VIRTIO_INPUT_VECTOR, 0) {
        pci_enable_msi_ex(&dev, 0, VIRTIO_INPUT_VECTOR);
    }

    let cfg = match dev.bar_mmio(1) {
        Some(b) => b as usize,
        None    => { log!("virtio_input: no BAR1"); return false; }
    };
    let notify_base = dev.bar_mmio(2).unwrap_or(cfg as u64 + 0x1000) as usize;

    unsafe { init(cfg, notify_base, 4) };
    true
}

unsafe fn init(cfg: usize, notify_base: usize, notify_mult: u32) {
    mm_wb(cfg, VCFG_DEVICE_STATUS, 0);
    mm_wb(cfg, VCFG_DEVICE_STATUS, STATUS_ACK);
    mm_wb(cfg, VCFG_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);
    // No feature bits required for basic event stream.
    mm_wb(cfg, VCFG_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK);

    // Set up eventq (queue 0).
    let mut eventq = Eventq::zeroed();
    mm_ww(cfg, VCFG_QUEUE_SELECT, 0);
    mm_ww(cfg, VCFG_QUEUE_SIZE, QUEUE_SIZE as u16);
    let (desc_pa, avail_pa, used_pa) = eventq.alloc();
    mm_wl(cfg, VCFG_QUEUE_DESC_LO,  (desc_pa  & 0xFFFF_FFFF) as u32);
    mm_wl(cfg, VCFG_QUEUE_DESC_HI,  (desc_pa  >> 32) as u32);
    mm_wl(cfg, VCFG_QUEUE_AVAIL_LO, (avail_pa & 0xFFFF_FFFF) as u32);
    mm_wl(cfg, VCFG_QUEUE_AVAIL_HI, (avail_pa >> 32) as u32);
    mm_wl(cfg, VCFG_QUEUE_USED_LO,  (used_pa  & 0xFFFF_FFFF) as u32);
    mm_wl(cfg, VCFG_QUEUE_USED_HI,  (used_pa  >> 32) as u32);
    mm_ww(cfg, VCFG_QUEUE_ENABLE, 1);

    // Pre-fill all slots.
    for _ in 0..QUEUE_SIZE {
        let buf = alloc_page_zeroed() as *mut VirtInputEvent;
        eventq.post_buf(buf);
    }

    // Notify device about posted buffers.
    let noff = mm_rw(cfg, VCFG_QUEUE_NOTIFY_OFF) as u32;
    let naddr = notify_base + (noff * notify_mult) as usize;
    (naddr as *mut u16).write_volatile(0);

    mm_wb(cfg, VCFG_DEVICE_STATUS,
          STATUS_ACK | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

    *DEV.lock() = Some(Dev { cfg_base: cfg, notify_base, notify_mult, eventq });
    log!("virtio_input: ready");
}

// ── IRQ ───────────────────────────────────────────────────────────────────────

/// Call from IDT handler at VIRTIO_INPUT_VECTOR.
pub fn virtio_input_irq() {
    let mut guard = DEV.lock();
    let Some(dev) = guard.as_mut() else { return; };
    unsafe {
        dev.eventq.drain(|ev| {
            push_event(InputEvent {
                typ:   EventType::from_u16(ev.typ),
                code:  ev.code,
                value: ev.value as i32,
            });
        });
        // Notify device about recycled buffers.
        mm_ww(dev.cfg_base, VCFG_QUEUE_SELECT, 0);
        let noff  = mm_rw(dev.cfg_base, VCFG_QUEUE_NOTIFY_OFF) as u32;
        let naddr = dev.notify_base + (noff * dev.notify_mult) as usize;
        (naddr as *mut u16).write_volatile(0);
    }
}

// ── MMIO helpers ─────────────────────────────────────────────────────────────

#[inline] unsafe fn mm_rb(b: usize, o: usize) -> u8  { core::ptr::read_volatile((b+o) as *const u8)  }
#[inline] unsafe fn mm_rw(b: usize, o: usize) -> u16 { core::ptr::read_volatile((b+o) as *const u16) }
#[inline] unsafe fn mm_wb(b: usize, o: usize, v: u8)  { core::ptr::write_volatile((b+o) as *mut u8,  v) }
#[inline] unsafe fn mm_ww(b: usize, o: usize, v: u16) { core::ptr::write_volatile((b+o) as *mut u16, v) }
#[inline] unsafe fn mm_wl(b: usize, o: usize, v: u32) { core::ptr::write_volatile((b+o) as *mut u32, v) }

// ── log! macro shim ───────────────────────────────────────────────────────────

macro_rules! log {
    ($($t:tt)*) => {
        crate::arch::x86_64::serial::serial_println!($($t)*)
    };
}
use log;
