//! VirtIO legacy PCI block device driver (device ID 0x1001, vendor 0x1AF4).
//!
//! ## Spec references
//!   - VirtIO 0.9.5 (legacy) PCI transport
//!   - VirtIO block device type: ID 2 (blk)
//!
//! ## Memory model
//!   The driver uses a single virtqueue (queue 0, REQUEST queue).
//!   All descriptors and buffers are identity-mapped (PA == VA).
//!   Requests are submitted synchronously: after kicking the queue we
//!   spin-poll the used ring until the device consumes our descriptor.
//!
//! ## PCI discovery
//!   We scan bus 0, devices 0-31, function 0 only.  QEMU exposes the
//!   virtio-blk device on bus 0, device 3 or 4, function 0 by default.
//!
//! ## Exposed API
//!   init()              — scan PCI, init queue, detect disk
//!   is_present() -> bool
//!   read_sectors(lba, buf)  -> Result<(), i32>   (512-byte sectors)
//!   write_sectors(lba, buf) -> Result<(), i32>

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

// ── PCI helpers ────────────────────────────────────────────────────────────

/// Read 32 bits from PCI config space using port I/O (CONFIG_ADDRESS 0xCF8,
/// CONFIG_DATA 0xCFC).
#[inline]
fn pci_read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
    let addr: u32 = 0x8000_0000
        | ((bus as u32)  << 16)
        | ((dev as u32)  << 11)
        | ((func as u32) << 8)
        | (offset as u32 & 0xFC);
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") 0xCF8u16, in("eax") addr, options(nostack)
        );
        let mut v: u32;
        core::arch::asm!(
            "in eax, dx",
            in("dx") 0xCFCu16, out("eax") v, options(nostack)
        );
        v
    }
}

#[inline]
fn pci_read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
    let d = pci_read32(bus, dev, func, offset & 0xFC);
    if offset & 2 != 0 { (d >> 16) as u16 } else { d as u16 }
}

/// Read the BAR0 I/O base of the device at (bus, dev, 0).
fn pci_bar0_io(bus: u8, dev: u8) -> u16 {
    let bar0 = pci_read32(bus, dev, 0, 0x10);
    (bar0 & !0x3) as u16   // bit 0 = I/O space indicator; mask it
}

/// Enable PCI bus-master + I/O space access.
fn pci_enable(bus: u8, dev: u8) {
    // Set bits [0] (I/O enable) and [2] (bus master) in command register (0x04).
    let cmd = pci_read16(bus, dev, 0, 0x04);
    let new_cmd = cmd | 0x05;
    let addr: u32 = 0x8000_0000
        | ((bus as u32) << 16)
        | ((dev as u32) << 11)
        | 0x04;
    unsafe {
        core::arch::asm!(
            "out dx, eax", in("dx") 0xCF8u16,
            in("eax") addr, options(nostack)
        );
        core::arch::asm!(
            "out dx, ax", in("dx") 0xCFCu16,
            in("ax") new_cmd, options(nostack)
        );
    }
}

// ── VirtIO legacy I/O port register layout ─────────────────────────────────
// Offsets from BAR0 base.

const VTIO_DEVICE_FEATURES:  u16 = 0x00; // R 32
const VTIO_GUEST_FEATURES:   u16 = 0x04; // W 32
const VTIO_QUEUE_PFN:        u16 = 0x08; // W 32  (queue page frame number)
const VTIO_QUEUE_SIZE:       u16 = 0x0C; // R 16
const VTIO_QUEUE_SELECT:     u16 = 0x0E; // W 16
const VTIO_QUEUE_NOTIFY:     u16 = 0x10; // W 16
const VTIO_DEVICE_STATUS:    u16 = 0x12; // RW 8
const VTIO_ISR_STATUS:       u16 = 0x13; // R 8

// Device-status bits.
const VTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VTIO_STATUS_DRIVER:      u8 = 2;
const VTIO_STATUS_DRIVER_OK:   u8 = 4;
const VTIO_STATUS_FEATURES_OK: u8 = 8;
const VTIO_STATUS_FAILED:      u8 = 128;

// Port I/O helpers.
#[inline]
unsafe fn vio_readb(base: u16, off: u16) -> u8 {
    let mut v: u8;
    core::arch::asm!("in al, dx", in("dx") base + off, out("al") v, options(nostack));
    v
}
#[inline]
unsafe fn vio_readw(base: u16, off: u16) -> u16 {
    let mut v: u16;
    core::arch::asm!("in ax, dx", in("dx") base + off, out("ax") v, options(nostack));
    v
}
#[inline]
unsafe fn vio_readl(base: u16, off: u16) -> u32 {
    let mut v: u32;
    core::arch::asm!("in eax, dx", in("dx") base + off, out("eax") v, options(nostack));
    v
}
#[inline]
unsafe fn vio_writeb(base: u16, off: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") base + off, in("al") val, options(nostack));
}
#[inline]
unsafe fn vio_writew(base: u16, off: u16, val: u16) {
    core::arch::asm!("out dx, ax", in("dx") base + off, in("ax") val, options(nostack));
}
#[inline]
unsafe fn vio_writel(base: u16, off: u16, val: u32) {
    core::arch::asm!("out dx, eax", in("dx") base + off, in("eax") val, options(nostack));
}

// ── Virtqueue layout ───────────────────────────────────────────────────────
// We allocate a single virtqueue at a page-aligned PA.  The layout follows
// the VirtIO legacy spec:
//   Descriptor Table:  QUEUE_SIZE × 16 bytes  (at page base)
//   Available Ring:    6 + QUEUE_SIZE × 2 bytes (immediately after)
//   Used Ring:         6 + QUEUE_SIZE × 8 bytes (at next 4096-aligned offset)

const QUEUE_SIZE: usize = 16;  // power-of-two, ≥ 3 for our 3-descriptor chain
const DESC_SIZE:  usize = 16;  // { addr:u64, len:u32, flags:u16, next:u16 }
const AVAIL_OFF:  usize = QUEUE_SIZE * DESC_SIZE;           // avail ring offset
const AVAIL_SIZE: usize = 6 + QUEUE_SIZE * 2;
const USED_OFF_UNALIGNED: usize = AVAIL_OFF + AVAIL_SIZE;
const USED_OFF:   usize = (USED_OFF_UNALIGNED + 4095) & !4095; // page-aligned
const QUEUE_BYTES: usize = USED_OFF + 6 + QUEUE_SIZE * 8;

// Descriptor flags.
const VRING_DESC_F_NEXT:  u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2; // device-writable (for read data + status)

// VirtIO block request types.
const VIRTIO_BLK_T_IN:  u32 = 0; // read
const VIRTIO_BLK_T_OUT: u32 = 1; // write

// ── Driver state ───────────────────────────────────────────────────────────

struct BlkDev {
    io_base:     u16,
    queue_va:    usize,
    last_used:   u16,   // last used-ring idx we consumed
    capacity:    u64,   // device capacity in 512-byte sectors
}

static DEV: Mutex<Option<BlkDev>> = Mutex::new(None);
static PRESENT: AtomicBool = AtomicBool::new(false);

// ── init ───────────────────────────────────────────────────────────────────

/// Scan PCI bus 0 for a VirtIO legacy block device and initialise it.
pub fn init() {
    const VIRTIO_VENDOR: u16 = 0x1AF4;
    const VIRTIO_BLK_DEV: u16 = 0x1001;

    let mut found_bus = 0u8;
    let mut found_dev = 0u8;
    let mut found = false;

    'outer: for bus in 0u8..=1 {
        for dev in 0u8..32 {
            let id = pci_read32(bus, dev, 0, 0);
            if id == 0xFFFF_FFFF { continue; }
            let vendor = id as u16;
            let device = (id >> 16) as u16;
            if vendor == VIRTIO_VENDOR && device == VIRTIO_BLK_DEV {
                found_bus = bus;
                found_dev = dev;
                found = true;
                break 'outer;
            }
        }
    }
    if !found { return; }

    pci_enable(found_bus, found_dev);
    let io_base = pci_bar0_io(found_bus, found_dev);
    if io_base == 0 { return; }

    unsafe { init_device(io_base) };
}

unsafe fn init_device(io_base: u16) {
    // 1. Reset device.
    vio_writeb(io_base, VTIO_DEVICE_STATUS, 0);

    // 2. Acknowledge + driver bits.
    vio_writeb(io_base, VTIO_DEVICE_STATUS, VTIO_STATUS_ACKNOWLEDGE);
    vio_writeb(io_base, VTIO_DEVICE_STATUS,
               VTIO_STATUS_ACKNOWLEDGE | VTIO_STATUS_DRIVER);

    // 3. Read device features; accept everything (legacy = no negotiation step).
    let _features = vio_readl(io_base, VTIO_DEVICE_FEATURES);
    vio_writel(io_base, VTIO_GUEST_FEATURES, _features);

    // 4. Allocate virtqueue memory (must be page-aligned, PA == VA).
    let queue_va = match crate::mm::pmm::alloc_page() {
        Some(p) => p,
        None => return,
    };
    // Two pages for safety (QUEUE_BYTES ≤ 4096 for QUEUE_SIZE=16).
    let queue_va2 = match crate::mm::pmm::alloc_page() {
        Some(p) => p,
        None => return,
    };
    core::ptr::write_bytes(queue_va  as *mut u8, 0, 4096);
    core::ptr::write_bytes(queue_va2 as *mut u8, 0, 4096);

    // 5. Tell device about queue 0.
    vio_writew(io_base, VTIO_QUEUE_SELECT, 0);
    let _qsz = vio_readw(io_base, VTIO_QUEUE_SIZE);
    // PFN in 4096-byte pages.
    vio_writel(io_base, VTIO_QUEUE_PFN, (queue_va as u32) >> 12);

    // 6. DRIVER_OK.
    vio_writeb(io_base, VTIO_DEVICE_STATUS,
               VTIO_STATUS_ACKNOWLEDGE | VTIO_STATUS_DRIVER | VTIO_STATUS_DRIVER_OK);

    // 7. Read capacity (virtio-blk config starts at BAR0+0x14 for legacy).
    let cap_lo = vio_readl(io_base, 0x14);
    let cap_hi = vio_readl(io_base, 0x18);
    let capacity = ((cap_hi as u64) << 32) | cap_lo as u64;

    let mut dev = DEV.lock();
    *dev = Some(BlkDev { io_base, queue_va, last_used: 0, capacity });
    PRESENT.store(true, Ordering::Release);
}

pub fn is_present() -> bool { PRESENT.load(Ordering::Acquire) }

// ── I/O ────────────────────────────────────────────────────────────────────

/// virtio-blk request header (16 bytes).
#[repr(C, packed)]
struct BlkReqHdr {
    typ:     u32,  // VIRTIO_BLK_T_IN / OUT
    _rsvd:   u32,
    sector:  u64,
}

/// Read `buf.len() / 512` consecutive sectors starting at `lba` into `buf`.
/// `buf.len()` must be a multiple of 512.
pub fn read_sectors(lba: u64, buf: &mut [u8]) -> Result<(), i32> {
    submit_request(VIRTIO_BLK_T_IN, lba, buf)
}

/// Write `buf.len() / 512` consecutive sectors starting at `lba` from `buf`.
pub fn write_sectors(lba: u64, buf: &[u8]) -> Result<(), i32> {
    // Safety: we cast &[u8] to &mut [u8] for the unified path — write data is
    // only read by the device, never written back.
    let buf_mut = unsafe {
        core::slice::from_raw_parts_mut(buf.as_ptr() as *mut u8, buf.len())
    };
    submit_request(VIRTIO_BLK_T_OUT, lba, buf_mut)
}

fn submit_request(typ: u32, lba: u64, buf: &mut [u8]) -> Result<(), i32> {
    if buf.len() == 0 || buf.len() % 512 != 0 { return Err(-22); }
    let mut guard = DEV.lock();
    let dev = guard.as_mut().ok_or(-6)?; // ENXIO

    let sectors = buf.len() / 512;
    let io_base  = dev.io_base;
    let qva      = dev.queue_va;

    // Allocate header and status byte at the end of page 0 (after desc table).
    // We carve out static offsets inside the queue page for these small items:
    //   offset 0x800: BlkReqHdr (16 bytes)
    //   offset 0x810: status byte (1 byte)
    const HDR_OFF:    usize = 0x800;
    const STATUS_OFF: usize = 0x810;

    let hdr_va     = qva + HDR_OFF;
    let status_va  = qva + STATUS_OFF;

    unsafe {
        (hdr_va as *mut BlkReqHdr).write_volatile(BlkReqHdr {
            typ, _rsvd: 0, sector: lba,
        });
        (status_va as *mut u8).write_volatile(0xFF); // sentinel
    }

    // Build 3-descriptor chain:
    //   [0] hdr  (device-readable)
    //   [1] data (device-readable for write, device-writable for read)
    //   [2] status byte (device-writable)
    let desc_base = qva as *mut u8;

    // Descriptor 0: header
    write_desc(desc_base, 0, hdr_va as u64,
               core::mem::size_of::<BlkReqHdr>() as u32,
               VRING_DESC_F_NEXT, 1);
    // Descriptor 1: data buffer
    let data_flags = if typ == VIRTIO_BLK_T_IN {
        VRING_DESC_F_WRITE | VRING_DESC_F_NEXT
    } else {
        VRING_DESC_F_NEXT
    };
    write_desc(desc_base, 1, buf.as_ptr() as u64, buf.len() as u32,
               data_flags, 2);
    // Descriptor 2: status
    write_desc(desc_base, 2, status_va as u64, 1, VRING_DESC_F_WRITE, 0);

    // Available ring: flags=0, idx, ring[0]=0 (head descriptor)
    let avail = unsafe { (qva + AVAIL_OFF) as *mut u16 };
    unsafe {
        avail.add(0).write_volatile(0);             // flags
        let old_idx = avail.add(1).read_volatile();
        avail.add(2 + (old_idx as usize % QUEUE_SIZE)).write_volatile(0); // ring[tail]=desc0
        core::sync::atomic::fence(Ordering::SeqCst);
        avail.add(1).write_volatile(old_idx.wrapping_add(1)); // idx++
        core::sync::atomic::fence(Ordering::SeqCst);
    }

    // Kick the queue.
    unsafe { vio_writew(io_base, VTIO_QUEUE_NOTIFY, 0); }

    // Spin-poll used ring until device posts a completion.
    let used = unsafe { (qva + USED_OFF) as *const u16 };
    let mut spins = 0usize;
    loop {
        core::sync::atomic::fence(Ordering::Acquire);
        let used_idx = unsafe { used.add(1).read_volatile() };
        if used_idx != dev.last_used { break; }
        spins += 1;
        if spins > 10_000_000 { return Err(-5); } // EIO — timeout
        core::hint::spin_loop();
    }
    dev.last_used = dev.last_used.wrapping_add(1);

    // Check status byte written by device: 0 = OK, 1 = error, 2 = unsupported.
    let status = unsafe { (status_va as *const u8).read_volatile() };
    if status != 0 { Err(-5) } else { Ok(()) } // EIO on non-zero
}

/// Write one 16-byte virtqueue descriptor.
#[inline]
fn write_desc(base: *mut u8, idx: usize, addr: u64, len: u32, flags: u16, next: u16) {
    let p = unsafe { base.add(idx * DESC_SIZE) } as *mut u64;
    unsafe {
        p.add(0).write_volatile(addr);                          // addr
        (p as *mut u32).add(2).write_volatile(len);             // len
        (p as *mut u16).add(6).write_volatile(flags);           // flags
        (p as *mut u16).add(7).write_volatile(next);            // next
    }
}
