//! virtio-blk block device driver (MMIO transport).
//!
//! ## virtio-blk over MMIO
//!   The device lives at a known physical address (typically 0x10001000 in
//!   QEMU virt machine) and uses a single virtqueue (queue 0) with a
//!   3-descriptor chain per request: header, data buffer, status byte.
//!
//! ## Request protocol
//!   Each I/O is a 3-descriptor chain:
//!     [0] struct virtio_blk_req header  (16 bytes, device-readable)
//!     [1] data buffer                   (sector-sized, R or W)
//!     [2] status byte                   (1 byte, device-writable)
//!   The kernel writes the chain to the available ring, kicks the device
//!   by writing 0 to the QueueNotify register, then polls the used ring.
//!
//! ## Sector size
//!   512 bytes.  The driver issues 1-sector requests; callers that want
//!   larger I/Os loop.
//!
//! ## Thread safety
//!   Single-queue, spin-locked.  Adequate for a cooperative kernel.

use core::cell::UnsafeCell;
use spin::Mutex;

// From virtio spec 4.2.2

const MMIO_MAGIC: usize = 0x000; // should read 0x74726976 ("virt")
const MMIO_VERSION: usize = 0x004; // must be 2 (non-legacy)
const MMIO_DEVICE_ID: usize = 0x008; // 2 = block device
const MMIO_VENDOR_ID: usize = 0x00C;
const MMIO_DEVICE_FEAT: usize = 0x010;
const MMIO_DEVICE_FEAT_SEL: usize = 0x014; // select feature word (0 or 1)
const MMIO_DRIVER_FEAT: usize = 0x020;
const MMIO_DRIVER_FEAT_SEL: usize = 0x024; // select feature word (0 or 1)
const MMIO_QUEUE_SEL: usize = 0x030;
const MMIO_QUEUE_NUM_MAX: usize = 0x034;
const MMIO_QUEUE_NUM: usize = 0x038;
const MMIO_QUEUE_READY: usize = 0x044;
const MMIO_QUEUE_NOTIFY: usize = 0x050;
const MMIO_INT_STATUS: usize = 0x060;
const MMIO_INT_ACK: usize = 0x064;
const MMIO_STATUS: usize = 0x070;
const MMIO_QUEUE_DESC_LO: usize = 0x080;
const MMIO_QUEUE_DESC_HI: usize = 0x084;
const MMIO_DRIVER_DESC_LO: usize = 0x090; // available ring ("driver" area)
const MMIO_DRIVER_DESC_HI: usize = 0x094;
const MMIO_DEVICE_DESC_LO: usize = 0x0A0; // used ring ("device" area)
const MMIO_DEVICE_DESC_HI: usize = 0x0A4;

// Device status bits
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_FAILED: u32 = 128;

// virtio-blk request types
const VIRTIO_BLK_T_IN: u32 = 0; // read
const VIRTIO_BLK_T_OUT: u32 = 1; // write

const SECTOR_SIZE: usize = 512;
const QUEUE_SIZE: usize = 8; // power of 2; must be <= QueueNumMax

const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2; // device writes to this buffer

#[repr(C, align(16))]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, align(2))]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE],
    used_event: u16,
}

#[repr(C)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C, align(4))]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; QUEUE_SIZE],
    avail_event: u16,
}

#[repr(C)]
struct BlkReqHeader {
    type_: u32,
    _reserved: u32,
    sector: u64,
}

// Padding so that `used` starts on a 4096-byte boundary within the struct.
const DESC_SIZE: usize = core::mem::size_of::<[VirtqDesc; QUEUE_SIZE]>();
const AVAIL_SIZE: usize = core::mem::size_of::<VirtqAvail>();
const PAD_SIZE: usize = (4096 - (DESC_SIZE + AVAIL_SIZE) % 4096) % 4096;

// All must be physically contiguous and correctly aligned.
// We use statics so addresses are known at link time.

#[repr(C, align(4096))]
struct Virtqueues {
    desc: [VirtqDesc; QUEUE_SIZE],
    avail: VirtqAvail,
    _pad: [u8; PAD_SIZE],
    used: VirtqUsed,
}

// VolatileCell: wraps device-shared buffers so the compiler cannot cache or
// reorder accesses to memory the device writes behind our back.
struct VolatileCell<T>(UnsafeCell<T>);
unsafe impl<T> Sync for VolatileCell<T> {}

impl<T: Copy> VolatileCell<T> {
    const fn new(v: T) -> Self {
        Self(UnsafeCell::new(v))
    }
    unsafe fn read(&self) -> T {
        self.0.get().read_volatile()
    }
    unsafe fn write(&self, v: T) {
        self.0.get().write_volatile(v)
    }
}

static mut QUEUES: Virtqueues = unsafe { core::mem::zeroed() };
static REQ_HDR: VolatileCell<BlkReqHeader> = VolatileCell::new(BlkReqHeader {
    type_: 0,
    _reserved: 0,
    sector: 0,
});
static REQ_STATUS: VolatileCell<u8> = VolatileCell::new(0xFF);
static REQ_BUF: VolatileCell<[u8; SECTOR_SIZE]> = VolatileCell::new([0u8; SECTOR_SIZE]);

static LOCK: Mutex<()> = Mutex::new(());
static mut MMIO_BASE: usize = 0;
static mut LAST_USED_IDX: u16 = 0;

/// Initialise the virtio-blk device at `mmio_pa`.
/// Call after PMM is up; `mmio_pa` must be identity-mapped.
pub fn virtio_blk_init(mmio_pa: usize) {
    unsafe {
        MMIO_BASE = mmio_pa;

        // 1. Verify magic and version.
        if mmio_r32(MMIO_MAGIC) != 0x74726976 {
            return; // not a virtio device
        }
        if mmio_r32(MMIO_VERSION) != 2 {
            return; // legacy device, not supported
        }
        if mmio_r32(MMIO_DEVICE_ID) != 2 {
            return; // not a block device
        }

        // 2. Reset device.
        mmio_w32(MMIO_STATUS, 0);

        // 3. Set ACKNOWLEDGE + DRIVER.
        mmio_w32(MMIO_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // 4. Negotiate features (we want none beyond the baseline). Must select each
        //    word before reading/writing per spec §4.2.2.
        mmio_w32(MMIO_DEVICE_FEAT_SEL, 0);
        let _dev_feats_lo = mmio_r32(MMIO_DEVICE_FEAT);
        mmio_w32(MMIO_DEVICE_FEAT_SEL, 1);
        let _dev_feats_hi = mmio_r32(MMIO_DEVICE_FEAT);

        mmio_w32(MMIO_DRIVER_FEAT_SEL, 0);
        mmio_w32(MMIO_DRIVER_FEAT, 0);
        mmio_w32(MMIO_DRIVER_FEAT_SEL, 1);
        mmio_w32(MMIO_DRIVER_FEAT, 0);

        mmio_w32(
            MMIO_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );
        if mmio_r32(MMIO_STATUS) & STATUS_FEATURES_OK == 0 {
            mmio_w32(MMIO_STATUS, STATUS_FAILED);
            return;
        }

        // 5. Set up queue 0.
        mmio_w32(MMIO_QUEUE_SEL, 0);
        let qmax = mmio_r32(MMIO_QUEUE_NUM_MAX) as usize;
        if qmax < QUEUE_SIZE {
            return;
        }
        mmio_w32(MMIO_QUEUE_NUM, QUEUE_SIZE as u32);

        let desc_pa = &QUEUES.desc as *const _ as u64;
        let avail_pa = &QUEUES.avail as *const _ as u64;
        let used_pa = &QUEUES.used as *const _ as u64;

        mmio_w32(MMIO_QUEUE_DESC_LO, (desc_pa & 0xFFFF_FFFF) as u32);
        mmio_w32(MMIO_QUEUE_DESC_HI, (desc_pa >> 32) as u32);
        mmio_w32(MMIO_DRIVER_DESC_LO, (avail_pa & 0xFFFF_FFFF) as u32);
        mmio_w32(MMIO_DRIVER_DESC_HI, (avail_pa >> 32) as u32);
        mmio_w32(MMIO_DEVICE_DESC_LO, (used_pa & 0xFFFF_FFFF) as u32);
        mmio_w32(MMIO_DEVICE_DESC_HI, (used_pa >> 32) as u32);
        mmio_w32(MMIO_QUEUE_READY, 1);

        // 6. Driver OK.
        mmio_w32(
            MMIO_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
    }
}

/// Read one 512-byte sector at `lba` into `buf`.
/// Returns true on success.
pub fn read_sector(lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> bool {
    do_request(VIRTIO_BLK_T_IN, lba, buf)
}

/// Write one 512-byte sector at `lba` from `buf`.
pub fn write_sector(lba: u64, buf: &[u8; SECTOR_SIZE]) -> bool {
    let mut tmp = *buf;
    do_request(VIRTIO_BLK_T_OUT, lba, &mut tmp)
}

fn do_request(req_type: u32, lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> bool {
    let _guard = LOCK.lock();
    unsafe {
        // Fill request header.
        REQ_HDR.write(BlkReqHeader {
            type_: req_type,
            _reserved: 0,
            sector: lba,
        });
        REQ_STATUS.write(0xFF); // 0 = OK, 1 = IOERR, 2 = UNSUPP

        // If write, copy caller's data into REQ_BUF.
        if req_type == VIRTIO_BLK_T_OUT {
            REQ_BUF.write(*buf);
        }

        // Build 3-descriptor chain.
        // Desc 0: header (device-readable)
        QUEUES.desc[0].addr = REQ_HDR.0.get() as u64;
        QUEUES.desc[0].len = core::mem::size_of::<BlkReqHeader>() as u32;
        QUEUES.desc[0].flags = VRING_DESC_F_NEXT;
        QUEUES.desc[0].next = 1;

        // Desc 1: data buffer
        QUEUES.desc[1].addr = REQ_BUF.0.get() as u64;
        QUEUES.desc[1].len = SECTOR_SIZE as u32;
        QUEUES.desc[1].flags = VRING_DESC_F_NEXT
            | if req_type == VIRTIO_BLK_T_IN {
                VRING_DESC_F_WRITE
            } else {
                0
            };
        QUEUES.desc[1].next = 2;

        // Desc 2: status byte (device-writable)
        QUEUES.desc[2].addr = REQ_STATUS.0.get() as u64;
        QUEUES.desc[2].len = 1;
        QUEUES.desc[2].flags = VRING_DESC_F_WRITE;
        QUEUES.desc[2].next = 0;

        // Place head descriptor (0) in available ring.
        let avail_idx = QUEUES.avail.idx as usize % QUEUE_SIZE;
        QUEUES.avail.ring[avail_idx] = 0;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        QUEUES.avail.idx = QUEUES.avail.idx.wrapping_add(1);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        // Kick device.
        mmio_w32(MMIO_QUEUE_NOTIFY, 0);

        // Poll used ring (timeout after ~5M spins).
        let mut spins = 0usize;
        loop {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            if QUEUES.used.idx != LAST_USED_IDX {
                break;
            }
            spins += 1;
            if spins > 5_000_000 {
                return false;
            }
            core::hint::spin_loop();
        }
        LAST_USED_IDX = LAST_USED_IDX.wrapping_add(1);

        // Ack interrupt.
        let isr = mmio_r32(MMIO_INT_STATUS);
        mmio_w32(MMIO_INT_ACK, isr);

        // If read, copy data out.
        if req_type == VIRTIO_BLK_T_IN {
            *buf = REQ_BUF.read();
        }

        REQ_STATUS.read() == 0
    }
}

unsafe fn mmio_r32(off: usize) -> u32 {
    let va = MMIO_BASE + off;
    (va as *const u32).read_volatile()
}

unsafe fn mmio_w32(off: usize, val: u32) {
    let va = MMIO_BASE + off;
    (va as *mut u32).write_volatile(val);
}
