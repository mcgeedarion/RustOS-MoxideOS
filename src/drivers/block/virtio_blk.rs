// src/drivers/block/virtio_blk.rs
//
// VirtIO Block Device Driver (MMIO, VirtIO 1.x spec)
// Supports: read, write, flush via virtqueue descriptor chains

use crate::drivers::virtio::{
    VirtioMmio, VirtqDesc, Virtqueue, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};
use crate::mm::phys::{phys_to_virt, virt_to_phys};
use crate::sync::Mutex;
use core::sync::atomic::{fence, Ordering};

// ---------------------------------------------------------------------------
// VirtIO-blk device feature bits
// ---------------------------------------------------------------------------
const VIRTIO_BLK_F_RO: u32 = 1 << 5;
const VIRTIO_BLK_F_BLK_SIZE: u32 = 1 << 6;
const VIRTIO_BLK_F_FLUSH: u32 = 1 << 9;

// Request type codes
const VIRTIO_BLK_T_IN: u32 = 0; // read
const VIRTIO_BLK_T_OUT: u32 = 1; // write
const VIRTIO_BLK_T_FLUSH: u32 = 4;

// Status byte written back by device
const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

pub const SECTOR_SIZE: usize = 512;
const QUEUE_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// On-wire request header (device-readable)
// ---------------------------------------------------------------------------
#[repr(C)]
struct VirtioBlkReqHeader {
    req_type: u32,
    _reserved: u32,
    sector: u64,
}

// ---------------------------------------------------------------------------
// Full request buffer: header + data + status byte
// We keep all three contiguous so their physical addresses are stable.
// ---------------------------------------------------------------------------
#[repr(C, align(512))]
struct VirtioBlkReq {
    header: VirtioBlkReqHeader,
    data: [u8; SECTOR_SIZE],
    status: u8,
}

impl VirtioBlkReq {
    const fn new() -> Self {
        Self {
            header: VirtioBlkReqHeader {
                req_type: 0,
                _reserved: 0,
                sector: 0,
            },
            data: [0u8; SECTOR_SIZE],
            status: 0xFF, // sentinel: not-yet-written
        }
    }
}

// ---------------------------------------------------------------------------
// Driver state
// ---------------------------------------------------------------------------
pub struct VirtioBlk {
    mmio: VirtioMmio,
    vq: Virtqueue<QUEUE_SIZE>,
    capacity: u64, // in 512-byte sectors
    read_only: bool,
}

impl VirtioBlk {
    /// Probe and initialize a virtio-blk MMIO device at `base`.
    ///
    /// Returns `None` if the device is absent or negotiation fails.
    pub fn new(base: usize) -> Option<Self> {
        let mut mmio = VirtioMmio::new(base)?;

        // Expect device ID 2 (block)
        if mmio.device_id() != 2 {
            return None;
        }

        // --- feature negotiation ---
        let dev_features = mmio.read_device_features(0);
        let mut drv_features: u32 = 0;

        // Accept flush and block-size hints; note read-only flag
        let read_only = dev_features & VIRTIO_BLK_F_RO != 0;
        if dev_features & VIRTIO_BLK_F_FLUSH != 0 {
            drv_features |= VIRTIO_BLK_F_FLUSH;
        }
        if dev_features & VIRTIO_BLK_F_BLK_SIZE != 0 {
            drv_features |= VIRTIO_BLK_F_BLK_SIZE;
        }
        if read_only {
            drv_features |= VIRTIO_BLK_F_RO;
        }

        mmio.write_driver_features(0, drv_features);
        mmio.set_features_ok()?; // returns None if device rejects features

        // --- set up the single virtqueue (queue 0) ---
        let vq = Virtqueue::new();
        mmio.init_queue(
            0,
            QUEUE_SIZE as u32,
            vq.desc_phys(),
            vq.avail_phys(),
            vq.used_phys(),
        );

        mmio.set_driver_ok();

        // Read capacity from device config space (offset 0, two 32-bit words)
        let cap_lo = mmio.read_config32(0) as u64;
        let cap_hi = mmio.read_config32(4) as u64;
        let capacity = (cap_hi << 32) | cap_lo;

        Some(Self {
            mmio,
            vq,
            capacity,
            read_only,
        })
    }

    pub fn capacity_sectors(&self) -> u64 {
        self.capacity
    }
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    // -----------------------------------------------------------------------
    // Public I/O interface
    // -----------------------------------------------------------------------

    /// Read one 512-byte sector at `lba` into `buf`.
    pub fn read_sector(&mut self, lba: u64, buf: &mut [u8; SECTOR_SIZE]) -> Result<(), BlkError> {
        let mut req = VirtioBlkReq::new();
        req.header.req_type = VIRTIO_BLK_T_IN;
        req.header.sector = lba;

        self.submit_and_wait(&mut req, false)?;
        buf.copy_from_slice(&req.data);
        Ok(())
    }

    /// Write one 512-byte sector at `lba` from `buf`.
    pub fn write_sector(&mut self, lba: u64, buf: &[u8; SECTOR_SIZE]) -> Result<(), BlkError> {
        if self.read_only {
            return Err(BlkError::ReadOnly);
        }
        let mut req = VirtioBlkReq::new();
        req.header.req_type = VIRTIO_BLK_T_OUT;
        req.header.sector = lba;
        req.data.copy_from_slice(buf);

        self.submit_and_wait(&mut req, true)
    }

    /// Issue a flush (requires VIRTIO_BLK_F_FLUSH to have been negotiated).
    pub fn flush(&mut self) -> Result<(), BlkError> {
        let mut req = VirtioBlkReq::new();
        req.header.req_type = VIRTIO_BLK_T_FLUSH;
        self.submit_and_wait(&mut req, false)
    }

    // -----------------------------------------------------------------------
    // Internal: build descriptor chain, notify device, poll used ring
    // -----------------------------------------------------------------------

    /// Builds a 3-descriptor chain for one block request and polls for
    /// completion.
    ///
    /// Chain layout (required by spec):
    ///   [0] header  — device-readable
    ///   [1] data    — device-readable (write) or device-writable (read)
    ///   [2] status  — device-writable (1 byte)
    fn submit_and_wait(&mut self, req: &mut VirtioBlkReq, is_write: bool) -> Result<(), BlkError> {
        let req_phys = virt_to_phys(req as *const _ as usize);

        // Descriptor 0: request header
        let d0 = VirtqDesc {
            addr: req_phys as u64,
            len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        };

        // Descriptor 1: data buffer
        let data_phys = req_phys + core::mem::offset_of!(VirtioBlkReq, data);
        let data_flags = VIRTQ_DESC_F_NEXT | if !is_write { VIRTQ_DESC_F_WRITE } else { 0 };
        let d1 = VirtqDesc {
            addr: data_phys as u64,
            len: SECTOR_SIZE as u32,
            flags: data_flags,
            next: 2,
        };

        // Descriptor 2: status byte (always device-writable)
        let status_phys = req_phys + core::mem::offset_of!(VirtioBlkReq, status);
        let d2 = VirtqDesc {
            addr: status_phys as u64,
            len: 1,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };

        // Place chain in virtqueue and kick device
        let head = self.vq.push_chain(&[d0, d1, d2]);
        fence(Ordering::SeqCst);
        self.mmio.notify_queue(0);

        // Poll used ring (no IRQ handler needed for synchronous I/O)
        while !self.vq.has_used(head) {
            core::hint::spin_loop();
        }
        self.vq.consume_used();
        fence(Ordering::Acquire);

        match req.status {
            VIRTIO_BLK_S_OK => Ok(()),
            VIRTIO_BLK_S_IOERR => Err(BlkError::IoError),
            VIRTIO_BLK_S_UNSUPP => Err(BlkError::Unsupported),
            _ => Err(BlkError::IoError),
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkError {
    IoError,
    Unsupported,
    ReadOnly,
}
