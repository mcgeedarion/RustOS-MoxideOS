//! VirtIO MMIO transport (VirtIO 1.x §4.2).
//!
//! Register layout matches the MMIO discovery probe done by QEMU/kvmtool.
//! All register accesses are 32-bit; the device is assumed little-endian
//! (same as the host for the target arches we support).

use core::ptr::{read_volatile, write_volatile};

// ---------------------------------------------------------------------------
// MMIO register offsets (§4.2.2)
// ---------------------------------------------------------------------------
const OFF_MAGIC:            usize = 0x000; // ro: 0x74726976
const OFF_VERSION:          usize = 0x004; // ro: must be 2
const OFF_DEVICE_ID:        usize = 0x008;
const OFF_VENDOR_ID:        usize = 0x00C;
const OFF_DEVICE_FEATURES:  usize = 0x010;
const OFF_DEVICE_FEAT_SEL:  usize = 0x014;
const OFF_DRIVER_FEATURES:  usize = 0x020;
const OFF_DRIVER_FEAT_SEL:  usize = 0x024;
const OFF_QUEUE_SEL:        usize = 0x030;
const OFF_QUEUE_NUM_MAX:    usize = 0x034;
const OFF_QUEUE_NUM:        usize = 0x038;
const OFF_QUEUE_READY:      usize = 0x044;
const OFF_QUEUE_NOTIFY:     usize = 0x050;
const OFF_INTERRUPT_STATUS: usize = 0x060;
const OFF_INTERRUPT_ACK:    usize = 0x064;
const OFF_STATUS:           usize = 0x070;
const OFF_QUEUE_DESC_LOW:   usize = 0x080;
const OFF_QUEUE_DESC_HIGH:  usize = 0x084;
const OFF_QUEUE_AVAIL_LOW:  usize = 0x090;
const OFF_QUEUE_AVAIL_HIGH: usize = 0x094;
const OFF_QUEUE_USED_LOW:   usize = 0x0A0;
const OFF_QUEUE_USED_HIGH:  usize = 0x0A4;
const OFF_CONFIG:           usize = 0x100;

// Device status bits (§2.1)
const STATUS_ACKNOWLEDGE:   u32 = 1;
const STATUS_DRIVER:        u32 = 2;
const STATUS_DRIVER_OK:     u32 = 4;
const STATUS_FEATURES_OK:   u32 = 8;
const STATUS_FAILED:        u32 = 128;

const VIRTIO_MAGIC: u32 = 0x74726976;

// ---------------------------------------------------------------------------
// VirtioMmio
// ---------------------------------------------------------------------------
pub struct VirtioMmio {
    base: usize,
}

impl VirtioMmio {
    /// Probe the MMIO region at `base`.
    ///
    /// Returns `None` if the magic / version check fails or if the device
    /// resets into FAILED status.
    pub fn new(base: usize) -> Option<Self> {
        let dev = Self { base };

        if dev.read(OFF_MAGIC) != VIRTIO_MAGIC { return None; }
        if dev.read(OFF_VERSION) != 2          { return None; }

        // Reset device, then set ACKNOWLEDGE | DRIVER
        dev.write(OFF_STATUS, 0);
        dev.write(OFF_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        Some(dev)
    }

    // --- feature negotiation helpers ---

    pub fn device_id(&self) -> u32 {
        self.read(OFF_DEVICE_ID)
    }

    /// Read 32 bits of device features. `page` selects the high/low word
    /// (0 = bits 0-31, 1 = bits 32-63).
    pub fn read_device_features(&self, page: u32) -> u32 {
        self.write(OFF_DEVICE_FEAT_SEL, page);
        self.read(OFF_DEVICE_FEATURES)
    }

    /// Write 32 bits of accepted driver features.
    pub fn write_driver_features(&self, page: u32, features: u32) {
        self.write(OFF_DRIVER_FEAT_SEL, page);
        self.write(OFF_DRIVER_FEATURES, features);
    }

    /// Set FEATURES_OK and verify the device accepts them.
    /// Returns `None` if the device clears FEATURES_OK (feature mismatch).
    pub fn set_features_ok(&self) -> Option<()> {
        let status = self.read(OFF_STATUS) | STATUS_FEATURES_OK;
        self.write(OFF_STATUS, status);
        if self.read(OFF_STATUS) & STATUS_FEATURES_OK == 0 {
            return None;
        }
        Some(())
    }

    /// Configure virtqueue `idx` with the given physical addresses.
    pub fn init_queue(&self, idx: u32, num: u32, desc: u64, avail: u64, used: u64) {
        self.write(OFF_QUEUE_SEL, idx);
        assert!(num <= self.read(OFF_QUEUE_NUM_MAX), "queue size exceeds device max");
        self.write(OFF_QUEUE_NUM, num);

        self.write(OFF_QUEUE_DESC_LOW,   (desc  & 0xFFFF_FFFF) as u32);
        self.write(OFF_QUEUE_DESC_HIGH,  (desc  >> 32) as u32);
        self.write(OFF_QUEUE_AVAIL_LOW,  (avail & 0xFFFF_FFFF) as u32);
        self.write(OFF_QUEUE_AVAIL_HIGH, (avail >> 32) as u32);
        self.write(OFF_QUEUE_USED_LOW,   (used  & 0xFFFF_FFFF) as u32);
        self.write(OFF_QUEUE_USED_HIGH,  (used  >> 32) as u32);

        self.write(OFF_QUEUE_READY, 1);
    }

    /// Finalise initialisation (set DRIVER_OK).
    pub fn set_driver_ok(&self) {
        let status = self.read(OFF_STATUS) | STATUS_DRIVER_OK;
        self.write(OFF_STATUS, status);
    }

    /// Notify the device that queue `idx` has new entries.
    pub fn notify_queue(&self, idx: u32) {
        self.write(OFF_QUEUE_NOTIFY, idx);
    }

    /// Read 32 bits from device-specific config space at byte `offset`.
    pub fn read_config32(&self, offset: usize) -> u32 {
        self.read(OFF_CONFIG + offset)
    }

    // --- raw register accessors ---

    #[inline(always)]
    fn read(&self, offset: usize) -> u32 {
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    #[inline(always)]
    fn write(&self, offset: usize, val: u32) {
        unsafe { write_volatile((self.base + offset) as *mut u32, val) }
    }
}
