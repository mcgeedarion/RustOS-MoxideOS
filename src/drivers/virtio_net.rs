//! virtio-net driver — PCI MMIO, two virtqueues (RX/TX), interrupt-driven receive.
//!
//! Layout:
//!   virtio_net_init()         called from kernel_main after PCIe scan
//!   VirtioNet::send_frame()   called by net::eth::send_frame()
//!   RX ISR                    wakes net::eth::rx_poll()

use crate::drivers::pcie::{pcie_find, PciBar};
use crate::mm::pmm::{phys_alloc_zeroed, PAGE_SIZE};
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;

// ── PCI IDs ──────────────────────────────────────────────────────────────────
const VENDOR_VIRTIO: u16 = 0x1AF4;
const DEV_NET:        u16 = 0x1000; // legacy (transitional) ID
const DEV_NET_MOD:    u16 = 0x1041; // modern (PCI cap) ID

// ── virtio legacy MMIO offsets (BAR0 I/O port space) ─────────────────────────
const VIRT_DEVICE_FEATURES: u16 = 0x00;
const VIRT_DRIVER_FEATURES: u16 = 0x04;
const VIRT_QUEUE_ADDRESS:   u16 = 0x08;
const VIRT_QUEUE_SIZE:      u16 = 0x0C;
const VIRT_QUEUE_SELECT:    u16 = 0x0E;
const VIRT_QUEUE_NOTIFY:    u16 = 0x10;
const VIRT_DEVICE_STATUS:   u16 = 0x12;
const VIRT_ISR_STATUS:      u16 = 0x13;
const VIRT_NET_MAC_BASE:    u16 = 0x14; // 6 bytes

// device status bits
const STATUS_ACK:         u8 = 0x01;
const STATUS_DRIVER:      u8 = 0x02;
const STATUS_DRIVER_OK:   u8 = 0x04;
const STATUS_FEATURES_OK: u8 = 0x08;
const STATUS_FAILED:      u8 = 0x80;

// virtio-net feature bits we care about
const FEAT_CSUM:     u32 = 1 << 0;
const FEAT_MAC:      u32 = 1 << 5;
const FEAT_STATUS:   u32 = 1 << 16;
const FEAT_CTRL_VQ:  u32 = 1 << 17;

// virtq descriptor flags
const VRING_DESC_F_NEXT:     u16 = 1;
const VRING_DESC_F_WRITE:    u16 = 2;

const QUEUE_SIZE: usize = 256;
const NET_HEADER_LEN: usize = 12; // virtio_net_hdr

/// Virtqueue split-ring descriptor.
#[repr(C)]
struct VirtDesc {
    addr:  u64,
    len:   u32,
    flags: u16,
    next:  u16,
}

/// Virtqueue available ring.
#[repr(C)]
struct VirtAvail {
    flags: u16,
    idx:   u16,
    ring:  [u16; QUEUE_SIZE],
    used_event: u16,
}

/// Virtqueue used element.
#[repr(C)]
struct VirtUsedElem {
    id:  u32,
    len: u32,
}

/// Virtqueue used ring.
#[repr(C)]
struct VirtUsed {
    flags: u16,
    idx:   u16,
    ring:  [VirtUsedElem; QUEUE_SIZE],
    avail_event: u16,
}

/// One split virtqueue.
struct Virtqueue {
    desc:  *mut VirtDesc,
    avail: *mut VirtAvail,
    used:  *mut VirtUsed,
    free_head: usize,
    last_used: u16,
    /// bounce buffers for each descriptor slot
    bufs:  [*mut u8; QUEUE_SIZE],
}

unsafe impl Send for Virtqueue {}
unsafe impl Sync for Virtqueue {}

impl Virtqueue {
    const fn zeroed() -> Self {
        Self {
            desc: core::ptr::null_mut(),
            avail: core::ptr::null_mut(),
            used: core::ptr::null_mut(),
            free_head: 0,
            last_used: 0,
            bufs: [core::ptr::null_mut(); QUEUE_SIZE],
        }
    }

    /// Allocate the three rings from physical memory.
    unsafe fn alloc(&mut self) {
        let desc_bytes  = core::mem::size_of::<VirtDesc>()  * QUEUE_SIZE;
        let avail_bytes = core::mem::size_of::<VirtAvail>();
        let used_bytes  = core::mem::size_of::<VirtUsed>();

        let pages_needed = (desc_bytes + avail_bytes + used_bytes + PAGE_SIZE - 1) / PAGE_SIZE;
        let phys = phys_alloc_zeroed(pages_needed);

        self.desc  = phys as *mut VirtDesc;
        self.avail = (phys + desc_bytes)  as *mut VirtAvail;
        self.used  = (phys + desc_bytes + avail_bytes) as *mut VirtUsed;

        // chain free list
        for i in 0..QUEUE_SIZE-1 {
            (*self.desc.add(i)).next = (i + 1) as u16;
        }
        self.free_head = 0;
    }

    /// Add a write-only descriptor for a receive buffer.
    unsafe fn add_rx_buf(&mut self, buf: *mut u8, len: u32) {
        let idx = self.free_head;
        self.free_head = (*self.desc.add(idx)).next as usize;
        let d = &mut *self.desc.add(idx);
        d.addr  = buf as u64;
        d.len   = len;
        d.flags = VRING_DESC_F_WRITE;
        d.next  = 0;
        self.bufs[idx] = buf;

        let avail = &mut *self.avail;
        let slot  = (avail.idx as usize) & (QUEUE_SIZE - 1);
        avail.ring[slot] = idx as u16;
        fence(Ordering::Release);
        avail.idx = avail.idx.wrapping_add(1);
    }

    /// Add a read-only descriptor for transmit.
    /// Returns descriptor index so caller can notify device.
    unsafe fn add_tx_buf(&mut self, buf: *const u8, len: u32) -> usize {
        let idx = self.free_head;
        self.free_head = (*self.desc.add(idx)).next as usize;
        let d = &mut *self.desc.add(idx);
        d.addr  = buf as u64;
        d.len   = len;
        d.flags = 0;
        d.next  = 0;
        self.bufs[idx] = buf as *mut u8;

        let avail = &mut *self.avail;
        let slot  = (avail.idx as usize) & (QUEUE_SIZE - 1);
        avail.ring[slot] = idx as u16;
        fence(Ordering::Release);
        avail.idx = avail.idx.wrapping_add(1);
        idx
    }

    /// Drain used ring; call f(buf_ptr, len) for each completed buffer.
    unsafe fn drain_used(&mut self, mut f: impl FnMut(*mut u8, u32)) {
        let used = &*self.used;
        fence(Ordering::Acquire);
        while self.last_used != used.idx {
            let slot = (self.last_used as usize) & (QUEUE_SIZE - 1);
            let elem = &used.ring[slot];
            let buf  = self.bufs[elem.id as usize];
            f(buf, elem.len);
            // return descriptor to free list
            (*self.desc.add(elem.id as usize)).next = self.free_head as u16;
            self.free_head = elem.id as usize;
            self.last_used = self.last_used.wrapping_add(1);
        }
    }
}

// ── Device state ─────────────────────────────────────────────────────────────

struct VirtioNetDev {
    io_base: u16,   // legacy: I/O port base
    mac:     [u8; 6],
    rxq:     Virtqueue,
    txq:     Virtqueue,
}

unsafe impl Send for VirtioNetDev {}
unsafe impl Sync for VirtioNetDev {}

static DEV: Mutex<Option<VirtioNetDev>> = Mutex::new(None);

// ── I/O port helpers (legacy virtio over PCI I/O BAR) ────────────────────────

#[cfg(target_arch = "x86_64")]
unsafe fn io_read8(port: u16) -> u8 {
    let v: u8;
    core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack));
    v
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_write8(port: u16, v: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack));
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_read16(port: u16) -> u16 {
    let v: u16;
    core::arch::asm!("in ax, dx", out("ax") v, in("dx") port, options(nomem, nostack));
    v
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_write16(port: u16, v: u16) {
    core::arch::asm!("out dx, ax", in("dx") port, in("ax") v, options(nomem, nostack));
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_read32(port: u16) -> u32 {
    let v: u32;
    core::arch::asm!("in eax, dx", out("eax") v, in("dx") port, options(nomem, nostack));
    v
}
#[cfg(target_arch = "x86_64")]
unsafe fn io_write32(port: u16, v: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") v, options(nomem, nostack));
}

// RISC-V stubs
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_read8(_: u16) -> u8   { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_write8(_: u16, _: u8) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_read16(_: u16) -> u16  { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_write16(_: u16, _: u16) {}
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_read32(_: u16) -> u32  { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn io_write32(_: u16, _: u32) {}

// ── Public init ──────────────────────────────────────────────────────────────

/// Called from kernel_main / PCIe scan.
pub fn virtio_net_init() {
    let dev_info = pcie_find(VENDOR_VIRTIO, DEV_NET)
        .or_else(|| pcie_find(VENDOR_VIRTIO, DEV_NET_MOD));
    let Some(info) = dev_info else {
        log::warn!("virtio-net: no device found");
        return;
    };

    let io_base = match info.bar0 {
        PciBar::Io(base) => base as u16,
        _ => {
            log::warn!("virtio-net: BAR0 is not I/O space (MMIO path not yet implemented)");
            return;
        }
    };

    unsafe {
        // 1. Reset
        io_write8(io_base + VIRT_DEVICE_STATUS, 0);
        // 2. ACK + DRIVER
        io_write8(io_base + VIRT_DEVICE_STATUS, STATUS_ACK | STATUS_DRIVER);

        // 3. Feature negotiation
        let dev_features = io_read32(io_base + VIRT_DEVICE_FEATURES);
        let drv_features = dev_features & (FEAT_MAC | FEAT_CSUM);
        io_write32(io_base + VIRT_DRIVER_FEATURES, drv_features);

        // 4. FEATURES_OK
        let status = io_read8(io_base + VIRT_DEVICE_STATUS) | STATUS_FEATURES_OK;
        io_write8(io_base + VIRT_DEVICE_STATUS, status);
        if io_read8(io_base + VIRT_DEVICE_STATUS) & STATUS_FEATURES_OK == 0 {
            log::error!("virtio-net: FEATURES_OK not set by device");
            io_write8(io_base + VIRT_DEVICE_STATUS, STATUS_FAILED);
            return;
        }

        // 5. Read MAC
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = io_read8(io_base + VIRT_NET_MAC_BASE + i as u16);
        }
        log::info!("virtio-net: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        // 6. Set up RX virtqueue (index 0)
        io_write16(io_base + VIRT_QUEUE_SELECT, 0);
        let qsize = io_read16(io_base + VIRT_QUEUE_SIZE) as usize;
        let qsize = qsize.min(QUEUE_SIZE);
        let _ = qsize; // we use our own QUEUE_SIZE
        let mut rxq = Virtqueue::zeroed();
        rxq.alloc();
        io_write32(io_base + VIRT_QUEUE_ADDRESS,
            (rxq.desc as usize >> 12) as u32);
        // pre-fill RX descriptors
        for _ in 0..QUEUE_SIZE/2 {
            let buf = phys_alloc_zeroed(1) as *mut u8;
            rxq.add_rx_buf(buf, PAGE_SIZE as u32);
        }

        // 7. Set up TX virtqueue (index 1)
        io_write16(io_base + VIRT_QUEUE_SELECT, 1);
        let mut txq = Virtqueue::zeroed();
        txq.alloc();
        io_write32(io_base + VIRT_QUEUE_ADDRESS,
            (txq.desc as usize >> 12) as u32);

        // 8. DRIVER_OK
        let s = io_read8(io_base + VIRT_DEVICE_STATUS) | STATUS_DRIVER_OK;
        io_write8(io_base + VIRT_DEVICE_STATUS, s);

        let dev = VirtioNetDev { io_base, mac, rxq, txq };
        *DEV.lock() = Some(dev);

        // Inform the network stack of our MAC so it can initialise.
        crate::net::eth::set_mac(mac);
        log::info!("virtio-net: device ready");
    }
}

/// Send one Ethernet frame (including FCS if required; caller supplies raw bytes).
/// Prepends a 12-byte virtio_net_hdr of zeros (no offloads).
pub fn send_frame(frame: &[u8]) -> bool {
    let mut guard = DEV.lock();
    let Some(dev) = guard.as_mut() else { return false; };
    unsafe {
        // Allocate a bounce buffer: hdr + frame
        let total = NET_HEADER_LEN + frame.len();
        let pages = (total + PAGE_SIZE - 1) / PAGE_SIZE;
        let buf = phys_alloc_zeroed(pages) as *mut u8;
        // hdr already zeroed; copy frame after hdr
        core::ptr::copy_nonoverlapping(frame.as_ptr(), buf.add(NET_HEADER_LEN), frame.len());
        let _idx = dev.txq.add_tx_buf(buf, total as u32);
        // Notify device: write queue index (1 = TX) to QUEUE_NOTIFY
        io_write16(dev.io_base + VIRT_QUEUE_NOTIFY, 1);
    }
    true
}

/// Poll for received frames; called from IRQ handler / idle loop.
pub fn rx_poll() {
    let mut guard = DEV.lock();
    let Some(dev) = guard.as_mut() else { return };
    unsafe {
        dev.rxq.drain_used(|buf, len| {
            if len as usize > NET_HEADER_LEN {
                let frame = core::slice::from_raw_parts(
                    buf.add(NET_HEADER_LEN),
                    len as usize - NET_HEADER_LEN,
                );
                crate::net::eth::receive_frame(frame);
            }
            // Re-add buffer to RX queue
            dev.rxq.add_rx_buf(buf, PAGE_SIZE as u32);
        });
        // Notify device about recycled RX descriptors
        io_write16(dev.io_base + VIRT_QUEUE_NOTIFY, 0);
    }
}

/// Called from IRQ handler when virtio-net line fires.
pub fn virtio_net_irq() {
    let guard = DEV.lock();
    let Some(dev) = guard.as_ref() else { return };
    unsafe {
        // Acknowledge ISR
        let _ = io_read8(dev.io_base + VIRT_ISR_STATUS);
    }
    drop(guard);
    rx_poll();
}

/// Return our MAC address.
pub fn mac_address() -> [u8; 6] {
    DEV.lock().as_ref().map(|d| d.mac).unwrap_or([0u8; 6])
}
