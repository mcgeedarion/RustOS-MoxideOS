//! virtio-net userspace driver
//!
//! This binary runs as a privileged userspace process.  It owns the
//! virtio-net PCI device entirely — no NIC code runs in the kernel.
//!
//! # Startup sequence
//!
//! 1. `sys_driver_bind`    — claim the PCI device, get MMIO mapping.
//! 2. `sys_dma_alloc`      — allocate physically contiguous RX/TX descriptor rings.
//! 3. Device initialisation via MMIO writes (virtio spec section 3.1).
//! 4. `sys_irq_subscribe`  — IRQs arrive as `IrqNotification` messages.
//! 5. `sys_scheme_register("net", ep)` — publish `net:` scheme.
//! 6. Event loop: handle IRQs and scheme requests.
//!
//! # Scheme interface
//!
//! | URL          | open flags | Description                              |
//! |--------------|------------|------------------------------------------|
//! | `net:eth0`   | R+W        | Raw Ethernet frame I/O for the TCP stack |
//! | `net:eth0`   | R only     | Capture / monitor mode                   |
//!
//! `write(fd, frame)` enqueues a frame on the TX virtqueue.
//! `read(fd, buf)`    dequeues the next received frame from the RX virtqueue.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::{
    collections::VecDeque,
    string::String,
    vec::Vec,
};

use scheme_api::{
    DriverHandle, IpcEndpoint, IrqNotification,
    OpenFlags, SchemeError, SchemeFileId,
    SchemeRequest, SchemeResponse,
};

// Kernel syscall stubs
// In a real build these are thin wrappers around `syscall` instructions.
// We declare them as `extern "C"` here; the linker resolves them from the
// syscall shim library built alongside the kernel.

extern "C" {
    fn sys_driver_bind(bdf: u32, cap_flags: u32) -> i64;
    fn sys_dma_alloc(handle: u64, size: usize, align: usize, phys_out: *mut u64) -> i64;
    fn sys_irq_subscribe(handle: u64, irq: u32, endpoint: u64) -> i64;
    fn sys_scheme_register(name_ptr: *const u8, name_len: usize, endpoint: u64) -> i64;
    fn sys_ipc_endpoint_create() -> u64;
    fn sys_ipc_recv(endpoint: u64, buf: *mut u8, buf_len: usize) -> i64;
    fn sys_ipc_send(endpoint: u64, buf: *const u8, buf_len: usize) -> i64;
    fn sys_irq_ack(handle: u64, irq: u32) -> i64;
    fn sys_exit(code: i32) -> !;
}

/// Magic value at offset 0x000: must equal 0x74726976 ("virt").
const VIRTIO_MAGIC:           u32 = 0x74726976;
const VIRTIO_MMIO_MAGIC:      usize = 0x000;
const VIRTIO_MMIO_VERSION:    usize = 0x004;
const VIRTIO_MMIO_DEVICE_ID:  usize = 0x008;  // 1 = net
const VIRTIO_MMIO_STATUS:     usize = 0x070;
const VIRTIO_MMIO_QUEUE_SEL:  usize = 0x030;
const VIRTIO_MMIO_QUEUE_NUM:  usize = 0x038;
const VIRTIO_MMIO_QUEUE_DESC: usize = 0x080;
const VIRTIO_MMIO_QUEUE_AVAIL:usize = 0x090;
const VIRTIO_MMIO_QUEUE_USED: usize = 0x0a0;
const VIRTIO_MMIO_QUEUE_READY:usize = 0x044;
const VIRTIO_MMIO_QUEUE_NOTIFY:usize= 0x050;
const VIRTIO_MMIO_INT_STATUS: usize = 0x060;
const VIRTIO_MMIO_INT_ACK:    usize = 0x064;

/// Device status bits (virtio spec section 2.1).
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER:      u32 = 2;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_DRIVER_OK:   u32 = 4;

/// Virtqueue sizes (must be a power of two).
const RX_QUEUE_IDX:  u32 = 0;
const TX_QUEUE_IDX:  u32 = 1;
const QUEUE_SIZE:    u16 = 256;
const MAX_FRAME_LEN: usize = 1526; // 1500 + 14 (Ethernet) + 12 (virtio header)

#[repr(C)]
struct VirtqDesc {
    addr:  u64,   // physical address of buffer
    len:   u32,
    flags: u16,   // 0=read-only, VIRTQ_DESC_F_WRITE=2 for device-writable
    next:  u16,
}

#[repr(C)]
struct VirtqAvail {
    flags: u16,
    idx:   u16,
    ring:  [u16; QUEUE_SIZE as usize],
}

#[repr(C)]
struct VirtqUsedElem {
    id:  u32,
    len: u32,
}

#[repr(C)]
struct VirtqUsed {
    flags: u16,
    idx:   u16,
    ring:  [VirtqUsedElem; QUEUE_SIZE as usize],
}

struct NetDriver {
    mmio_base:    *mut u8,
    handle:       DriverHandle,
    endpoint:     IpcEndpoint,
    irq:          u32,

    // RX virtqueue
    rx_desc:      *mut VirtqDesc,
    rx_avail:     *mut VirtqAvail,
    rx_used:      *mut VirtqUsed,
    rx_bufs:      Vec<(*mut u8, u64)>,  // (virt, phys) per descriptor
    rx_last_used: u16,

    // TX virtqueue
    tx_desc:      *mut VirtqDesc,
    tx_avail:     *mut VirtqAvail,
    tx_used:      *mut VirtqUsed,
    tx_free:      VecDeque<u16>,         // free descriptor indices

    // Pending received frames waiting to be read by scheme consumers.
    rx_pending:   VecDeque<Vec<u8>>,
}

// SAFETY: this process is single-threaded; no concurrent access.
unsafe impl Send for NetDriver {}
unsafe impl Sync for NetDriver {}

impl NetDriver {

    unsafe fn init(mmio_base: *mut u8, handle: DriverHandle, irq: u32) -> Self {
        // Verify magic and device type.
        let magic = mmio_read32(mmio_base, VIRTIO_MMIO_MAGIC);
        assert_eq!(magic, VIRTIO_MAGIC, "not a virtio-mmio device");
        let dev_id = mmio_read32(mmio_base, VIRTIO_MMIO_DEVICE_ID);
        assert_eq!(dev_id, 1, "device is not virtio-net (id={})", dev_id);

        mmio_write32(mmio_base, VIRTIO_MMIO_STATUS, 0);
        mmio_write32(mmio_base, VIRTIO_MMIO_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // Negotiate features (we keep it simple: no offloads).
        mmio_write32(mmio_base, VIRTIO_MMIO_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);

        let (rx_desc, rx_avail, rx_used, rx_bufs) =
            Self::setup_rx_queue(handle, mmio_base);

        let (tx_desc, tx_avail, tx_used, tx_free) =
            Self::setup_tx_queue(handle, mmio_base);

        mmio_write32(mmio_base, VIRTIO_MMIO_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);

        // Create IPC endpoint for scheme requests + IRQ notifications.
        let endpoint = IpcEndpoint(sys_ipc_endpoint_create());

        Self {
            mmio_base,
            handle,
            endpoint,
            irq,
            rx_desc, rx_avail, rx_used, rx_bufs,
            rx_last_used: 0,
            tx_desc, tx_avail, tx_used, tx_free,
            rx_pending: VecDeque::new(),
        }
    }

    unsafe fn setup_rx_queue(
        handle: DriverHandle,
        base: *mut u8,
    ) -> (*mut VirtqDesc, *mut VirtqAvail, *mut VirtqUsed, Vec<(*mut u8, u64)>) {
        mmio_write32(base, VIRTIO_MMIO_QUEUE_SEL, RX_QUEUE_IDX);
        mmio_write32(base, VIRTIO_MMIO_QUEUE_NUM, QUEUE_SIZE as u32);

        let desc_size  = core::mem::size_of::<VirtqDesc>()  * QUEUE_SIZE as usize;
        let avail_size = core::mem::size_of::<VirtqAvail>();
        let used_size  = core::mem::size_of::<VirtqUsed>();

        let mut phys_desc: u64 = 0;
        let virt_desc = sys_dma_alloc(handle.0, desc_size, 4096, &mut phys_desc);
        assert!(virt_desc > 0);

        let mut phys_avail: u64 = 0;
        let virt_avail = sys_dma_alloc(handle.0, avail_size, 2, &mut phys_avail);
        assert!(virt_avail > 0);

        let mut phys_used: u64 = 0;
        let virt_used = sys_dma_alloc(handle.0, used_size, 4, &mut phys_used);
        assert!(virt_used > 0);

        mmio_write64(base, VIRTIO_MMIO_QUEUE_DESC,  phys_desc);
        mmio_write64(base, VIRTIO_MMIO_QUEUE_AVAIL, phys_avail);
        mmio_write64(base, VIRTIO_MMIO_QUEUE_USED,  phys_used);
        mmio_write32(base, VIRTIO_MMIO_QUEUE_READY, 1);

        let desc  = virt_desc  as *mut VirtqDesc;
        let avail = virt_avail as *mut VirtqAvail;
        let used  = virt_used  as *mut VirtqUsed;

        // Pre-fill RX descriptors with receive buffers.
        let mut rx_bufs = Vec::with_capacity(QUEUE_SIZE as usize);
        for i in 0..QUEUE_SIZE as usize {
            let mut phys_buf: u64 = 0;
            let virt_buf = sys_dma_alloc(handle.0, MAX_FRAME_LEN, 64, &mut phys_buf);
            assert!(virt_buf > 0);
            let d = &mut *desc.add(i);
            d.addr  = phys_buf;
            d.len   = MAX_FRAME_LEN as u32;
            d.flags = 0x0002; // VIRTQ_DESC_F_WRITE (device writes into it)
            d.next  = 0;
            (*avail).ring[i] = i as u16;
            rx_bufs.push((virt_buf as *mut u8, phys_buf));
        }
        (*avail).idx = QUEUE_SIZE;

        (desc, avail, used, rx_bufs)
    }

    unsafe fn setup_tx_queue(
        handle: DriverHandle,
        base: *mut u8,
    ) -> (*mut VirtqDesc, *mut VirtqAvail, *mut VirtqUsed, VecDeque<u16>) {
        mmio_write32(base, VIRTIO_MMIO_QUEUE_SEL, TX_QUEUE_IDX);
        mmio_write32(base, VIRTIO_MMIO_QUEUE_NUM, QUEUE_SIZE as u32);

        let desc_size  = core::mem::size_of::<VirtqDesc>()  * QUEUE_SIZE as usize;
        let avail_size = core::mem::size_of::<VirtqAvail>();
        let used_size  = core::mem::size_of::<VirtqUsed>();

        let mut phys_desc: u64 = 0;
        let virt_desc = sys_dma_alloc(handle.0, desc_size, 4096, &mut phys_desc);
        let mut phys_avail: u64 = 0;
        let virt_avail = sys_dma_alloc(handle.0, avail_size, 2, &mut phys_avail);
        let mut phys_used: u64 = 0;
        let virt_used = sys_dma_alloc(handle.0, used_size, 4, &mut phys_used);

        mmio_write64(base, VIRTIO_MMIO_QUEUE_DESC,  phys_desc);
        mmio_write64(base, VIRTIO_MMIO_QUEUE_AVAIL, phys_avail);
        mmio_write64(base, VIRTIO_MMIO_QUEUE_USED,  phys_used);
        mmio_write32(base, VIRTIO_MMIO_QUEUE_READY, 1);

        let desc  = virt_desc  as *mut VirtqDesc;
        let avail = virt_avail as *mut VirtqAvail;
        let used  = virt_used  as *mut VirtqUsed;

        let tx_free: VecDeque<u16> = (0..QUEUE_SIZE).collect();
        (desc, avail, used, tx_free)
    }

    unsafe fn handle_irq(&mut self) {
        // Acknowledge the interrupt in the device.
        let status = mmio_read32(self.mmio_base, VIRTIO_MMIO_INT_STATUS);
        mmio_write32(self.mmio_base, VIRTIO_MMIO_INT_ACK, status);

        if status & 1 != 0 {
            // Virtqueue interrupt: process RX used ring.
            self.drain_rx();
            // Reclaim TX used descriptors.
            self.reclaim_tx();
        }

        // ACK the IRQ to the kernel (unmask at interrupt controller).
        sys_irq_ack(self.handle.0, self.irq);
    }

    unsafe fn drain_rx(&mut self) {
        let used = &*self.rx_used;
        while self.rx_last_used != used.idx {
            let idx  = (self.rx_last_used % QUEUE_SIZE) as usize;
            let elem = &used.ring[idx];
            let desc_idx = elem.id as usize;
            let len = elem.len as usize;

            let (virt_buf, _) = self.rx_bufs[desc_idx];
            let frame = core::slice::from_raw_parts(virt_buf, len.min(MAX_FRAME_LEN));
            self.rx_pending.push_back(frame.to_vec());

            // Recycle the descriptor back to the avail ring.
            let avail = &mut *self.rx_avail;
            let next_avail = avail.idx % QUEUE_SIZE;
            avail.ring[next_avail as usize] = desc_idx as u16;
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            avail.idx = avail.idx.wrapping_add(1);

            self.rx_last_used = self.rx_last_used.wrapping_add(1);
        }
        mmio_write32(self.mmio_base, VIRTIO_MMIO_QUEUE_NOTIFY, RX_QUEUE_IDX);
    }

    unsafe fn reclaim_tx(&mut self) {
        let used = &*self.tx_used;
        let mut last = self.tx_free.len() as u16; // proxy for last_used_tx
        // Iterate over newly used TX descriptors and return them to the free pool.
        // (We keep a simple linear scan here; a shadow index avoids redundant work.)
        let total_used = used.idx;
        for i in 0..total_used {
            let elem = &used.ring[(i % QUEUE_SIZE) as usize];
            if !self.tx_free.contains(&(elem.id as u16)) {
                self.tx_free.push_back(elem.id as u16);
            }
        }
    }

    /// Decode one `SchemeRequest` from `buf` and return the encoded response.
    unsafe fn handle_scheme_request(&mut self, buf: &[u8]) -> Vec<u8> {
        // Decode tag.
        let Some((&tag, rest)) = buf.split_first() else {
            return encode_err(SchemeError::InvalidArg);
        };

        match tag {
            // open: tag(1) | flags(4) | path_len(4) | path_bytes
            1 => {
                if rest.len() < 8 { return encode_err(SchemeError::InvalidArg); }
                let _flags = u32::from_le_bytes(rest[..4].try_into().unwrap());
                let path_len = u32::from_le_bytes(rest[4..8].try_into().unwrap()) as usize;
                let path_bytes = &rest[8..8 + path_len];
                let path = core::str::from_utf8(path_bytes)
                    .unwrap_or("");
                // We expose a single interface: "eth0".
                if path == "eth0" || path.is_empty() {
                    // SchemeFileId = 1 (only one interface).
                    encode_fd(1)
                } else {
                    encode_err(SchemeError::NotFound)
                }
            }
            // read: tag(1) | fd(8) | len(8)
            2 => {
                let _fd = u64::from_le_bytes(rest[..8].try_into().unwrap_or([0;8]));
                if let Some(frame) = self.rx_pending.pop_front() {
                    encode_data(&frame)
                } else {
                    encode_err(SchemeError::WouldBlock)
                }
            }
            // write: tag(1) | fd(8) | data_len(4) | data
            3 => {
                let _fd   = u64::from_le_bytes(rest[..8].try_into().unwrap_or([0;8]));
                let dlen  = u32::from_le_bytes(rest[8..12].try_into().unwrap_or([0;4])) as usize;
                let data  = &rest[12..12 + dlen];
                let n = self.transmit(data);
                encode_count(n)
            }
            // close
            6 => encode_ok(),
            _ => encode_err(SchemeError::InvalidArg),
        }
    }

    unsafe fn transmit(&mut self, data: &[u8]) -> usize {
        let Some(desc_idx) = self.tx_free.pop_front() else {
            return 0; // no free descriptors
        };

        // Allocate a temporary DMA buffer for this frame.
        // (In production you would use pre-allocated TX buffers.)
        let mut phys: u64 = 0;
        let virt = sys_dma_alloc(self.handle.0, MAX_FRAME_LEN, 64, &mut phys);
        if virt <= 0 { self.tx_free.push_front(desc_idx); return 0; }

        let n = data.len().min(MAX_FRAME_LEN);
        core::ptr::copy_nonoverlapping(data.as_ptr(), virt as *mut u8, n);

        let d = &mut *self.tx_desc.add(desc_idx as usize);
        d.addr  = phys;
        d.len   = n as u32;
        d.flags = 0;
        d.next  = 0;

        let avail = &mut *self.tx_avail;
        let slot = avail.idx % QUEUE_SIZE;
        avail.ring[slot as usize] = desc_idx;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        avail.idx = avail.idx.wrapping_add(1);

        mmio_write32(self.mmio_base, VIRTIO_MMIO_QUEUE_NOTIFY, TX_QUEUE_IDX);
        n
    }
}

/// Virtio-net PCI BDF used in QEMU: bus=0, dev=3, func=0  →  0x000300
const VIRTIO_NET_BDF: u32 = 0x0003_00;
/// IRQ line assigned by QEMU to the first virtio-net device.
const VIRTIO_NET_IRQ: u32 = 10;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    unsafe {
        // 1. Claim the PCI device.
        let h = sys_driver_bind(VIRTIO_NET_BDF, 0);
        assert!(h > 0, "sys_driver_bind failed: {}", h);
        let handle = DriverHandle(h as u64);

        // 2. The kernel mapped the MMIO BAR into our address space during
        //    sys_driver_bind.  For QEMU virtio-mmio the canonical base is
        //    0xa000_0000; adjust if your QEMU args differ.
        let mmio_base = 0xa000_0000usize as *mut u8;

        // 3. Initialise the device and virtqueues.
        let mut drv = NetDriver::init(mmio_base, handle, VIRTIO_NET_IRQ);

        // 4. Subscribe to the device IRQ.
        let r = sys_irq_subscribe(handle.0, VIRTIO_NET_IRQ, drv.endpoint.0);
        assert_eq!(r, 0, "sys_irq_subscribe failed");

        // 5. Register the "net" scheme.
        let name = b"net";
        let r = sys_scheme_register(name.as_ptr(), name.len(), drv.endpoint.0);
        assert_eq!(r, 0, "sys_scheme_register failed");

        // 6. Event loop: drain IPC messages (scheme requests + IRQ notifications).
        let mut msg_buf = [0u8; 4096];
        loop {
            let n = sys_ipc_recv(drv.endpoint.0, msg_buf.as_mut_ptr(), msg_buf.len());
            if n < 0 { continue; }
            let msg = &msg_buf[..n as usize];

            // Distinguish IRQ notification (first byte == 0xFF) from
            // scheme request (first byte < 0x80).
            if msg.first() == Some(&0xFF) {
                drv.handle_irq();
            } else {
                let resp = drv.handle_scheme_request(msg);
                sys_ipc_send(drv.endpoint.0, resp.as_ptr(), resp.len());
            }
        }
    }
}

unsafe fn mmio_read32(base: *mut u8, offset: usize) -> u32 {
    let ptr = base.add(offset) as *const u32;
    core::ptr::read_volatile(ptr)
}
unsafe fn mmio_write32(base: *mut u8, offset: usize, val: u32) {
    let ptr = base.add(offset) as *mut u32;
    core::ptr::write_volatile(ptr, val);
}
unsafe fn mmio_write64(base: *mut u8, offset: usize, val: u64) {
    let ptr = base.add(offset) as *mut u64;
    core::ptr::write_volatile(ptr, val);
}

fn encode_fd(id: u64) -> Vec<u8> {
    let mut v = vec![0x80u8];
    v.extend_from_slice(&id.to_le_bytes());
    v
}
fn encode_data(data: &[u8]) -> Vec<u8> {
    let mut v = vec![0x81u8];
    v.extend_from_slice(data);
    v
}
fn encode_count(n: usize) -> Vec<u8> {
    let mut v = vec![0x82u8];
    v.extend_from_slice(&(n as u64).to_le_bytes());
    v
}
fn encode_ok() -> Vec<u8> { vec![0x84] }
fn encode_err(e: SchemeError) -> Vec<u8> {
    let mut v = vec![0xFFu8];
    v.extend_from_slice(&(e as u32).to_le_bytes());
    v
}

// Panic handler required for no_std binaries.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    // In a real build, log to kernel serial console then exit.
    unsafe { sys_exit(1) }
}
