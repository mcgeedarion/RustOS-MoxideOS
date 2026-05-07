//! VirtIO GPU driver (virtio-gpu, device ID 0x1050, vendor 0x1AF4).
//!
//! ## Spec references
//!   - VirtIO 1.2 §5.7 (GPU device)
//!   - VirtIO legacy PCI transport (device ID 0x1010 + type offset)
//!     QEMU exposes virtio-gpu-pci as legacy ID 0x1050 or modern ID 0x1040+16=0x1050
//!
//! ## What this driver does
//!   1. PCI scan — finds virtio-gpu on bus 0
//!   2. Virtqueue setup — two queues:
//!        q0 (controlq) — command/response
//!        q1 (cursorq)  — cursor updates (unused for now)
//!   3. RESOURCE_CREATE_2D — allocates a host-side 2-D RGBA8 resource
//!   4. RESOURCE_ATTACH_BACKING — backs the resource with guest RAM pages
//!   5. SET_SCANOUT — wires resource to scanout 0 (the virtual monitor)
//!   6. flush() — TRANSFER_TO_HOST_2D + RESOURCE_FLUSH to push pixels
//!
//! ## Pixel format
//!   VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM (1) — matches QEMU default.
//!   The guest framebuffer is a plain `u32` per pixel in BGRX order
//!   (byte 0 = B, byte 1 = G, byte 2 = R, byte 3 = unused/0xFF).
//!   This also matches the GOP/DRM convention already used in `gop.rs`.
//!
//! ## Memory
//!   The pixel buffer is a contiguous region allocated from the PMM
//!   (width × height × 4 bytes, page-rounded).
//!   PA == VA (identity map), so host DMA addresses equal kernel pointers.
//!
//! ## Exposed API
//!   init()                      — scan + init; no-op if not found
//!   is_present() -> bool
//!   dimensions() -> Option<(u32,u32)>
//!   fb_phys()  -> Option<u64>   — physical (= virtual) address of pixel buf
//!   flush(x,y,w,h)              — push a dirty rectangle to the display
//!   flush_all()                 — flush the entire framebuffer

extern crate alloc;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

// ─────────────────────────────────────────────────────────────────────────────
// PCI helpers  (identical pattern to virtio_blk.rs)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
mod pci {
    #[inline]
    pub fn read32(bus: u8, dev: u8, func: u8, offset: u8) -> u32 {
        let addr: u32 = 0x8000_0000
            | ((bus  as u32) << 16)
            | ((dev  as u32) << 11)
            | ((func as u32) <<  8)
            | (offset as u32 & 0xFC);
        unsafe {
            core::arch::asm!("out dx, eax",
                in("dx") 0xCF8u16, in("eax") addr, options(nostack));
            let mut v: u32;
            core::arch::asm!("in eax, dx",
                in("dx") 0xCFCu16, out("eax") v, options(nostack));
            v
        }
    }
    pub fn read16(bus: u8, dev: u8, func: u8, offset: u8) -> u16 {
        let d = read32(bus, dev, func, offset & 0xFC);
        if offset & 2 != 0 { (d >> 16) as u16 } else { d as u16 }
    }
    pub fn bar0_io(bus: u8, dev: u8) -> u16 {
        (read32(bus, dev, 0, 0x10) & !0x3) as u16
    }
    pub fn enable(bus: u8, dev: u8) {
        let cmd = read16(bus, dev, 0, 0x04) | 0x05;
        let addr: u32 = 0x8000_0000 | ((bus as u32)<<16) | ((dev as u32)<<11) | 0x04;
        unsafe {
            core::arch::asm!("out dx, eax",
                in("dx") 0xCF8u16, in("eax") addr, options(nostack));
            core::arch::asm!("out dx, ax",
                in("dx") 0xCFCu16, in("ax") cmd, options(nostack));
        }
    }
}

// On RISC-V virtio-gpu is accessed via MMIO (not PCI port-IO).
// Provide stub scan that always returns "not found" so the code compiles
// on riscv64; a real MMIO path would be wired through ACPI/DT discovery.
#[cfg(not(target_arch = "x86_64"))]
mod pci {
    pub fn read32(_: u8, _: u8, _: u8, _: u8) -> u32 { 0xFFFF_FFFF }
    pub fn read16(_: u8, _: u8, _: u8, _: u8) -> u16 { 0xFFFF }
    pub fn bar0_io(_: u8, _: u8) -> u16 { 0 }
    pub fn enable(_: u8, _: u8) {}
}

// ─────────────────────────────────────────────────────────────────────────────
// VirtIO legacy register layout  (same as virtio_blk.rs)
// ─────────────────────────────────────────────────────────────────────────────

const VTIO_DEVICE_FEATURES: u16 = 0x00;
const VTIO_GUEST_FEATURES:  u16 = 0x04;
const VTIO_QUEUE_PFN:       u16 = 0x08;
const VTIO_QUEUE_SIZE:      u16 = 0x0C;
const VTIO_QUEUE_SELECT:    u16 = 0x0E;
const VTIO_QUEUE_NOTIFY:    u16 = 0x10;
const VTIO_DEVICE_STATUS:   u16 = 0x12;

const VTIO_STATUS_ACK:        u8 = 1;
const VTIO_STATUS_DRIVER:     u8 = 2;
const VTIO_STATUS_DRIVER_OK:  u8 = 4;

#[cfg(target_arch = "x86_64")]
mod io {
    #[inline] pub unsafe fn rb(base: u16, off: u16) -> u8 {
        let mut v: u8;
        core::arch::asm!("in al, dx",  in("dx") base+off, out("al") v,  options(nostack)); v
    }
    #[inline] pub unsafe fn rw(base: u16, off: u16) -> u16 {
        let mut v: u16;
        core::arch::asm!("in ax, dx",  in("dx") base+off, out("ax") v,  options(nostack)); v
    }
    #[inline] pub unsafe fn rl(base: u16, off: u16) -> u32 {
        let mut v: u32;
        core::arch::asm!("in eax, dx", in("dx") base+off, out("eax") v, options(nostack)); v
    }
    #[inline] pub unsafe fn wb(base: u16, off: u16, v: u8)  {
        core::arch::asm!("out dx, al",  in("dx") base+off, in("al")  v, options(nostack));
    }
    #[inline] pub unsafe fn ww(base: u16, off: u16, v: u16) {
        core::arch::asm!("out dx, ax",  in("dx") base+off, in("ax")  v, options(nostack));
    }
    #[inline] pub unsafe fn wl(base: u16, off: u16, v: u32) {
        core::arch::asm!("out dx, eax", in("dx") base+off, in("eax") v, options(nostack));
    }
}
#[cfg(not(target_arch = "x86_64"))]
mod io {
    pub unsafe fn rb(_:u16,_:u16)->u8{0} pub unsafe fn rw(_:u16,_:u16)->u16{0}
    pub unsafe fn rl(_:u16,_:u16)->u32{0} pub unsafe fn wb(_:u16,_:u16,_:u8){}
    pub unsafe fn ww(_:u16,_:u16,_:u16){} pub unsafe fn wl(_:u16,_:u16,_:u32){}
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtqueue layout
// ─────────────────────────────────────────────────────────────────────────────

const QUEUE_SIZE: usize = 64;
const DESC_SIZE:  usize = 16;
const AVAIL_OFF:  usize = QUEUE_SIZE * DESC_SIZE;
const AVAIL_SIZE: usize = 6 + QUEUE_SIZE * 2;
const USED_OFF:   usize = (AVAIL_OFF + AVAIL_SIZE + 4095) & !4095;
const QUEUE_BYTES: usize = USED_OFF + 6 + QUEUE_SIZE * 8;
const QUEUE_PAGES: usize = (QUEUE_BYTES + 4095) / 4096;

const VRING_DESC_F_NEXT:  u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

// ─────────────────────────────────────────────────────────────────────────────
// VirtIO-GPU command / response structures  (VirtIO 1.2 §5.7.6)
// ─────────────────────────────────────────────────────────────────────────────

/// Shared command/response header.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct GpuCtrlHdr {
    hdr_type: u32,
    flags:    u32,
    fence_id: u64,
    ctx_id:   u32,
    _padding: u32,
}

// Command types.
const VIRTIO_GPU_CMD_GET_DISPLAY_INFO:    u32 = 0x0100;
const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const VIRTIO_GPU_CMD_RESOURCE_UNREF:     u32 = 0x0102;
const VIRTIO_GPU_CMD_SET_SCANOUT:        u32 = 0x0103;
const VIRTIO_GPU_CMD_RESOURCE_FLUSH:     u32 = 0x0104;
const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:u32 = 0x0105;
const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const VIRTIO_GPU_RESP_OK_NODATA:         u32 = 0x1100;
const VIRTIO_GPU_RESP_OK_DISPLAY_INFO:   u32 = 0x1101;

// Pixel format — BGRX 32-bit (same as GOP default).
const VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM: u32 = 1;

/// VIRTIO_GPU_CMD_RESOURCE_CREATE_2D payload.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct GpuResourceCreate2d {
    hdr:         GpuCtrlHdr,
    resource_id: u32,
    format:      u32,
    width:       u32,
    height:      u32,
}

/// One entry in VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct GpuMemEntry {
    addr:    u64,
    length:  u32,
    padding: u32,
}

/// VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING payload.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct GpuAttachBacking {
    hdr:         GpuCtrlHdr,
    resource_id: u32,
    nr_entries:  u32,
    // Followed immediately by nr_entries × GpuMemEntry in memory.
    // We embed one entry here for the single-contiguous-buffer case.
    entry:       GpuMemEntry,
}

/// Rect used in set_scanout, transfer, flush.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct GpuRect {
    x: u32, y: u32, width: u32, height: u32,
}

/// VIRTIO_GPU_CMD_SET_SCANOUT.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct GpuSetScanout {
    hdr:         GpuCtrlHdr,
    r:           GpuRect,
    scanout_id:  u32,
    resource_id: u32,
}

/// VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct GpuTransferToHost2d {
    hdr:         GpuCtrlHdr,
    r:           GpuRect,
    offset:      u64,
    resource_id: u32,
    padding:     u32,
}

/// VIRTIO_GPU_CMD_RESOURCE_FLUSH.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct GpuResourceFlush {
    hdr:         GpuCtrlHdr,
    r:           GpuRect,
    resource_id: u32,
    padding:     u32,
}

/// VIRTIO_GPU_CMD_GET_DISPLAY_INFO response.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct GpuDisplayOne {
    r:       GpuRect,
    enabled: u32,
    flags:   u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct GpuRespDisplayInfo {
    hdr:      GpuCtrlHdr,
    pmodes:   [GpuDisplayOne; 16],
}

// ─────────────────────────────────────────────────────────────────────────────
// Driver state
// ─────────────────────────────────────────────────────────────────────────────

/// The resource ID we assign to our single 2-D surface.
const RESOURCE_ID: u32 = 1;
/// Default resolution — used when GET_DISPLAY_INFO gives nothing useful.
const DEFAULT_W: u32 = 1280;
const DEFAULT_H: u32 = 720;

struct GpuDev {
    io_base:    u16,
    q0_va:      usize,   // controlq ring
    q0_last:    u16,     // last used-ring index consumed on q0
    fb_va:      usize,   // kernel VA of pixel buffer
    fb_pages:   usize,   // number of 4096-byte pages in pixel buffer
    width:      u32,
    height:     u32,
}

static DEV:     Mutex<Option<GpuDev>> = Mutex::new(None);
static PRESENT: AtomicBool            = AtomicBool::new(false);

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Scan PCI bus for virtio-gpu and initialise it.  No-op if not found.
pub fn init() {
    const VENDOR: u16 = 0x1AF4;
    // Legacy virtio-gpu device ID: 0x1040 + GPU_TYPE(16) = 0x1050
    const DEV_ID: u16 = 0x1050;

    let mut found_bus = 0u8;
    let mut found_dev = 0u8;
    let mut found = false;

    'outer: for bus in 0u8..=1 {
        for dev in 0u8..32 {
            let id = pci::read32(bus, dev, 0, 0);
            if id == 0xFFFF_FFFF { continue; }
            let vendor = id as u16;
            let device = (id >> 16) as u16;
            if vendor == VENDOR && device == DEV_ID {
                found_bus = bus;
                found_dev = dev;
                found = true;
                break 'outer;
            }
        }
    }
    if !found { return; }

    pci::enable(found_bus, found_dev);
    let io_base = pci::bar0_io(found_bus, found_dev);
    if io_base == 0 { return; }

    unsafe { init_device(io_base) };
}

pub fn is_present() -> bool { PRESENT.load(Ordering::Acquire) }

/// Returns `(width, height)` of the initialised framebuffer, if any.
pub fn dimensions() -> Option<(u32, u32)> {
    DEV.lock().as_ref().map(|d| (d.width, d.height))
}

/// Physical (= virtual, identity-mapped) address of the pixel buffer.
/// Pixel format: BGRX u32 per pixel, row-major.
pub fn fb_phys() -> Option<u64> {
    DEV.lock().as_ref().map(|d| d.fb_va as u64)
}

/// Push a dirty rectangle [x, y, x+w, y+h) to the QEMU display.
/// Sends TRANSFER_TO_HOST_2D followed by RESOURCE_FLUSH.
pub fn flush(x: u32, y: u32, w: u32, h: u32) {
    let mut guard = DEV.lock();
    let dev = match guard.as_mut() { Some(d) => d, None => return };
    unsafe {
        gpu_transfer_to_host_2d(dev, x, y, w, h);
        gpu_resource_flush(dev, x, y, w, h);
    }
}

/// Push the entire framebuffer to the QEMU display.
pub fn flush_all() {
    let (w, h) = match dimensions() { Some(d) => d, None => return };
    flush(0, 0, w, h);
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialisation
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn init_device(io_base: u16) {
    use io::*;

    // 1. Reset.
    wb(io_base, VTIO_DEVICE_STATUS, 0);

    // 2. ACKNOWLEDGE + DRIVER.
    wb(io_base, VTIO_DEVICE_STATUS, VTIO_STATUS_ACK);
    wb(io_base, VTIO_DEVICE_STATUS, VTIO_STATUS_ACK | VTIO_STATUS_DRIVER);

    // 3. Feature negotiation — accept all device features.
    let dev_feat = rl(io_base, VTIO_DEVICE_FEATURES);
    wl(io_base, VTIO_GUEST_FEATURES, dev_feat);

    // 4. Set up controlq (queue 0).
    let q0_va = match alloc_queue_pages() { Some(p) => p, None => return };
    ww(io_base, VTIO_QUEUE_SELECT, 0);
    let _qsz = rw(io_base, VTIO_QUEUE_SIZE);
    wl(io_base, VTIO_QUEUE_PFN, (q0_va as u32) >> 12);

    // 5. Set up cursorq (queue 1) — minimal setup, we won't use it.
    let q1_va = match alloc_queue_pages() { Some(p) => p, None => return };
    ww(io_base, VTIO_QUEUE_SELECT, 1);
    wl(io_base, VTIO_QUEUE_PFN, (q1_va as u32) >> 12);

    // 6. DRIVER_OK.
    wb(io_base, VTIO_DEVICE_STATUS,
       VTIO_STATUS_ACK | VTIO_STATUS_DRIVER | VTIO_STATUS_DRIVER_OK);

    // 7. Build a temporary GpuDev so we can issue the display-info query.
    let mut dev = GpuDev {
        io_base,
        q0_va,
        q0_last: 0,
        fb_va:   0,
        fb_pages: 0,
        width:   DEFAULT_W,
        height:  DEFAULT_H,
    };

    // 8. GET_DISPLAY_INFO to discover the preferred resolution.
    query_display_info(&mut dev);

    // 9. Allocate the pixel framebuffer (width × height × 4 bytes).
    let fb_bytes = dev.width as usize * dev.height as usize * 4;
    let fb_pages = (fb_bytes + 4095) / 4096;
    let mut fb_va: usize = 0;
    for i in 0..fb_pages {
        let page = match crate::mm::pmm::alloc_page() {
            Some(p) => p,
            None    => return,
        };
        if i == 0 { fb_va = page; }
        // Zero-fill each page (black screen).
        core::ptr::write_bytes(page as *mut u8, 0, 4096);
    }
    dev.fb_va    = fb_va;
    dev.fb_pages = fb_pages;

    // 10. RESOURCE_CREATE_2D.
    gpu_resource_create_2d(&mut dev);

    // 11. RESOURCE_ATTACH_BACKING.
    gpu_resource_attach_backing(&mut dev);

    // 12. SET_SCANOUT — wire resource to the virtual monitor.
    gpu_set_scanout(&mut dev);

    // 13. Initial flush — display the (currently black) framebuffer.
    gpu_transfer_to_host_2d(&mut dev, 0, 0, dev.width, dev.height);
    gpu_resource_flush(&mut dev, 0, 0, dev.width, dev.height);

    // 14. Register driver state.
    *DEV.lock() = Some(dev);
    PRESENT.store(true, Ordering::Release);
}

/// Allocate QUEUE_PAGES pages for one virtqueue ring.
unsafe fn alloc_queue_pages() -> Option<usize> {
    let first = crate::mm::pmm::alloc_page()?;
    core::ptr::write_bytes(first as *mut u8, 0, 4096);
    for _ in 1..QUEUE_PAGES {
        let p = crate::mm::pmm::alloc_page()?;
        core::ptr::write_bytes(p as *mut u8, 0, 4096);
    }
    Some(first)
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtqueue helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Write a 16-byte descriptor at slot `idx`.
unsafe fn write_desc(q_va: usize, idx: usize,
                     addr: u64, len: u32, flags: u16, next: u16) {
    let p = (q_va + idx * DESC_SIZE) as *mut u64;
    p.add(0).write_volatile(addr);
    (p as *mut u32).add(2).write_volatile(len);
    (p as *mut u16).add(6).write_volatile(flags);
    (p as *mut u16).add(7).write_volatile(next);
}

/// Place one command+response pair onto controlq and wait for completion.
/// cmd_buf  — driver-to-device (device-readable)
/// resp_buf — device-to-driver (device-writable)
unsafe fn submit_controlq(dev: &mut GpuDev, cmd: *const u8, cmd_len: u32,
                           resp: *mut u8, resp_len: u32) {
    let qva    = dev.q0_va;
    let notify = dev.io_base;

    // Descriptor 0: command (device-readable)
    write_desc(qva, 0, cmd  as u64, cmd_len,  VRING_DESC_F_NEXT, 1);
    // Descriptor 1: response (device-writable)
    write_desc(qva, 1, resp as u64, resp_len, VRING_DESC_F_WRITE, 0);

    // Post to available ring.
    let avail = (qva + AVAIL_OFF) as *mut u16;
    avail.add(0).write_volatile(0);                          // flags = 0
    let old_idx = avail.add(1).read_volatile();
    avail.add(2 + (old_idx as usize % QUEUE_SIZE)).write_volatile(0); // ring[tail] = desc 0
    core::sync::atomic::fence(Ordering::SeqCst);
    avail.add(1).write_volatile(old_idx.wrapping_add(1));
    core::sync::atomic::fence(Ordering::SeqCst);

    // Kick queue 0.
    io::ww(notify, VTIO_QUEUE_NOTIFY, 0);

    // Spin-poll used ring.
    let used_idx_ptr = (qva + USED_OFF + 2) as *const u16;
    let mut spins = 0usize;
    loop {
        core::sync::atomic::fence(Ordering::Acquire);
        if used_idx_ptr.read_volatile() != dev.q0_last { break; }
        spins += 1;
        if spins > 20_000_000 { return; } // give up — device hung
        core::hint::spin_loop();
    }
    dev.q0_last = dev.q0_last.wrapping_add(1);
}

// ─────────────────────────────────────────────────────────────────────────────
// GPU command helpers
// ─────────────────────────────────────────────────────────────────────────────

unsafe fn query_display_info(dev: &mut GpuDev) {
    let cmd  = GpuCtrlHdr { hdr_type: VIRTIO_GPU_CMD_GET_DISPLAY_INFO, ..Default::default() };
    let mut resp: GpuRespDisplayInfo = Default::default();
    submit_controlq(
        dev,
        &cmd  as *const _ as *const u8, core::mem::size_of::<GpuCtrlHdr>()  as u32,
        &mut resp as *mut _ as *mut u8, core::mem::size_of::<GpuRespDisplayInfo>() as u32,
    );
    if resp.hdr.hdr_type == VIRTIO_GPU_RESP_OK_DISPLAY_INFO {
        let m = &resp.pmodes[0];
        if m.enabled != 0 && m.r.width > 0 && m.r.height > 0 {
            dev.width  = m.r.width;
            dev.height = m.r.height;
        }
    }
}

unsafe fn gpu_resource_create_2d(dev: &mut GpuDev) {
    let cmd = GpuResourceCreate2d {
        hdr:         GpuCtrlHdr { hdr_type: VIRTIO_GPU_CMD_RESOURCE_CREATE_2D, ..Default::default() },
        resource_id: RESOURCE_ID,
        format:      VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM,
        width:       dev.width,
        height:      dev.height,
    };
    let mut resp: GpuCtrlHdr = Default::default();
    submit_controlq(
        dev,
        &cmd  as *const _ as *const u8, core::mem::size_of::<GpuResourceCreate2d>() as u32,
        &mut resp as *mut _ as *mut u8, core::mem::size_of::<GpuCtrlHdr>() as u32,
    );
}

unsafe fn gpu_resource_attach_backing(dev: &mut GpuDev) {
    let fb_bytes = dev.width as u64 * dev.height as u64 * 4;
    let cmd = GpuAttachBacking {
        hdr:         GpuCtrlHdr { hdr_type: VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING, ..Default::default() },
        resource_id: RESOURCE_ID,
        nr_entries:  1,
        entry:       GpuMemEntry { addr: dev.fb_va as u64, length: fb_bytes as u32, padding: 0 },
    };
    let mut resp: GpuCtrlHdr = Default::default();
    submit_controlq(
        dev,
        &cmd  as *const _ as *const u8, core::mem::size_of::<GpuAttachBacking>() as u32,
        &mut resp as *mut _ as *mut u8, core::mem::size_of::<GpuCtrlHdr>() as u32,
    );
}

unsafe fn gpu_set_scanout(dev: &mut GpuDev) {
    let cmd = GpuSetScanout {
        hdr:         GpuCtrlHdr { hdr_type: VIRTIO_GPU_CMD_SET_SCANOUT, ..Default::default() },
        r:           GpuRect { x: 0, y: 0, width: dev.width, height: dev.height },
        scanout_id:  0,
        resource_id: RESOURCE_ID,
    };
    let mut resp: GpuCtrlHdr = Default::default();
    submit_controlq(
        dev,
        &cmd  as *const _ as *const u8, core::mem::size_of::<GpuSetScanout>() as u32,
        &mut resp as *mut _ as *mut u8, core::mem::size_of::<GpuCtrlHdr>() as u32,
    );
}

unsafe fn gpu_transfer_to_host_2d(dev: &mut GpuDev, x: u32, y: u32, w: u32, h: u32) {
    let offset = (y as u64 * dev.width as u64 + x as u64) * 4;
    let cmd = GpuTransferToHost2d {
        hdr:         GpuCtrlHdr { hdr_type: VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D, ..Default::default() },
        r:           GpuRect { x, y, width: w, height: h },
        offset,
        resource_id: RESOURCE_ID,
        padding:     0,
    };
    let mut resp: GpuCtrlHdr = Default::default();
    submit_controlq(
        dev,
        &cmd  as *const _ as *const u8, core::mem::size_of::<GpuTransferToHost2d>() as u32,
        &mut resp as *mut _ as *mut u8, core::mem::size_of::<GpuCtrlHdr>() as u32,
    );
}

unsafe fn gpu_resource_flush(dev: &mut GpuDev, x: u32, y: u32, w: u32, h: u32) {
    let cmd = GpuResourceFlush {
        hdr:         GpuCtrlHdr { hdr_type: VIRTIO_GPU_CMD_RESOURCE_FLUSH, ..Default::default() },
        r:           GpuRect { x, y, width: w, height: h },
        resource_id: RESOURCE_ID,
        padding:     0,
    };
    let mut resp: GpuCtrlHdr = Default::default();
    submit_controlq(
        dev,
        &cmd  as *const _ as *const u8, core::mem::size_of::<GpuResourceFlush>() as u32,
        &mut resp as *mut _ as *mut u8, core::mem::size_of::<GpuCtrlHdr>() as u32,
    );
}
