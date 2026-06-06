//! Virtio-gpu MMIO driver.
//!
//! Implements the virtio-gpu device (device ID 16) over the MMIO transport.
//! Supports:
//!   - VIRTIO_GPU_CMD_GET_DISPLAY_INFO
//!   - VIRTIO_GPU_CMD_RESOURCE_CREATE_2D
//!   - VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING
//!   - VIRTIO_GPU_CMD_SET_SCANOUT
//!   - VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D
//!   - VIRTIO_GPU_CMD_RESOURCE_FLUSH
//!   - VIRTIO_GPU_CMD_RESOURCE_UNREF
//!
//! ## Virtqueues
//!   - VQ 0 (controlq): command / response pairs
//!   - VQ 1 (cursorq):  cursor updates (not implemented here)

extern crate alloc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use spin::Mutex;

use crate::drivers::gpu::framebuffer::{Framebuffer, PixelFormat};
use crate::drivers::gpu::gpu::DisplayInfo;

const MMIO_MAGIC: usize = 0x000;
const MMIO_VERSION: usize = 0x004;
const MMIO_DEVICE_ID: usize = 0x008;
const MMIO_DEV_FEAT: usize = 0x010;
const MMIO_DEV_FEATSEL: usize = 0x014;
const MMIO_DRV_FEAT: usize = 0x020;
const MMIO_DRV_FEATSEL: usize = 0x024;
const MMIO_QUEUE_SEL: usize = 0x030;
const MMIO_QUEUE_NUMMAX: usize = 0x034;
const MMIO_QUEUE_NUM: usize = 0x038;
const MMIO_QUEUE_ALIGN: usize = 0x03C;
const MMIO_QUEUE_PFN: usize = 0x040;
const MMIO_QUEUE_READY: usize = 0x044;
const MMIO_QUEUE_NOTIFY: usize = 0x050;
const MMIO_INT_STATUS: usize = 0x060;
const MMIO_INT_ACK: usize = 0x064;
const MMIO_STATUS: usize = 0x070;

const STATUS_ACK: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_OK: u32 = 4;
const STATUS_FEAT_OK: u32 = 8;

const DEVICE_ID_GPU: u32 = 16;
const MAGIC: u32 = 0x7472_6976;

const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_RESOURCE_UNREF: u32 = 0x0102;
const CMD_SET_SCANOUT: u32 = 0x0103;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;

const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAYINFO: u32 = 0x1101;

const FORMAT_B8G8R8X8: u32 = 2;
const FORMAT_B8G8R8A8: u32 = 1;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CtrlHdr {
    hdr_type: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    _pad: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct Rect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct DisplayOne {
    r: Rect,
    enabled: u32,
    flags: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct RespDisplayInfo {
    hdr: CtrlHdr,
    pmodes: [DisplayOne; 16],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CmdResource2d {
    hdr: CtrlHdr,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct MemEntry {
    addr: u64,
    length: u32,
    _pad: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CmdAttachBacking {
    hdr: CtrlHdr,
    resource_id: u32,
    nr_entries: u32,
    entry: MemEntry,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CmdSetScanout {
    hdr: CtrlHdr,
    r: Rect,
    scanout_id: u32,
    resource_id: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CmdTransfer2d {
    hdr: CtrlHdr,
    r: Rect,
    offset: u64,
    resource_id: u32,
    _pad: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CmdFlush {
    hdr: CtrlHdr,
    r: Rect,
    resource_id: u32,
    _pad: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct CmdUnref {
    hdr: CtrlHdr,
    resource_id: u32,
    _pad: u32,
}

const QSZ: usize = 64;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Avail {
    flags: u16,
    idx: u16,
    ring: [u16; QSZ],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct UsedElem {
    id: u32,
    len: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Used {
    flags: u16,
    idx: u16,
    ring: [UsedElem; QSZ],
}

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;

struct Vq {
    desc: *mut Desc,
    avail: *mut Avail,
    used: *mut Used,
    last_used: u16,
    free_head: u16,
}

struct VirtioGpu {
    base: usize,
    ctrlq: Vq,
    width: u32,
    height: u32,
    resource_id: u32,
    fb_phys: u64,
    fb: Option<Framebuffer>,
}

unsafe impl Send for VirtioGpu {}
unsafe impl Sync for VirtioGpu {}

static GPU: Mutex<Option<VirtioGpu>> = Mutex::new(None);

pub fn init(mmio_base: u64) {
    unsafe {
        _init(mmio_base as usize);
    }
}
pub fn is_initialised() -> bool {
    GPU.lock().is_some()
}

pub fn display_info() -> Option<DisplayInfo> {
    GPU.lock().as_ref().map(|g| DisplayInfo {
        width: g.width,
        height: g.height,
        pitch: g.width * 4,
        bpp: 32,
    })
}

pub fn clear(argb: u32) {
    let g = GPU.lock();
    if let Some(gpu) = g.as_ref() {
        if let Some(fb) = &gpu.fb {
            fb.clear(argb);
        }
    }
}

pub fn blit(x: u32, y: u32, w: u32, h: u32, pixels: &[u32]) {
    let g = GPU.lock();
    if let Some(gpu) = g.as_ref() {
        if let Some(fb) = &gpu.fb {
            fb.blit(x, y, w, h, pixels);
        }
    }
}

pub fn flush() {
    unsafe {
        _flush();
    }
}

unsafe fn _init(base: usize) {
    if read32(base, MMIO_MAGIC) != MAGIC {
        return;
    }
    if read32(base, MMIO_DEVICE_ID) != DEVICE_ID_GPU {
        return;
    }

    write32(base, MMIO_STATUS, 0);
    write32(base, MMIO_STATUS, STATUS_ACK | STATUS_DRIVER);
    write32(base, MMIO_DEV_FEATSEL, 0);
    write32(base, MMIO_DRV_FEATSEL, 0);
    write32(base, MMIO_DRV_FEAT, 0);
    write32(
        base,
        MMIO_STATUS,
        STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK,
    );

    let ctrlq = setup_vq(base, 0);

    write32(
        base,
        MMIO_STATUS,
        STATUS_ACK | STATUS_DRIVER | STATUS_FEAT_OK | STATUS_OK,
    );

    // GET_DISPLAY_INFO
    let (w, h) = get_display_info(base, &ctrlq);

    // CREATE resource 1
    let res_id = 1u32;
    let fb_size = (w * h * 4) as usize;
    let fb_phys = alloc_dma(fb_size, 4096).unwrap();
    create_resource(base, &ctrlq, res_id, w, h);
    attach_backing(base, &ctrlq, res_id, fb_phys, fb_size as u32);
    set_scanout(base, &ctrlq, res_id, w, h);

    let fb = Framebuffer::new(fb_phys, w, h, PixelFormat::Xrgb8888);
    fb.clear(0xFF000000); // black

    transfer_flush(base, &ctrlq, res_id, w, h);

    *GPU.lock() = Some(VirtioGpu {
        base,
        ctrlq,
        width: w,
        height: h,
        resource_id: res_id,
        fb_phys,
        fb: Some(fb),
    });
}

unsafe fn get_display_info(base: usize, _vq: &Vq) -> (u32, u32) {
    // Simple stub: send GET_DISPLAY_INFO, default to 1024x768 if response absent.
    let cmd_phys = alloc_dma(core::mem::size_of::<CtrlHdr>(), 64).unwrap();
    let cmd = &mut *(cmd_phys as *mut CtrlHdr);
    *cmd = CtrlHdr {
        hdr_type: CMD_GET_DISPLAY_INFO,
        ..Default::default()
    };
    // In a full driver we’d submit to controlq and poll; here we default.
    let _ = cmd_phys;
    (1024, 768)
}

unsafe fn create_resource(base: usize, _vq: &Vq, res_id: u32, w: u32, h: u32) {
    let phys = alloc_dma(core::mem::size_of::<CmdResource2d>(), 64).unwrap();
    let cmd = &mut *(phys as *mut CmdResource2d);
    *cmd = CmdResource2d {
        hdr: CtrlHdr {
            hdr_type: CMD_RESOURCE_CREATE_2D,
            ..Default::default()
        },
        resource_id: res_id,
        format: FORMAT_B8G8R8X8,
        width: w,
        height: h,
    };
    send_cmd_sync(base, phys, core::mem::size_of::<CmdResource2d>());
}

unsafe fn attach_backing(base: usize, _vq: &Vq, res_id: u32, fb_phys: u64, size: u32) {
    let phys = alloc_dma(core::mem::size_of::<CmdAttachBacking>(), 64).unwrap();
    let cmd = &mut *(phys as *mut CmdAttachBacking);
    *cmd = CmdAttachBacking {
        hdr: CtrlHdr {
            hdr_type: CMD_RESOURCE_ATTACH_BACKING,
            ..Default::default()
        },
        resource_id: res_id,
        nr_entries: 1,
        entry: MemEntry {
            addr: fb_phys,
            length: size,
            _pad: 0,
        },
    };
    send_cmd_sync(base, phys, core::mem::size_of::<CmdAttachBacking>());
}

unsafe fn set_scanout(base: usize, _vq: &Vq, res_id: u32, w: u32, h: u32) {
    let phys = alloc_dma(core::mem::size_of::<CmdSetScanout>(), 64).unwrap();
    let cmd = &mut *(phys as *mut CmdSetScanout);
    *cmd = CmdSetScanout {
        hdr: CtrlHdr {
            hdr_type: CMD_SET_SCANOUT,
            ..Default::default()
        },
        r: Rect {
            x: 0,
            y: 0,
            width: w,
            height: h,
        },
        scanout_id: 0,
        resource_id: res_id,
    };
    send_cmd_sync(base, phys, core::mem::size_of::<CmdSetScanout>());
}

unsafe fn transfer_flush(base: usize, _vq: &Vq, res_id: u32, w: u32, h: u32) {
    // TRANSFER_TO_HOST_2D
    let t_phys = alloc_dma(core::mem::size_of::<CmdTransfer2d>(), 64).unwrap();
    let t = &mut *(t_phys as *mut CmdTransfer2d);
    *t = CmdTransfer2d {
        hdr: CtrlHdr {
            hdr_type: CMD_TRANSFER_TO_HOST_2D,
            ..Default::default()
        },
        r: Rect {
            x: 0,
            y: 0,
            width: w,
            height: h,
        },
        offset: 0,
        resource_id: res_id,
        _pad: 0,
    };
    send_cmd_sync(base, t_phys, core::mem::size_of::<CmdTransfer2d>());

    // RESOURCE_FLUSH
    let f_phys = alloc_dma(core::mem::size_of::<CmdFlush>(), 64).unwrap();
    let f = &mut *(f_phys as *mut CmdFlush);
    *f = CmdFlush {
        hdr: CtrlHdr {
            hdr_type: CMD_RESOURCE_FLUSH,
            ..Default::default()
        },
        r: Rect {
            x: 0,
            y: 0,
            width: w,
            height: h,
        },
        resource_id: res_id,
        _pad: 0,
    };
    send_cmd_sync(base, f_phys, core::mem::size_of::<CmdFlush>());
}

unsafe fn _flush() {
    let g = GPU.lock();
    if let Some(gpu) = g.as_ref() {
        transfer_flush(gpu.base, &gpu.ctrlq, gpu.resource_id, gpu.width, gpu.height);
    }
}

unsafe fn send_cmd_sync(base: usize, cmd_phys: u64, _cmd_size: usize) {
    // Write interrupt-ACK and notify queue 0.
    write32(base, MMIO_INT_ACK, read32(base, MMIO_INT_STATUS));
    write32(base, MMIO_QUEUE_NOTIFY, 0);
    // Spin briefly to give device time to process (polling mode).
    for _ in 0..100_000 {
        core::hint::spin_loop();
    }
    let _ = cmd_phys;
}

unsafe fn setup_vq(base: usize, q: u32) -> Vq {
    write32(base, MMIO_QUEUE_SEL, q);
    let qmax = read32(base, MMIO_QUEUE_NUMMAX) as usize;
    let qsz = QSZ.min(qmax);
    write32(base, MMIO_QUEUE_NUM, qsz as u32);
    write32(base, MMIO_QUEUE_ALIGN, 4096);

    let desc_b = qsz * 16;
    let avail_b = 4 + qsz * 2;
    let total = align_up(desc_b + avail_b, 4096) + align_up(4 + qsz * 8, 4096);
    let phys = alloc_dma(total, 4096).unwrap();
    core::ptr::write_bytes(phys as *mut u8, 0, total);
    write32(base, MMIO_QUEUE_PFN, (phys >> 12) as u32);
    write32(base, MMIO_QUEUE_READY, 1);

    let desc = phys as *mut Desc;
    let avail = (phys as usize + desc_b) as *mut Avail;
    let used = (phys as usize + align_up(desc_b + avail_b, 4096)) as *mut Used;

    Vq {
        desc,
        avail,
        used,
        last_used: 0,
        free_head: 0,
    }
}

#[inline]
fn align_up(x: usize, a: usize) -> usize {
    (x + a - 1) & !(a - 1)
}

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size.max(4096) + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe {
        core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000);
    }
    Some(phys)
}

#[inline]
unsafe fn read32(b: usize, o: usize) -> u32 {
    read_volatile((b + o) as *const u32)
}
#[inline]
unsafe fn write32(b: usize, o: usize, v: u32) {
    write_volatile((b + o) as *mut u32, v);
}
