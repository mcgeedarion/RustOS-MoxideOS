//! virtio-gpu device driver — controlq (TRANSFER + FLUSH) and cursorq
//! (UPDATE_CURSOR / MOVE_CURSOR).
//!
//! ## Multi-head extensions
//!
//! | Function | Purpose |
//! |---|---|
//! | `num_scanouts()` | Number of virtual displays reported by GET_DISPLAY_INFO |
//! | `scanout_info(idx)` | Resolution + physical backing address for scanout `idx` |
//! | `flush_scanout(idx)` | TRANSFER + FLUSH for one scanout's resource |
//! | `cursor_update_scanout(idx, ..)` | Upload cursor bitmap for scanout `idx` |
//! | `cursor_move_scanout(idx, ..)` | Move/hide cursor on scanout `idx` |
//!
//! ## Transport
//!
//! Uses the **virtio 1.x modern PCI** transport:
//! - Walks the PCI capability list for `VIRTIO_PCI_CAP_COMMON_CFG`,
//!   `VIRTIO_PCI_CAP_NOTIFY_CFG`, and `VIRTIO_PCI_CAP_DEVICE_CFG`.
//! - Programs two split-ring virtqueues: controlq (idx 0) and cursorq (idx 1).
//! - Kicks queues by writing the queue index to the notify MMIO register.
//! - Polls the used ring for synchronous completions (controlq only;
//!   cursorq is fire-and-forget per spec).
//!
//! ## Resource layout
//!
//! | Resource ID  | Purpose |
//! |---|---|
//! | `RES_FB_BASE + scanout` | Per-scanout framebuffer resource |
//! | `RES_CURSOR_BASE + scanout` | Per-scanout 64×64 ARGB cursor |

extern crate alloc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, fence, Ordering};
use spin::Mutex;

use crate::drivers::gop;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_GPU_MODERN: u16 = 0x1050;
const VIRTIO_GPU_TRANS: u16 = 0x1002;

const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

const STATUS_RESET: u8 = 0;
const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FAILED: u8 = 128;

const CONTROLQ: u16 = 0;
const CURSORQ: u16 = 1;

const QUEUE_SIZE: usize = 16;
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

mod cmd {
    pub const GET_DISPLAY_INFO: u32 = 0x0100;
    pub const RESOURCE_CREATE_2D: u32 = 0x0101;
    pub const SET_SCANOUT: u32 = 0x0103;
    pub const RESOURCE_FLUSH: u32 = 0x0104;
    pub const TRANSFER_TO_HOST_2D: u32 = 0x0105;
    pub const RESOURCE_ATTACH_BACKING: u32 = 0x0106;
    pub const UPDATE_CURSOR: u32 = 0x0300;
    pub const MOVE_CURSOR: u32 = 0x0301;
    pub const RESP_OK_NODATA: u32 = 0x1100;
    pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
}

const FORMAT_B8G8R8X8_UNORM: u32 = 2;
/// Maximum scanouts we will ever configure (virtio-gpu spec allows up to 16).
pub const MAX_SCANOUTS: usize = 4;
/// Resource IDs: scanout i gets RES_FB_BASE+i (fb) and RES_CURSOR_BASE+i (cursor).
const RES_FB_BASE: u32 = 1;
const RES_CURSOR_BASE: u32 = 32;
const CURSOR_W: u32 = 64;
const CURSOR_H: u32 = 64;

// ─────────────────────────────────────────────────────────────────────────────
// common-cfg MMIO layout
// ─────────────────────────────────────────────────────────────────────────────

mod common_cfg_off {
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    pub const DEVICE_FEATURE:        usize = 0x04;
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    pub const DRIVER_FEATURE:        usize = 0x0C;
    pub const MSIX_CONFIG:           usize = 0x10;
    pub const NUM_QUEUES:            usize = 0x12;
    pub const DEVICE_STATUS:         usize = 0x14;
    pub const CONFIG_GENERATION:     usize = 0x15;
    pub const QUEUE_SELECT:          usize = 0x16;
    pub const QUEUE_SIZE:            usize = 0x18;
    pub const QUEUE_MSIX_VECTOR:     usize = 0x1A;
    pub const QUEUE_ENABLE:          usize = 0x1C;
    pub const QUEUE_NOTIFY_OFF:      usize = 0x1E;
    pub const QUEUE_DESC_LO:         usize = 0x20;
    pub const QUEUE_DESC_HI:         usize = 0x24;
    pub const QUEUE_AVAIL_LO:        usize = 0x28;
    pub const QUEUE_AVAIL_HI:        usize = 0x2C;
    pub const QUEUE_USED_LO:         usize = 0x30;
    pub const QUEUE_USED_HI:         usize = 0x34;
}

// ─────────────────────────────────────────────────────────────────────────────
// Split-ring virtqueue
// ─────────────────────────────────────────────────────────────────────────────

const DESC_BYTES: usize = QUEUE_SIZE * 16;
const AVAIL_OFF: usize = DESC_BYTES;
const USED_PAGE_OFF: usize = 4096;
const USED_OFF: usize = USED_PAGE_OFF;

struct Virtqueue {
    desc_pa:    u64,
    used_pa:    u64,
    base_va:    *mut u8,
    free_head:  usize,
    avail_idx:  u16,
    last_used:  u16,
    notify_off: u16,
}
unsafe impl Send for Virtqueue {}

impl Virtqueue {
    unsafe fn write_desc(&mut self, idx: usize, addr: u64, len: u32, flags: u16, next: u16) {
        let p = self.base_va.add(idx * 16) as *mut u64;
        p.add(0).write_volatile(addr);
        let p32 = p as *mut u32;
        p32.add(2).write_volatile(len);
        let p16 = p as *mut u16;
        p16.add(6).write_volatile(flags);
        p16.add(7).write_volatile(next);
    }
    unsafe fn avail_push(&mut self, head_desc: u16) {
        let avail = self.base_va.add(AVAIL_OFF) as *mut u16;
        let slot = self.avail_idx as usize % QUEUE_SIZE;
        avail.add(2 + slot).write_volatile(head_desc);
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        avail.add(1).write_volatile(self.avail_idx);
        fence(Ordering::SeqCst);
    }
    unsafe fn poll_used(&mut self) -> u32 {
        let used = self.base_va.add(USED_OFF) as *const u16;
        let mut spins = 0usize;
        loop {
            fence(Ordering::Acquire);
            if used.add(1).read_volatile() != self.last_used { break; }
            spins += 1;
            if spins > 50_000_000 { return 0; }
            core::hint::spin_loop();
        }
        let used_elem = (self.base_va.add(USED_OFF + 4)) as *const u32;
        let len = used_elem.add(1).read_volatile();
        self.last_used = self.last_used.wrapping_add(1);
        len
    }
    fn alloc_chain(&mut self, n: usize) -> usize {
        let head = self.free_head;
        self.free_head = (self.free_head + n) % QUEUE_SIZE;
        head
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire structs
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C)] #[derive(Clone, Copy, Default)]
struct CtrlHdr { type_: u32, flags: u32, fence_id: u64, ctx_id: u32, _pad: u32 }

#[repr(C)] #[derive(Clone, Copy, Default)]
struct Rect { x: u32, y: u32, width: u32, height: u32 }

#[repr(C)] #[derive(Clone, Copy, Default)]
struct RespNodata { hdr: CtrlHdr }

#[repr(C)] #[derive(Clone, Copy, Default)]
struct ResourceCreate2d { hdr: CtrlHdr, resource_id: u32, format: u32, width: u32, height: u32 }

#[repr(C)] #[derive(Clone, Copy, Default)]
struct SetScanout { hdr: CtrlHdr, r: Rect, scanout_id: u32, resource_id: u32 }

#[repr(C)] #[derive(Clone, Copy, Default)]
struct TransferToHost2d { hdr: CtrlHdr, r: Rect, offset: u64, resource_id: u32, _pad: u32 }

#[repr(C)] #[derive(Clone, Copy, Default)]
struct ResourceFlush { hdr: CtrlHdr, r: Rect, resource_id: u32, _pad: u32 }

#[repr(C)] #[derive(Clone, Copy, Default)]
struct AttachBacking { hdr: CtrlHdr, resource_id: u32, nr_entries: u32 }

#[repr(C)] #[derive(Clone, Copy, Default)]
struct MemEntry { addr: u64, length: u32, _pad: u32 }

#[repr(C)] #[derive(Clone, Copy, Default)]
struct CursorPos { scanout_id: u32, x: u32, y: u32, _pad: u32 }

#[repr(C)] #[derive(Clone, Copy, Default)]
struct UpdateCursor {
    hdr: CtrlHdr, pos: CursorPos,
    resource_id: u32, hot_x: u32, hot_y: u32, _pad: u32,
}

#[repr(C)] #[derive(Clone, Copy, Default)]
struct DisplayOne { r: Rect, enabled: u32, flags: u32 }

#[repr(C)] #[derive(Clone, Copy)]
struct DisplayInfoResp { hdr: CtrlHdr, modes: [DisplayOne; 16] }

// ─────────────────────────────────────────────────────────────────────────────
// Per-scanout state (allocated at init)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
pub struct ScanoutDesc {
    pub width:       u32,
    pub height:      u32,
    /// Guest-physical address of the framebuffer for this scanout.
    pub fb_phys:     u64,
    /// Guest-physical address of the cursor bitmap for this scanout.
    pub cursor_phys: u64,
    /// virtio-gpu resource ID for the framebuffer.
    pub res_fb:      u32,
    /// virtio-gpu resource ID for the cursor.
    pub res_cursor:  u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Command scratch buffers
// ─────────────────────────────────────────────────────────────────────────────

const SCRATCH_CMD_BYTES: usize = 128;
const SCRATCH_RSP_BYTES: usize = core::mem::size_of::<DisplayInfoResp>();

static CTRL_CMD_BUF:  Mutex<[u8; SCRATCH_CMD_BYTES]> = Mutex::new([0u8; SCRATCH_CMD_BYTES]);
static CTRL_CMD_BUF2: Mutex<[u8; SCRATCH_CMD_BYTES]> = Mutex::new([0u8; SCRATCH_CMD_BYTES]);
static CTRL_RSP_BUF:  Mutex<[u8; SCRATCH_RSP_BYTES]> = Mutex::new([0u8; SCRATCH_RSP_BYTES]);
static CUR_CMD_BUF:   Mutex<[u8; core::mem::size_of::<UpdateCursor>()]> =
    Mutex::new([0u8; core::mem::size_of::<UpdateCursor>()]);

// ─────────────────────────────────────────────────────────────────────────────
// Device singleton
// ─────────────────────────────────────────────────────────────────────────────

struct VirtioGpu {
    common_cfg:            u64,
    notify_base:           u64,
    notify_off_multiplier: u32,
    /// Configured scanouts (index 0 = primary).
    scanouts:              Vec<ScanoutDesc>,
    ctrlq:   Virtqueue,
    cursorq: Virtqueue,
}

static DEVICE:  Mutex<Option<VirtioGpu>> = Mutex::new(None);
static PRESENT: AtomicBool               = AtomicBool::new(false);

// ─────────────────────────────────────────────────────────────────────────────
// Public API — single-head compatibility shims
// ─────────────────────────────────────────────────────────────────────────────

#[inline] pub fn is_present() -> bool { PRESENT.load(Ordering::Relaxed) }

pub fn dimensions() -> Option<(u32, u32)> {
    DEVICE.lock().as_ref().and_then(|d| d.scanouts.first().map(|s| (s.width, s.height)))
}

pub fn fb_phys() -> Option<u64> {
    DEVICE.lock().as_ref().and_then(|d| d.scanouts.first().map(|s| s.fb_phys))
}

/// Flush the entire primary scanout (scanout 0).
pub fn flush_all() { flush_scanout(0); }

/// Upload cursor bitmap and show on primary scanout.
pub fn cursor_update(pixels: &[u32], x: i32, y: i32) {
    cursor_update_scanout(0, pixels, x, y);
}

/// Move/hide cursor on primary scanout.
pub fn cursor_move(x: i32, y: i32, visible: bool) {
    cursor_move_scanout(0, x, y, visible);
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API — multi-head extensions
// ─────────────────────────────────────────────────────────────────────────────

/// Number of active virtual display scanouts.
pub fn num_scanouts() -> usize {
    DEVICE.lock().as_ref().map_or(0, |d| d.scanouts.len())
}

/// Resolution and physical backing address for one scanout.
/// Returns `(width, height, fb_phys)` or `None` if `idx` is out of range.
pub fn scanout_info(idx: usize) -> Option<(u32, u32, u64)> {
    DEVICE.lock().as_ref().and_then(|d| {
        d.scanouts.get(idx).map(|s| (s.width, s.height, s.fb_phys))
    })
}

/// TRANSFER_TO_HOST_2D + RESOURCE_FLUSH for the full framebuffer of `scanout`.
pub fn flush_scanout(scanout_idx: usize) {
    let (phys, w, h, res_id) = {
        let dev = DEVICE.lock();
        let s = dev.as_ref().and_then(|d| d.scanouts.get(scanout_idx).copied());
        match s {
            Some(s) => (s.fb_phys, s.width, s.height, s.res_fb),
            None => return,
        }
    };
    let _ = phys; // physical address is implicit via the resource
    let transfer = TransferToHost2d {
        hdr: ctrl_hdr(cmd::TRANSFER_TO_HOST_2D),
        r: Rect { x: 0, y: 0, width: w, height: h },
        offset: 0,
        resource_id: res_id,
        _pad: 0,
    };
    let flush = ResourceFlush {
        hdr: ctrl_hdr(cmd::RESOURCE_FLUSH),
        r: Rect { x: 0, y: 0, width: w, height: h },
        resource_id: res_id,
        _pad: 0,
    };
    controlq_send_recv(&transfer as *const _ as *const u8, core::mem::size_of_val(&transfer));
    controlq_send_recv(&flush   as *const _ as *const u8, core::mem::size_of_val(&flush));
}

/// Upload a 64×64 ARGB cursor bitmap for `scanout_idx` and position it at (x, y).
pub fn cursor_update_scanout(scanout_idx: usize, pixels: &[u32], x: i32, y: i32) {
    let (cursor_phys, res_cursor) = {
        let dev = DEVICE.lock();
        match dev.as_ref().and_then(|d| d.scanouts.get(scanout_idx).copied()) {
            Some(s) => (s.cursor_phys, s.res_cursor),
            None => return,
        }
    };
    let n = (CURSOR_W * CURSOR_H) as usize;
    unsafe {
        core::ptr::copy_nonoverlapping(
            pixels.as_ptr(),
            cursor_phys as *mut u32,
            n.min(pixels.len()),
        );
    }
    let transfer = TransferToHost2d {
        hdr: ctrl_hdr(cmd::TRANSFER_TO_HOST_2D),
        r: Rect { x: 0, y: 0, width: CURSOR_W, height: CURSOR_H },
        offset: 0,
        resource_id: res_cursor,
        _pad: 0,
    };
    controlq_send_recv(&transfer as *const _ as *const u8, core::mem::size_of_val(&transfer));
    let upd = UpdateCursor {
        hdr: ctrl_hdr(cmd::UPDATE_CURSOR),
        pos: CursorPos {
            scanout_id: scanout_idx as u32,
            x: x.max(0) as u32,
            y: y.max(0) as u32,
            _pad: 0,
        },
        resource_id: res_cursor,
        hot_x: 0, hot_y: 0, _pad: 0,
    };
    cursorq_send(&upd as *const _ as *const u8, core::mem::size_of_val(&upd));
}

/// Move or hide the cursor on `scanout_idx` without re-uploading the bitmap.
pub fn cursor_move_scanout(scanout_idx: usize, x: i32, y: i32, visible: bool) {
    if !is_present() { return; }
    let res_cursor = {
        let dev = DEVICE.lock();
        match dev.as_ref().and_then(|d| d.scanouts.get(scanout_idx).copied()) {
            Some(s) => s.res_cursor,
            None => return,
        }
    };
    let upd = UpdateCursor {
        hdr: ctrl_hdr(cmd::MOVE_CURSOR),
        pos: CursorPos {
            scanout_id: scanout_idx as u32,
            x: x.max(0) as u32,
            y: y.max(0) as u32,
            _pad: 0,
        },
        resource_id: if visible { res_cursor } else { 0 },
        hot_x: 0, hot_y: 0, _pad: 0,
    };
    cursorq_send(&upd as *const _ as *const u8, core::mem::size_of_val(&upd));
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialisation
// ─────────────────────────────────────────────────────────────────────────────

pub fn init() {
    let (mmio_bar0, ecam_base, bus, dev_slot) = match probe_pci() { Some(x) => x, None => return };
    let (common_cfg, notify_base, notify_off_mult, _device_cfg) =
        match walk_caps(ecam_base, bus, dev_slot) { Some(x) => x, None => return };
    let _ = mmio_bar0;

    // Feature negotiation.
    unsafe {
        ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS, STATUS_RESET);
        ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        ccfg_writel(common_cfg, common_cfg_off::DEVICE_FEATURE_SELECT, 0);
        let feat0 = ccfg_readl(common_cfg, common_cfg_off::DEVICE_FEATURE);
        ccfg_writel(common_cfg, common_cfg_off::DRIVER_FEATURE_SELECT, 0);
        ccfg_writel(common_cfg, common_cfg_off::DRIVER_FEATURE, feat0);
        ccfg_writel(common_cfg, common_cfg_off::DEVICE_FEATURE_SELECT, 1);
        let feat1 = ccfg_readl(common_cfg, common_cfg_off::DEVICE_FEATURE);
        ccfg_writel(common_cfg, common_cfg_off::DRIVER_FEATURE_SELECT, 1);
        ccfg_writel(common_cfg, common_cfg_off::DRIVER_FEATURE, feat1);
        ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS,
                    STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK);
        let st = ccfg_readb(common_cfg, common_cfg_off::DEVICE_STATUS);
        if st & STATUS_FEATURES_OK == 0 {
            ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS, STATUS_FAILED);
            return;
        }
    }

    let ctrlq   = match setup_queue(common_cfg, CONTROLQ)  { Some(q) => q, None => { unsafe { ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS, STATUS_FAILED); } return; } };
    let cursorq = match setup_queue(common_cfg, CURSORQ)   { Some(q) => q, None => { unsafe { ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS, STATUS_FAILED); } return; } };

    unsafe {
        ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS,
                    STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK);
    }

    // Publish skeleton so controlq helpers work during query.
    *DEVICE.lock() = Some(VirtioGpu {
        common_cfg, notify_base,
        notify_off_multiplier: notify_off_mult,
        scanouts: Vec::new(),
        ctrlq, cursorq,
    });
    PRESENT.store(true, Ordering::Release);

    // Query all enabled scanouts.
    let display_modes = query_all_display_info();
    let n_scanouts = display_modes.iter().filter(|m| m.0 > 0).count().min(MAX_SCANOUTS);

    // Allocate per-scanout backing stores and configure GPU resources.
    let mut scanouts: Vec<ScanoutDesc> = Vec::with_capacity(n_scanouts);
    for i in 0..n_scanouts {
        let (w, h) = display_modes[i];
        let fb_pages  = size_pages(w as usize * h as usize * 4);
        let cur_pages = size_pages(CURSOR_W as usize * CURSOR_H as usize * 4);

        let fb_phys = match crate::mm::pmm::alloc_pages(fb_pages) {
            Some(p) => p.as_ptr() as u64,
            None => break,
        };
        let cursor_phys = match crate::mm::pmm::alloc_pages(cur_pages) {
            Some(p) => p.as_ptr() as u64,
            None => {
                crate::mm::pmm::free_pages(
                    unsafe { core::ptr::NonNull::new_unchecked(fb_phys as *mut u8) }, fb_pages);
                break;
            }
        };

        let res_fb     = RES_FB_BASE     + i as u32;
        let res_cursor = RES_CURSOR_BASE + i as u32;

        // RESOURCE_CREATE_2D
        let c = ResourceCreate2d { hdr: ctrl_hdr(cmd::RESOURCE_CREATE_2D),
            resource_id: res_fb, format: FORMAT_B8G8R8X8_UNORM, width: w, height: h };
        controlq_send_recv(&c as *const _ as *const u8, core::mem::size_of_val(&c));

        let c = ResourceCreate2d { hdr: ctrl_hdr(cmd::RESOURCE_CREATE_2D),
            resource_id: res_cursor, format: FORMAT_B8G8R8X8_UNORM,
            width: CURSOR_W, height: CURSOR_H };
        controlq_send_recv(&c as *const _ as *const u8, core::mem::size_of_val(&c));

        // RESOURCE_ATTACH_BACKING
        attach_backing(res_fb,     fb_phys,     w * h * 4);
        attach_backing(res_cursor, cursor_phys, CURSOR_W * CURSOR_H * 4);

        // SET_SCANOUT
        let ss = SetScanout { hdr: ctrl_hdr(cmd::SET_SCANOUT),
            r: Rect { x: 0, y: 0, width: w, height: h },
            scanout_id: i as u32, resource_id: res_fb };
        controlq_send_recv(&ss as *const _ as *const u8, core::mem::size_of_val(&ss));

        scanouts.push(ScanoutDesc { width: w, height: h, fb_phys, cursor_phys, res_fb, res_cursor });
    }

    if let Some(d) = DEVICE.lock().as_mut() {
        d.scanouts = scanouts;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Display info query — returns up to MAX_SCANOUTS (w, h) pairs
// ─────────────────────────────────────────────────────────────────────────────

/// Query GET_DISPLAY_INFO and return (width, height) for each scanout.
/// Disabled or zero-sized scanouts are returned as (0, 0).
fn query_all_display_info() -> [(u32, u32); MAX_SCANOUTS] {
    let mut out = [(0u32, 0u32); MAX_SCANOUTS];

    let req    = ctrl_hdr(cmd::GET_DISPLAY_INFO);
    let rsp_pa = CTRL_RSP_BUF.lock().as_ptr() as u64;
    let cmd_pa;
    {
        let mut buf = CTRL_CMD_BUF.lock();
        unsafe {
            core::ptr::copy_nonoverlapping(
                &req as *const _ as *const u8,
                buf.as_mut_ptr(),
                core::mem::size_of::<CtrlHdr>(),
            )
        };
        cmd_pa = buf.as_ptr() as u64;
    }
    {
        let mut dev_guard = DEVICE.lock();
        let dev = match dev_guard.as_mut() { Some(d) => d, None => return out };
        unsafe {
            let head = dev.ctrlq.alloc_chain(2);
            dev.ctrlq.write_desc(head, cmd_pa,
                core::mem::size_of::<CtrlHdr>() as u32, VRING_DESC_F_NEXT, (head+1) as u16);
            dev.ctrlq.write_desc(head+1, rsp_pa,
                core::mem::size_of::<DisplayInfoResp>() as u32, VRING_DESC_F_WRITE, 0);
            dev.ctrlq.avail_push(head as u16);
            queue_notify(dev, CONTROLQ);
            dev.ctrlq.poll_used();
        }
    }
    let rsp_buf = CTRL_RSP_BUF.lock();
    let rsp = unsafe { &*(rsp_buf.as_ptr() as *const DisplayInfoResp) };
    if rsp.hdr.type_ == cmd::RESP_OK_DISPLAY_INFO {
        for i in 0..MAX_SCANOUTS {
            let m = &rsp.modes[i];
            if m.enabled != 0 && m.r.width > 0 && m.r.height > 0 {
                out[i] = (m.r.width, m.r.height);
            } else if i == 0 {
                // Fallback for scanout 0.
                let (fw, fh) = gop::get()
                    .map(|g| (g.width, g.height))
                    .unwrap_or((1024, 768));
                out[0] = (fw, fh);
            }
        }
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtqueue send helpers (unchanged from original)
// ─────────────────────────────────────────────────────────────────────────────

fn controlq_send_recv(cmd_ptr: *const u8, cmd_len: usize) {
    let cmd_pa; let rsp_pa;
    {
        let mut buf = CTRL_CMD_BUF.lock();
        let len = cmd_len.min(SCRATCH_CMD_BYTES);
        unsafe { core::ptr::copy_nonoverlapping(cmd_ptr, buf.as_mut_ptr(), len) };
        cmd_pa = buf.as_ptr() as u64;
        drop(buf);
        let rsp = CTRL_RSP_BUF.lock();
        rsp_pa = rsp.as_ptr() as u64;
    }
    let mut dev_guard = DEVICE.lock();
    let dev = match dev_guard.as_mut() { Some(d) => d, None => return };
    unsafe {
        let head = dev.ctrlq.alloc_chain(2);
        dev.ctrlq.write_desc(head, cmd_pa, cmd_len as u32, VRING_DESC_F_NEXT, (head+1) as u16);
        dev.ctrlq.write_desc(head+1, rsp_pa,
            core::mem::size_of::<RespNodata>() as u32, VRING_DESC_F_WRITE, 0);
        dev.ctrlq.avail_push(head as u16);
        queue_notify(dev, CONTROLQ);
        dev.ctrlq.poll_used();
    }
}

fn controlq_send2_recv(cmd1_ptr: *const u8, cmd1_len: usize,
                       cmd2_ptr: *const u8, cmd2_len: usize) {
    let pa1; let pa2; let rsp_pa;
    {
        let mut b1 = CTRL_CMD_BUF.lock();
        let l1 = cmd1_len.min(SCRATCH_CMD_BYTES);
        unsafe { core::ptr::copy_nonoverlapping(cmd1_ptr, b1.as_mut_ptr(), l1) };
        pa1 = b1.as_ptr() as u64;
        drop(b1);
        let mut b2 = CTRL_CMD_BUF2.lock();
        let l2 = cmd2_len.min(SCRATCH_CMD_BYTES);
        unsafe { core::ptr::copy_nonoverlapping(cmd2_ptr, b2.as_mut_ptr(), l2) };
        pa2 = b2.as_ptr() as u64;
        drop(b2);
        let rsp = CTRL_RSP_BUF.lock();
        rsp_pa = rsp.as_ptr() as u64;
    }
    let mut dev_guard = DEVICE.lock();
    let dev = match dev_guard.as_mut() { Some(d) => d, None => return };
    unsafe {
        let head = dev.ctrlq.alloc_chain(3);
        dev.ctrlq.write_desc(head, pa1, cmd1_len as u32, VRING_DESC_F_NEXT, (head+1) as u16);
        dev.ctrlq.write_desc(head+1, pa2, cmd2_len as u32, VRING_DESC_F_NEXT, (head+2) as u16);
        dev.ctrlq.write_desc(head+2, rsp_pa,
            core::mem::size_of::<RespNodata>() as u32, VRING_DESC_F_WRITE, 0);
        dev.ctrlq.avail_push(head as u16);
        queue_notify(dev, CONTROLQ);
        dev.ctrlq.poll_used();
    }
}

fn cursorq_send(cmd_ptr: *const u8, cmd_len: usize) {
    let cmd_pa;
    {
        let mut buf = CUR_CMD_BUF.lock();
        let len = cmd_len.min(buf.len());
        unsafe { core::ptr::copy_nonoverlapping(cmd_ptr, buf.as_mut_ptr(), len) };
        cmd_pa = buf.as_ptr() as u64;
    }
    let mut dev_guard = DEVICE.lock();
    let dev = match dev_guard.as_mut() { Some(d) => d, None => return };
    unsafe {
        let head = dev.cursorq.alloc_chain(1);
        dev.cursorq.write_desc(head, cmd_pa, cmd_len as u32, 0, 0);
        dev.cursorq.avail_push(head as u16);
        queue_notify(dev, CURSORQ);
    }
}

fn attach_backing(resource_id: u32, phys: u64, byte_len: u32) {
    let hdr   = AttachBacking { hdr: ctrl_hdr(cmd::RESOURCE_ATTACH_BACKING), resource_id, nr_entries: 1 };
    let entry = MemEntry { addr: phys, length: byte_len, _pad: 0 };
    controlq_send2_recv(
        &hdr   as *const _ as *const u8, core::mem::size_of::<AttachBacking>(),
        &entry as *const _ as *const u8, core::mem::size_of::<MemEntry>(),
    );
}

#[inline]
unsafe fn queue_notify(dev: &VirtioGpu, queue_idx: u16) {
    let notify_off = if queue_idx == CONTROLQ {
        dev.ctrlq.notify_off
    } else {
        dev.cursorq.notify_off
    };
    let addr = dev.notify_base + (notify_off as u32 * dev.notify_off_multiplier) as u64;
    (addr as *mut u16).write_volatile(queue_idx);
    fence(Ordering::SeqCst);
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtqueue allocation
// ─────────────────────────────────────────────────────────────────────────────

fn setup_queue(common_cfg: u64, queue_idx: u16) -> Option<Virtqueue> {
    unsafe {
        ccfg_writew(common_cfg, common_cfg_off::QUEUE_SELECT, queue_idx);
        let dev_size = ccfg_readw(common_cfg, common_cfg_off::QUEUE_SIZE) as usize;
        let qsize = dev_size.min(QUEUE_SIZE);
        if qsize == 0 { return None; }
        let p0 = crate::mm::pmm::alloc_page()? as u64;
        let p1 = crate::mm::pmm::alloc_page()? as u64;
        core::ptr::write_bytes(p0 as *mut u8, 0, 4096);
        core::ptr::write_bytes(p1 as *mut u8, 0, 4096);
        let desc_pa  = p0;
        let avail_pa = p0 + AVAIL_OFF as u64;
        let used_pa  = p1;
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_SIZE,     qsize as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_DESC_LO,  desc_pa  as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_DESC_HI,  (desc_pa  >> 32) as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_AVAIL_LO, avail_pa as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_AVAIL_HI, (avail_pa >> 32) as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_USED_LO,  used_pa  as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_USED_HI,  (used_pa  >> 32) as u32);
        let notify_off = ccfg_readw(common_cfg, common_cfg_off::QUEUE_NOTIFY_OFF);
        ccfg_writew(common_cfg, common_cfg_off::QUEUE_ENABLE, 1);
        Some(Virtqueue {
            desc_pa, used_pa, base_va: p0 as *mut u8,
            free_head: 0, avail_idx: 0, last_used: 0, notify_off,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PCIe probe
// ─────────────────────────────────────────────────────────────────────────────

fn probe_pci() -> Option<(u64, u64, u8, u8)> {
    let ecam_base: u64 = crate::acpi::pcie_ecam_base().unwrap_or(0x3000_0000);
    for dev in 0u8..32 {
        let cfg = ecam_cfg(ecam_base, 0, dev, 0);
        let id  = unsafe { (cfg as *const u32).read_volatile() };
        if id == 0xFFFF_FFFF { continue; }
        let vendor = (id & 0xFFFF) as u16;
        let device = (id >> 16) as u16;
        if vendor != VIRTIO_VENDOR { continue; }
        if device != VIRTIO_GPU_MODERN && device != VIRTIO_GPU_TRANS { continue; }
        let cmd_addr = cfg + 0x04;
        let cmd = unsafe { (cmd_addr as *const u16).read_volatile() };
        unsafe { (cmd_addr as *mut u16).write_volatile(cmd | 0x06) };
        let bar0 = unsafe { ((cfg + 0x10) as *const u32).read_volatile() };
        if bar0 & 1 != 0 { continue; }
        let bar_type = (bar0 >> 1) & 3;
        let bar0_phys: u64 = if bar_type == 2 {
            let bar1 = unsafe { ((cfg + 0x14) as *const u32).read_volatile() };
            (bar0 as u64 & !0xF) | ((bar1 as u64) << 32)
        } else { bar0 as u64 & !0xF };
        return Some((bar0_phys, ecam_base, 0, dev));
    }
    None
}

fn walk_caps(ecam_base: u64, bus: u8, dev: u8, func: u8) -> Option<(u64, u64, u32, u64)> {
    let cfg_base = ecam_cfg(ecam_base, bus, dev, func);
    let mut cap_ptr = unsafe { ((cfg_base + 0x34) as *const u8).read_volatile() } & !3;
    let mut common_cfg = 0u64; let mut notify_base = 0u64;
    let mut notify_mult = 4u32; let mut device_cfg = 0u64;
    while cap_ptr != 0 {
        let cap_off = cfg_base + cap_ptr as u64;
        let cap_id  = unsafe { (cap_off as *const u8).read_volatile() };
        let next    = unsafe { ((cap_off + 1) as *const u8).read_volatile() } & !3;
        if cap_id == 0x09 {
            let cfg_type = unsafe { ((cap_off + 2) as *const u8).read_volatile() };
            let bar_idx  = unsafe { ((cap_off + 3) as *const u8).read_volatile() };
            let bar_off  = unsafe { ((cap_off + 8) as *const u32).read_volatile() } as u64;
            let bar_phys = read_bar(ecam_base, bus, dev, func, bar_idx);
            match cfg_type {
                c if c == VIRTIO_PCI_CAP_COMMON_CFG => { common_cfg  = bar_phys + bar_off; }
                c if c == VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    notify_base = bar_phys + bar_off;
                    notify_mult = unsafe { ((cap_off + 16) as *const u32).read_volatile() };
                }
                c if c == VIRTIO_PCI_CAP_DEVICE_CFG => { device_cfg  = bar_phys + bar_off; }
                _ => {}
            }
        }
        cap_ptr = next;
    }
    if common_cfg == 0 || notify_base == 0 { return None; }
    Some((common_cfg, notify_base, notify_mult, device_cfg))
}

fn read_bar(ecam_base: u64, bus: u8, dev: u8, func: u8, bar: u8) -> u64 {
    if bar > 5 { return 0; }
    let cfg = ecam_cfg(ecam_base, bus, dev, func);
    let bar_reg = unsafe { ((cfg + 0x10 + bar as u64 * 4) as *const u32).read_volatile() };
    if bar_reg & 1 != 0 { return 0; }
    let bar_type = (bar_reg >> 1) & 3;
    if bar_type == 2 && bar < 5 {
        let bar_hi = unsafe { ((cfg + 0x10 + (bar as u64 + 1) * 4) as *const u32).read_volatile() };
        (bar_reg as u64 & !0xF) | ((bar_hi as u64) << 32)
    } else { bar_reg as u64 & !0xF }
}

#[inline]
fn ecam_cfg(base: u64, bus: u8, dev: u8, func: u8) -> u64 {
    base + ((bus as u64) << 20) + ((dev as u64) << 15) + ((func as u64) << 12)
}

// ─────────────────────────────────────────────────────────────────────────────
// common-cfg MMIO accessors
// ─────────────────────────────────────────────────────────────────────────────

#[inline] unsafe fn ccfg_readb(base: u64, off: usize) -> u8   { ((base + off as u64) as *const u8 ).read_volatile() }
#[inline] unsafe fn ccfg_readw(base: u64, off: usize) -> u16  { ((base + off as u64) as *const u16).read_volatile() }
#[inline] unsafe fn ccfg_readl(base: u64, off: usize) -> u32  { ((base + off as u64) as *const u32).read_volatile() }
#[inline] unsafe fn ccfg_writeb(base: u64, off: usize, v: u8 ) { ((base + off as u64) as *mut u8 ).write_volatile(v); }
#[inline] unsafe fn ccfg_writew(base: u64, off: usize, v: u16) { ((base + off as u64) as *mut u16).write_volatile(v); }
#[inline] unsafe fn ccfg_writel(base: u64, off: usize, v: u32) { ((base + off as u64) as *mut u32).write_volatile(v); }

#[inline]
fn ctrl_hdr(type_: u32) -> CtrlHdr { CtrlHdr { type_, flags: 0, fence_id: 0, ctx_id: 0, _pad: 0 } }

#[inline]
fn size_pages(bytes: usize) -> usize { (bytes + 0xFFF) / 0x1000 }
