//! virtio-gpu device driver — controlq (TRANSFER + FLUSH) and cursorq
//! (UPDATE_CURSOR / MOVE_CURSOR).
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
//! ## Ring layout (per queue)
//!
//! ```text
//! Page 0  [0x0000] Descriptor Table  QUEUE_SIZE × 16 bytes
//!         [DESC_END] Available Ring  6 + QUEUE_SIZE × 2 bytes
//! Page N  (4 KiB-aligned) Used Ring  6 + QUEUE_SIZE × 8 bytes
//! ```
//!
//! ## Resource layout
//!
//! | Resource ID  | Purpose                     |
//! |--------------|-----------------------------|
//! | `RES_FB`     | Primary scanout framebuffer |
//! | `RES_CURSOR` | 64×64 ARGB cursor bitmap    |

extern crate alloc;

use core::sync::atomic::{AtomicBool, fence, Ordering};
use spin::Mutex;

use crate::drivers::gop;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// virtio-gpu PCI IDs.
const VIRTIO_VENDOR: u16 = 0x1AF4;
const VIRTIO_GPU_MODERN: u16 = 0x1050;
const VIRTIO_GPU_TRANS: u16 = 0x1002;

/// virtio PCI capability types (virtio 1.x spec §4.1.4).
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;

/// virtio device-status bits.
const STATUS_RESET: u8 = 0;
const STATUS_ACKNOWLEDGE: u8 = 1;
const STATUS_DRIVER: u8 = 2;
const STATUS_FEATURES_OK: u8 = 8;
const STATUS_DRIVER_OK: u8 = 4;
const STATUS_FAILED: u8 = 128;

/// Queue indices.
const CONTROLQ: u16 = 0;
const CURSORQ: u16 = 1;

/// Descriptor-ring size (must be power-of-two; 16 is plenty for our use).
const QUEUE_SIZE: usize = 16;

/// Descriptor flags.
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

/// virtio-gpu command codes.
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
const SCANOUT_ID: u32 = 0;
const RES_FB: u32 = 1;
const RES_CURSOR: u32 = 2;
const CURSOR_W: u32 = 64;
const CURSOR_H: u32 = 64;

// ─────────────────────────────────────────────────────────────────────────────
// virtio-pci common-cfg MMIO layout  (spec §4.1.4.3)
// All fields little-endian; we use volatile reads/writes.
// ─────────────────────────────────────────────────────────────────────────────

/// Byte offsets into the common-cfg BAR region.
mod common_cfg_off {
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    pub const DEVICE_FEATURE: usize = 0x04;
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    pub const DRIVER_FEATURE: usize = 0x0C;
    pub const MSIX_CONFIG: usize = 0x10;
    pub const NUM_QUEUES: usize = 0x12;
    pub const DEVICE_STATUS: usize = 0x14;
    pub const CONFIG_GENERATION: usize = 0x15;
    pub const QUEUE_SELECT: usize = 0x16;
    pub const QUEUE_SIZE: usize = 0x18;
    pub const QUEUE_MSIX_VECTOR: usize = 0x1A;
    pub const QUEUE_ENABLE: usize = 0x1C;
    pub const QUEUE_NOTIFY_OFF: usize = 0x1E;
    pub const QUEUE_DESC_LO: usize = 0x20;
    pub const QUEUE_DESC_HI: usize = 0x24;
    pub const QUEUE_AVAIL_LO: usize = 0x28;
    pub const QUEUE_AVAIL_HI: usize = 0x2C;
    pub const QUEUE_USED_LO: usize = 0x30;
    pub const QUEUE_USED_HI: usize = 0x34;
}

// ─────────────────────────────────────────────────────────────────────────────
// Split-ring virtqueue
// ─────────────────────────────────────────────────────────────────────────────
//
// Memory layout for ONE queue (QUEUE_SIZE = 16):
//
//   [desc_pa]  Descriptor Table:  16 × 16 = 256 bytes
//              Available Ring:    6 + 16×2 = 38 bytes   (fits in page 0)
//   [used_pa]  Used Ring:         6 + 16×8 = 134 bytes  (next 4KiB-aligned page)
//
// We allocate two physically-contiguous pages per queue from the PMM.

const DESC_BYTES: usize = QUEUE_SIZE * 16;
const AVAIL_OFF: usize = DESC_BYTES;
const AVAIL_BYTES: usize = 6 + QUEUE_SIZE * 2;
// Used ring on its own page so the device only writes to a separate cache line.
const USED_PAGE_OFF: usize = 4096;
const USED_OFF: usize = USED_PAGE_OFF; // always 0 within the used page

struct Virtqueue {
    /// Guest-physical base of descriptor + avail pages.
    desc_pa: u64,
    /// Guest-physical base of used page.
    used_pa: u64,
    /// Virtual (= physical, identity-mapped) base pointer.
    base_va: *mut u8,
    /// Next descriptor index to use (0..QUEUE_SIZE, wraps).
    free_head: usize,
    /// Avail ring index (driver-side, monotonically increasing).
    avail_idx: u16,
    /// Last used-ring index we consumed.
    last_used: u16,
    /// Per-queue notify multiplier offset (from notify-cfg cap).
    notify_off: u16,
}

// SAFETY: we only ever touch Virtqueue from behind a Mutex<Option<VirtioGpu>>.
unsafe impl Send for Virtqueue {}

impl Virtqueue {
    /// Write one 16-byte descriptor.
    ///
    /// Layout: addr(8) | len(4) | flags(2) | next(2)
    unsafe fn write_desc(&mut self, idx: usize, addr: u64, len: u32, flags: u16, next: u16) {
        let p = self.base_va.add(idx * 16) as *mut u64;
        p.add(0).write_volatile(addr);
        let p32 = p as *mut u32;
        p32.add(2).write_volatile(len);
        let p16 = p as *mut u16;
        p16.add(6).write_volatile(flags);
        p16.add(7).write_volatile(next);
    }

    /// Place `head_desc` into the available ring and advance avail_idx.
    unsafe fn avail_push(&mut self, head_desc: u16) {
        let avail = self.base_va.add(AVAIL_OFF) as *mut u16;
        // avail[0] = flags (0), avail[1] = idx, avail[2+i] = ring entries
        let slot = self.avail_idx as usize % QUEUE_SIZE;
        avail.add(2 + slot).write_volatile(head_desc);
        fence(Ordering::SeqCst);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        avail.add(1).write_volatile(self.avail_idx);
        fence(Ordering::SeqCst);
    }

    /// Poll used ring until `expected_avail_idx` is consumed.
    /// Returns the used element's `len` field (0 for GPU commands).
    unsafe fn poll_used(&mut self) -> u32 {
        let used = self.base_va.add(USED_OFF) as *const u16;
        // used[0] = flags, used[1] = idx; used elements start at byte 4
        let mut spins = 0usize;
        loop {
            fence(Ordering::Acquire);
            let used_idx = used.add(1).read_volatile();
            if used_idx != self.last_used {
                break;
            }
            spins += 1;
            if spins > 50_000_000 {
                // Device timed out — return 0 and move on.
                return 0;
            }
            core::hint::spin_loop();
        }
        // Read len from used element: struct { id: u32, len: u32 } at byte 4
        let used_elem = (self.base_va.add(USED_OFF + 4)) as *const u32;
        let _id = used_elem.read_volatile();
        let len = used_elem.add(1).read_volatile();
        self.last_used = self.last_used.wrapping_add(1);
        len
    }

    /// Allocate `n` chained descriptors (n ≤ QUEUE_SIZE).
    /// Returns the head descriptor index.
    fn alloc_chain(&mut self, n: usize) -> usize {
        // Simple linear allocator — reuse from free_head, wrapping.
        // Works because all our commands are synchronous (we wait before reusing).
        let head = self.free_head;
        self.free_head = (self.free_head + n) % QUEUE_SIZE;
        head
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire structs
// ─────────────────────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CtrlHdr {
    type_: u32,
    flags: u32,
    fence_id: u64,
    ctx_id: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Rect {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RespNodata {
    hdr: CtrlHdr,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ResourceCreate2d {
    hdr: CtrlHdr,
    resource_id: u32,
    format: u32,
    width: u32,
    height: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SetScanout {
    hdr: CtrlHdr,
    r: Rect,
    scanout_id: u32,
    resource_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct TransferToHost2d {
    hdr: CtrlHdr,
    r: Rect,
    offset: u64,
    resource_id: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ResourceFlush {
    hdr: CtrlHdr,
    r: Rect,
    resource_id: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct AttachBacking {
    hdr: CtrlHdr,
    resource_id: u32,
    nr_entries: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MemEntry {
    addr: u64,
    length: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CursorPos {
    scanout_id: u32,
    x: u32,
    y: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct UpdateCursor {
    hdr: CtrlHdr,
    pos: CursorPos,
    resource_id: u32,
    hot_x: u32,
    hot_y: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct DisplayOne {
    r: Rect,
    enabled: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DisplayInfoResp {
    hdr: CtrlHdr,
    modes: [DisplayOne; 16],
}

// ─────────────────────────────────────────────────────────────────────────────
// Command scratch buffers
//
// The virtqueue descriptors point directly at these statics so the device
// can DMA from/to them.  They must remain valid for the lifetime of any
// in-flight descriptor — which is always the case here because we submit
// synchronously and wait for completion before returning.
// ─────────────────────────────────────────────────────────────────────────────

/// Single command + response scratch area (controlq).
/// Large enough for the biggest command we send (AttachBacking + MemEntry).
const SCRATCH_CMD_BYTES: usize = 128;
const SCRATCH_RSP_BYTES: usize = core::mem::size_of::<DisplayInfoResp>();

static CTRL_CMD_BUF: Mutex<[u8; SCRATCH_CMD_BYTES]> = Mutex::new([0u8; SCRATCH_CMD_BYTES]);
static CTRL_CMD_BUF2: Mutex<[u8; SCRATCH_CMD_BYTES]> = Mutex::new([0u8; SCRATCH_CMD_BYTES]);
static CTRL_RSP_BUF: Mutex<[u8; SCRATCH_RSP_BYTES]> = Mutex::new([0u8; SCRATCH_RSP_BYTES]);

/// Cursor command scratch (cursorq — fire-and-forget, no response).
static CUR_CMD_BUF: Mutex<[u8; core::mem::size_of::<UpdateCursor>()]> =
    Mutex::new([0u8; core::mem::size_of::<UpdateCursor>()]);

// ─────────────────────────────────────────────────────────────────────────────
// Device singleton
// ─────────────────────────────────────────────────────────────────────────────

struct VirtioGpu {
    /// MMIO base of the common-cfg region.
    common_cfg: u64,
    /// MMIO base + multiplier for queue notifications.
    notify_base: u64,
    notify_off_multiplier: u32,
    /// Framebuffer backing store.
    fb_phys: u64,
    width: u32,
    height: u32,
    /// Cursor bitmap backing store.
    cursor_phys: u64,
    /// The two virtqueues.
    ctrlq: Virtqueue,
    cursorq: Virtqueue,
}

static DEVICE: Mutex<Option<VirtioGpu>> = Mutex::new(None);
static PRESENT: AtomicBool = AtomicBool::new(false);

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
pub fn is_present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}

pub fn dimensions() -> Option<(u32, u32)> {
    DEVICE.lock().as_ref().map(|d| (d.width, d.height))
}

pub fn fb_phys() -> Option<u64> {
    DEVICE.lock().as_ref().map(|d| d.fb_phys)
}

/// Flush the entire primary framebuffer to the host display.
pub fn flush_all() {
    let (phys, w, h) = {
        let dev = DEVICE.lock();
        match dev.as_ref() {
            Some(d) => (d.fb_phys, d.width, d.height),
            None => return,
        }
    };
    flush_rect(phys, w, h, 0, 0, w, h);
}

/// Flush a sub-rectangle (damage-tracked path).
#[allow(dead_code)]
pub fn flush_rect(_phys: u64, fb_w: u32, _fb_h: u32, x: u32, y: u32, rw: u32, rh: u32) {
    let transfer = TransferToHost2d {
        hdr: ctrl_hdr(cmd::TRANSFER_TO_HOST_2D),
        r: Rect { x, y, width: rw, height: rh },
        offset: (y * fb_w + x) as u64 * 4,
        resource_id: RES_FB,
        _pad: 0,
    };
    let flush = ResourceFlush {
        hdr: ctrl_hdr(cmd::RESOURCE_FLUSH),
        r: Rect { x, y, width: rw, height: rh },
        resource_id: RES_FB,
        _pad: 0,
    };
    controlq_send_recv(
        &transfer as *const _ as *const u8,
        core::mem::size_of::<TransferToHost2d>(),
    );
    controlq_send_recv(
        &flush as *const _ as *const u8,
        core::mem::size_of::<ResourceFlush>(),
    );
}

/// Upload a new 64×64 ARGB cursor bitmap and show it at (x, y).
pub fn cursor_update(pixels: &[u32], x: i32, y: i32) {
    let cursor_phys = {
        let dev = DEVICE.lock();
        match dev.as_ref() {
            Some(d) => d.cursor_phys,
            None => return,
        }
    };

    // Copy pixels into the DMA-backed cursor buffer.
    let n = (CURSOR_W * CURSOR_H) as usize;
    unsafe {
        core::ptr::copy_nonoverlapping(
            pixels.as_ptr(),
            cursor_phys as *mut u32,
            n.min(pixels.len()),
        );
    }

    // TRANSFER_TO_HOST_2D for the cursor resource.
    let transfer = TransferToHost2d {
        hdr: ctrl_hdr(cmd::TRANSFER_TO_HOST_2D),
        r: Rect { x: 0, y: 0, width: CURSOR_W, height: CURSOR_H },
        offset: 0,
        resource_id: RES_CURSOR,
        _pad: 0,
    };
    controlq_send_recv(
        &transfer as *const _ as *const u8,
        core::mem::size_of::<TransferToHost2d>(),
    );

    // UPDATE_CURSOR on the cursorq.
    let upd = UpdateCursor {
        hdr: ctrl_hdr(cmd::UPDATE_CURSOR),
        pos: CursorPos {
            scanout_id: SCANOUT_ID,
            x: x.max(0) as u32,
            y: y.max(0) as u32,
            _pad: 0,
        },
        resource_id: RES_CURSOR,
        hot_x: 0,
        hot_y: 0,
        _pad: 0,
    };
    cursorq_send(
        &upd as *const _ as *const u8,
        core::mem::size_of::<UpdateCursor>(),
    );
}

/// Move the hardware cursor without re-uploading the bitmap.
/// `visible = false` hides the cursor (resource_id = 0).
pub fn cursor_move(x: i32, y: i32, visible: bool) {
    if !is_present() {
        return;
    }
    let upd = UpdateCursor {
        hdr: ctrl_hdr(cmd::MOVE_CURSOR),
        pos: CursorPos {
            scanout_id: SCANOUT_ID,
            x: x.max(0) as u32,
            y: y.max(0) as u32,
            _pad: 0,
        },
        resource_id: if visible { RES_CURSOR } else { 0 },
        hot_x: 0,
        hot_y: 0,
        _pad: 0,
    };
    cursorq_send(
        &upd as *const _ as *const u8,
        core::mem::size_of::<UpdateCursor>(),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialisation
// ─────────────────────────────────────────────────────────────────────────────

pub fn init() {
    let (mmio_bar0, ecam_base, bus, dev_slot) = match probe_pci() {
        Some(x) => x,
        None => return,
    };

    // Walk the PCI capability list for the three virtio-pci caps we need.
    let (common_cfg, notify_base, notify_off_mult, _device_cfg) =
        match walk_caps(ecam_base, bus, dev_slot) {
            Some(x) => x,
            None => return,
        };
    let _ = mmio_bar0; // bar0 is decoded into common_cfg/notify_base above

    // ── Feature negotiation ────────────────────────────────────────────────
    unsafe {
        ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS, STATUS_RESET);
        ccfg_writeb(
            common_cfg,
            common_cfg_off::DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER,
        );

        // Select feature bits 0-31 and accept whatever the device offers.
        ccfg_writel(common_cfg, common_cfg_off::DEVICE_FEATURE_SELECT, 0);
        let feat0 = ccfg_readl(common_cfg, common_cfg_off::DEVICE_FEATURE);
        ccfg_writel(common_cfg, common_cfg_off::DRIVER_FEATURE_SELECT, 0);
        ccfg_writel(common_cfg, common_cfg_off::DRIVER_FEATURE, feat0);

        // Feature bits 32-63.
        ccfg_writel(common_cfg, common_cfg_off::DEVICE_FEATURE_SELECT, 1);
        let feat1 = ccfg_readl(common_cfg, common_cfg_off::DEVICE_FEATURE);
        ccfg_writel(common_cfg, common_cfg_off::DRIVER_FEATURE_SELECT, 1);
        ccfg_writel(common_cfg, common_cfg_off::DRIVER_FEATURE, feat1);

        // Signal FEATURES_OK and verify the device accepted.
        ccfg_writeb(
            common_cfg,
            common_cfg_off::DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
        );
        let st = ccfg_readb(common_cfg, common_cfg_off::DEVICE_STATUS);
        if st & STATUS_FEATURES_OK == 0 {
            ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS, STATUS_FAILED);
            return;
        }
    }

    // ── Virtqueue setup ────────────────────────────────────────────────────
    let ctrlq = match setup_queue(common_cfg, CONTROLQ) {
        Some(q) => q,
        None => {
            unsafe {
                ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS, STATUS_FAILED);
            }
            return;
        }
    };
    let cursorq = match setup_queue(common_cfg, CURSORQ) {
        Some(q) => q,
        None => {
            unsafe {
                ccfg_writeb(common_cfg, common_cfg_off::DEVICE_STATUS, STATUS_FAILED);
            }
            return;
        }
    };

    // ── DRIVER_OK ──────────────────────────────────────────────────────────
    unsafe {
        ccfg_writeb(
            common_cfg,
            common_cfg_off::DEVICE_STATUS,
            STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
        );
    }

    // Publish device skeleton so controlq_send_recv can use it.
    *DEVICE.lock() = Some(VirtioGpu {
        common_cfg,
        notify_base,
        notify_off_multiplier: notify_off_mult,
        fb_phys: 0,
        width: 0,
        height: 0,
        cursor_phys: 0,
        ctrlq,
        cursorq,
    });
    PRESENT.store(true, Ordering::Release);

    // ── Query display info ─────────────────────────────────────────────────
    let (width, height) = query_display_info().unwrap_or_else(|| {
        gop::get()
            .map(|g| (g.width, g.height))
            .unwrap_or((1024, 768))
    });

    // ── Allocate backing stores ────────────────────────────────────────────
    let fb_pages = size_pages(width as usize * height as usize * 4);
    let cur_pages = size_pages(CURSOR_W as usize * CURSOR_H as usize * 4);

    let fb_phys = match crate::mm::pmm::alloc_pages(fb_pages) {
        Some(p) => p.as_ptr() as u64,
        None => {
            PRESENT.store(false, Ordering::Release);
            *DEVICE.lock() = None;
            return;
        }
    };
    let cursor_phys = match crate::mm::pmm::alloc_pages(cur_pages) {
        Some(p) => p.as_ptr() as u64,
        None => {
            crate::mm::pmm::free_pages(
                unsafe { core::ptr::NonNull::new_unchecked(fb_phys as *mut u8) },
                fb_pages,
            );
            PRESENT.store(false, Ordering::Release);
            *DEVICE.lock() = None;
            return;
        }
    };

    // ── GPU resource setup commands ────────────────────────────────────────
    // RESOURCE_CREATE_2D — framebuffer
    let c = ResourceCreate2d {
        hdr: ctrl_hdr(cmd::RESOURCE_CREATE_2D),
        resource_id: RES_FB,
        format: FORMAT_B8G8R8X8_UNORM,
        width,
        height,
    };
    controlq_send_recv(&c as *const _ as *const u8, core::mem::size_of_val(&c));

    // RESOURCE_CREATE_2D — cursor
    let c = ResourceCreate2d {
        hdr: ctrl_hdr(cmd::RESOURCE_CREATE_2D),
        resource_id: RES_CURSOR,
        format: FORMAT_B8G8R8X8_UNORM,
        width: CURSOR_W,
        height: CURSOR_H,
    };
    controlq_send_recv(&c as *const _ as *const u8, core::mem::size_of_val(&c));

    // RESOURCE_ATTACH_BACKING — framebuffer
    attach_backing(RES_FB, fb_phys, width * height * 4);

    // RESOURCE_ATTACH_BACKING — cursor
    attach_backing(RES_CURSOR, cursor_phys, CURSOR_W * CURSOR_H * 4);

    // SET_SCANOUT
    let ss = SetScanout {
        hdr: ctrl_hdr(cmd::SET_SCANOUT),
        r: Rect { x: 0, y: 0, width, height },
        scanout_id: SCANOUT_ID,
        resource_id: RES_FB,
    };
    controlq_send_recv(&ss as *const _ as *const u8, core::mem::size_of_val(&ss));

    // Publish dimensions and backing stores.
    if let Some(d) = DEVICE.lock().as_mut() {
        d.fb_phys = fb_phys;
        d.width = width;
        d.height = height;
        d.cursor_phys = cursor_phys;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtqueue send helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Submit `cmd_buf` on the controlq and wait for the device's response.
/// The response is discarded (callers that need it use `controlq_request`).
fn controlq_send_recv(cmd_ptr: *const u8, cmd_len: usize) {
    // Copy command into the static scratch buffer so the descriptor points
    // at a stable physical address.
    let cmd_pa;
    let rsp_pa;
    {
        let mut buf = CTRL_CMD_BUF.lock();
        let len = cmd_len.min(SCRATCH_CMD_BYTES);
        unsafe { core::ptr::copy_nonoverlapping(cmd_ptr, buf.as_mut_ptr(), len) };
        cmd_pa = buf.as_ptr() as u64;
        // Unlock buf before locking rsp (avoid ordering issues).
        drop(buf);
        let rsp = CTRL_RSP_BUF.lock();
        rsp_pa = rsp.as_ptr() as u64;
        drop(rsp);
    }

    let mut dev_guard = DEVICE.lock();
    let dev = match dev_guard.as_mut() {
        Some(d) => d,
        None => return,
    };

    unsafe {
        // 2-descriptor chain: [0] cmd (device-readable) → [1] rsp (device-writable)
        let head = dev.ctrlq.alloc_chain(2);
        dev.ctrlq.write_desc(
            head,
            cmd_pa,
            cmd_len as u32,
            VRING_DESC_F_NEXT,
            (head + 1) as u16,
        );
        dev.ctrlq.write_desc(
            head + 1,
            rsp_pa,
            core::mem::size_of::<RespNodata>() as u32,
            VRING_DESC_F_WRITE,
            0,
        );
        dev.ctrlq.avail_push(head as u16);
        queue_notify(dev, CONTROLQ);
        dev.ctrlq.poll_used();
    }
}

/// Submit a 2-part command on the controlq (AttachBacking + MemEntry chain).
fn controlq_send2_recv(
    cmd1_ptr: *const u8,
    cmd1_len: usize,
    cmd2_ptr: *const u8,
    cmd2_len: usize,
) {
    let pa1;
    let pa2;
    let rsp_pa;
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
        drop(rsp);
    }

    let mut dev_guard = DEVICE.lock();
    let dev = match dev_guard.as_mut() {
        Some(d) => d,
        None => return,
    };

    unsafe {
        // 3-descriptor chain: [0] hdr → [1] mem-entry → [2] response
        let head = dev.ctrlq.alloc_chain(3);
        dev.ctrlq.write_desc(
            head,
            pa1,
            cmd1_len as u32,
            VRING_DESC_F_NEXT,
            (head + 1) as u16,
        );
        dev.ctrlq.write_desc(
            head + 1,
            pa2,
            cmd2_len as u32,
            VRING_DESC_F_NEXT,
            (head + 2) as u16,
        );
        dev.ctrlq.write_desc(
            head + 2,
            rsp_pa,
            core::mem::size_of::<RespNodata>() as u32,
            VRING_DESC_F_WRITE,
            0,
        );
        dev.ctrlq.avail_push(head as u16);
        queue_notify(dev, CONTROLQ);
        dev.ctrlq.poll_used();
    }
}

/// Submit a command on the cursorq (no response; spec §5.7.6.8).
fn cursorq_send(cmd_ptr: *const u8, cmd_len: usize) {
    let cmd_pa;
    {
        let mut buf = CUR_CMD_BUF.lock();
        let len = cmd_len.min(buf.len());
        unsafe { core::ptr::copy_nonoverlapping(cmd_ptr, buf.as_mut_ptr(), len) };
        cmd_pa = buf.as_ptr() as u64;
        drop(buf);
    }

    let mut dev_guard = DEVICE.lock();
    let dev = match dev_guard.as_mut() {
        Some(d) => d,
        None => return,
    };

    unsafe {
        let head = dev.cursorq.alloc_chain(1);
        dev.cursorq.write_desc(head, cmd_pa, cmd_len as u32, 0, 0);
        dev.cursorq.avail_push(head as u16);
        queue_notify(dev, CURSORQ);
        // No poll — cursorq is fire-and-forget.
    }
}

/// Send RESOURCE_ATTACH_BACKING as a 2-part command.
fn attach_backing(resource_id: u32, phys: u64, byte_len: u32) {
    let hdr = AttachBacking {
        hdr: ctrl_hdr(cmd::RESOURCE_ATTACH_BACKING),
        resource_id,
        nr_entries: 1,
    };
    let entry = MemEntry { addr: phys, length: byte_len, _pad: 0 };
    controlq_send2_recv(
        &hdr as *const _ as *const u8,
        core::mem::size_of::<AttachBacking>(),
        &entry as *const _ as *const u8,
        core::mem::size_of::<MemEntry>(),
    );
}

/// Write queue index to the notify register for `queue_idx`.
#[inline]
unsafe fn queue_notify(dev: &VirtioGpu, queue_idx: u16) {
    let notify_off = if queue_idx == CONTROLQ {
        dev.ctrlq.notify_off
    } else {
        dev.cursorq.notify_off
    };
    let addr = dev.notify_base
        + (notify_off as u32 * dev.notify_off_multiplier) as u64;
    (addr as *mut u16).write_volatile(queue_idx);
    fence(Ordering::SeqCst);
}

// ─────────────────────────────────────────────────────────────────────────────
// Display-info query
// ─────────────────────────────────────────────────────────────────────────────

fn query_display_info() -> Option<(u32, u32)> {
    let req = ctrl_hdr(cmd::GET_DISPLAY_INFO);

    // Use rsp buffer directly for the large response.
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
        let dev = dev_guard.as_mut()?;
        unsafe {
            let head = dev.ctrlq.alloc_chain(2);
            dev.ctrlq.write_desc(
                head,
                cmd_pa,
                core::mem::size_of::<CtrlHdr>() as u32,
                VRING_DESC_F_NEXT,
                (head + 1) as u16,
            );
            dev.ctrlq.write_desc(
                head + 1,
                rsp_pa,
                core::mem::size_of::<DisplayInfoResp>() as u32,
                VRING_DESC_F_WRITE,
                0,
            );
            dev.ctrlq.avail_push(head as u16);
            queue_notify(dev, CONTROLQ);
            dev.ctrlq.poll_used();
        }
    }

    // Parse response from scratch buffer.
    let rsp_buf = CTRL_RSP_BUF.lock();
    let rsp = unsafe { &*(rsp_buf.as_ptr() as *const DisplayInfoResp) };
    if rsp.hdr.type_ == cmd::RESP_OK_DISPLAY_INFO && rsp.modes[0].enabled != 0 {
        let w = rsp.modes[0].r.width;
        let h = rsp.modes[0].r.height;
        if w > 0 && h > 0 {
            return Some((w, h));
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtqueue allocation
// ─────────────────────────────────────────────────────────────────────────────

fn setup_queue(common_cfg: u64, queue_idx: u16) -> Option<Virtqueue> {
    unsafe {
        // Select the queue.
        ccfg_writew(common_cfg, common_cfg_off::QUEUE_SELECT, queue_idx);

        // Read negotiated size (device may clamp it).
        let dev_size = ccfg_readw(common_cfg, common_cfg_off::QUEUE_SIZE) as usize;
        let qsize = dev_size.min(QUEUE_SIZE);
        if qsize == 0 {
            return None;
        }

        // Allocate 2 pages: page 0 = desc + avail, page 1 = used.
        let p0 = crate::mm::pmm::alloc_page()? as u64;
        let p1 = crate::mm::pmm::alloc_page()? as u64;
        core::ptr::write_bytes(p0 as *mut u8, 0, 4096);
        core::ptr::write_bytes(p1 as *mut u8, 0, 4096);

        let desc_pa = p0;
        let avail_pa = p0 + AVAIL_OFF as u64;
        let used_pa = p1;

        // Program the queue addresses into common-cfg.
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_SIZE, qsize as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_DESC_LO, desc_pa as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_DESC_HI, (desc_pa >> 32) as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_AVAIL_LO, avail_pa as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_AVAIL_HI, (avail_pa >> 32) as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_USED_LO, used_pa as u32);
        ccfg_writel(common_cfg, common_cfg_off::QUEUE_USED_HI, (used_pa >> 32) as u32);

        // Read back notify offset for this queue.
        let notify_off = ccfg_readw(common_cfg, common_cfg_off::QUEUE_NOTIFY_OFF);

        // Enable the queue.
        ccfg_writew(common_cfg, common_cfg_off::QUEUE_ENABLE, 1);

        Some(Virtqueue {
            desc_pa,
            used_pa,
            base_va: p0 as *mut u8,
            free_head: 0,
            avail_idx: 0,
            last_used: 0,
            notify_off,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PCIe probe
// ─────────────────────────────────────────────────────────────────────────────

/// Scan ECAM bus 0 for a virtio-gpu device.
/// Returns (bar0_phys, ecam_base, bus, dev_slot).
fn probe_pci() -> Option<(u64, u64, u8, u8)> {
    let ecam_base: u64 = crate::acpi::pcie_ecam_base().unwrap_or(0x3000_0000);

    for dev in 0u8..32 {
        let cfg = ecam_cfg(ecam_base, 0, dev, 0);
        let id = unsafe { (cfg as *const u32).read_volatile() };
        if id == 0xFFFF_FFFF {
            continue;
        }
        let vendor = (id & 0xFFFF) as u16;
        let device = (id >> 16) as u16;
        if vendor != VIRTIO_VENDOR {
            continue;
        }
        if device != VIRTIO_GPU_MODERN && device != VIRTIO_GPU_TRANS {
            continue;
        }

        // Enable bus-master + memory-space access (command register at 0x04).
        let cmd_addr = cfg + 0x04;
        let cmd = unsafe { (cmd_addr as *const u16).read_volatile() };
        unsafe { (cmd_addr as *mut u16).write_volatile(cmd | 0x06) };

        // BAR0 at offset 0x10.
        let bar0 = unsafe { ((cfg + 0x10) as *const u32).read_volatile() };
        if bar0 & 1 != 0 {
            continue; // I/O BAR — modern virtio uses memory BARs only
        }
        let bar_type = (bar0 >> 1) & 3;
        let bar0_phys: u64 = if bar_type == 2 {
            let bar1 = unsafe { ((cfg + 0x14) as *const u32).read_volatile() };
            (bar0 as u64 & !0xF) | ((bar1 as u64) << 32)
        } else {
            bar0 as u64 & !0xF
        };

        return Some((bar0_phys, ecam_base, 0, dev));
    }
    None
}

/// Walk the PCI capability list for the three virtio-pci caps.
/// Returns (common_cfg_va, notify_base_va, notify_off_multiplier, device_cfg_va).
fn walk_caps(ecam_base: u64, bus: u8, dev: u8, func: u8) -> Option<(u64, u64, u32, u64)> {
    let cfg_base = ecam_cfg(ecam_base, bus, dev, func);

    // Cap pointer is at config offset 0x34.
    let mut cap_ptr =
        unsafe { ((cfg_base + 0x34) as *const u8).read_volatile() } & !3;

    let mut common_cfg = 0u64;
    let mut notify_base = 0u64;
    let mut notify_mult = 4u32; // spec default
    let mut device_cfg = 0u64;

    while cap_ptr != 0 {
        let cap_off = cfg_base + cap_ptr as u64;
        // PCI cap header: [0] cap_id, [1] next_ptr
        let cap_id = unsafe { (cap_off as *const u8).read_volatile() };
        let next = unsafe { ((cap_off + 1) as *const u8).read_volatile() } & !3;

        // virtio-pci caps have cap_id = 0x09 (Vendor Specific).
        if cap_id == 0x09 {
            // virtio-pci cap layout (spec §4.1.4):
            //   [2]  cfg_type  u8
            //   [3]  bar       u8
            //   [4]  pad[3]
            //   [8]  offset    u32
            //   [12] length    u32
            //   [16] (notify only) notify_off_multiplier u32
            let cfg_type = unsafe { ((cap_off + 2) as *const u8).read_volatile() };
            let bar_idx = unsafe { ((cap_off + 3) as *const u8).read_volatile() };
            let bar_off = unsafe { ((cap_off + 8) as *const u32).read_volatile() } as u64;

            let bar_phys = read_bar(ecam_base, bus, dev, func, bar_idx);

            match cfg_type {
                c if c == VIRTIO_PCI_CAP_COMMON_CFG => {
                    common_cfg = bar_phys + bar_off;
                }
                c if c == VIRTIO_PCI_CAP_NOTIFY_CFG => {
                    notify_base = bar_phys + bar_off;
                    notify_mult =
                        unsafe { ((cap_off + 16) as *const u32).read_volatile() };
                }
                c if c == VIRTIO_PCI_CAP_DEVICE_CFG => {
                    device_cfg = bar_phys + bar_off;
                }
                _ => {}
            }
        }

        cap_ptr = next;
    }

    if common_cfg == 0 || notify_base == 0 {
        return None;
    }
    Some((common_cfg, notify_base, notify_mult, device_cfg))
}

/// Return the MMIO physical address of BARn for the given device.
fn read_bar(ecam_base: u64, bus: u8, dev: u8, func: u8, bar: u8) -> u64 {
    if bar > 5 {
        return 0;
    }
    let cfg = ecam_cfg(ecam_base, bus, dev, func);
    let bar_reg = unsafe { ((cfg + 0x10 + bar as u64 * 4) as *const u32).read_volatile() };
    if bar_reg & 1 != 0 {
        return 0; // I/O BAR
    }
    let bar_type = (bar_reg >> 1) & 3;
    if bar_type == 2 && bar < 5 {
        let bar_hi = unsafe {
            ((cfg + 0x10 + (bar as u64 + 1) * 4) as *const u32).read_volatile()
        };
        (bar_reg as u64 & !0xF) | ((bar_hi as u64) << 32)
    } else {
        bar_reg as u64 & !0xF
    }
}

/// Compute ECAM config-space address for bus/dev/func.
#[inline]
fn ecam_cfg(base: u64, bus: u8, dev: u8, func: u8) -> u64 {
    base + ((bus as u64) << 20) + ((dev as u64) << 15) + ((func as u64) << 12)
}

// ─────────────────────────────────────────────────────────────────────────────
// common-cfg MMIO accessors
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
unsafe fn ccfg_readb(base: u64, off: usize) -> u8 {
    ((base + off as u64) as *const u8).read_volatile()
}
#[inline]
unsafe fn ccfg_readw(base: u64, off: usize) -> u16 {
    ((base + off as u64) as *const u16).read_volatile()
}
#[inline]
unsafe fn ccfg_readl(base: u64, off: usize) -> u32 {
    ((base + off as u64) as *const u32).read_volatile()
}
#[inline]
unsafe fn ccfg_writeb(base: u64, off: usize, val: u8) {
    ((base + off as u64) as *mut u8).write_volatile(val);
}
#[inline]
unsafe fn ccfg_writew(base: u64, off: usize, val: u16) {
    ((base + off as u64) as *mut u16).write_volatile(val);
}
#[inline]
unsafe fn ccfg_writel(base: u64, off: usize, val: u32) {
    ((base + off as u64) as *mut u32).write_volatile(val);
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn ctrl_hdr(type_: u32) -> CtrlHdr {
    CtrlHdr { type_, flags: 0, fence_id: 0, ctx_id: 0, _pad: 0 }
}

#[inline]
fn size_pages(bytes: usize) -> usize {
    (bytes + 0xFFF) / 0x1000
}
