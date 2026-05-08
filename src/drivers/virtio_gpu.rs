//! virtio-gpu device driver — controlq (TRANSFER + FLUSH) and cursorq
//! (UPDATE_CURSOR / MOVE_CURSOR).
//!
//! ## Architecture
//!
//! ```text
//! drm.rs / framebuffer.rs
//!        |
//!        v
//! virtio_gpu::flush_all()        -- TRANSFER_TO_HOST_2D + RESOURCE_FLUSH
//! virtio_gpu::cursor_update()    -- UPDATE_CURSOR (upload + show)
//! virtio_gpu::cursor_move()      -- MOVE_CURSOR   (position only)
//! ```
//!
//! The driver is initialised once at boot via `init()`.  After that the
//! static `DEVICE` singleton holds the negotiated resource id, the
//! scanout dimensions, and the framebuffer physical address returned by
//! `VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING`.
//!
//! ### Resource layout
//!
//! | Resource ID  | Purpose                          |
//! |--------------|----------------------------------|
//! | `RES_FB`     | Primary scanout framebuffer      |
//! | `RES_CURSOR` | 64×64 ARGB cursor bitmap         |

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use crate::drivers::gop;

// ─────────────────────────────────────────────────────────────────────────────
// virtio-gpu command / response type codes
// ─────────────────────────────────────────────────────────────────────────────

#[allow(dead_code)]
mod cmd {
    pub const GET_DISPLAY_INFO: u32 = 0x0100;
    pub const RESOURCE_CREATE_2D: u32 = 0x0101;
    pub const RESOURCE_UNREF: u32 = 0x0102;
    pub const SET_SCANOUT: u32 = 0x0103;
    pub const RESOURCE_FLUSH: u32 = 0x0104;
    pub const TRANSFER_TO_HOST_2D: u32 = 0x0105;
    pub const RESOURCE_ATTACH_BACKING: u32 = 0x0106;
    pub const RESOURCE_DETACH_BACKING: u32 = 0x0107;
    pub const GET_CAPSET_INFO: u32 = 0x0108;
    pub const GET_CAPSET: u32 = 0x0109;
    pub const GET_EDID: u32 = 0x010a;
    // cursor commands
    pub const UPDATE_CURSOR: u32 = 0x0300;
    pub const MOVE_CURSOR: u32 = 0x0301;
    // response codes
    pub const RESP_OK_NODATA: u32 = 0x1100;
    pub const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
    pub const RESP_ERR_UNSPEC: u32 = 0x1200;
}

/// Pixel format — BGRX / XRGB 32bpp (same as DRM_FORMAT_XRGB8888).
const FORMAT_B8G8R8X8_UNORM: u32 = 2;

/// Scanout index (we always use scanout 0).
const SCANOUT_ID: u32 = 0;

/// virtio-gpu resource IDs (kernel-chosen, must be != 0).
const RES_FB: u32 = 1;
const RES_CURSOR: u32 = 2;

/// Cursor dimensions (must match drm.rs CURSOR_W/CURSOR_H).
const CURSOR_W: u32 = 64;
const CURSOR_H: u32 = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Wire structs  (repr C, little-endian as spec requires)
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

// ─────────────────────────────────────────────────────────────────────────────
// Device singleton
// ─────────────────────────────────────────────────────────────────────────────

struct VirtioGpu {
    /// Physical address of the framebuffer backing store.
    fb_phys: u64,
    /// Framebuffer dimensions (pixels).
    width: u32,
    height: u32,
    /// Physical address of the cursor bitmap backing store.
    cursor_phys: u64,
    /// MMIO base of the virtio-gpu device registers.
    mmio_base: u64,
    /// controlq descriptor-ring physical base.
    ctrlq_phys: u64,
    /// cursorq descriptor-ring physical base.
    cursorq_phys: u64,
}

static DEVICE: Mutex<Option<VirtioGpu>> = Mutex::new(None);
static PRESENT: AtomicBool = AtomicBool::new(false);

// ─────────────────────────────────────────────────────────────────────────────
// Public API (called by drm.rs and framebuffer.rs)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns `true` if a virtio-gpu device was detected and initialised.
#[inline]
pub fn is_present() -> bool {
    PRESENT.load(Ordering::Relaxed)
}

/// Returns the scanout dimensions, or `None` if no virtio-gpu device.
pub fn dimensions() -> Option<(u32, u32)> {
    let dev = DEVICE.lock();
    dev.as_ref().map(|d| (d.width, d.height))
}

/// Returns the physical address of the primary framebuffer, or `None`.
pub fn fb_phys() -> Option<u64> {
    let dev = DEVICE.lock();
    dev.as_ref().map(|d| d.fb_phys)
}

/// Flush the entire primary framebuffer to the host display:
/// issues TRANSFER_TO_HOST_2D followed by RESOURCE_FLUSH.
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

/// Flush a sub-rectangle of the framebuffer (damage tracking).
#[allow(dead_code)]
pub fn flush_rect(phys: u64, fb_w: u32, fb_h: u32, x: u32, y: u32, rw: u32, rh: u32) {
    let transfer = TransferToHost2d {
        hdr: ctrl_hdr(cmd::TRANSFER_TO_HOST_2D),
        r: Rect {
            x,
            y,
            width: rw,
            height: rh,
        },
        offset: (y * fb_w + x) as u64 * 4,
        resource_id: RES_FB,
        _pad: 0,
    };
    let flush = ResourceFlush {
        hdr: ctrl_hdr(cmd::RESOURCE_FLUSH),
        r: Rect {
            x,
            y,
            width: rw,
            height: rh,
        },
        resource_id: RES_FB,
        _pad: 0,
    };
    let _ = (phys, fb_h); // used only when virtqueue is wired in
    controlq_send(
        &transfer as *const _ as *const u8,
        core::mem::size_of::<TransferToHost2d>(),
    );
    controlq_send(
        &flush as *const _ as *const u8,
        core::mem::size_of::<ResourceFlush>(),
    );
}

/// Upload a new 64×64 ARGB cursor bitmap and show it at (x, y).
/// Sends VIRTIO_GPU_CMD_UPDATE_CURSOR on the cursorq.
pub fn cursor_update(pixels: &[u32], x: i32, y: i32) {
    let cursor_phys = {
        let dev = DEVICE.lock();
        match dev.as_ref() {
            Some(d) => d.cursor_phys,
            // No virtio-gpu; the software cursor in drm.rs handles it.
            None => return,
        }
    };

    let n = (CURSOR_W * CURSOR_H) as usize;
    let src = pixels.as_ptr();
    let dst = cursor_phys as *mut u32;
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, n.min(pixels.len()));
    }

    let cmd = UpdateCursor {
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
        &cmd as *const _ as *const u8,
        core::mem::size_of::<UpdateCursor>(),
    );
}

/// Move the hardware cursor without re-uploading the bitmap.
/// Sends VIRTIO_GPU_CMD_MOVE_CURSOR on the cursorq.
/// `visible = false` hides the cursor by setting resource_id = 0.
pub fn cursor_move(x: i32, y: i32, visible: bool) {
    if !is_present() {
        return;
    }
    let cmd = UpdateCursor {
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
        &cmd as *const _ as *const u8,
        core::mem::size_of::<UpdateCursor>(),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Initialisation
// ─────────────────────────────────────────────────────────────────────────────

/// Probe and initialise the virtio-gpu device.
///
/// Called once from `kernel_main` after PCIe enumeration completes.
/// On success, `is_present()` returns `true` and `dimensions()` /
/// `fb_phys()` are valid.
///
/// Failure is non-fatal: the GOP framebuffer fallback in `gop.rs`
/// remains available.
pub fn init() {
    let mmio = match probe_pci() {
        Some(m) => m,
        // No virtio-gpu on this machine — silently fall back to GOP.
        None => return,
    };

    let (width, height) = query_display_info(mmio).unwrap_or_else(|| {
        gop::get()
            .map(|g| (g.width, g.height))
            .unwrap_or((1024, 768))
    });

    let fb_pages = fb_size_pages(width, height);
    let cursor_pages = cursor_size_pages();

    let fb_phys = match crate::mm::pmm::alloc_pages(fb_pages) {
        Some(p) => p.as_ptr() as u64,
        None => return,
    };
    let cursor_phys = match crate::mm::pmm::alloc_pages(cursor_pages) {
        Some(p) => p.as_ptr() as u64,
        None => {
            crate::mm::pmm::free_pages(
                unsafe { core::ptr::NonNull::new_unchecked(fb_phys as *mut u8) },
                fb_pages,
            );
            return;
        }
    };

    let create_fb = ResourceCreate2d {
        hdr: ctrl_hdr(cmd::RESOURCE_CREATE_2D),
        resource_id: RES_FB,
        format: FORMAT_B8G8R8X8_UNORM,
        width,
        height,
    };
    let create_cur = ResourceCreate2d {
        hdr: ctrl_hdr(cmd::RESOURCE_CREATE_2D),
        resource_id: RES_CURSOR,
        format: FORMAT_B8G8R8X8_UNORM,
        width: CURSOR_W,
        height: CURSOR_H,
    };
    let attach_fb = AttachBacking {
        hdr: ctrl_hdr(cmd::RESOURCE_ATTACH_BACKING),
        resource_id: RES_FB,
        nr_entries: 1,
    };
    let entry_fb = MemEntry {
        addr: fb_phys,
        length: (width * height * 4) as u32,
        _pad: 0,
    };
    let attach_cur = AttachBacking {
        hdr: ctrl_hdr(cmd::RESOURCE_ATTACH_BACKING),
        resource_id: RES_CURSOR,
        nr_entries: 1,
    };
    let entry_cur = MemEntry {
        addr: cursor_phys,
        length: (CURSOR_W * CURSOR_H * 4) as u32,
        _pad: 0,
    };
    let scanout = SetScanout {
        hdr: ctrl_hdr(cmd::SET_SCANOUT),
        r: Rect {
            x: 0,
            y: 0,
            width,
            height,
        },
        scanout_id: SCANOUT_ID,
        resource_id: RES_FB,
    };

    controlq_send(
        &create_fb as *const _ as *const u8,
        core::mem::size_of::<ResourceCreate2d>(),
    );
    controlq_send(
        &create_cur as *const _ as *const u8,
        core::mem::size_of::<ResourceCreate2d>(),
    );
    send_attach_backing(&attach_fb, &entry_fb);
    send_attach_backing(&attach_cur, &entry_cur);
    controlq_send(
        &scanout as *const _ as *const u8,
        core::mem::size_of::<SetScanout>(),
    );

    *DEVICE.lock() = Some(VirtioGpu {
        fb_phys,
        width,
        height,
        cursor_phys,
        mmio_base: mmio,
        ctrlq_phys: 0,   // TODO: full virtqueue ring setup
        cursorq_phys: 0,
    });
    PRESENT.store(true, Ordering::Release);
}

// ─────────────────────────────────────────────────────────────────────────────
// PCIe probe
// ─────────────────────────────────────────────────────────────────────────────

/// Walk PCIe ECAM config space for a virtio-gpu device.
/// Returns the MMIO BAR0 base address, or `None` if not found.
fn probe_pci() -> Option<u64> {
    const VIRTIO_VENDOR: u16 = 0x1AF4;
    const VIRTIO_GPU_DEV_MODERN: u16 = 0x1050;
    const VIRTIO_GPU_DEV_TRANS: u16 = 0x1002;

    let ecam_base: u64 = crate::acpi::pcie_ecam_base().unwrap_or(0x3000_0000);

    for dev in 0u64..32 {
        let cfg = (ecam_base + (dev << 15)) as *const u32;
        let id = unsafe { cfg.read_volatile() };
        let vendor = (id & 0xFFFF) as u16;
        let device = (id >> 16) as u16;
        if vendor != VIRTIO_VENDOR {
            continue;
        }
        if device != VIRTIO_GPU_DEV_MODERN && device != VIRTIO_GPU_DEV_TRANS {
            continue;
        }
        // BAR0 at config offset 0x10.
        let bar0 = unsafe { cfg.add(4).read_volatile() };
        if bar0 & 1 != 0 {
            continue; // I/O BAR — skip
        }
        let bar_type = (bar0 >> 1) & 3;
        let mmio: u64 = if bar_type == 2 {
            let bar1 = unsafe { cfg.add(5).read_volatile() };
            (bar0 as u64 & !0xF) | ((bar1 as u64) << 32)
        } else {
            (bar0 as u64) & !0xF
        };
        return Some(mmio);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Display-info query
// ─────────────────────────────────────────────────────────────────────────────

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

fn query_display_info(mmio: u64) -> Option<(u32, u32)> {
    let _ = mmio;
    let req = ctrl_hdr(cmd::GET_DISPLAY_INFO);
    let mut resp = DisplayInfoResp {
        hdr: CtrlHdr::default(),
        modes: [DisplayOne::default(); 16],
    };
    controlq_request(
        &req as *const _ as *const u8,
        core::mem::size_of::<CtrlHdr>(),
        &mut resp as *mut _ as *mut u8,
        core::mem::size_of::<DisplayInfoResp>(),
    );
    if resp.hdr.type_ == cmd::RESP_OK_DISPLAY_INFO && resp.modes[0].enabled != 0 {
        let w = resp.modes[0].r.width;
        let h = resp.modes[0].r.height;
        if w > 0 && h > 0 {
            return Some((w, h));
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Virtqueue I/O stubs
// ─────────────────────────────────────────────────────────────────────────────
//
// A full virtqueue implementation involves:
//   - negotiating features via the virtio MMIO/PCI common-cfg registers
//   - setting up descriptor rings (avail / used / desc tables)
//   - writing descriptors, kicking the queue via the notify register
//   - polling the used ring for completions
//
// The stubs below provide the correct call signatures used throughout
// this file.  Replace the bodies with real ring operations when the
// full virtqueue layer is wired in.

/// Send a command on the controlq and discard the response.
fn controlq_send(cmd_buf: *const u8, cmd_len: usize) {
    // TODO: wire to real virtqueue descriptor + notify
    let _ = (cmd_buf, cmd_len);
}

/// Send a command on the controlq and wait for a response.
fn controlq_request(
    cmd_buf: *const u8,
    cmd_len: usize,
    resp_buf: *mut u8,
    resp_len: usize,
) {
    // TODO: wire to real virtqueue with completion poll
    let _ = (cmd_buf, cmd_len, resp_buf, resp_len);
}

/// Send a command on the cursorq (no response expected per spec).
fn cursorq_send(cmd_buf: *const u8, cmd_len: usize) {
    // TODO: wire to real virtqueue descriptor + notify
    let _ = (cmd_buf, cmd_len);
}

/// Send an ATTACH_BACKING command followed by its memory-entry descriptor.
fn send_attach_backing(hdr: &AttachBacking, entry: &MemEntry) {
    controlq_send(
        hdr as *const _ as *const u8,
        core::mem::size_of::<AttachBacking>(),
    );
    controlq_send(
        entry as *const _ as *const u8,
        core::mem::size_of::<MemEntry>(),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

#[inline]
fn ctrl_hdr(type_: u32) -> CtrlHdr {
    CtrlHdr {
        type_,
        flags: 0,
        fence_id: 0,
        ctx_id: 0,
        _pad: 0,
    }
}

#[inline]
fn fb_size_pages(w: u32, h: u32) -> usize {
    let bytes = (w as usize) * (h as usize) * 4;
    (bytes + 0xFFF) / 0x1000
}

#[inline]
fn cursor_size_pages() -> usize {
    let bytes = (CURSOR_W as usize) * (CURSOR_H as usize) * 4;
    (bytes + 0xFFF) / 0x1000
}
