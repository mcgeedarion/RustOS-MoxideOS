//! DRM/KMS subsystem (kernel-mode setting).
//!
//! Implements a minimal DRM-compatible KMS layer:
//!   - CRTC management (one virtual CRTC per display)
//!   - Connector enumeration (HDMI, DisplayPort, VGA)
//!   - Plane management (primary plane + one overlay)
//!   - Atomic modesetting via `drm_atomic_commit`
//!   - GEM buffer object lifecycle (alloc/free/map)
//!
//! ## Architecture
//!   DrmDevice
//!     ├─ Vec<Crtc>     (one per physical display controller)
//!     ├─ Vec<Connector>(one per physical output port)
//!     ├─ Vec<Plane>    (primary + overlay planes)
//!     └─ GemHeap       (DMA-coherent GEM buffer allocator)
//!
//! ## Usage
//!   ```rust
//!   drm::init();
//!   let fb = drm::gem_alloc(width * height * 4)?;
//!   drm::atomic_commit(crtc_id, connector_id, &mode, fb);
//!   ```

extern crate alloc;
use alloc::vec::Vec;
use spin::Mutex;

use crate::drivers::gpu::framebuffer::{Framebuffer, PixelFormat};

// ---------------------------------------------------------------------------
// Display mode
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DisplayMode {
    pub hdisplay:    u16,
    pub vdisplay:    u16,
    pub clock_khz:   u32,  // pixel clock
    pub hsync_start: u16,
    pub hsync_end:   u16,
    pub htotal:      u16,
    pub vsync_start: u16,
    pub vsync_end:   u16,
    pub vtotal:      u16,
    pub flags:       u32,
}

impl DisplayMode {
    /// Standard 1920x1080 @ 60 Hz
    pub fn fullhd_60() -> Self {
        Self {
            hdisplay: 1920, vdisplay: 1080, clock_khz: 148_500,
            hsync_start: 2008, hsync_end: 2052, htotal: 2200,
            vsync_start: 1084, vsync_end: 1089, vtotal: 1125,
            flags: 0,
        }
    }
    /// Standard 1280x720 @ 60 Hz
    pub fn hd_60() -> Self {
        Self {
            hdisplay: 1280, vdisplay: 720, clock_khz: 74_250,
            hsync_start: 1390, hsync_end: 1430, htotal: 1650,
            vsync_start: 725, vsync_end: 730, vtotal: 750,
            flags: 0,
        }
    }
    /// 800x600 @ 60 Hz (SVGA)
    pub fn svga_60() -> Self {
        Self {
            hdisplay: 800, vdisplay: 600, clock_khz: 40_000,
            hsync_start: 840, hsync_end: 968, htotal: 1056,
            vsync_start: 601, vsync_end: 605, vtotal: 628,
            flags: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Connector types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectorType {
    HDMI,
    DisplayPort,
    VGA,
    LVDS,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Connector {
    pub id:         u32,
    pub kind:       ConnectorType,
    pub connected:  bool,
    pub modes:      Vec<DisplayMode>,
    pub crtc_id:    Option<u32>,
}

// ---------------------------------------------------------------------------
// CRTC
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Crtc {
    pub id:       u32,
    pub mode:     Option<DisplayMode>,
    pub fb_id:    Option<u32>,
    pub x:        u32,
    pub y:        u32,
    pub enabled:  bool,
}

// ---------------------------------------------------------------------------
// Plane
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlaneType { Primary, Overlay, Cursor }

#[derive(Clone, Debug)]
pub struct Plane {
    pub id:        u32,
    pub kind:      PlaneType,
    pub crtc_id:   Option<u32>,
    pub fb_id:     Option<u32>,
    pub src_x:     u32,
    pub src_y:     u32,
    pub src_w:     u32,
    pub src_h:     u32,
    pub crtc_x:    i32,
    pub crtc_y:    i32,
    pub crtc_w:    u32,
    pub crtc_h:    u32,
}

// ---------------------------------------------------------------------------
// GEM buffer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct GemBo {
    pub handle:  u32,
    pub size:    usize,
    pub phys:    u64,
    pub width:   u32,
    pub height:  u32,
    pub pitch:   u32,
    pub format:  PixelFormat,
}

// ---------------------------------------------------------------------------
// DRM device
// ---------------------------------------------------------------------------

struct DrmDevice {
    crtcs:      Vec<Crtc>,
    connectors: Vec<Connector>,
    planes:     Vec<Plane>,
    gem_bos:    Vec<GemBo>,
    next_handle:u32,
}

static DRM: Mutex<Option<DrmDevice>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialise the DRM subsystem with one CRTC, one connector and two planes.
pub fn init() {
    let crtcs = alloc::vec![
        Crtc { id: 1, mode: None, fb_id: None, x: 0, y: 0, enabled: false },
    ];
    let connectors = alloc::vec![
        Connector {
            id: 1, kind: ConnectorType::HDMI, connected: true,
            modes: alloc::vec![DisplayMode::fullhd_60(), DisplayMode::hd_60(), DisplayMode::svga_60()],
            crtc_id: None,
        },
    ];
    let planes = alloc::vec![
        Plane { id: 1, kind: PlaneType::Primary, crtc_id: None, fb_id: None,
                src_x: 0, src_y: 0, src_w: 0, src_h: 0, crtc_x: 0, crtc_y: 0, crtc_w: 0, crtc_h: 0 },
        Plane { id: 2, kind: PlaneType::Overlay, crtc_id: None, fb_id: None,
                src_x: 0, src_y: 0, src_w: 0, src_h: 0, crtc_x: 0, crtc_y: 0, crtc_w: 0, crtc_h: 0 },
    ];
    *DRM.lock() = Some(DrmDevice {
        crtcs, connectors, planes, gem_bos: Vec::new(), next_handle: 1,
    });
}

pub fn is_initialised() -> bool { DRM.lock().is_some() }

// ---------------------------------------------------------------------------
// GEM operations
// ---------------------------------------------------------------------------

/// Allocate a GEM buffer object.  Returns handle or None on OOM.
pub fn gem_alloc(width: u32, height: u32, format: PixelFormat) -> Option<u32> {
    let bpp  = format.bytes_per_pixel() as u32;
    let pitch = width * bpp;
    let size = (pitch * height) as usize;
    let phys = alloc_dma(size, 4096)?;

    let mut drm = DRM.lock();
    let d = drm.as_mut()?;
    let handle = d.next_handle;
    d.next_handle += 1;
    d.gem_bos.push(GemBo { handle, size, phys, width, height, pitch, format });
    Some(handle)
}

/// Free a GEM buffer object by handle.
pub fn gem_free(handle: u32) {
    let mut drm = DRM.lock();
    if let Some(d) = drm.as_mut() {
        d.gem_bos.retain(|bo| bo.handle != handle);
    }
}

/// Get a reference to a GEM BO’s physical address and pitch.
pub fn gem_info(handle: u32) -> Option<GemBo> {
    DRM.lock().as_ref()?.gem_bos.iter().find(|b| b.handle == handle).cloned()
}

/// Map a GEM BO into kernel virtual address space (identity-mapped).
pub fn gem_map(handle: u32) -> Option<*mut u32> {
    gem_info(handle).map(|b| b.phys as *mut u32)
}

// ---------------------------------------------------------------------------
// Modesetting
// ---------------------------------------------------------------------------

/// Atomic commit: attach `fb_handle` to `crtc_id` with `mode`.
/// Updates connector and primary plane state.
pub fn atomic_commit(crtc_id: u32, connector_id: u32, mode: &DisplayMode, fb_handle: u32)
    -> Result<(), &'static str>
{
    let mut drm = DRM.lock();
    let d = drm.as_mut().ok_or("drm not initialised")?;

    // Validate IDs.
    let crtc = d.crtcs.iter_mut().find(|c| c.id == crtc_id)
        .ok_or("invalid crtc_id")?;
    crtc.mode   = Some(*mode);
    crtc.fb_id  = Some(fb_handle);
    crtc.enabled = true;

    if let Some(conn) = d.connectors.iter_mut().find(|c| c.id == connector_id) {
        conn.crtc_id = Some(crtc_id);
    }

    // Update primary plane.
    if let Some(plane) = d.planes.iter_mut().find(|p| p.kind == PlaneType::Primary) {
        plane.crtc_id = Some(crtc_id);
        plane.fb_id   = Some(fb_handle);
        plane.src_w   = mode.hdisplay as u32;
        plane.src_h   = mode.vdisplay as u32;
        plane.crtc_w  = mode.hdisplay as u32;
        plane.crtc_h  = mode.vdisplay as u32;
    }

    // Delegate actual scanout to the GPU backend.
    if let Some(bo) = d.gem_bos.iter().find(|b| b.handle == fb_handle) {
        let fb = Framebuffer::from_gem(bo);
        crate::drivers::gpu::gpu::set_scanout(&fb);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Connector / CRTC queries
// ---------------------------------------------------------------------------

pub fn connectors() -> Vec<Connector> {
    DRM.lock().as_ref().map(|d| d.connectors.clone()).unwrap_or_default()
}

pub fn crtcs() -> Vec<Crtc> {
    DRM.lock().as_ref().map(|d| d.crtcs.clone()).unwrap_or_default()
}

pub fn planes() -> Vec<Plane> {
    DRM.lock().as_ref().map(|d| d.planes.clone()).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn alloc_dma(size: usize, align: usize) -> Option<u64> {
    let pages = (size + 0xFFF) / 0x1000;
    let phys = crate::mm::pmm::alloc_pages_aligned(pages, align)?.as_ptr() as u64;
    unsafe { core::ptr::write_bytes(phys as *mut u8, 0, pages * 0x1000); }
    Some(phys)
}
