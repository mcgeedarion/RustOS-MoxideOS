//! DRM/KMS stub backed by the UEFI GOP framebuffer.
//!
//! ## What this provides
//!
//! A minimal DRM-like interface over the linear framebuffer captured by
//! `drivers::gop` before ExitBootServices.  It is intentionally simple:
//! one CRTC, one plane, one connector — enough for a Wayland compositor
//! or a direct-rendering userspace app to draw pixels.
//!
//! ## Linux compatibility surface
//!
//! The ioctls that userspace typically issues against /dev/dri/card0 are
//! handled in `fs/ioctl.rs` by dispatching to the functions here.  The
//! subset implemented covers what a minimal EGL/GBM or fbdev-compatible
//! path needs:
//!
//!   DRM_IOCTL_VERSION          — driver name, version
//!   DRM_IOCTL_GET_CAP          — advertise DUMB_BUFFER
//!   DRM_IOCTL_MODE_GETRESOURCES — list crtc/connector/encoder ids
//!   DRM_IOCTL_MODE_GETCRTC     — current CRTC state
//!   DRM_IOCTL_MODE_GETCONNECTOR — connector + current mode
//!   DRM_IOCTL_MODE_SETCRTC     — program a mode (no-op if resolution matches)
//!   DRM_IOCTL_MODE_CREATE_DUMB — allocate a dumb buffer (backed by gopfb)
//!   DRM_IOCTL_MODE_MAP_DUMB    — get mmap offset for the dumb buffer
//!   DRM_IOCTL_MODE_DESTROY_DUMB— release dumb buffer
//!   DRM_IOCTL_MODE_ADDFB       — register framebuffer object
//!   DRM_IOCTL_MODE_RMFB        — release framebuffer object
//!   DRM_IOCTL_MODE_PAGE_FLIP   — schedule scanout (immediate in our stub)

extern crate alloc;
use alloc::string::String;
use spin::Mutex;
use crate::drivers::gop::{self, GopInfo};

// ── Object IDs ───────────────────────────────────────────────────────────────────
pub const CRTC_ID:      u32 = 1;
pub const ENCODER_ID:   u32 = 1;
pub const CONNECTOR_ID: u32 = 1;
pub const PLANE_ID:     u32 = 1;

// ── Mode descriptor ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
pub struct DrmModeInfo {
    pub clock:       u32,   // pixel clock in kHz
    pub hdisplay:    u16,
    pub vdisplay:    u16,
    pub vrefresh:    u32,   // Hz
    pub name:        [u8; 32],
}

impl DrmModeInfo {
    pub fn from_gop(g: &GopInfo) -> Self {
        let mut m = DrmModeInfo {
            clock:    (g.width as u32 * g.height as u32 * 60) / 1_000,
            hdisplay: g.width  as u16,
            vdisplay: g.height as u16,
            vrefresh: 60,
            name:     [0u8; 32],
        };
        // Write e.g. "1920x1080" into name.
        let label = format_mode_name(g.width, g.height);
        let n = label.len().min(31);
        m.name[..n].copy_from_slice(&label.as_bytes()[..n]);
        m
    }
}

fn format_mode_name(w: u32, h: u32) -> String {
    let mut s = String::new();
    push_u32(&mut s, w);
    s.push('x');
    push_u32(&mut s, h);
    s
}

fn push_u32(s: &mut String, mut v: u32) {
    if v == 0 { s.push('0'); return; }
    let mut digits = [0u8; 10];
    let mut i = 0;
    while v > 0 { digits[i] = (v % 10) as u8 + b'0'; i += 1; v /= 10; }
    for d in digits[..i].iter().rev() { s.push(*d as char); }
}

// ── Dumb buffer registry ──────────────────────────────────────────────────────────
// We support exactly one dumb buffer at a time (the GOP framebuffer itself).

#[derive(Clone, Copy)]
pub struct DumbBuffer {
    pub handle:  u32,
    pub width:   u32,
    pub height:  u32,
    pub bpp:     u32,
    pub pitch:   u32,   // bytes per row
    pub size:    u64,   // total bytes
    pub phys:    u64,   // physical address (= GOP fb_phys)
}

static DUMB: Mutex<Option<DumbBuffer>> = Mutex::new(None);
static NEXT_HANDLE: spin::Mutex<u32> = spin::Mutex::new(1);

// ── Framebuffer object registry ───────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct FbObject {
    pub id:     u32,
    pub handle: u32,   // dumb buffer handle
    pub width:  u32,
    pub height: u32,
    pub pitch:  u32,
    pub bpp:    u32,
}

static FB_OBJ:    Mutex<Option<FbObject>> = Mutex::new(None);
static NEXT_FB_ID: spin::Mutex<u32> = spin::Mutex::new(1);

// ── Current scanout state ─────────────────────────────────────────────────────────

static ACTIVE_FB: Mutex<u32> = Mutex::new(0); // fb object id, 0 = none

// ── Public API ────────────────────────────────────────────────────────────────────

/// DRM driver version string.
pub fn driver_name() -> &'static str { "rustosdrm" }
pub fn driver_version() -> (i32, i32, i32) { (0, 1, 0) }

/// Returns the current mode derived from GOP, or None if GOP is unavailable.
pub fn current_mode() -> Option<DrmModeInfo> {
    gop::get().map(|g| DrmModeInfo::from_gop(&g))
}

/// Allocate a dumb buffer backed by the GOP framebuffer.
/// Only one dumb buffer is supported at a time.
///
/// Returns `(handle, pitch, size)` on success, or an error code.
pub fn create_dumb(width: u32, height: u32, bpp: u32) -> Result<(u32, u32, u64), isize> {
    let info = gop::get().ok_or(-19isize)?; // ENODEV
    if width != info.width || height != info.height || bpp != 32 {
        return Err(-22); // EINVAL
    }
    let pitch = info.pixels_per_line * 4;
    let size  = pitch as u64 * height as u64;
    let mut h = NEXT_HANDLE.lock();
    let handle = *h;
    *h = h.wrapping_add(1);
    *DUMB.lock() = Some(DumbBuffer {
        handle, width, height, bpp, pitch, size,
        phys: info.fb_phys,
    });
    Ok((handle, pitch, size))
}

/// Return the physical address for a dumb buffer handle (used by mmap).
pub fn map_dumb(handle: u32) -> Result<u64, isize> {
    DUMB.lock()
        .filter(|d| d.handle == handle)
        .map(|d| d.phys)
        .ok_or(-9) // EBADF
}

/// Destroy a dumb buffer.
pub fn destroy_dumb(handle: u32) -> Result<(), isize> {
    let mut slot = DUMB.lock();
    if slot.map_or(false, |d| d.handle == handle) {
        *slot = None;
        Ok(())
    } else {
        Err(-9) // EBADF
    }
}

/// Register a framebuffer object over a dumb buffer.
pub fn add_fb(handle: u32, width: u32, height: u32, pitch: u32, bpp: u32)
    -> Result<u32, isize>
{
    let d = DUMB.lock();
    let db = d.filter(|d| d.handle == handle).ok_or(-9isize)?;
    if db.width != width || db.height != height { return Err(-22); }
    let mut id_slot = NEXT_FB_ID.lock();
    let id = *id_slot;
    *id_slot = id_slot.wrapping_add(1);
    *FB_OBJ.lock() = Some(FbObject { id, handle, width, height, pitch, bpp });
    Ok(id)
}

/// Remove a framebuffer object.
pub fn rm_fb(id: u32) -> Result<(), isize> {
    let mut slot = FB_OBJ.lock();
    if slot.map_or(false, |f| f.id == id) {
        *slot = None;
        Ok(())
    } else {
        Err(-9)
    }
}

/// Set CRTC — programs the display to scan out `fb_id`.
/// Since the GOP framebuffer is already the live display buffer,
/// this is a no-op as long as fb_id matches our registered object.
pub fn set_crtc(fb_id: u32) -> Result<(), isize> {
    let fb = FB_OBJ.lock();
    if fb.map_or(false, |f| f.id == fb_id) {
        *ACTIVE_FB.lock() = fb_id;
        Ok(())
    } else {
        Err(-22) // EINVAL
    }
}

/// Page flip — schedules `fb_id` as the next scanout frame.
/// Immediate in our stub (no vblank wait).
pub fn page_flip(fb_id: u32) -> Result<(), isize> {
    set_crtc(fb_id)
}

/// Returns the GopInfo, exposed so ioctl handlers can fill fb_fix/var structs.
pub fn gop_info() -> Option<GopInfo> { gop::get() }
