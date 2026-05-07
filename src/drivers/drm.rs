//! DRM/KMS driver backed by the UEFI GOP framebuffer or virtio-gpu.
//!
//! ## Feature summary
//!
//! | Feature | Status |
//! |---|---|
//! | Legacy mode-set (SETCRTC / PAGE_FLIP) | ✅ |
//! | Atomic KMS (MODE_ATOMIC) | ✅ |
//! | GEM dumb-buffer alloc/map/destroy | ✅ |
//! | Framebuffer objects (ADDFB / RMFB) | ✅ |
//! | Primary plane | ✅ |
//! | Overlay plane | ✅ (software composite into primary) |
//! | Cursor plane | ✅ (64×64 ARGB, software blend) |
//! | Simulated vblank (eventfd delivery) | ✅ |
//! | PRIME handle↔fd cross-process sharing | ✅ |
//! | renderD128 capability gate (CapSet) | ✅ |
//!
//! ## Linux ioctl compatibility surface
//!
//!   DRM_IOCTL_VERSION
//!   DRM_IOCTL_GET_CAP
//!   DRM_IOCTL_MODE_GETRESOURCES
//!   DRM_IOCTL_MODE_GETCRTC
//!   DRM_IOCTL_MODE_GETCONNECTOR
//!   DRM_IOCTL_MODE_SETCRTC
//!   DRM_IOCTL_MODE_CREATE_DUMB
//!   DRM_IOCTL_MODE_MAP_DUMB
//!   DRM_IOCTL_MODE_DESTROY_DUMB
//!   DRM_IOCTL_MODE_ADDFB
//!   DRM_IOCTL_MODE_RMFB
//!   DRM_IOCTL_MODE_PAGE_FLIP
//!   DRM_IOCTL_MODE_GETPLANE
//!   DRM_IOCTL_MODE_SETPLANE
//!   DRM_IOCTL_MODE_GETPLANERESOURCES
//!   DRM_IOCTL_MODE_ATOMIC
//!   DRM_IOCTL_PRIME_HANDLE_TO_FD
//!   DRM_IOCTL_PRIME_FD_TO_HANDLE
//!   DRM_IOCTL_WAIT_VBLANK

extern crate alloc;
use alloc::{string::String, vec::Vec};
use spin::Mutex;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::drivers::gop::{self, GopInfo};
use crate::security::capset::CapSet;

// ─────────────────────────────────────────────────────────────────────────────
// Static KMS object IDs
// ─────────────────────────────────────────────────────────────────────────────

pub const CRTC_ID:        u32 = 1;
pub const ENCODER_ID:     u32 = 1;
pub const CONNECTOR_ID:   u32 = 1;
/// Primary plane — covers the full CRTC.
pub const PLANE_PRIMARY:  u32 = 1;
/// Overlay plane — composited in software over the primary.
pub const PLANE_OVERLAY:  u32 = 2;
/// Cursor plane — 64×64 ARGB, hot-spot tracked, blended last.
pub const PLANE_CURSOR:   u32 = 3;

// ─────────────────────────────────────────────────────────────────────────────
// Mode descriptor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
pub struct DrmModeInfo {
    pub clock:    u32,
    pub hdisplay: u16,
    pub vdisplay: u16,
    pub vrefresh: u32,
    pub name:     [u8; 32],
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
        let label = format_mode_name(g.width, g.height);
        let n = label.len().min(31);
        m.name[..n].copy_from_slice(&label.as_bytes()[..n]);
        m
    }
}

fn format_mode_name(w: u32, h: u32) -> String {
    let mut s = String::new();
    push_u32(&mut s, w); s.push('x'); push_u32(&mut s, h); s
}
fn push_u32(s: &mut String, mut v: u32) {
    if v == 0 { s.push('0'); return; }
    let mut d = [0u8; 10]; let mut i = 0;
    while v > 0 { d[i] = (v % 10) as u8 + b'0'; i += 1; v /= 10; }
    for c in d[..i].iter().rev() { s.push(*c as char); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plane descriptors
// ─────────────────────────────────────────────────────────────────────────────

/// KMS plane type — mirrors DRM_PLANE_TYPE_* values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlaneType {
    Primary  = 1,
    Overlay  = 2,
    Cursor   = 3,
}

/// Per-plane mutable state (driven by SETPLANE / ATOMIC).
#[derive(Clone, Copy, Default)]
pub struct PlaneState {
    /// Framebuffer object currently attached to this plane (0 = none).
    pub fb_id:   u32,
    /// Destination rectangle on the CRTC (in pixels).
    pub crtc_x:  i32,
    pub crtc_y:  i32,
    pub crtc_w:  u32,
    pub crtc_h:  u32,
    /// Source rectangle inside the framebuffer (16.16 fixed-point).
    pub src_x:   u32,
    pub src_y:   u32,
    pub src_w:   u32,
    pub src_h:   u32,
    pub enabled: bool,
}

static PLANE_PRIMARY_STATE: Mutex<PlaneState> = Mutex::new(PlaneState {
    fb_id: 0, crtc_x: 0, crtc_y: 0, crtc_w: 0, crtc_h: 0,
    src_x: 0, src_y:  0, src_w:  0, src_h:  0, enabled: false,
});
static PLANE_OVERLAY_STATE: Mutex<PlaneState> = Mutex::new(PlaneState {
    fb_id: 0, crtc_x: 0, crtc_y: 0, crtc_w: 0, crtc_h: 0,
    src_x: 0, src_y:  0, src_w:  0, src_h:  0, enabled: false,
});
static PLANE_CURSOR_STATE: Mutex<PlaneState> = Mutex::new(PlaneState {
    fb_id: 0, crtc_x: 0, crtc_y: 0, crtc_w: 0, crtc_h: 0,
    src_x: 0, src_y:  0, src_w:  0, src_h:  0, enabled: false,
});

// ─────────────────────────────────────────────────────────────────────────────
// Software cursor state (ARGB 64×64 bitmap + hotspot)
// ─────────────────────────────────────────────────────────────────────────────

pub const CURSOR_W: u32 = 64;
pub const CURSOR_H: u32 = 64;

/// Cursor pixel buffer (ARGB u32, row-major, CURSOR_W×CURSOR_H).
/// Written by DRM_IOCTL_MODE_CURSOR / atomic cursor-plane update.
static CURSOR_BUF: Mutex<[u32; (CURSOR_W * CURSOR_H) as usize]> =
    Mutex::new([0u32; (CURSOR_W * CURSOR_H) as usize]);

/// Current cursor screen position (hot-spot relative).
static CURSOR_X: AtomicU64 = AtomicU64::new(0);
static CURSOR_Y: AtomicU64 = AtomicU64::new(0);
static CURSOR_VISIBLE: AtomicBool = AtomicBool::new(false);

/// Move the software cursor without a full page-flip.
/// Called from the input layer (mouse delta events).
pub fn cursor_move(x: i32, y: i32) {
    CURSOR_X.store(x as u64, Ordering::Relaxed);
    CURSOR_Y.store(y as u64, Ordering::Relaxed);
}

/// Upload a new 64×64 ARGB cursor bitmap.
/// `pixels` must be exactly CURSOR_W*CURSOR_H u32 values.
pub fn cursor_set(pixels: &[u32], x: i32, y: i32) {
    if pixels.len() < (CURSOR_W * CURSOR_H) as usize { return; }
    let mut buf = CURSOR_BUF.lock();
    buf.copy_from_slice(&pixels[..(CURSOR_W * CURSOR_H) as usize]);
    cursor_move(x, y);
    CURSOR_VISIBLE.store(true, Ordering::Relaxed);
    // Forward to virtio-gpu cursorq for zero-copy hardware path.
    crate::drivers::virtio_gpu::cursor_update(&*buf, x, y);
}

pub fn cursor_hide() {
    CURSOR_VISIBLE.store(false, Ordering::Relaxed);
    crate::drivers::virtio_gpu::cursor_move(0, 0, false);
}

/// Blit the cursor bitmap over the framebuffer at the current position.
/// Called by `page_flip` / `atomic_commit` after writing the primary plane.
/// Uses alpha-blending: dst = src_a * src_rgb + (1 - src_a) * dst_rgb.
fn blit_cursor(fb_phys: u64, fb_w: u32, fb_h: u32) {
    if !CURSOR_VISIBLE.load(Ordering::Relaxed) { return; }
    let cx = CURSOR_X.load(Ordering::Relaxed) as i32;
    let cy = CURSOR_Y.load(Ordering::Relaxed) as i32;
    let buf = CURSOR_BUF.lock();
    let fb = fb_phys as *mut u32;

    for row in 0..(CURSOR_H as i32) {
        let dy = cy + row;
        if dy < 0 || dy >= fb_h as i32 { continue; }
        for col in 0..(CURSOR_W as i32) {
            let dx = cx + col;
            if dx < 0 || dx >= fb_w as i32 { continue; }
            let src = buf[(row as u32 * CURSOR_W + col as u32) as usize];
            let a   = (src >> 24) & 0xFF;
            if a == 0 { continue; }
            let fb_idx = (dy as u32 * fb_w + dx as u32) as usize;
            let dst = unsafe { (*fb.add(fb_idx)) };
            let blend = |s: u32, d: u32| -> u32 {
                (s * a + d * (255 - a)) / 255
            };
            let r = blend((src >> 16) & 0xFF, (dst >> 16) & 0xFF);
            let g = blend((src >>  8) & 0xFF, (dst >>  8) & 0xFF);
            let b = blend( src        & 0xFF,  dst        & 0xFF);
            unsafe { fb.add(fb_idx).write_volatile(0xFF00_0000 | (r << 16) | (g << 8) | b); }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vblank simulation
// ─────────────────────────────────────────────────────────────────────────────

/// Monotonically-increasing vblank counter.
static VBLANK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Ring of pending vblank waiters (capped at 16).
/// Each entry is an eventfd kernel object id that should be signalled.
struct VblankWaiter {
    eventfd_id: u64,
    seq:        u64, // signal after this vblank count
}
static VBLANK_WAITERS: Mutex<Vec<VblankWaiter>> = Mutex::new(Vec::new());

/// Called by the timer interrupt (or by `page_flip` in the immediate path)
/// to advance the vblank counter and wake pending waiters.
pub fn vblank_tick() {
    let new_seq = VBLANK_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    let mut waiters = VBLANK_WAITERS.lock();
    waiters.retain(|w| {
        if w.seq <= new_seq {
            // Signal the eventfd — increments its counter by 1.
            crate::fs::eventfd::signal(w.eventfd_id);
            false // remove from list
        } else {
            true
        }
    });
}

/// Register an eventfd to be signalled at the next vblank (or after `seq`).
/// Maps to DRM_IOCTL_WAIT_VBLANK with DRM_VBLANK_EVENT set.
pub fn wait_vblank(eventfd_id: u64, after_seq: u64) {
    let current = VBLANK_COUNT.load(Ordering::SeqCst);
    let target  = if after_seq == 0 { current + 1 } else { after_seq };
    if target <= current {
        // Already past — signal immediately.
        crate::fs::eventfd::signal(eventfd_id);
        return;
    }
    VBLANK_WAITERS.lock().push(VblankWaiter { eventfd_id, seq: target });
}

/// Current vblank sequence counter (for DRM_IOCTL_WAIT_VBLANK reply).
pub fn vblank_count() -> u64 { VBLANK_COUNT.load(Ordering::SeqCst) }

// ─────────────────────────────────────────────────────────────────────────────
// PRIME buffer sharing (dma-buf handle ↔ fd)
// ─────────────────────────────────────────────────────────────────────────────

/// A PRIME export descriptor: one per exported GEM handle.
/// The "fd" is a kernel dma-buf file descriptor number in the
/// calling process's fd table.  The physical address is the shared
/// backing store.  Cross-process import creates a new GEM handle
/// pointing at the same physical pages (zero-copy).
#[derive(Clone, Copy)]
pub struct PrimeExport {
    pub gem_handle: u32,
    pub phys:       u64,
    pub size:       u64,
    pub dmabuf_fd:  i32,  // fd in the exporting process
    pub ref_count:  u32,
}

/// Global PRIME export table (keyed by dmabuf_fd).
/// A real implementation would use a per-process fd table; this
/// kernel-global table is sufficient for single-compositor use.
static PRIME_EXPORTS: Mutex<Vec<PrimeExport>> = Mutex::new(Vec::new());
static NEXT_DMABUF_FD: Mutex<i32> = Mutex::new(100); // start well above stdin/stdout/stderr

/// Export a GEM dumb-buffer handle to a dma-buf file descriptor.
/// Implements DRM_IOCTL_PRIME_HANDLE_TO_FD.
pub fn prime_handle_to_fd(handle: u32) -> Result<i32, isize> {
    let dumb = DUMB.lock();
    let db   = dumb.filter(|d| d.handle == handle).ok_or(-9isize)?; // EBADF

    // Re-use an existing export for the same handle (ref-count).
    {
        let mut exports = PRIME_EXPORTS.lock();
        if let Some(e) = exports.iter_mut().find(|e| e.gem_handle == handle) {
            e.ref_count += 1;
            return Ok(e.dmabuf_fd);
        }
    }

    // Allocate a new synthetic fd number.
    let fd = { let mut n = NEXT_DMABUF_FD.lock(); let v = *n; *n += 1; v };
    PRIME_EXPORTS.lock().push(PrimeExport {
        gem_handle: handle,
        phys:       db.phys,
        size:       db.size,
        dmabuf_fd:  fd,
        ref_count:  1,
    });
    Ok(fd)
}

/// Import a dma-buf fd and create a new GEM handle pointing at the same pages.
/// Implements DRM_IOCTL_PRIME_FD_TO_HANDLE.
pub fn prime_fd_to_handle(dmabuf_fd: i32) -> Result<u32, isize> {
    let exports = PRIME_EXPORTS.lock();
    let export  = exports.iter().find(|e| e.dmabuf_fd == dmabuf_fd).ok_or(-9isize)?;

    // Allocate a new handle aliasing the same physical pages.
    let mut h_slot = NEXT_HANDLE.lock();
    let new_handle = *h_slot;
    *h_slot = h_slot.wrapping_add(1);

    // Register a new dumb-buffer entry for the imported handle.
    // The width/height/pitch are inferred from the export's size at 32bpp.
    // A real driver would store these in the export descriptor.
    let imported = DumbBuffer {
        handle: new_handle,
        width:  0, // caller must query via GET_CAP after import
        height: 0,
        bpp:    32,
        pitch:  0,
        size:   export.size,
        phys:   export.phys,
    };
    // Park as a pending import — real multi-handle support would use a Vec.
    *DUMB_IMPORTED.lock() = Some(imported);
    Ok(new_handle)
}

/// Release one reference to a PRIME export.  When ref_count reaches 0
/// the entry is removed.  Called when a dma-buf fd is closed.
pub fn prime_release_fd(dmabuf_fd: i32) {
    let mut exports = PRIME_EXPORTS.lock();
    if let Some(pos) = exports.iter().position(|e| e.dmabuf_fd == dmabuf_fd) {
        exports[pos].ref_count -= 1;
        if exports[pos].ref_count == 0 {
            exports.remove(pos);
        }
    }
}

// Slot for an imported dumb buffer (PRIME import path).
static DUMB_IMPORTED: Mutex<Option<DumbBuffer>> = Mutex::new(None);

// ─────────────────────────────────────────────────────────────────────────────
// renderD128 CapSet gate
// ─────────────────────────────────────────────────────────────────────────────

/// `DRM_RENDER_ALLOW` capability bit — processes must hold this to open
/// `/dev/dri/renderD128` and issue render-only ioctls.
/// The bit lives in the process's `CapSet::permitted` set.
/// Master ioctls (mode-setting, page-flip) additionally require
/// `DRM_MASTER` which is granted only to the DRM master (the compositor).
pub const DRM_RENDER_ALLOW: u64 = 1 << 40; // bit 40 of the capability word
pub const DRM_MASTER:       u64 = 1 << 41;

/// Check whether the calling process may use the render-only node.
/// Returns `Err(-1)` (EPERM) if the capability is absent.
pub fn check_render_cap(caps: &CapSet) -> Result<(), isize> {
    if caps.permitted & DRM_RENDER_ALLOW != 0 { Ok(()) } else { Err(-1) }
}

/// Check whether the calling process is the DRM master (mode-setting access).
pub fn check_master_cap(caps: &CapSet) -> Result<(), isize> {
    if caps.permitted & DRM_MASTER != 0 { Ok(()) } else { Err(-1) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Atomic KMS
// ─────────────────────────────────────────────────────────────────────────────

/// One property change inside an atomic request.
#[derive(Clone, Copy)]
pub struct AtomicProp {
    pub object_id:   u32,
    pub property_id: u32,
    pub value:       u64,
}

/// DRM property IDs used in atomic commits.
/// These match the Linux kernel's standard property names.
pub mod prop_id {
    pub const CRTC_ACTIVE:      u32 = 1;
    pub const CRTC_MODE_ID:     u32 = 2;
    pub const PLANE_CRTC_ID:    u32 = 3;
    pub const PLANE_FB_ID:      u32 = 4;
    pub const PLANE_CRTC_X:     u32 = 5;
    pub const PLANE_CRTC_Y:     u32 = 6;
    pub const PLANE_CRTC_W:     u32 = 7;
    pub const PLANE_CRTC_H:     u32 = 8;
    pub const PLANE_SRC_X:      u32 = 9;
    pub const PLANE_SRC_Y:      u32 = 10;
    pub const PLANE_SRC_W:      u32 = 11;
    pub const PLANE_SRC_H:      u32 = 12;
    pub const CONNECTOR_CRTC_ID:u32 = 13;
    pub const CURSOR_HOT_X:     u32 = 14;
    pub const CURSOR_HOT_Y:     u32 = 15;
}

/// Atomic commit flags (subset of DRM_MODE_ATOMIC_*).
pub const ATOMIC_FLAG_TEST_ONLY:    u32 = 0x0100;
pub const ATOMIC_FLAG_ALLOW_MODESET:u32 = 0x0400;
pub const ATOMIC_FLAG_NONBLOCK:     u32 = 0x0200;

/// Process a DRM_IOCTL_MODE_ATOMIC request.
///
/// `props` — the flat list of (object_id, property_id, value) triples
///           unmarshalled from the ioctl argument by `fs/ioctl.rs`.
/// `flags` — DRM_MODE_ATOMIC_* bitmask.
///
/// Returns 0 on success, negative errno on failure.
pub fn atomic_commit(props: &[AtomicProp], flags: u32) -> Result<(), isize> {
    // Shadow mutable plane states for validation before commit.
    let mut ps_primary = *PLANE_PRIMARY_STATE.lock();
    let mut ps_overlay = *PLANE_OVERLAY_STATE.lock();
    let mut ps_cursor  = *PLANE_CURSOR_STATE.lock();
    let mut crtc_active = true; // can be toggled via CRTC_ACTIVE property

    for p in props {
        match p.object_id {
            CRTC_ID => {
                match p.property_id {
                    prop_id::CRTC_ACTIVE  => { crtc_active = p.value != 0; }
                    prop_id::CRTC_MODE_ID => { /* mode blobs not yet persisted */ }
                    _ => {}
                }
            }
            PLANE_PRIMARY => {
                apply_plane_prop(&mut ps_primary, p.property_id, p.value);
            }
            PLANE_OVERLAY => {
                apply_plane_prop(&mut ps_overlay, p.property_id, p.value);
            }
            PLANE_CURSOR => {
                apply_plane_prop(&mut ps_cursor, p.property_id, p.value);
                if p.property_id == prop_id::PLANE_FB_ID {
                    // Cursor plane FB change: update cursor buffer from dumb.
                    let _ = refresh_cursor_from_fb(p.value as u32);
                }
            }
            CONNECTOR_ID => {
                // CONNECTOR_CRTC_ID — only CRTC_ID=1 is supported.
            }
            _ => { return Err(-22); } // EINVAL — unknown object
        }
    }

    if flags & ATOMIC_FLAG_TEST_ONLY != 0 {
        return Ok(()); // Validation-only pass — do not commit.
    }

    // Commit plane states.
    *PLANE_PRIMARY_STATE.lock() = ps_primary;
    *PLANE_OVERLAY_STATE.lock() = ps_overlay;
    *PLANE_CURSOR_STATE.lock()  = ps_cursor;

    // If the primary plane has an active framebuffer, perform a page-flip.
    if crtc_active && ps_primary.enabled && ps_primary.fb_id != 0 {
        do_page_flip(ps_primary.fb_id);
    }

    // Non-blocking mode: signal page-flip complete immediately (no real vblank).
    if flags & ATOMIC_FLAG_NONBLOCK == 0 {
        vblank_tick(); // synchronous tick so WAIT_VBLANK callers unblock
    }

    Ok(())
}

/// Apply a single property update to a shadow PlaneState.
fn apply_plane_prop(ps: &mut PlaneState, prop: u32, val: u64) {
    use prop_id::*;
    match prop {
        PLANE_FB_ID   => { ps.fb_id   = val as u32; ps.enabled = val != 0; }
        PLANE_CRTC_X  => { ps.crtc_x  = val as i32; }
        PLANE_CRTC_Y  => { ps.crtc_y  = val as i32; }
        PLANE_CRTC_W  => { ps.crtc_w  = val as u32; }
        PLANE_CRTC_H  => { ps.crtc_h  = val as u32; }
        PLANE_SRC_X   => { ps.src_x   = val as u32; }
        PLANE_SRC_Y   => { ps.src_y   = val as u32; }
        PLANE_SRC_W   => { ps.src_w   = val as u32; }
        PLANE_SRC_H   => { ps.src_h   = val as u32; }
        _             => {}
    }
}

/// Load cursor pixels from a dumb-buffer framebuffer object id.
fn refresh_cursor_from_fb(fb_id: u32) -> Result<(), isize> {
    if fb_id == 0 {
        cursor_hide();
        return Ok(());
    }
    let fb_slot = FB_OBJ.lock();
    let fb = fb_slot.filter(|f| f.id == fb_id).ok_or(-22isize)?;
    let dumb = DUMB.lock();
    let db   = dumb.filter(|d| d.handle == fb.handle).ok_or(-22isize)?;
    let pixels = unsafe {
        core::slice::from_raw_parts(
            db.phys as *const u32,
            (CURSOR_W * CURSOR_H) as usize,
        )
    };
    let x = CURSOR_X.load(Ordering::Relaxed) as i32;
    let y = CURSOR_Y.load(Ordering::Relaxed) as i32;
    cursor_set(pixels, x, y);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// GEM dumb-buffer registry (primary + imported)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct DumbBuffer {
    pub handle:  u32,
    pub width:   u32,
    pub height:  u32,
    pub bpp:     u32,
    pub pitch:   u32,
    pub size:    u64,
    pub phys:    u64,
}

static DUMB: Mutex<Option<DumbBuffer>> = Mutex::new(None);
static NEXT_HANDLE: Mutex<u32> = Mutex::new(1);

pub fn create_dumb(width: u32, height: u32, bpp: u32) -> Result<(u32, u32, u64), isize> {
    // Prefer virtio-gpu physical address if present.
    let (fb_phys, fb_w, fb_h) =
        if let Some((w, h)) = crate::drivers::virtio_gpu::dimensions() {
            (crate::drivers::virtio_gpu::fb_phys().ok_or(-19isize)?, w, h)
        } else {
            let g = gop::get().ok_or(-19isize)?;
            (g.fb_phys, g.width, g.height)
        };

    if width != fb_w || height != fb_h || bpp != 32 { return Err(-22); }
    let pitch = fb_w * 4;
    let size  = pitch as u64 * height as u64;
    let mut h = NEXT_HANDLE.lock();
    let handle = *h;
    *h = h.wrapping_add(1);
    *DUMB.lock() = Some(DumbBuffer { handle, width, height, bpp, pitch, size, phys: fb_phys });
    Ok((handle, pitch, size))
}

pub fn map_dumb(handle: u32) -> Result<u64, isize> {
    // Check primary slot first, then imported.
    if let Some(d) = DUMB.lock().filter(|d| d.handle == handle) { return Ok(d.phys); }
    DUMB_IMPORTED.lock().filter(|d| d.handle == handle).map(|d| d.phys).ok_or(-9)
}

pub fn destroy_dumb(handle: u32) -> Result<(), isize> {
    let mut slot = DUMB.lock();
    if slot.map_or(false, |d| d.handle == handle) { *slot = None; return Ok(()); }
    let mut imp = DUMB_IMPORTED.lock();
    if imp.map_or(false, |d| d.handle == handle) { *imp = None; return Ok(()); }
    Err(-9)
}

// ─────────────────────────────────────────────────────────────────────────────
// Framebuffer object registry
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct FbObject {
    pub id:     u32,
    pub handle: u32,
    pub width:  u32,
    pub height: u32,
    pub pitch:  u32,
    pub bpp:    u32,
}

static FB_OBJ:     Mutex<Option<FbObject>> = Mutex::new(None);
static NEXT_FB_ID: Mutex<u32>              = Mutex::new(1);
static ACTIVE_FB:  Mutex<u32>             = Mutex::new(0);

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

pub fn rm_fb(id: u32) -> Result<(), isize> {
    let mut slot = FB_OBJ.lock();
    if slot.map_or(false, |f| f.id == id) { *slot = None; Ok(()) } else { Err(-9) }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy SETCRTC / PAGE_FLIP paths
// ─────────────────────────────────────────────────────────────────────────────

pub fn set_crtc(fb_id: u32) -> Result<(), isize> {
    let fb = FB_OBJ.lock();
    if fb.map_or(false, |f| f.id == fb_id) {
        *ACTIVE_FB.lock() = fb_id;
        do_page_flip(fb_id);
        Ok(())
    } else {
        Err(-22)
    }
}

pub fn page_flip(fb_id: u32) -> Result<(), isize> {
    set_crtc(fb_id)?;
    vblank_tick(); // deliver DRM_EVENT_FLIP_COMPLETE
    Ok(())
}

/// Internal scanout: flush virtio-gpu (or leave GOP linear fb as-is),
/// composite the overlay plane, then blit the software cursor.
fn do_page_flip(fb_id: u32) {
    // Resolve physical address from fb_id.
    let (fb_phys, fb_w, fb_h) = {
        let fb_slot = FB_OBJ.lock();
        let fb = match fb_slot.filter(|f| f.id == fb_id) { Some(f) => f, None => return };
        let dumb = DUMB.lock();
        let db   = match dumb.filter(|d| d.handle == fb.handle) { Some(d) => d, None => return };
        (db.phys, fb.width, fb.height)
    };

    // Composite overlay plane (software, over primary).
    composite_overlay(fb_phys, fb_w, fb_h);

    // Blit software cursor (always last so it's on top).
    blit_cursor(fb_phys, fb_w, fb_h);

    // Push to virtio-gpu if active.
    if crate::drivers::virtio_gpu::is_present() {
        crate::drivers::virtio_gpu::flush_all();
    }
}

/// Software-composite the overlay plane into the primary framebuffer.
/// Supports ARGB (alpha != 0 → blend, alpha == 0 → transparent).
fn composite_overlay(primary_phys: u64, fb_w: u32, fb_h: u32) {
    let ps = *PLANE_OVERLAY_STATE.lock();
    if !ps.enabled || ps.fb_id == 0 { return; }

    let ov_fb = { let s = FB_OBJ.lock(); match s.filter(|f| f.id == ps.fb_id) { Some(f) => f, None => return } };
    let ov_db = { let s = DUMB.lock();   match s.filter(|d| d.handle == ov_fb.handle) { Some(d) => d, None => return } };

    let src   = ov_db.phys as *const u32;
    let dst   = primary_phys as *mut u32;
    let src_w = ov_fb.width;

    for row in 0..ps.crtc_h {
        let dy = ps.crtc_y + row as i32;
        if dy < 0 || dy >= fb_h as i32 { continue; }
        for col in 0..ps.crtc_w {
            let dx = ps.crtc_x + col as i32;
            if dx < 0 || dx >= fb_w as i32 { continue; }
            let si = ((ps.src_y >> 16) + row) * src_w + (ps.src_x >> 16) + col;
            let di = dy as u32 * fb_w + dx as u32;
            let s_px = unsafe { src.add(si as usize).read_volatile() };
            let alpha = (s_px >> 24) & 0xFF;
            if alpha == 0 { continue; }
            if alpha == 255 {
                unsafe { dst.add(di as usize).write_volatile(s_px); }
                continue;
            }
            let d_px = unsafe { dst.add(di as usize).read_volatile() };
            let blend = |s: u32, d: u32| (s * alpha + d * (255 - alpha)) / 255;
            let r = blend((s_px >> 16) & 0xFF, (d_px >> 16) & 0xFF);
            let g = blend((s_px >>  8) & 0xFF, (d_px >>  8) & 0xFF);
            let b = blend( s_px        & 0xFF,  d_px        & 0xFF);
            unsafe { dst.add(di as usize).write_volatile(0xFF00_0000 | (r<<16)|(g<<8)|b); }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plane query helpers (used by ioctl dispatcher)
// ─────────────────────────────────────────────────────────────────────────────

/// Returns the list of plane IDs exposed by the driver.
pub fn plane_ids() -> &'static [u32] { &[PLANE_PRIMARY, PLANE_OVERLAY, PLANE_CURSOR] }

/// Returns the type of a plane by its ID.
pub fn plane_type(id: u32) -> Option<PlaneType> {
    match id {
        PLANE_PRIMARY => Some(PlaneType::Primary),
        PLANE_OVERLAY => Some(PlaneType::Overlay),
        PLANE_CURSOR  => Some(PlaneType::Cursor),
        _ => None,
    }
}

/// Returns a copy of the current state for a plane.
pub fn get_plane_state(id: u32) -> Option<PlaneState> {
    match id {
        PLANE_PRIMARY => Some(*PLANE_PRIMARY_STATE.lock()),
        PLANE_OVERLAY => Some(*PLANE_OVERLAY_STATE.lock()),
        PLANE_CURSOR  => Some(*PLANE_CURSOR_STATE.lock()),
        _ => None,
    }
}

/// Directly set a plane's state (used by legacy SETPLANE ioctl).
pub fn set_plane(id: u32, state: PlaneState) -> Result<(), isize> {
    match id {
        PLANE_PRIMARY => { *PLANE_PRIMARY_STATE.lock() = state; Ok(()) }
        PLANE_OVERLAY => { *PLANE_OVERLAY_STATE.lock() = state; Ok(()) }
        PLANE_CURSOR  => {
            *PLANE_CURSOR_STATE.lock() = state;
            // Propagate cursor position from crtc_x/crtc_y.
            cursor_move(state.crtc_x, state.crtc_y);
            if state.fb_id != 0 { let _ = refresh_cursor_from_fb(state.fb_id); }
            Ok(())
        }
        _ => Err(-22),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Misc public API
// ─────────────────────────────────────────────────────────────────────────────

pub fn driver_name()    -> &'static str      { "rustosdrm" }
pub fn driver_version() -> (i32, i32, i32)  { (0, 2, 0) }

pub fn current_mode() -> Option<DrmModeInfo> {
    // virtio-gpu resolution takes priority over GOP.
    if let Some((w, h)) = crate::drivers::virtio_gpu::dimensions() {
        let mut m = DrmModeInfo {
            clock:    (w * h * 60) / 1_000,
            hdisplay: w as u16,
            vdisplay: h as u16,
            vrefresh: 60,
            name:     [0u8; 32],
        };
        let label = format_mode_name(w, h);
        let n = label.len().min(31);
        m.name[..n].copy_from_slice(&label.as_bytes()[..n]);
        return Some(m);
    }
    gop::get().map(|g| DrmModeInfo::from_gop(&g))
}

pub fn gop_info() -> Option<GopInfo> { gop::get() }
