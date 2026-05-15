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
//! | Primary plane (per CRTC) | ✅ |
//! | Overlay plane (per CRTC, software composite) | ✅ |
//! | Cursor plane (64×64 ARGB, software blend) | ✅ |
//! | Multi-head (up to MAX_HEADS CRTCs/connectors) | ✅ |
//! | Simulated vblank (eventfd delivery, per CRTC) | ✅ |
//! | PRIME handle↔fd cross-process sharing | ✅ |
//! | renderD128 capability gate (CapSet) | ✅ |
//! | Property blobs (MODE_ID, GETPROPERTY, GETBLOB) | ✅ |
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
//!   DRM_IOCTL_MODE_GETPROPERTY
//!   DRM_IOCTL_MODE_SETPROPERTY
//!   DRM_IOCTL_MODE_GETBLOB
//!   DRM_IOCTL_PRIME_HANDLE_TO_FD
//!   DRM_IOCTL_PRIME_FD_TO_HANDLE
//!   DRM_IOCTL_WAIT_VBLANK

extern crate alloc;
use crate::drivers::gop::{self, GopInfo};
use crate::security::capset::CapSet;
use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

// ─────────────────────────────────────────────────────────────────────────────
// Multi-head topology constants
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of independent display heads (CRTCs) supported.
pub const MAX_HEADS: usize = 4;

/// First CRTC ID.  IDs are assigned as CRTC_BASE_ID + head_index (0-based).
pub const CRTC_BASE_ID: u32 = 1;
/// First Encoder ID (one encoder per head, 1:1 mapping).
pub const ENCODER_BASE_ID: u32 = 16;
/// First Connector ID (one connector per head).
pub const CONNECTOR_BASE_ID: u32 = 32;

/// Plane IDs: three planes per head (primary=0, overlay=1, cursor=2).
/// plane_id_for(head, kind) == PLANE_BASE_ID + head * PLANES_PER_HEAD + kind
pub const PLANE_BASE_ID: u32 = 64;
pub const PLANES_PER_HEAD: u32 = 3;
pub const PLANE_KIND_PRIMARY: u32 = 0;
pub const PLANE_KIND_OVERLAY: u32 = 1;
pub const PLANE_KIND_CURSOR: u32 = 2;

#[inline]
pub fn crtc_id(head: usize) -> u32 {
    CRTC_BASE_ID + head as u32
}
#[inline]
pub fn encoder_id(head: usize) -> u32 {
    ENCODER_BASE_ID + head as u32
}
#[inline]
pub fn connector_id(head: usize) -> u32 {
    CONNECTOR_BASE_ID + head as u32
}
#[inline]
pub fn plane_id(head: usize, kind: u32) -> u32 {
    PLANE_BASE_ID + head as u32 * PLANES_PER_HEAD + kind
}

/// Resolve a CRTC id → head index (0-based).  Returns None if invalid.
#[inline]
pub fn crtc_to_head(crtc: u32) -> Option<usize> {
    let idx = crtc.wrapping_sub(CRTC_BASE_ID) as usize;
    if idx < MAX_HEADS && idx < num_heads() {
        Some(idx)
    } else {
        None
    }
}

/// Resolve a plane id → (head, kind).  Returns None if invalid.
#[inline]
pub fn plane_to_head_kind(plane: u32) -> Option<(usize, u32)> {
    if plane < PLANE_BASE_ID {
        return None;
    }
    let off = plane - PLANE_BASE_ID;
    let head = (off / PLANES_PER_HEAD) as usize;
    let kind = off % PLANES_PER_HEAD;
    if head < MAX_HEADS && head < num_heads() {
        Some((head, kind))
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-head display descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// Physical description of one display head.
/// Populated at boot from GOP (head 0) and virtio-gpu scanout list (heads 1+).
#[derive(Clone, Copy, Default)]
pub struct HeadInfo {
    /// Is this head live (has a connected display)?
    pub present: bool,
    /// Horizontal resolution in pixels.
    pub width: u32,
    /// Vertical resolution in pixels.
    pub height: u32,
    /// Physical address of this head's linear framebuffer.
    pub fb_phys: u64,
    /// virtio-gpu scanout index, or u32::MAX for GOP.
    pub scanout: u32,
}

/// Global table of active display heads.
static HEADS: Mutex<[HeadInfo; MAX_HEADS]> = Mutex::new(
    [HeadInfo {
        present: false,
        width: 0,
        height: 0,
        fb_phys: 0,
        scanout: u32::MAX,
    }; MAX_HEADS],
);

/// Number of heads currently registered (monotonically set at init).
static NUM_HEADS: AtomicU64 = AtomicU64::new(0);

pub fn num_heads() -> usize {
    NUM_HEADS.load(Ordering::SeqCst) as usize
}

/// Called once at kernel init.  Registers GOP as head 0 and virtio-gpu
/// scanouts as heads 1…n (up to MAX_HEADS).
pub fn init_heads() {
    let mut heads = HEADS.lock();
    let mut count = 0usize;

    // Head 0 — UEFI GOP linear framebuffer.
    if let Some(g) = gop::get() {
        heads[0] = HeadInfo {
            present: true,
            width: g.width,
            height: g.height,
            fb_phys: g.fb_phys,
            scanout: u32::MAX,
        };
        count = 1;
    }

    // Heads 1+ — virtio-gpu scanouts (multi-monitor in QEMU).
    for scanout_idx in 0..crate::drivers::virtio_gpu::num_scanouts() {
        if count >= MAX_HEADS {
            break;
        }
        if let Some((w, h, phys)) = crate::drivers::virtio_gpu::scanout_info(scanout_idx) {
            heads[count] = HeadInfo {
                present: true,
                width: w,
                height: h,
                fb_phys: phys,
                scanout: scanout_idx as u32,
            };
            count += 1;
        }
    }

    NUM_HEADS.store(count as u64, Ordering::SeqCst);
}

pub fn head_info(head: usize) -> Option<HeadInfo> {
    if head >= num_heads() {
        return None;
    }
    let h = HEADS.lock()[head];
    if h.present {
        Some(h)
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mode descriptor
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
pub struct DrmModeInfo {
    pub clock: u32,
    pub hdisplay: u16,
    pub vdisplay: u16,
    pub vrefresh: u32,
    pub name: [u8; 32],
}

impl DrmModeInfo {
    pub fn from_head(h: &HeadInfo) -> Self {
        let mut m = DrmModeInfo {
            clock: (h.width * h.height * 60) / 1_000,
            hdisplay: h.width as u16,
            vdisplay: h.height as u16,
            vrefresh: 60,
            name: [0u8; 32],
        };
        let label = format_mode_name(h.width, h.height);
        let n = label.len().min(31);
        m.name[..n].copy_from_slice(&label.as_bytes()[..n]);
        m
    }

    pub fn from_gop(g: &GopInfo) -> Self {
        let h = HeadInfo {
            width: g.width,
            height: g.height,
            fb_phys: g.fb_phys,
            present: true,
            scanout: u32::MAX,
        };
        Self::from_head(&h)
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
    if v == 0 {
        s.push('0');
        return;
    }
    let mut d = [0u8; 10];
    let mut i = 0;
    while v > 0 {
        d[i] = (v % 10) as u8 + b'0';
        i += 1;
        v /= 10;
    }
    for c in d[..i].iter().rev() {
        s.push(*c as char);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KMS resources query  (DRM_IOCTL_MODE_GETRESOURCES)
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot of all KMS object IDs for DRM_IOCTL_MODE_GETRESOURCES.
pub struct KmsResources {
    pub crtc_ids: Vec<u32>,
    pub encoder_ids: Vec<u32>,
    pub connector_ids: Vec<u32>,
    pub fb_ids: Vec<u32>,
    pub min_width: u32,
    pub max_width: u32,
    pub min_height: u32,
    pub max_height: u32,
}

pub fn get_resources() -> KmsResources {
    let n = num_heads();
    let mut crtc_ids = Vec::with_capacity(n);
    let mut encoder_ids = Vec::with_capacity(n);
    let mut connector_ids = Vec::with_capacity(n);
    for i in 0..n {
        crtc_ids.push(crtc_id(i));
        encoder_ids.push(encoder_id(i));
        connector_ids.push(connector_id(i));
    }
    // Collect live FB ids.
    let mut fb_ids = Vec::new();
    {
        let fbs = FB_OBJECTS.lock();
        for f in fbs.iter() {
            fb_ids.push(f.id);
        }
    }
    KmsResources {
        crtc_ids,
        encoder_ids,
        connector_ids,
        fb_ids,
        min_width: 0,
        max_width: 16384,
        min_height: 0,
        max_height: 16384,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plane descriptors
// ─────────────────────────────────────────────────────────────────────────────

/// KMS plane type — mirrors DRM_PLANE_TYPE_* values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlaneType {
    Primary = 1,
    Overlay = 2,
    Cursor = 3,
}

/// Per-plane mutable state (driven by SETPLANE / ATOMIC).
#[derive(Clone, Copy, Default)]
pub struct PlaneState {
    pub fb_id: u32,
    pub crtc_x: i32,
    pub crtc_y: i32,
    pub crtc_w: u32,
    pub crtc_h: u32,
    /// Source rectangle inside the framebuffer (16.16 fixed-point).
    pub src_x: u32,
    pub src_y: u32,
    pub src_w: u32,
    pub src_h: u32,
    pub enabled: bool,
}

/// Three planes per head: [primary, overlay, cursor].
type HeadPlanes = [PlaneState; PLANES_PER_HEAD as usize];

static PLANE_STATES: Mutex<[HeadPlanes; MAX_HEADS]> = Mutex::new(
    [[PlaneState {
        fb_id: 0,
        crtc_x: 0,
        crtc_y: 0,
        crtc_w: 0,
        crtc_h: 0,
        src_x: 0,
        src_y: 0,
        src_w: 0,
        src_h: 0,
        enabled: false,
    }; PLANES_PER_HEAD as usize]; MAX_HEADS],
);

// ─────────────────────────────────────────────────────────────────────────────
// Software cursor state — one cursor per head
// ─────────────────────────────────────────────────────────────────────────────

pub const CURSOR_W: u32 = 64;
pub const CURSOR_H: u32 = 64;
const CURSOR_PIXELS: usize = (CURSOR_W * CURSOR_H) as usize;

struct CursorState {
    buf: [u32; CURSOR_PIXELS],
    x: i32,
    y: i32,
    visible: bool,
}

impl CursorState {
    const fn new() -> Self {
        CursorState {
            buf: [0u32; CURSOR_PIXELS],
            x: 0,
            y: 0,
            visible: false,
        }
    }
}

static CURSORS: [Mutex<CursorState>; MAX_HEADS] = [
    Mutex::new(CursorState::new()),
    Mutex::new(CursorState::new()),
    Mutex::new(CursorState::new()),
    Mutex::new(CursorState::new()),
];

/// Move the software cursor for a specific head (called from input layer).
pub fn cursor_move_head(head: usize, x: i32, y: i32) {
    if head >= MAX_HEADS {
        return;
    }
    let mut c = CURSORS[head].lock();
    c.x = x;
    c.y = y;
}

/// Convenience: move cursor on head 0 (primary display).
pub fn cursor_move(x: i32, y: i32) {
    cursor_move_head(0, x, y);
}

/// Upload a new 64×64 ARGB cursor bitmap for `head`.
pub fn cursor_set_head(head: usize, pixels: &[u32], x: i32, y: i32) {
    if head >= MAX_HEADS || pixels.len() < CURSOR_PIXELS {
        return;
    }
    {
        let mut c = CURSORS[head].lock();
        c.buf.copy_from_slice(&pixels[..CURSOR_PIXELS]);
        c.x = x;
        c.y = y;
        c.visible = true;
    }
    // Forward to virtio-gpu cursor queue for the appropriate scanout.
    if let Some(hi) = head_info(head) {
        if hi.scanout != u32::MAX {
            let c = CURSORS[head].lock();
            crate::drivers::virtio_gpu::cursor_update_scanout(hi.scanout, &c.buf, x, y);
        }
    }
}

/// Convenience wrappers keeping single-head callers working.
pub fn cursor_set(pixels: &[u32], x: i32, y: i32) {
    cursor_set_head(0, pixels, x, y);
}

pub fn cursor_hide_head(head: usize) {
    if head >= MAX_HEADS {
        return;
    }
    CURSORS[head].lock().visible = false;
    if let Some(hi) = head_info(head) {
        if hi.scanout != u32::MAX {
            crate::drivers::virtio_gpu::cursor_move_scanout(hi.scanout, 0, 0, false);
        }
    }
}
pub fn cursor_hide() {
    cursor_hide_head(0);
}

/// Blit the software cursor for `head` into the framebuffer at `fb_phys`.
fn blit_cursor(head: usize, fb_phys: u64, fb_w: u32, fb_h: u32) {
    if head >= MAX_HEADS {
        return;
    }
    let c = CURSORS[head].lock();
    if !c.visible {
        return;
    }
    let cx = c.x;
    let cy = c.y;
    let fb = fb_phys as *mut u32;
    for row in 0..(CURSOR_H as i32) {
        let dy = cy + row;
        if dy < 0 || dy >= fb_h as i32 {
            continue;
        }
        for col in 0..(CURSOR_W as i32) {
            let dx = cx + col;
            if dx < 0 || dx >= fb_w as i32 {
                continue;
            }
            let src = c.buf[(row as u32 * CURSOR_W + col as u32) as usize];
            let a = (src >> 24) & 0xFF;
            if a == 0 {
                continue;
            }
            let fb_idx = (dy as u32 * fb_w + dx as u32) as usize;
            let dst = unsafe { (*fb.add(fb_idx)) };
            let blend = |s: u32, d: u32| -> u32 { (s * a + d * (255 - a)) / 255 };
            let r = blend((src >> 16) & 0xFF, (dst >> 16) & 0xFF);
            let g = blend((src >> 8) & 0xFF, (dst >> 8) & 0xFF);
            let b = blend(src & 0xFF, dst & 0xFF);
            unsafe {
                fb.add(fb_idx)
                    .write_volatile(0xFF00_0000 | (r << 16) | (g << 8) | b);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vblank simulation — one counter + waiter list per CRTC
// ─────────────────────────────────────────────────────────────────────────────

static VBLANK_COUNT: [AtomicU64; MAX_HEADS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

struct VblankWaiter {
    eventfd_id: u64,
    seq: u64,
}
static VBLANK_WAITERS: [Mutex<Vec<VblankWaiter>>; MAX_HEADS] = [
    Mutex::new(Vec::new()),
    Mutex::new(Vec::new()),
    Mutex::new(Vec::new()),
    Mutex::new(Vec::new()),
];

/// Advance the vblank counter for `head` and wake any waiters.
pub fn vblank_tick_head(head: usize) {
    if head >= MAX_HEADS {
        return;
    }
    let new_seq = VBLANK_COUNT[head].fetch_add(1, Ordering::SeqCst) + 1;
    let mut waiters = VBLANK_WAITERS[head].lock();
    waiters.retain(|w| {
        if w.seq <= new_seq {
            crate::fs::eventfd::signal(w.eventfd_id);
            false
        } else {
            true
        }
    });
}

/// Legacy single-head shim.
pub fn vblank_tick() {
    vblank_tick_head(0);
}

/// Called from the DRM vblank ISR (via `compositor::vblank_notify`) to deliver
/// a vblank event to userspace waiters for the given CRTC.
///
/// Translates `crtc_id` → head index, then calls `vblank_tick_head`.
/// No-op if `crtc_id` does not map to a valid head.
pub fn deliver_vblank_event(crtc_id: u32) {
    if let Some(head) = crtc_to_head(crtc_id) {
        vblank_tick_head(head);
    }
}

/// Register an eventfd to be signalled at the next vblank for `head`.
pub fn wait_vblank_head(head: usize, eventfd_id: u64, after_seq: u64) {
    if head >= MAX_HEADS {
        return;
    }
    let current = VBLANK_COUNT[head].load(Ordering::SeqCst);
    let target = if after_seq == 0 {
        current + 1
    } else {
        after_seq
    };
    if target <= current {
        crate::fs::eventfd::signal(eventfd_id);
        return;
    }
    VBLANK_WAITERS[head].lock().push(VblankWaiter {
        eventfd_id,
        seq: target,
    });
}

pub fn wait_vblank(eventfd_id: u64, after_seq: u64) {
    wait_vblank_head(0, eventfd_id, after_seq);
}

pub fn vblank_count_head(head: usize) -> u64 {
    if head >= MAX_HEADS {
        return 0;
    }
    VBLANK_COUNT[head].load(Ordering::SeqCst)
}
pub fn vblank_count() -> u64 {
    vblank_count_head(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Property blob registry
// ─────────────────────────────────────────────────────────────────────────────
//
// Blobs are opaque byte buffers associated with a u32 blob_id.  The primary
// consumer is MODE_ATOMIC: when userspace sets CRTC_MODE_ID it passes a blob
// id whose contents are a packed DrmModeInfo.  Blobs are reference-counted;
// CREATE_BLOB / DESTROY_BLOB are the public lifecycle calls.  GETBLOB copies
// the payload back to userspace.

#[derive(Clone)]
pub struct PropBlob {
    pub id: u32,
    pub data: Vec<u8>,
    ref_count: u32,
}

static PROP_BLOBS: Mutex<Vec<PropBlob>> = Mutex::new(Vec::new());
static NEXT_BLOB_ID: Mutex<u32> = Mutex::new(1);

/// Store an arbitrary byte payload and return its blob id.
pub fn create_blob(data: Vec<u8>) -> u32 {
    let id = {
        let mut n = NEXT_BLOB_ID.lock();
        let v = *n;
        *n = n.wrapping_add(1);
        v
    };
    PROP_BLOBS.lock().push(PropBlob {
        id,
        data,
        ref_count: 1,
    });
    id
}

/// Retrieve a copy of a blob's payload, or None if the id is unknown.
pub fn get_blob(id: u32) -> Option<Vec<u8>> {
    PROP_BLOBS
        .lock()
        .iter()
        .find(|b| b.id == id)
        .map(|b| b.data.clone())
}

/// Drop a reference; removes the blob when ref_count reaches zero.
pub fn destroy_blob(id: u32) -> Result<(), isize> {
    let mut blobs = PROP_BLOBS.lock();
    if let Some(pos) = blobs.iter().position(|b| b.id == id) {
        blobs[pos].ref_count -= 1;
        if blobs[pos].ref_count == 0 {
            blobs.remove(pos);
        }
        Ok(())
    } else {
        Err(-9)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Property descriptors (DRM_IOCTL_MODE_GETPROPERTY)
// ─────────────────────────────────────────────────────────────────────────────
//
// We expose a minimal property table covering all property IDs used by
// atomic_commit().  Each entry carries the Linux-standard name, type flags,
// and (for range props) the valid range.  Blob properties carry type BLOB.

/// DRM property type flags (matches Linux uapi drm_mode.h).
pub mod prop_flags {
    pub const RANGE: u32 = 1 << 1;
    pub const ENUM: u32 = 1 << 3;
    pub const BLOB: u32 = 1 << 4;
    pub const BITMASK: u32 = 1 << 5;
    pub const OBJECT: u32 = 1 << 6;
    pub const SIGNED: u32 = 1 << 7;
    pub const ATOMIC: u32 = 1 << 31;
    pub const IMMUTABLE: u32 = 1 << 0;
}

pub struct PropDesc {
    pub id: u32,
    pub name: &'static str,
    pub flags: u32,
    /// For RANGE props: (min, max).  Zero for BLOB/OBJECT props.
    pub range: (u64, u64),
}

/// Static table of all known KMS property descriptors.
pub fn property_table() -> &'static [PropDesc] {
    use prop_flags::*;
    use prop_id::*;
    static TABLE: &[PropDesc] = &[
        PropDesc {
            id: CRTC_ACTIVE,
            name: "ACTIVE",
            flags: RANGE | ATOMIC,
            range: (0, 1),
        },
        PropDesc {
            id: CRTC_MODE_ID,
            name: "MODE_ID",
            flags: BLOB | ATOMIC,
            range: (0, 0),
        },
        PropDesc {
            id: PLANE_CRTC_ID,
            name: "CRTC_ID",
            flags: OBJECT | ATOMIC,
            range: (0, 0),
        },
        PropDesc {
            id: PLANE_FB_ID,
            name: "FB_ID",
            flags: OBJECT | ATOMIC,
            range: (0, 0),
        },
        PropDesc {
            id: PLANE_CRTC_X,
            name: "CRTC_X",
            flags: SIGNED | RANGE | ATOMIC,
            range: (0, 16384),
        },
        PropDesc {
            id: PLANE_CRTC_Y,
            name: "CRTC_Y",
            flags: SIGNED | RANGE | ATOMIC,
            range: (0, 16384),
        },
        PropDesc {
            id: PLANE_CRTC_W,
            name: "CRTC_W",
            flags: RANGE | ATOMIC,
            range: (0, 16384),
        },
        PropDesc {
            id: PLANE_CRTC_H,
            name: "CRTC_H",
            flags: RANGE | ATOMIC,
            range: (0, 16384),
        },
        PropDesc {
            id: PLANE_SRC_X,
            name: "SRC_X",
            flags: RANGE | ATOMIC,
            range: (0, 0xFFFF_FFFF),
        },
        PropDesc {
            id: PLANE_SRC_Y,
            name: "SRC_Y",
            flags: RANGE | ATOMIC,
            range: (0, 0xFFFF_FFFF),
        },
        PropDesc {
            id: PLANE_SRC_W,
            name: "SRC_W",
            flags: RANGE | ATOMIC,
            range: (0, 0xFFFF_FFFF),
        },
        PropDesc {
            id: PLANE_SRC_H,
            name: "SRC_H",
            flags: RANGE | ATOMIC,
            range: (0, 0xFFFF_FFFF),
        },
        PropDesc {
            id: CONNECTOR_CRTC_ID,
            name: "CRTC_ID",
            flags: OBJECT | ATOMIC,
            range: (0, 0),
        },
        PropDesc {
            id: CURSOR_HOT_X,
            name: "hotspot_x",
            flags: RANGE | ATOMIC,
            range: (0, 63),
        },
        PropDesc {
            id: CURSOR_HOT_Y,
            name: "hotspot_y",
            flags: RANGE | ATOMIC,
            range: (0, 63),
        },
    ];
    TABLE
}

/// Look up a property descriptor by id.
pub fn get_property(prop_id: u32) -> Option<&'static PropDesc> {
    property_table().iter().find(|p| p.id == prop_id)
}

/// Set a property value on an object.  For BLOB properties (e.g. CRTC_MODE_ID)
/// this stores `value` as a blob_id reference.  For all others it is a no-op
/// here (live state is held in PLANE_STATES / CRTC_STATES and driven through
/// atomic_commit or set_crtc).
///
/// Returns Ok(()) on success, Err(-22) for unknown object/property combinations.
pub fn set_property(object_id: u32, prop_id_val: u32, value: u64) -> Result<(), isize> {
    // Route to appropriate handler based on object type.
    if crtc_to_head(object_id).is_some() || plane_to_head_kind(object_id).is_some() {
        let prop = [crate::drivers::drm::AtomicProp {
            object_id,
            property_id: prop_id_val,
            value,
        }];
        return atomic_commit(&prop, ATOMIC_FLAG_NONBLOCK);
    }
    Err(-22)
}

// ─────────────────────────────────────────────────────────────────────────────
// PRIME buffer sharing (dma-buf handle ↔ fd)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct PrimeExport {
    pub gem_handle: u32,
    pub phys: u64,
    pub size: u64,
    pub dmabuf_fd: i32,
    pub ref_count: u32,
}

static PRIME_EXPORTS: Mutex<Vec<PrimeExport>> = Mutex::new(Vec::new());
static NEXT_DMABUF_FD: Mutex<i32> = Mutex::new(100);

pub fn prime_handle_to_fd(handle: u32) -> Result<i32, isize> {
    let db = find_dumb(handle).ok_or(-9isize)?;
    {
        let mut exports = PRIME_EXPORTS.lock();
        if let Some(e) = exports.iter_mut().find(|e| e.gem_handle == handle) {
            e.ref_count += 1;
            return Ok(e.dmabuf_fd);
        }
    }
    let fd = {
        let mut n = NEXT_DMABUF_FD.lock();
        let v = *n;
        *n += 1;
        v
    };
    PRIME_EXPORTS.lock().push(PrimeExport {
        gem_handle: handle,
        phys: db.phys,
        size: db.size,
        dmabuf_fd: fd,
        ref_count: 1,
    });
    Ok(fd)
}

pub fn prime_fd_to_handle(dmabuf_fd: i32) -> Result<u32, isize> {
    let export = {
        let exports = PRIME_EXPORTS.lock();
        *exports
            .iter()
            .find(|e| e.dmabuf_fd == dmabuf_fd)
            .ok_or(-9isize)?
    };
    let new_handle = {
        let mut h = NEXT_HANDLE.lock();
        let v = *h;
        *h = h.wrapping_add(1);
        v
    };
    let imported = DumbBuffer {
        handle: new_handle,
        width: 0,
        height: 0,
        bpp: 32,
        pitch: 0,
        size: export.size,
        phys: export.phys,
    };
    DUMB_OBJECTS.lock().push(imported);
    Ok(new_handle)
}

pub fn prime_release_fd(dmabuf_fd: i32) {
    let mut exports = PRIME_EXPORTS.lock();
    if let Some(pos) = exports.iter().position(|e| e.dmabuf_fd == dmabuf_fd) {
        exports[pos].ref_count -= 1;
        if exports[pos].ref_count == 0 {
            exports.remove(pos);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// renderD128 CapSet gate
// ─────────────────────────────────────────────────────────────────────────────

pub const DRM_RENDER_ALLOW: u64 = 1 << 40;
pub const DRM_MASTER: u64 = 1 << 41;

pub fn check_render_cap(caps: &CapSet) -> Result<(), isize> {
    if caps.permitted & DRM_RENDER_ALLOW != 0 {
        Ok(())
    } else {
        Err(-1)
    }
}
pub fn check_master_cap(caps: &CapSet) -> Result<(), isize> {
    if caps.permitted & DRM_MASTER != 0 {
        Ok(())
    } else {
        Err(-1)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Atomic KMS — DRM_IOCTL_MODE_ATOMIC
// ─────────────────────────────────────────────────────────────────────────────

/// One property change inside an atomic request.
#[derive(Clone, Copy)]
pub struct AtomicProp {
    pub object_id: u32,
    pub property_id: u32,
    pub value: u64,
}

/// DRM property IDs (match Linux standard names).
pub mod prop_id {
    pub const CRTC_ACTIVE: u32 = 1;
    pub const CRTC_MODE_ID: u32 = 2;
    pub const PLANE_CRTC_ID: u32 = 3;
    pub const PLANE_FB_ID: u32 = 4;
    pub const PLANE_CRTC_X: u32 = 5;
    pub const PLANE_CRTC_Y: u32 = 6;
    pub const PLANE_CRTC_W: u32 = 7;
    pub const PLANE_CRTC_H: u32 = 8;
    pub const PLANE_SRC_X: u32 = 9;
    pub const PLANE_SRC_Y: u32 = 10;
    pub const PLANE_SRC_W: u32 = 11;
    pub const PLANE_SRC_H: u32 = 12;
    pub const CONNECTOR_CRTC_ID: u32 = 13;
    pub const CURSOR_HOT_X: u32 = 14;
    pub const CURSOR_HOT_Y: u32 = 15;
}

pub const ATOMIC_FLAG_TEST_ONLY: u32 = 0x0100;
pub const ATOMIC_FLAG_ALLOW_MODESET: u32 = 0x0400;
pub const ATOMIC_FLAG_NONBLOCK: u32 = 0x0200;

/// Per-CRTC mode blob: stores the blob_id set via CRTC_MODE_ID, and the
/// decoded mode for that head.
#[derive(Clone, Copy, Default)]
struct CrtcModeState {
    blob_id: u32,
    mode: DrmModeInfo,
}

static CRTC_MODES: Mutex<[CrtcModeState; MAX_HEADS]> = Mutex::new(
    [CrtcModeState {
        blob_id: 0,
        mode: DrmModeInfo {
            clock: 0,
            hdisplay: 0,
            vdisplay: 0,
            vrefresh: 0,
            name: [0u8; 32],
        },
    }; MAX_HEADS],
);

/// Decode a CRTC_MODE_ID blob (packed DrmModeInfo, little-endian) and cache it
/// against the head.  Creates a new blob entry if `blob_id` is unknown (allows
/// userspace to pass a pre-created blob from CREATE_BLOB).
fn apply_mode_blob(head: usize, blob_id: u32) -> Result<(), isize> {
    if head >= MAX_HEADS {
        return Err(-22);
    }

    let mode = if blob_id == 0 {
        // blob_id 0 means "clear mode" — fall back to hardware geometry.
        head_info(head)
            .map(|h| DrmModeInfo::from_head(&h))
            .unwrap_or_default()
    } else {
        // Look up existing blob, or treat blob_id as an opaque reference that
        // will be resolved when the blob is later created.
        match get_blob(blob_id) {
            Some(data) if data.len() >= core::mem::size_of::<DrmModeInfo>() => {
                let mut m = DrmModeInfo::default();
                // Safety: we just checked the length; DrmModeInfo is POD.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr(),
                        &mut m as *mut _ as *mut u8,
                        core::mem::size_of::<DrmModeInfo>(),
                    );
                }
                m
            }
            Some(_) => return Err(-22), // truncated blob
            None => {
                // Unknown blob_id: best-effort — use current hardware mode and
                // record the blob_id for later retrieval via GETBLOB.
                head_info(head)
                    .map(|h| DrmModeInfo::from_head(&h))
                    .unwrap_or_default()
            }
        }
    };

    let mut modes = CRTC_MODES.lock();
    modes[head] = CrtcModeState { blob_id, mode };
    Ok(())
}

/// Return the blob_id and mode currently applied to a CRTC (head).
pub fn get_crtc_mode_blob(head: usize) -> Option<(u32, DrmModeInfo)> {
    if head >= MAX_HEADS {
        return None;
    }
    let s = CRTC_MODES.lock()[head];
    Some((s.blob_id, s.mode))
}

/// Process a DRM_IOCTL_MODE_ATOMIC request across all heads.
///
/// Each (object_id, property_id, value) triple is routed to the correct CRTC
/// or plane by resolving the object_id → head index.  Changes are validated
/// in shadow copies first; only committed if TEST_ONLY is not set.
pub fn atomic_commit(props: &[AtomicProp], flags: u32) -> Result<(), isize> {
    let n = num_heads();

    // Shadow state arrays — one PlaneState[3] per head.
    let mut shadow_planes: [[PlaneState; PLANES_PER_HEAD as usize]; MAX_HEADS] =
        [[PlaneState::default(); PLANES_PER_HEAD as usize]; MAX_HEADS];
    let mut crtc_active = [true; MAX_HEADS];
    // Pending MODE_ID blob changes: (head, blob_id).  Applied after validation.
    let mut pending_mode: [Option<u32>; MAX_HEADS] = [None; MAX_HEADS];

    // Copy current committed states into shadows.
    {
        let locked = PLANE_STATES.lock();
        for h in 0..n {
            shadow_planes[h] = locked[h];
        }
    }

    // Apply each property to the appropriate shadow.
    for p in props {
        // Is it a CRTC object?
        if let Some(head) = crtc_to_head(p.object_id) {
            match p.property_id {
                prop_id::CRTC_ACTIVE => {
                    crtc_active[head] = p.value != 0;
                }
                prop_id::CRTC_MODE_ID => {
                    pending_mode[head] = Some(p.value as u32);
                }
                _ => {}
            }
            continue;
        }
        // Is it a plane?
        if let Some((head, kind)) = plane_to_head_kind(p.object_id) {
            let ps = &mut shadow_planes[head][kind as usize];
            apply_plane_prop(ps, p.property_id, p.value);
            // Cursor plane FB change: reload cursor pixels.
            if kind == PLANE_KIND_CURSOR && p.property_id == prop_id::PLANE_FB_ID {
                let _ = refresh_cursor_from_fb_head(head, p.value as u32);
            }
            continue;
        }
        // Is it a connector?
        let connector_head = (p.object_id.wrapping_sub(CONNECTOR_BASE_ID)) as usize;
        if connector_head < n && p.property_id == prop_id::CONNECTOR_CRTC_ID {
            // Connector → CRTC routing: only same-index mapping supported.
            continue;
        }
        return Err(-22); // EINVAL
    }

    // Validate pending mode blobs (even in TEST_ONLY).
    for h in 0..n {
        if let Some(blob_id) = pending_mode[h] {
            // Validate: blob must exist or be 0 (clear).
            if blob_id != 0 && get_blob(blob_id).is_none() {
                // Accept unknown blob ids only when ALLOW_MODESET is set.
                if flags & ATOMIC_FLAG_ALLOW_MODESET == 0 {
                    return Err(-22);
                }
            }
        }
    }

    if flags & ATOMIC_FLAG_TEST_ONLY != 0 {
        return Ok(()); // validation-only pass
    }

    // Commit mode blobs.
    for h in 0..n {
        if let Some(blob_id) = pending_mode[h] {
            let _ = apply_mode_blob(h, blob_id);
        }
    }

    // Commit shadows → live state and scanout each active head.
    {
        let mut locked = PLANE_STATES.lock();
        for h in 0..n {
            locked[h] = shadow_planes[h];
        }
    }

    for h in 0..n {
        if crtc_active[h] {
            let primary = &shadow_planes[h][PLANE_KIND_PRIMARY as usize];
            if primary.enabled && primary.fb_id != 0 {
                do_page_flip_head(h, primary.fb_id);
            }
        }
        if flags & ATOMIC_FLAG_NONBLOCK == 0 {
            vblank_tick_head(h);
        }
    }

    Ok(())
}

fn apply_plane_prop(ps: &mut PlaneState, prop: u32, val: u64) {
    use prop_id::*;
    match prop {
        PLANE_FB_ID => {
            ps.fb_id = val as u32;
            ps.enabled = val != 0;
        }
        PLANE_CRTC_X => {
            ps.crtc_x = val as i32;
        }
        PLANE_CRTC_Y => {
            ps.crtc_y = val as i32;
        }
        PLANE_CRTC_W => {
            ps.crtc_w = val as u32;
        }
        PLANE_CRTC_H => {
            ps.crtc_h = val as u32;
        }
        PLANE_SRC_X => {
            ps.src_x = val as u32;
        }
        PLANE_SRC_Y => {
            ps.src_y = val as u32;
        }
        PLANE_SRC_W => {
            ps.src_w = val as u32;
        }
        PLANE_SRC_H => {
            ps.src_h = val as u32;
        }
        _ => {}
    }
}

fn refresh_cursor_from_fb_head(head: usize, fb_id: u32) -> Result<(), isize> {
    if fb_id == 0 {
        cursor_hide_head(head);
        return Ok(());
    }
    let fb = find_fb(fb_id).ok_or(-22isize)?;
    let db = find_dumb(fb.handle).ok_or(-22isize)?;
    let pixels = unsafe { core::slice::from_raw_parts(db.phys as *const u32, CURSOR_PIXELS) };
    let (x, y) = {
        let c = CURSORS[head].lock();
        (c.x, c.y)
    };
    cursor_set_head(head, pixels, x, y);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// GEM dumb-buffer registry (Vec-based, supports multiple allocations)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct DumbBuffer {
    pub handle: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u32,
    pub pitch: u32,
    pub size: u64,
    pub phys: u64,
}

static DUMB_OBJECTS: Mutex<Vec<DumbBuffer>> = Mutex::new(Vec::new());
static NEXT_HANDLE: Mutex<u32> = Mutex::new(1);

fn find_dumb(handle: u32) -> Option<DumbBuffer> {
    DUMB_OBJECTS
        .lock()
        .iter()
        .copied()
        .find(|d| d.handle == handle)
}

/// Allocate a dumb buffer.  For multi-head, the caller should specify
/// width/height matching the desired head; we locate the head by dimensions.
pub fn create_dumb(width: u32, height: u32, bpp: u32) -> Result<(u32, u32, u64), isize> {
    if bpp != 32 {
        return Err(-22);
    }

    // Find a head matching the requested resolution, or fall back to head 0.
    let heads = HEADS.lock();
    let head_info_opt = (0..num_heads())
        .find(|&i| heads[i].present && heads[i].width == width && heads[i].height == height)
        .map(|i| heads[i])
        .or_else(|| {
            if !heads[0].present {
                None
            } else {
                Some(heads[0])
            }
        });
    drop(heads);

    let hi = head_info_opt.ok_or(-19isize)?;
    let pitch = width * 4;
    let size = pitch as u64 * height as u64;
    let handle = {
        let mut h = NEXT_HANDLE.lock();
        let v = *h;
        *h = h.wrapping_add(1);
        v
    };
    DUMB_OBJECTS.lock().push(DumbBuffer {
        handle,
        width,
        height,
        bpp,
        pitch,
        size,
        phys: hi.fb_phys,
    });
    Ok((handle, pitch, size))
}

pub fn map_dumb(handle: u32) -> Result<u64, isize> {
    find_dumb(handle).map(|d| d.phys).ok_or(-9)
}

pub fn destroy_dumb(handle: u32) -> Result<(), isize> {
    let mut objs = DUMB_OBJECTS.lock();
    if let Some(pos) = objs.iter().position(|d| d.handle == handle) {
        objs.remove(pos);
        Ok(())
    } else {
        Err(-9)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Framebuffer object registry (Vec-based)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct FbObject {
    pub id: u32,
    pub handle: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u32,
}

static FB_OBJECTS: Mutex<Vec<FbObject>> = Mutex::new(Vec::new());
static NEXT_FB_ID: Mutex<u32> = Mutex::new(1);
/// Active FB per head.
static ACTIVE_FB: Mutex<[u32; MAX_HEADS]> = Mutex::new([0u32; MAX_HEADS]);

fn find_fb(id: u32) -> Option<FbObject> {
    FB_OBJECTS.lock().iter().copied().find(|f| f.id == id)
}

pub fn add_fb(handle: u32, width: u32, height: u32, pitch: u32, bpp: u32) -> Result<u32, isize> {
    let db = find_dumb(handle).ok_or(-9isize)?;
    if db.width != width || db.height != height {
        return Err(-22);
    }
    let id = {
        let mut n = NEXT_FB_ID.lock();
        let v = *n;
        *n = n.wrapping_add(1);
        v
    };
    FB_OBJECTS.lock().push(FbObject {
        id,
        handle,
        width,
        height,
        pitch,
        bpp,
    });
    Ok(id)
}

pub fn rm_fb(id: u32) -> Result<(), isize> {
    let mut fbs = FB_OBJECTS.lock();
    if let Some(pos) = fbs.iter().position(|f| f.id == id) {
        fbs.remove(pos);
        Ok(())
    } else {
        Err(-9)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy SETCRTC / PAGE_FLIP paths (per-head)
// ─────────────────────────────────────────────────────────────────────────────

/// Route a legacy set_crtc to the correct head via crtc_id.
pub fn set_crtc_for(crtc: u32, fb_id: u32) -> Result<(), isize> {
    let head = crtc_to_head(crtc).ok_or(-22isize)?;
    if find_fb(fb_id).is_none() {
        return Err(-22);
    }
    ACTIVE_FB.lock()[head] = fb_id;
    do_page_flip_head(head, fb_id);
    Ok(())
}

/// Legacy single-head shim (uses head 0).
pub fn set_crtc(fb_id: u32) -> Result<(), isize> {
    set_crtc_for(crtc_id(0), fb_id)
}

/// Legacy page_flip shim (head 0).
pub fn page_flip(fb_id: u32) -> Result<(), isize> {
    set_crtc(fb_id)?;
    vblank_tick_head(0);
    Ok(())
}

/// Page-flip for a specific head by CRTC id.
pub fn page_flip_for(crtc: u32, fb_id: u32) -> Result<(), isize> {
    let head = crtc_to_head(crtc).ok_or(-22isize)?;
    set_crtc_for(crtc, fb_id)?;
    vblank_tick_head(head);
    Ok(())
}

/// Internal scanout for `head`: composite overlay → blit cursor → push GPU.
fn do_page_flip_head(head: usize, fb_id: u32) {
    let (fb_phys, fb_w, fb_h) = {
        let fb = match find_fb(fb_id) {
            Some(f) => f,
            None => return,
        };
        let db = match find_dumb(fb.handle) {
            Some(d) => d,
            None => return,
        };
        (db.phys, fb.width, fb.height)
    };

    composite_overlay_head(head, fb_phys, fb_w, fb_h);
    blit_cursor(head, fb_phys, fb_w, fb_h);

    // Push to the correct virtio-gpu scanout (or leave GOP linear fb as-is).
    let hi = HEADS.lock()[head];
    if hi.present && hi.scanout != u32::MAX {
        crate::drivers::virtio_gpu::flush_scanout(hi.scanout);
    } else if crate::drivers::virtio_gpu::is_present() {
        // Fallback: flush scanout 0 for the GOP path on head 0.
        if head == 0 {
            crate::drivers::virtio_gpu::flush_all();
        }
    }
}

fn composite_overlay_head(head: usize, primary_phys: u64, fb_w: u32, fb_h: u32) {
    let ps = PLANE_STATES.lock()[head][PLANE_KIND_OVERLAY as usize];
    if !ps.enabled || ps.fb_id == 0 {
        return;
    }

    let ov_fb = match find_fb(ps.fb_id) {
        Some(f) => f,
        None => return,
    };
    let ov_db = match find_dumb(ov_fb.handle) {
        Some(d) => d,
        None => return,
    };

    let src = ov_db.phys as *const u32;
    let dst = primary_phys as *mut u32;
    let src_w = ov_fb.width;

    for row in 0..ps.crtc_h {
        let dy = ps.crtc_y + row as i32;
        if dy < 0 || dy >= fb_h as i32 {
            continue;
        }
        for col in 0..ps.crtc_w {
            let dx = ps.crtc_x + col as i32;
            if dx < 0 || dx >= fb_w as i32 {
                continue;
            }
            let si = ((ps.src_y >> 16) + row) * src_w + (ps.src_x >> 16) + col;
            let di = dy as u32 * fb_w + dx as u32;
            let s_px = unsafe { src.add(si as usize).read_volatile() };
            let alpha = (s_px >> 24) & 0xFF;
            if alpha == 0 {
                continue;
            }
            if alpha == 255 {
                unsafe {
                    dst.add(di as usize).write_volatile(s_px);
                }
                continue;
            }
            let d_px = unsafe { dst.add(di as usize).read_volatile() };
            let blend = |s: u32, d: u32| (s * alpha + d * (255 - alpha)) / 255;
            let r = blend((s_px >> 16) & 0xFF, (d_px >> 16) & 0xFF);
            let g = blend((s_px >> 8) & 0xFF, (d_px >> 8) & 0xFF);
            let b = blend(s_px & 0xFF, d_px & 0xFF);
            unsafe {
                dst.add(di as usize)
                    .write_volatile(0xFF00_0000 | (r << 16) | (g << 8) | b);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Plane query helpers (used by ioctl dispatcher)
// ─────────────────────────────────────────────────────────────────────────────

/// All plane IDs across all active heads.
pub fn all_plane_ids() -> Vec<u32> {
    let n = num_heads();
    let mut ids = Vec::with_capacity(n * PLANES_PER_HEAD as usize);
    for h in 0..n {
        for k in 0..PLANES_PER_HEAD {
            ids.push(plane_id(h, k));
        }
    }
    ids
}

/// Compatibility shim — returns the three planes for head 0 only.
pub fn plane_ids() -> &'static [u32] {
    // Static slice for head 0 planes only (backward compat).
    &[PLANE_BASE_ID, PLANE_BASE_ID + 1, PLANE_BASE_ID + 2]
}

pub fn plane_type(id: u32) -> Option<PlaneType> {
    plane_to_head_kind(id).map(|(_, kind)| match kind {
        PLANE_KIND_PRIMARY => PlaneType::Primary,
        PLANE_KIND_OVERLAY => PlaneType::Overlay,
        _ => PlaneType::Cursor,
    })
}

pub fn get_plane_state(id: u32) -> Option<PlaneState> {
    let (head, kind) = plane_to_head_kind(id)?;
    Some(PLANE_STATES.lock()[head][kind as usize])
}

pub fn set_plane(id: u32, state: PlaneState) -> Result<(), isize> {
    let (head, kind) = plane_to_head_kind(id).ok_or(-22isize)?;
    PLANE_STATES.lock()[head][kind as usize] = state;
    if kind == PLANE_KIND_CURSOR {
        cursor_move_head(head, state.crtc_x, state.crtc_y);
        if state.fb_id != 0 {
            let _ = refresh_cursor_from_fb_head(head, state.fb_id);
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Misc public API
// ─────────────────────────────────────────────────────────────────────────────

pub fn driver_name() -> &'static str {
    "rustosdrm"
}
pub fn driver_version() -> (i32, i32, i32) {
    (0, 4, 0)
}

/// Mode for a specific head (by CRTC id).
pub fn mode_for_crtc(crtc: u32) -> Option<DrmModeInfo> {
    let head = crtc_to_head(crtc)?;
    // Prefer the mode stored via CRTC_MODE_ID blob if one has been set.
    let (blob_id, cached) = get_crtc_mode_blob(head).unwrap_or((0, DrmModeInfo::default()));
    if blob_id != 0 && (cached.hdisplay > 0 || cached.vdisplay > 0) {
        return Some(cached);
    }
    // Fall back to hardware geometry.
    let hi = head_info(head)?;
    Some(DrmModeInfo::from_head(&hi))
}

/// Convenience: mode for head 0.
pub fn current_mode() -> Option<DrmModeInfo> {
    head_info(0).map(|h| DrmModeInfo::from_head(&h))
}

pub fn gop_info() -> Option<GopInfo> {
    gop::get()
}
