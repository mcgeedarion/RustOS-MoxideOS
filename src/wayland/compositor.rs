//! Wayland compositor — kernel interface layer.
//!
//! ## What lives here (kernel side)
//!
//! This module is now intentionally minimal.  The full compositor logic
//! (wire protocol parsing, surface tree, input routing, frame callbacks)
//! has moved to the privileged userspace process at
//! `userspace/wayland/compositor.c`.
//!
//! The kernel retains only two thin responsibilities:
//!
//!   1. `wl_surface_commit_kernel` — called by the DRM ioctl handler when
//!      the compositor userspace process issues `DRM_IOCTL_MODE_PAGE_FLIP`
//!      or `DRM_IOCTL_MODE_ATOMIC`.  This is the *only* path that writes
//!      to the physical framebuffer from kernel space, and it only does so
//!      through the already-audited `drm::page_flip` codepath.
//!
//!   2. `vblank_notify` — invoked from the DRM vblank ISR to wake the
//!      compositor process (which is blocked in `DRM_IOCTL_WAIT_VBLANK`
//!      via the normal DRM eventfd delivery path).
//!
//! All other compositor state — client connections, object tables, surface
//! trees, damage tracking — is owned by the userspace compositor process.
//! The kernel never touches it.
//!
//! ## Security improvement
//!
//! Previously this file contained ~150 lines of surface compositing logic
//! that performed raw pointer arithmetic over physical framebuffer memory
//! and client-provided buffer PAs — in ring 0.  A single out-of-bounds
//! `copy_nonoverlapping` would have been a kernel write primitive.
//!
//! Now the kernel only calls `drm::page_flip(fb_id)` — a function that
//! already validates the framebuffer object's bounds before touching any
//! physical memory.  The compositor's surface blending runs in ring 3
//! against mmap'd DRM dumb buffers; an out-of-bounds write there is a
//! normal userspace segfault.

/// Called by the DRM vblank ISR to deliver the vblank event to the
/// compositor process via the eventfd registered with
/// `DRM_IOCTL_WAIT_VBLANK`.
///
/// This is a pure pass-through to `drm::deliver_vblank_event()`; no
/// compositor logic runs in the kernel.
pub fn vblank_notify(crtc_id: u32) {
    crate::drivers::drm::deliver_vblank_event(crtc_id);
}
