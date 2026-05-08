//! Wayland server — kernel side.
//!
//! ## Architecture
//!
//! The Wayland compositor runs as a **privileged userspace process**
//! (`/usr/bin/rustos-compositor`), not as a kernel thread.  The kernel's
//! only responsibilities here are:
//!
//!   1. Expose `/dev/dri/card0` so the compositor can open it and call
//!      DRM ioctls to allocate/map framebuffers and receive vblank events.
//!   2. Expose `/dev/input/event0` (evdev) so the compositor can read
//!      keyboard and pointer events.
//!   3. Support `AF_UNIX` sockets so the compositor can bind
//!      `/run/wayland-0` and accept client connections.
//!   4. After init (PID 1) is running, exec the compositor binary and
//!      pass it the DRM fd and input fd via the standard fd-passing
//!      convention (`WAYLAND_DRM_FD` env var).
//!
//! Everything else — wire protocol parsing, surface compositing, frame
//! callbacks, seat/input routing — lives in `userspace/wayland/compositor.c`.
//!
//! ## Why userspace?
//!
//! Running a Wayland compositor in kernel mode is unsafe:
//!   - GPU/DRM code has a high bug density; a compositor crash becomes a
//!     kernel panic.
//!   - The compositor has no need for ring-0 privileges; it only needs an
//!     open fd to `/dev/dri/card0` (DRM master) and `/dev/input/event0`.
//!   - A userspace compositor crash is recoverable: PID 1 (init) receives
//!     SIGCHLD and can restart it without rebooting.
//!   - The seccomp filter in the compositor binary restricts it to fewer
//!     than 15 syscalls, dramatically reducing the attack surface.

/// Path to the compositor binary in the initramfs.
pub const COMPOSITOR_BIN: &str = "/usr/bin/rustos-compositor";

/// Environment variable the compositor reads to learn which fd is the DRM
/// master fd (passed via `fcntl(F_DUPFD_CLOEXEC)` before exec).
pub const WAYLAND_DRM_FD_ENV: &str = "WAYLAND_DRM_FD";

/// Launch the Wayland compositor as a privileged userspace process.
///
/// Called once from `kernel_main` after:
///   - The VFS is mounted (so `/dev/dri/card0` is accessible)
///   - PID 1 (init) is already running
///   - The DRM driver has set up `/dev/dri/card0`
///
/// The compositor inherits:
///   - fd 0  → `/dev/null`  (stdin)
///   - fd 1  → `/dev/console` (stdout / log)
///   - fd 2  → `/dev/console` (stderr / log)
///   - fd 3  → `/dev/dri/card0` opened with O_RDWR (DRM master)
///   - fd 4  → `/dev/input/event0` opened with O_RDONLY | O_NONBLOCK
///
/// The compositor is spawned with a minimal capability set:
///   CAP_SYS_ADMIN is NOT granted — it only needs the open DRM fd.
pub fn spawn_compositor() {
    use crate::fs::vfs;
    use crate::proc::exec;
    use crate::proc::scheduler;

    // ── Open device fds that will be inherited by the compositor ────────────
    let drm_fd = vfs::open("/dev/dri/card0", vfs::O_RDWR);
    if drm_fd < 0 {
        log::warn!("[wayland] /dev/dri/card0 not available — compositor not started");
        return;
    }
    let input_fd = vfs::open("/dev/input/event0", vfs::O_RDONLY | vfs::O_NONBLOCK);

    // ── Build argv and envp ──────────────────────────────────────────────────
    let argv: &[&str] = &[COMPOSITOR_BIN];
    let drm_fd_str = alloc::format!("{}={}", WAYLAND_DRM_FD_ENV, drm_fd);
    let input_fd_str = alloc::format!("WAYLAND_INPUT_FD={}", input_fd);
    let envp: alloc::vec::Vec<alloc::string::String> = alloc::vec![
        alloc::string::String::from("HOME=/root"),
        alloc::string::String::from("PATH=/usr/bin:/bin"),
        alloc::string::String::from("XDG_RUNTIME_DIR=/run"),
        alloc::string::String::from("WAYLAND_DISPLAY=wayland-0"),
        drm_fd_str,
        input_fd_str,
    ];

    // ── Spawn ────────────────────────────────────────────────────────────────
    let ok = exec::spawn_user_process(COMPOSITOR_BIN, argv, &envp);
    if ok {
        log::info!("[wayland] compositor spawned as PID {}",
            scheduler::last_spawned_pid());
    } else {
        log::warn!("[wayland] failed to spawn compositor (binary missing?)");
    }
}
