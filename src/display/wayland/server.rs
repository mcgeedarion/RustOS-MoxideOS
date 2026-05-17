//! Wayland server — kernel side.
//!
//! ## Architecture
//!
//! The Wayland compositor runs as a **privileged userspace process**
//! (`/usr/bin/rustos-compositor`), not as a kernel thread.
//!
//! ### Lifecycle ownership
//!
//! Compositor lifecycle is owned entirely by **PID 1** (`/sbin/init`,
//! built from `userspace/init/init.c`).  The sequence is:
//!
//!   1. The kernel boots, mounts devfs, and execs `/sbin/init`.
//!   2. init opens `/dev/dri/card0` (O_RDWR, DRM master) and
//!      `/dev/input/event0` (O_RDONLY|O_NONBLOCK).
//!   3. init forks and execs `/usr/bin/rustos-compositor`, passing the
//!      open fds via the `WAYLAND_DRM_FD` and `WAYLAND_INPUT_FD`
//!      environment variables.
//!   4. init sits in a `waitpid(-1, ...)` supervisor loop.  If the
//!      compositor crashes or exits, init closes the old device fds,
//!      sleeps one second, reopens them (releasing and reacquiring DRM
//!      master), and re-execs the compositor binary.
//!
//! ### Why init, not the kernel?
//!
//! A Wayland compositor needs no kernel privileges — it only needs an
//! open fd to `/dev/dri/card0` (DRM master) and `/dev/input/event0`.
//! Spawning it from PID 1 means:
//!
//!   - The kernel Wayland code is reduced to a thin vblank pass-through.
//!   - A compositor crash produces an ordinary `SIGCHLD` to init, not a
//!     kernel panic.
//!   - The compositor binary is restricted by a seccomp filter to fewer
//!     than 15 syscalls; restart policy is enforced without kernel changes.
//!   - DRM master is cleanly released when the compositor process exits,
//!     because the fd is closed automatically by the process teardown path.
//!
//! ### Kernel responsibilities
//!
//! The kernel retains only four responsibilities related to Wayland:
//!
//!   1. Expose `/dev/dri/card0` via devfs so init can open it.
//!   2. Expose `/dev/input/event0` via the evdev driver so init can open it.
//!   3. Support `AF_UNIX` sockets so the compositor can bind
//!      `/run/wayland-0` and accept client connections.
//!   4. Deliver vblank events via `drm::deliver_vblank_event()`, called
//!      from the DRM vblank ISR through `compositor::vblank_notify()`.
//!
//! Everything else — wire protocol, surface tree, damage tracking,
//! input routing, frame callbacks — lives in the compositor userspace
//! process (`userspace/wayland/compositor.c`).

// No public API: this module exists only to document the architecture.
