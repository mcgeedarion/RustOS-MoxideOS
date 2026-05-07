# RustOS

A hobby operating-system kernel written in **Rust**, targeting **RISC-V 64** (primary) and **x86_64** (secondary). Runs on bare metal and under QEMU. No C runtime, no external libc.

---

## Architecture support

| Target | Boot | Paging | Syscall | Status |
|---|---|---|---|---|
| `riscv64-uefi.json` | **UEFI** (default) | sv39 | `ecall` | **Primary** |
| `riscv64gc-unknown-none-elf` | SBI (`--boot sbi`) | sv39 | `ecall` | Secondary |
| `x86_64-unknown-none` | UEFI | 4-level (PML4) | `syscall`/`sysret` | Tertiary |

RISC-V boot modes:
- **UEFI** (default) — EDK2 RiscVVirt calls `uefi_start`; output is a PE/COFF `.efi` binary on a FAT ESP; requires `qemu-efi-riscv64`
- **SBI** (`--boot sbi`) — OpenSBI hands off to `_start` in S-mode; no extra firmware; pass `--no-default-features` to disable `uefi_boot`

---

## Feature overview

### Hardware abstraction
- RISC-V: UEFI + SBI boot, CSR helpers, PLIC, CLINT, sv39 trap handling
- x86_64: GDT, IDT, APIC (local + I/O), TSS, `RDMSR`/`WRMSR`, serial UART, PS/2
- PCIe MMIO enumeration; virtio-blk (read + write), virtio-net

### Memory management
- Physical memory manager (PMM): buddy-style free-list
- Virtual memory manager (VMM): sorted VMA list, O(log n) `find_vma` / `insert_vma`
- Demand paging: anonymous zero-fill, file-backed (`VmaKind::FileBacked`), SIGBUS on short read
- Copy-on-Write (CoW) fork; `mmap` / `munmap` / `mprotect`; `brk` with proper VMA tracking
- `MAP_FIXED` correctly evicts stale VMAs before remapping
- Kernel heap: slab-style allocator over the buddy PMM

### Processes & scheduling
- `fork`, `clone` (POSIX thread ABI), `execve`, `exit`, `waitpid`
- Round-robin scheduler; `futex` (FUTEX_WAIT / FUTEX_WAKE)
- Full POSIX signal delivery: `sigaction`, `sigprocmask`, `kill`, `tkill`, real-time queued signals
- `vfork` / `CLONE_VFORK` with parent suspension
- `pidfd_open`, `pidfd_send_signal`
- Per-process capability sets (`CapSet`)

### Filesystem
- VFS layer with fd table, `fcntl`, `dup2`, `O_CLOEXEC`
- ext2 (read + write), initramfs (read-only tarball)
- devfs (`/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/tty`, `/dev/fb0`, block devices)
- procfs: `/proc/self/{exe,maps,status,fd/N}`, `/proc/{cpuinfo,meminfo,version}`
- `pipe`, `eventfd`, `poll`/`epoll`, `ioctl`, `getdents64`, `fstat`/`newfstatat`
- `pread64` (user-space) and `vfs::pread` (kernel-internal, used by demand-pager & ELF loader)

### Networking
- smoltcp-backed stack: Ethernet, ARP, IPv4, TCP, UDP, ICMP, DHCP, DNS
- BSD socket API: `socket`, `bind`, `connect`, `listen`, `accept`, `send`/`recv`, `sendto`/`recvfrom`

### Dynamic linking
- ELF loader: `PT_LOAD`, `PT_INTERP`, `PT_PHDR`; full aux-vector (`AT_*`) construction
- Interpreter (dynamic linker) loaded at `INTERP_BASE`; `LD_PRELOAD` support

### DRM/KMS subsystem

The kernel exposes a Linux-compatible Direct Rendering Manager (DRM) and Kernel Mode Setting (KMS) interface via `/dev/dri/card0`. The stack is layered as follows:

```
Userspace (EGL / GBM / Wayland / libdrm)
        |   ioctl(fd, DRM_IOCTL_*, ...)
        v
  VFS ioctl dispatcher  (fs/ioctl.rs)
        |
        v
  DRM core  (drivers/drm.rs)
  +-------------------------------------------------+
  |  KMS objects: CRTC . Connector . Encoder        |
  |  Planes: primary . overlay . cursor (64×64)     |
  |  Atomic commit pipeline (MODE_ATOMIC)           |
  |  Dumb-buffer allocator (GEM handle registry)    |
  |  Framebuffer object table (add_fb / rm_fb)      |
  |  Simulated vblank (eventfd delivery)            |
  |  PRIME dma-buf export/import                    |
  |  renderD128 CapSet gate                         |
  +-------------------------------------------------+
        |                         |
        v                         v
  GOP framebuffer           virtio-gpu (drivers/virtio_gpu.rs)
  (UEFI linear fb)          controlq: TRANSFER / FLUSH
                            cursorq:  UPDATE_CURSOR / MOVE_CURSOR
```

#### Implemented ioctls (`/dev/dri/card0`)

| ioctl | Purpose |
|---|---|
| `DRM_IOCTL_VERSION` | Driver name (`rustosdrm`), version `0.2.0` |
| `DRM_IOCTL_GET_CAP` | Advertises `DUMB_BUFFER`, `VBLANK_HIGH_CRTC`, `PRIME_IMPORT`, `PRIME_EXPORT` |
| `DRM_IOCTL_MODE_GETRESOURCES` | Returns CRTC / connector / encoder ID lists |
| `DRM_IOCTL_MODE_GETCRTC` | Current CRTC state (mode, fb_id, position) |
| `DRM_IOCTL_MODE_GETCONNECTOR` | Connector type, status, current mode |
| `DRM_IOCTL_MODE_SETCRTC` | Programs a mode; performs immediate page-flip |
| `DRM_IOCTL_MODE_CREATE_DUMB` | Allocates a dumb buffer backed by the GOP/virtio-gpu framebuffer |
| `DRM_IOCTL_MODE_MAP_DUMB` | Returns mmap offset for a dumb buffer handle |
| `DRM_IOCTL_MODE_DESTROY_DUMB` | Releases a dumb buffer handle |
| `DRM_IOCTL_MODE_ADDFB` | Registers a framebuffer object over a dumb buffer |
| `DRM_IOCTL_MODE_RMFB` | Releases a framebuffer object |
| `DRM_IOCTL_MODE_PAGE_FLIP` | Schedules scanout; triggers vblank tick and eventfd delivery |
| `DRM_IOCTL_MODE_GETPLANERESOURCES` | Returns plane ID list (primary, overlay, cursor) |
| `DRM_IOCTL_MODE_GETPLANE` | Returns plane type, CRTC mask, current fb_id |
| `DRM_IOCTL_MODE_SETPLANE` | Attaches a framebuffer to a plane, sets src/dst rects |
| `DRM_IOCTL_MODE_ATOMIC` | Atomic commit with test-only, non-blocking, allow-modeset flags |
| `DRM_IOCTL_PRIME_HANDLE_TO_FD` | Exports a GEM handle as a dma-buf fd |
| `DRM_IOCTL_PRIME_FD_TO_HANDLE` | Imports a dma-buf fd as a new GEM handle (zero-copy) |
| `DRM_IOCTL_WAIT_VBLANK` | Registers an eventfd to be signalled at the next vblank |

#### KMS object model

A single fixed topology is exposed (one real display is the target use case):

```
Connector #1  -->  Encoder #1  -->  CRTC #1
 (HDMI/GOP)                           |
                          +-----------+-----------+
                          |           |           |
                     Plane #1    Plane #2    Plane #3
                    (primary)   (overlay)   (cursor)
```

- **CRTC** holds the active `DrmModeInfo` (pixel clock, `hdisplay`, `vdisplay`, `vrefresh`) derived from the GOP resolution at boot, or from the virtio-gpu display info query.
- **Connector** reports `status = connected`, `connector_type = HDMI_A`, and exposes the single available mode.
- **Planes**: primary covers the full CRTC; overlay and cursor are composited in software.

#### GEM dumb-buffer path

```
libdrm / app                      kernel
-----------------------------------------
DRM_IOCTL_MODE_CREATE_DUMB  -->  drm::create_dumb(w, h, 32bpp)
                                   +- allocates handle, records pitch/size/phys
DRM_IOCTL_MODE_MAP_DUMB     -->  drm::map_dumb(handle) -> phys offset
mmap(..., offset)           -->  mm::mmap with VmaKind::FileBacked -> GOP fb phys
DRM_IOCTL_MODE_ADDFB        -->  drm::add_fb(handle, w, h, pitch, bpp) -> fb_id
DRM_IOCTL_MODE_SETCRTC      -->  drm::set_crtc(fb_id)
                                   +- composites overlay + cursor, then flushes
DRM_IOCTL_MODE_PAGE_FLIP    -->  drm::page_flip(fb_id)
                                   +- calls vblank_tick() -> eventfd signal
                                   +- flushes virtio-gpu (TRANSFER + FLUSH)
```

#### Atomic KMS path

The atomic API allows an all-or-nothing property update across all KMS objects in a single syscall, preventing partial state:

```
DRM_IOCTL_MODE_ATOMIC  -->  drm::atomic_commit(props, flags)

  props = [
    (CRTC_ID=1,       CRTC_ACTIVE,       1),
    (PLANE_PRIMARY=1, PLANE_FB_ID,        fb_id),
    (PLANE_PRIMARY=1, PLANE_CRTC_W,       1920),
    (PLANE_PRIMARY=1, PLANE_CRTC_H,       1080),
    (PLANE_OVERLAY=2, PLANE_FB_ID,        overlay_fb_id),
    (PLANE_OVERLAY=2, PLANE_CRTC_X,       100),
    (PLANE_CURSOR=3,  PLANE_FB_ID,        cursor_fb_id),
    (PLANE_CURSOR=3,  PLANE_CRTC_X,       mouse_x),
    (PLANE_CURSOR=3,  PLANE_CRTC_Y,       mouse_y),
  ]

  flags:
    ATOMIC_FLAG_TEST_ONLY    — validate without committing
    ATOMIC_FLAG_NONBLOCK     — return immediately; flip on next tick
    ATOMIC_FLAG_ALLOW_MODESET— allow CRTC mode change
```

The commit pipeline validates all property changes on shadow state first. If `TEST_ONLY` is not set, the shadow is promoted to live state and a page-flip is issued.

#### Overlay and cursor planes

Both planes are software-composited into the primary framebuffer on every page-flip:

- **Overlay plane** (plane #2): arbitrary position and size within the CRTC. Source rectangle uses 16.16 fixed-point sub-pixel coordinates. ARGB pixels are alpha-blended over the primary plane.
- **Cursor plane** (plane #3): 64×64 ARGB bitmap, position tracked via `PLANE_CRTC_X/Y`. On virtio-gpu, the bitmap is also uploaded via `VIRTIO_GPU_CMD_UPDATE_CURSOR` on the cursorq so the host compositor can render it natively (zero-copy hardware path). `MOVE_CURSOR` is used for position-only updates.

#### Simulated vblank

Since there is no real display timing interrupt, vblank is simulated:

- `vblank_tick()` is called by `page_flip` (synchronous path) and by the kernel timer interrupt at ~60 Hz.
- Each tick increments `VBLANK_COUNT` and drains the `VBLANK_WAITERS` ring, signalling any registered eventfds.
- `DRM_IOCTL_WAIT_VBLANK` registers an eventfd; `drm::wait_vblank(eventfd_id, after_seq)` enqueues the waiter.

#### PRIME buffer sharing

PRIME enables zero-copy buffer handoff between the GPU driver and a Wayland compositor:

```
exporter (GPU / compositor)        importer (client / decoder)
-----------------------------       ---------------------------
DRM_IOCTL_PRIME_HANDLE_TO_FD  -->  fd = prime_handle_to_fd(gem_handle)
   returns dmabuf_fd                 +- allocates synthetic fd number
                                     +- records phys addr + size

                                  DRM_IOCTL_PRIME_FD_TO_HANDLE
                                     fd -> prime_fd_to_handle(dmabuf_fd)
                                     +- creates new GEM handle aliasing same phys
                                     +- zero-copy: no memcpy
```

Reference counting: `prime_release_fd()` is called on dma-buf fd close. When `ref_count` reaches 0 the export descriptor is removed.

#### `/dev/dri/` device nodes and capability gate

| Node | Minor | Capability required | Purpose |
|---|---|---|---|
| `/dev/dri/card0` | 0 | `DRM_MASTER` (bit 41) | Full KMS: mode-setting, page-flip, atomic |
| `/dev/dri/renderD128` | 128 | `DRM_RENDER_ALLOW` (bit 40) | Render-only: dumb buffers, PRIME, off-screen rendering |

`DRM_RENDER_ALLOW` and `DRM_MASTER` are bits in `CapSet::permitted`:

```rust
// Granted at process creation for the compositor (DRM master):
caps.permitted |= drm::DRM_MASTER | drm::DRM_RENDER_ALLOW;

// Granted for unprivileged GPU clients:
caps.permitted |= drm::DRM_RENDER_ALLOW;

// Enforced at open(2) / ioctl time:
drm::check_render_cap(&proc.caps)?;  // renderD128
drm::check_master_cap(&proc.caps)?;  // card0 mode-setting ioctls
```

#### Wayland compositor integration

`src/wayland/` hosts a minimal in-kernel Wayland compositor that drives the DRM stack:

- `wayland/server.rs` — Unix domain socket listener at `/run/wayland-0`; dispatches `wl_display`, `wl_registry`, `wl_compositor`, `wl_shm`, `xdg_wm_base` globals
- `wayland/compositor.rs` — surface tree, damage tracking, frame callbacks; on commit, copies the `wl_shm` buffer into the active DRM framebuffer and issues an atomic page flip

The compositor holds `DRM_MASTER` and uses the atomic API for all display updates.

#### Running a graphical demo under QEMU

```sh
# RISC-V UEFI with virtio-gpu
bash run_qemu_riscv.sh --gpu

# x86_64 with virtio-gpu
bash run_qemu.sh --gpu
```

Both launchers append `-device virtio-gpu-pci -display sdl,gl=on` to the QEMU command line. The kernel detects the virtio-gpu device during PCIe enumeration and uses it in preference to the GOP framebuffer.

---

### Userspace programs (compiled into initramfs)
`init`, `sh`, `cat`, `ls`, `echo`, `hello`, `devtest`, `thread_test`

---

## Building

All builds go through `cargo xtask`. No shell scripts required.

### Prerequisites

```sh
# Rust nightly toolchain (targets pinned in rust-toolchain.toml)
rustup toolchain install nightly
rustup component add rust-src llvm-tools-preview

# QEMU
apt install qemu-system-misc             # RISC-V
apt install qemu-system-x86             # x86_64
# or: brew install qemu

# UEFI RISC-V firmware (required for default UEFI boot)
apt install qemu-efi-riscv64            # Debian/Ubuntu

# x86_64 only: nasm (assembles the multiboot2 entry stub)
apt install nasm

# lld (for UEFI PE/COFF linking -- usually bundled with clang)
apt install lld
```

### RISC-V 64 -- UEFI (default)

```sh
cargo xtask build
# or explicitly:
cargo xtask build --arch riscv64 --boot uefi
```

Produces `esp/EFI/BOOT/BOOTRISCV64.EFI`.

### RISC-V 64 -- SBI

```sh
cargo xtask build --arch riscv64 --boot sbi
# Debug + initramfs:
cargo xtask build --arch riscv64 --boot sbi --debug --initrd
```

### x86_64

```sh
cargo xtask build --arch x86_64
# Debug:
cargo xtask build --arch x86_64 --debug
```

Requires `nasm` on `$PATH` (used by `build.rs` to assemble `src/arch/x86_64/boot.s`).
Produces `kernel.bin` (flat binary via `objcopy`).

### All options

```
cargo xtask build [--arch <riscv64|x86_64>] [--boot <uefi|sbi>] [--debug] [--initrd]

  --arch    riscv64 (default) or x86_64
  --boot    uefi (default) or sbi  -- only meaningful for riscv64
  --debug   debug build instead of release
  --initrd  also build + pack initramfs.cpio (SBI mode only)
```

---

## Running under QEMU

### RISC-V 64 -- UEFI (default)

```sh
bash run_qemu_riscv.sh
```

### RISC-V 64 -- SBI

```sh
bash run_qemu_riscv.sh --sbi
```

### x86_64

```sh
bash run_qemu.sh
```

All scripts boot straight to the kernel shell. Serial output goes to stdio.

---

## Debugging with GDB

Terminal 1 -- start QEMU with GDB stub:

```sh
bash run_qemu_riscv.sh --gdb            # RISC-V UEFI (port :1235)
bash run_qemu_riscv.sh --sbi --gdb      # RISC-V SBI  (port :1235)
bash run_qemu.sh --gdb                  # x86_64      (port :1234)
```

Terminal 2 -- attach:

```sh
# RISC-V UEFI
gdb-multiarch \
  -ex 'set arch riscv:rv64' \
  -ex 'file target/riscv64-uefi/release/rustos.efi' \
  -ex 'target remote :1235'

# RISC-V SBI
gdb-multiarch \
  -ex 'set arch riscv:rv64' \
  -ex 'file target/riscv64gc-unknown-none-elf/debug/rustos' \
  -ex 'target remote :1235'

# x86_64
gdb target/x86_64-unknown-none/debug/rustos
```

[`.gdbinit`](.gdbinit) sets the architecture, loads symbols, connects to `localhost:1234`, and
defines helpers (`vmas`, `procs`, `klog`).

---

## Testing

```sh
# RISC-V UEFI (primary)
cargo test --target riscv64-uefi.json --features uefi_boot

# RISC-V SBI
cargo test --target riscv64gc-unknown-none-elf --no-default-features

# x86_64
cargo test --target x86_64-unknown-none --no-default-features
```

Integration tests live in [`tests/`](tests/). CI runs on every push via [`.github/workflows/`](.github/workflows/).
Jobs in priority order: **RISC-V UEFI** (debug + release) -> RISC-V SBI (debug) -> x86_64 (debug + release).

---

## Repository layout

```
src/
  arch/
    riscv64/     # UEFI + SBI entry, CSR, PLIC, sv39 paging, syscall, trampoline
    x86_64/      # GDT, IDT, APIC, UEFI entry, paging, syscall
  fs/            # VFS, ext2, devfs, procfs, pipe, poll, eventfd, ...
  mm/            # PMM, VMM, mmap, page_fault, CoW
  proc/          # PCB, scheduler, fork, exec, signal, futex
  drivers/       # virtio-blk, virtio-net, virtio-gpu, PCIe, PS/2, TTY
    drm.rs       #   DRM/KMS core: KMS objects, planes, atomic, vblank, PRIME
    virtio_gpu.rs#   virtio-gpu: controlq (flush) + cursorq (cursor)
    framebuffer.rs#  GOP linear framebuffer fallback
    gop.rs       #   UEFI GOP capture (pre-ExitBootServices)
  net/           # ARP, DHCP, DNS, Ethernet, ICMP, IPv4, TCP, UDP
  security/      # capability sets (CapSet) — DRM_RENDER_ALLOW / DRM_MASTER bits
  shell/         # in-kernel TTY shell
  wayland/       # in-kernel Wayland compositor
    server.rs    #   wl_display / wl_registry / wl_compositor / xdg_wm_base
    compositor.rs#   surface tree, damage tracking, DRM atomic page-flip integration
xtask/           # cargo xtask build automation (replaces build shell scripts)
tests/           # integration test harness
tools/           # mkfs helper, symbol scripts
linker.ld          # RISC-V SBI linker script (loads at 0x80200000)
x86_64.ld          # x86_64 linker script
riscv64-uefi.json  # custom Rust target spec (PE/COFF, RISC-V UEFI) -- default target
run_qemu_riscv.sh  # RISC-V QEMU launcher: UEFI (default) or --sbi; pass --gpu for virtio-gpu
run_qemu.sh        # x86_64 QEMU launcher; pass --gpu for virtio-gpu
```

---

## License

MIT
