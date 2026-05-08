# RustOS

An operating-system kernel written in **Rust**, targeting **RISC-V 64** (primary) and **x86_64** (secondary). Runs on bare metal and under QEMU. No C runtime, no external libc.

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
- **ext2** (read + write), initramfs (read-only tarball)
- **FAT32 / VFAT** (`src/fs/fat32.rs`) — BPB parsing, cluster-chain walking, LFN reconstruction, full read/write/truncate/mkdir/unlink/rename; mounted read-only at `/boot/efi` by default
- **tmpfs** (`src/fs/ramfs.rs`) — memory-backed filesystem; auto-mounted at `/tmp`, `/run`, and `/dev/shm`; per-instance size cap; supports `tmpfs_mount(mp, limit)` for dynamic mounts via `sys_mount`
- **overlayfs** (`src/fs/overlayfs.rs`) — union mount with `lowerdir=`, `upperdir=`, `workdir=` options; copy-up on write; used for container-style layered roots
- devfs (`/dev/null`, `/dev/zero`, `/dev/urandom`, `/dev/tty`, `/dev/fb0`, block devices)
- procfs: `/proc/self/{exe,maps,status,fd/N}`, `/proc/{cpuinfo,meminfo,version}`
- `pipe`, `eventfd`, `poll`/`epoll`, `ioctl`, `getdents64`, `fstat`/`newfstatat`
- `pread64` (user-space) and `vfs::pread` (kernel-internal, used by demand-pager & ELF loader)

### Syscall surface (musl / glibc compatibility)

The dispatch table (`src/syscall/mod.rs`) covers the full x86-64 Linux ABI required by musl and glibc. Notable additions:

| NR | Syscall | Notes |
|---|---|---|
| 36 | `getitimer` | Returns zeroed `itimerval`; no-op disarm |
| 38 | `setitimer` | Accepts and discards; old value written back |
| 98 | `getrusage` | Returns zeroed 144-byte `rusage`; `RUSAGE_SELF` / `RUSAGE_CHILDREN` |
| 100 | `times` | Returns monotonic ticks in `tms_utime`; other fields zero |
| 185 | `prctl` | `PR_SET_NAME`, `PR_GET_NAME`, `PR_SET_NO_NEW_PRIVS`, `PR_SET_DUMPABLE`, `PR_SET_PDEATHSIG` |
| 318 | `getrandom` | RDRAND-backed with LFSR fallback; capped at 4096 bytes/call |
| 332 | `statx` | Full `STATX_BASIC_STATS` transcoder from `struct stat` |
| 326 | `copy_file_range` | Kernel-side splice up to 1 MiB/call; offset pointers updated |
| 425 | `io_uring_setup` | Returns `ENOSYS`; placeholder for future io_uring support |
| 426 | `io_uring_enter` | Returns `ENOSYS` |
| 427 | `io_uring_register` | Returns `ENOSYS` |
| 437 | `openat2` | Full `open_how` struct; `RESOLVE_*` flags parsed; delegates to VFS |

Also wired: `statx` (NR 332), `copy_file_range` (NR 326), `close_range` (NR 334), `preadv2`/`pwritev2` (NR 327/328), full POSIX timer set (NR 222–226), IPC (NR 29–31, 64–71, 240–245), seccomp (NR 317), namespaces (NR 272, 308).

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
  |  KMS objects: CRTC . Connector . Encoder . Plane |
  |  Dumb-buffer allocator (GEM handle registry)     |
  |  Framebuffer object table (add_fb / rm_fb)       |
  |  Page-flip / vblank event delivery               |
  +-------------------------------------------------+
        |                         |
        v                         v
  GOP framebuffer           virtio-gpu (drivers/virtio_gpu.rs)
  (UEFI linear fb)          (QEMU accelerated path)
```

#### Implemented ioctls (`/dev/dri/card0`)

| ioctl | Purpose |
|---|---|
| `DRM_IOCTL_VERSION` | Driver name (`rustosdrm`), version `0.1.0` |
| `DRM_IOCTL_GET_CAP` | Advertises `DUMB_BUFFER`, `VBLANK_HIGH_CRTC` |
| `DRM_IOCTL_MODE_GETRESOURCES` | Returns CRTC / connector / encoder ID lists |
| `DRM_IOCTL_MODE_GETCRTC` | Current CRTC state (mode, fb_id, position) |
| `DRM_IOCTL_MODE_GETCONNECTOR` | Connector type, status, current mode |
| `DRM_IOCTL_MODE_SETCRTC` | Programs a mode; no-op when resolution matches |
| `DRM_IOCTL_MODE_CREATE_DUMB` | Allocates a dumb buffer backed by the GOP/virtio-gpu framebuffer |
| `DRM_IOCTL_MODE_MAP_DUMB` | Returns mmap offset for a dumb buffer handle |
| `DRM_IOCTL_MODE_DESTROY_DUMB` | Releases a dumb buffer handle |
| `DRM_IOCTL_MODE_ADDFB` | Registers a framebuffer object over a dumb buffer |
| `DRM_IOCTL_MODE_RMFB` | Releases a framebuffer object |
| `DRM_IOCTL_MODE_PAGE_FLIP` | Schedules scanout (immediate; vblank event sent to fd) |

#### KMS object model

A single fixed topology is exposed (one real display is the target use case):

```
Connector #1  -->  Encoder #1  -->  CRTC #1  -->  Plane #1 (primary)
 (HDMI/GOP)                          |
                                     +-- active framebuffer (fb_id)
```

- **CRTC** holds the active `DrmModeInfo` (pixel clock, `hdisplay`, `vdisplay`, `vrefresh`) derived from the GOP resolution at boot, or from the virtio-gpu display info query.
- **Connector** reports `status = connected`, `connector_type = HDMI_A`, and exposes the single available mode.
- **Plane** is a primary plane covering the full CRTC; no overlay/cursor planes yet.

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
                                   +- marks fb as active scanout
DRM_IOCTL_MODE_PAGE_FLIP    -->  drm::page_flip(fb_id)
                                   +- flushes virtio-gpu flush cmd (if virtio-gpu)
                                   +- sends DRM_EVENT_FLIP_COMPLETE to fd epoll
```

#### virtio-gpu accelerated path

When QEMU's `virtio-gpu-pci` device is enumerated via PCIe, `drivers/virtio_gpu.rs` is preferred over the GOP linear framebuffer:

- `VIRTIO_GPU_CMD_GET_DISPLAY_INFO` — queries virtual display resolution
- `VIRTIO_GPU_CMD_RESOURCE_CREATE_2D` — allocates a host-side RGBA resource
- `VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING` — pins guest pages as the resource backing
- `VIRTIO_GPU_CMD_SET_SCANOUT` — maps the resource onto the virtual display
- `VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D` — pushes dirty rectangles from guest RAM to host
- `VIRTIO_GPU_CMD_RESOURCE_FLUSH` — signals the host to present the updated region

The DRM dumb-buffer `phys` field points to the guest-side backing pages; a page-flip issues `TRANSFER_TO_HOST_2D` + `RESOURCE_FLUSH` to make the frame visible.

#### `/dev/dri/` device nodes

| Node | Minor | Purpose |
|---|---|---|
| `/dev/dri/card0` | 0 | Full KMS/DRM (mode-setting, dumb buffers) |
| `/dev/dri/renderD128` | 128 | Render-only node (no mode-setting; for off-screen rendering) |

Both nodes appear in devfs. `renderD128` currently mirrors `card0`; a render-only capability gate (`DRM_RENDER_ALLOW`) will enforce the distinction once per-file capability tracking lands.

#### Wayland compositor integration

`src/wayland/` hosts a minimal in-kernel Wayland compositor that drives the DRM stack:

- `wayland/server.rs` — Unix domain socket listener at `/run/wayland-0`; dispatches `wl_display`, `wl_registry`, `wl_compositor`, `wl_shm`, `xdg_wm_base` globals
- `wayland/compositor.rs` — surface tree, damage tracking, frame callbacks; on commit, copies the `wl_shm` buffer into the active DRM framebuffer and issues a page flip

The compositor is intentionally single-threaded and synchronous; a future async event loop will integrate with `epoll`/`eventfd`.

#### Running a graphical demo under QEMU

```sh
# RISC-V UEFI with virtio-gpu
bash run_qemu_riscv.sh --gpu

# x86_64 with virtio-gpu
bash run_qemu.sh --gpu
```

Both launchers append `-device virtio-gpu-pci -display sdl,gl=on` to the QEMU command line. The kernel detects the virtio-gpu device during PCIe enumeration and uses it in preference to the GOP framebuffer.

#### Known limitations / TODO

- **No GEM object sharing** — `DRM_IOCTL_PRIME_HANDLE_TO_FD` / `PRIME_FD_TO_HANDLE` not yet implemented; cross-process buffer sharing requires `wl_shm` copies
- **renderD128 capability gate** — render-node vs. master-node access control pending per-file `CapSet` integration

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
  fs/            # VFS, ext2, fat32, ramfs (tmpfs), overlayfs, devfs, procfs, pipe, poll, ...
    fat32.rs     #   FAT32/VFAT: BPB, cluster chains, LFN, r/w/truncate/mkdir/unlink/rename
    ramfs.rs     #   tmpfs: memory-backed FS; auto-mounted at /tmp, /run, /dev/shm
    overlayfs.rs #   overlayfs: lowerdir/upperdir/workdir union mount, copy-up on write
  mm/            # PMM, VMM, mmap, page_fault, CoW
  proc/          # PCB, scheduler, fork, exec, signal, futex
  drivers/       # virtio-blk, virtio-net, virtio-gpu, PCIe, PS/2, TTY
    drm.rs       #   DRM/KMS core: KMS objects, dumb buffers, page-flip
    virtio_gpu.rs#   virtio-gpu: resource create/attach/flush commands
    framebuffer.rs#  GOP linear framebuffer fallback
    gop.rs       #   UEFI GOP capture (pre-ExitBootServices)
  net/           # ARP, DHCP, DNS, Ethernet, ICMP, IPv4, TCP, UDP
  security/      # capability sets (CapSet)
  shell/         # in-kernel TTY shell
  syscall/
    mod.rs       #   x86-64 syscall dispatch table (NR 0-437)
    stubs.rs     #   trivial / constant-return implementations
    posix_full.rs#   full POSIX implementations (timers, statx, copy_file_range, ...)
    p0_gaps.rs   #   permission/attribute stubs
  wayland/       # in-kernel Wayland compositor
    server.rs    #   wl_display / wl_registry / wl_compositor / xdg_wm_base
    compositor.rs#   surface tree, damage tracking, DRM page-flip integration
xtask/           # cargo xtask build automation (replaces build shell scripts)
tests/           # integration test harness
tools/           # mkfs helper, symbol scripts
linker.ld          # RISC-V SBI linker script (loads at 0x80200000)
x86_64.ld          # x86_64 linker script
riscv64-uefi.json  # custom Rust target spec (PE/COFF, RISC-V UEFI) -- default target
run_qemu_riscv.sh  # RISC-V QEMU launcher: UEFI (default) or --sbi
run_qemu.sh        # x86_64 QEMU launcher
```

---

## Changelog

### v0.2.0
- **FAT32/VFAT** filesystem driver (`src/fs/fat32.rs`): BPB parsing, cluster-chain traversal, LFN support, full read/write/truncate/mkdir/unlink/rename; auto-mounted read-only at `/boot/efi`
- **tmpfs** (`src/fs/ramfs.rs`): memory-backed FS with per-instance size cap; auto-mounted at `/tmp`, `/run`, `/dev/shm`; dynamic `tmpfs_mount()` API for `sys_mount`
- **overlayfs** (`src/fs/overlayfs.rs`): union mount driver with `lowerdir=`/`upperdir=`/`workdir=` mount options and copy-up-on-write semantics
- **Syscall additions** for musl/glibc compatibility: `getitimer`/`setitimer` (NR 36/38); `times` (NR 100); `openat2` (NR 437) with `open_how` / `RESOLVE_*` flag parsing; `io_uring_setup`/`enter`/`register` (NR 425-427) stubs returning `ENOSYS`
- **DRM/KMS subsystem** (`src/drivers/drm.rs`, `src/drivers/virtio_gpu.rs`): full Linux-compatible KMS object model, GEM dumb-buffer allocator, page-flip with vblank event delivery, virtio-gpu accelerated path
- **Wayland compositor** (`src/wayland/`): in-kernel compositor at `/run/wayland-0`, `wl_shm` buffer -> DRM framebuffer copy-on-commit

### v0.1.0
- Initial kernel: RISC-V UEFI + SBI boot, x86_64 UEFI boot
- PMM/VMM, CoW fork, demand paging
- ext2 read/write, initramfs, devfs, procfs
- POSIX signals, futex, POSIX timers
- smoltcp networking stack, BSD socket API
- ELF loader with dynamic linker support
- System V IPC (shm, sem, msg), POSIX mqueue
- seccomp, namespaces (unshare/setns)

---

## License

MIT
