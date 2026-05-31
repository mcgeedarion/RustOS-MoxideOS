# RustOS

A monolithic kernel written entirely in Rust, targeting **x86_64**, **RISC-V 64**, and **AArch64**. The kernel is structured as a single Cargo workspace with the kernel crate at the root and supporting library crates under `crates/`.

---

## Architecture Support

| Target | Boot Firmware | Status |
|---|---|---|
| x86_64 | Multiboot2 / UEFI | Active |
| riscv64 | SBI + FDT | Active |
| aarch64 | UEFI / QEMU virt GICv3 | Early bring-up |

Per-architecture linker scripts (`linker_x86_64.ld`, `linker_riscv.ld`, `linker_aarch64.ld`) and QEMU launch helpers (`run_qemu_*.sh`) live at the repo root. Custom target JSON specs are in `targets/`.

---

## Repository Layout

```
.
├── src/                  # Kernel source tree
│   ├── arch/             # Architecture-specific code (x86_64, riscv64, aarch64)
│   ├── mm/               # Memory management (PMM, VMM, slab, heap)
│   ├── proc/             # Process management, scheduler, cgroups, namespaces
│   ├── fs/               # VFS + filesystem drivers
│   ├── drivers/          # Device drivers (block, net, gpu, input, platform)
│   ├── net/              # Network stack (TCP/IP, ARP, DHCP)
│   ├── syscall/          # Syscall dispatch table
│   ├── ipc/              # Pipes, shared memory, message queues, signals
│   ├── irq/              # IRQ abstraction + arch-specific controllers
│   ├── smp/              # SMP / per-CPU infrastructure
│   ├── sync/             # Kernel synchronisation primitives
│   ├── security/         # ASLR, stack canaries, seccomp, LSM hooks
│   ├── display/          # Framebuffer, DRM/KMS, Wayland compositor
│   ├── block/            # Block layer (virtio-blk)
│   ├── console/          # Kernel console / serial output
│   ├── tty/              # TTY layer
│   ├── shell/            # Built-in debug shell
│   ├── time/             # Timekeeping (RISC-V mtime, x86 TSC/HPET)
│   ├── debug/            # GDB RSP stub, oops handler, trace ring-buffer
│   ├── io_uring/         # io_uring submission/completion queue
│   ├── init/             # initramfs mount + scheme registration
│   ├── firmware/         # UEFI / SBI / FDT helpers
│   ├── exec/             # ELF loader / execve
│   ├── input/            # Input event subsystem
│   ├── device/           # Device model
│   ├── kernel/           # Core kernel utilities
│   ├── kmtest/           # In-kernel test harness (see `--features kmtest`)
│   ├── kernel_main.rs    # Arch-independent boot dispatcher
│   └── lib.rs            # Crate root
├── crates/
│   ├── scheme-api/       # Userspace scheme protocol types
│   ├── kmtest/           # kmtest runtime library
│   └── kmtest-macros/    # Proc-macros for #[kmtest]
├── userspace/            # Userspace programs and init
├── tools/                # Host-side build/debug tooling
├── tests/                # Integration / QEMU test harness
├── xtask/                # cargo xtask build automation
├── docs/                 # Design documents
└── flake.nix             # Nix dev-shell (reproduces build environment)
```

---

## Kernel Subsystems

### Memory Management (`src/mm`)
Two-level allocator: a physical memory manager (`pmm`) initialised from FDT/E820 memory maps, feeding a slab allocator and a general heap. The VMM handles page tables, COW mappings, and mmap.

### Process Management (`src/proc`)
Unix process model: fork/exec/wait, CFS-style scheduler, cgroups v2 (`ROOT_CGROUP`), Linux-compatible namespaces (PID, UTS, mount, network), and pidfd support.

### Virtual Filesystem (`src/fs`)
A VFS layer with dentry cache (`dcache`) and full `vfs_ops` dispatch. Supported filesystems:

- **Disk**: ext2, ext4 (read/write), FAT32, exFAT, NTFS (read), btrfs (early)
- **Network**: NFS
- **Virtual**: ramfs, tmpfs, procfs, sysfs, devfs, cgroupfs, overlayfs, ISO 9660 (cdfs)
- **FD types**: pipe, eventfd, timerfd, epoll, inotify, fanotify, shm, pidfd
- **Async**: io_uring bridge (`vfs_uring`)

### Drivers (`src/drivers`)
- **Block**: virtio-blk (MMIO)
- **Network**: virtio-net (MMIO)
- **GPU**: virtio-gpu; stubs for AMD Radeon, Intel i915
- **Input**: USB-HID keyboard & mouse, virtio input, evdev event layer
- **Platform**: platform bus

### Network Stack (`src/net`)
Full userspace-facing TCP/IP stack: Ethernet → ARP → IPv4 → TCP/UDP, with a DHCP client bootstrapped early in the boot sequence.

### IPC (`src/ipc`)
POSIX pipes, POSIX shared memory, POSIX message queues, Unix-domain sockets, and signal delivery.

### Display (`src/display`)
Virtio-GPU framebuffer console → DRM/KMS object model → in-kernel Wayland compositor.

### Security (`src/security`)
ASLR, stack canaries, seccomp filter tables, and LSM hook stubs.

### Syscall Interface (`src/syscall`)
Linux-ABI-compatible syscall table dispatched from the arch trap handler. Each arch registers its own entry point; syscall numbers follow the Linux convention for that architecture.

---

## Build

### Requirements
- Rust nightly (pinned in `rust-toolchain.toml`)
- QEMU (`qemu-system-x86_64`, `qemu-system-riscv64`, `qemu-system-aarch64`)
- A Nix-capable shell is the easiest way to get a complete environment:
  ```sh
  nix develop   # enters the flake dev-shell with all tools on PATH
  ```

### Compile
```sh
# x86_64
cargo build --target targets/x86_64-unknown-none.json

# RISC-V 64
cargo build --target targets/riscv64gc-unknown-none-elf.json

# AArch64
bash build_aarch64.sh
```

### Run in QEMU
```sh
bash run_qemu_x86_64.sh
bash run_qemu_riscv.sh
bash run_qemu_aarch64.sh
```

### Debug Build
```sh
# Enables GDB RSP stub + oops backtrace + trace ring-buffer
cargo build --features debug --target targets/x86_64-unknown-none.json
```
Attach GDB with `target remote :1234` after starting QEMU with `-s -S`.

### In-Kernel Tests
```sh
cargo build --features kmtest --target targets/x86_64-unknown-none.json
```
Test suites are registered by `kmtest::init()` at boot and triggered via `SYS_KMTEST_LIST` / `SYS_KMTEST_RUN` from userspace.

---

## Cargo Features

| Feature | Description |
|---|---|
| `debug` | Full debug bundle: GDB stub + oops handler + trace drain |
| `debug_stub` | GDB Remote Serial Protocol stub only |
| `trace` | Ring-buffer trace event drain (flushed to serial on panic) |
| `kmtest` | In-kernel test harness |

---

## Boot Sequence (RISC-V)

```
trap_init → fdt_phase1 → pmm::init → plic::init → heap::init → mm::init
→ security::init → [debug::init] → display init → fdt_phase2 → block/input/net
→ initramfs::mount → namespace::init → time::init → dhcp::init
→ cgroup::init → shell::init → [kmtest::init] → proc::spawn_init  (pid 1)
```

See [`src/kernel_main.rs`](src/kernel_main.rs) for the full annotated sequence and the x86_64 / AArch64 variants.
