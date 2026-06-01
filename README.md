# RustOS

RustOS is a `no_std` hybrid kernel written in Rust. It keeps
latency-sensitive core mechanisms in kernel space while supporting
microkernel-style userspace drivers and service servers through schemes, IPC,
and capability-checked driver handles. The repository is a
single Cargo workspace: the root package contains the kernel binary/library,
`xtask` provides host-side build automation, and helper crates under `crates/`
provide shared protocol types and the in-kernel test harness.

The current architecture is organized around a small boot handoff contract:
every supported boot path constructs an `init::boot_info::BootInfo`, enters the
exported `kernel_main(boot_info)` symbol, and then dispatches once through
`arch::init()` into the active architecture implementation.

---

## Architecture Support

| Architecture | Boot paths represented in tree | Primary entry files | Status |
|---|---|---|---|
| `x86_64` | UEFI loader and direct kernel / Multiboot2-style path | `src/arch/x86_64/uefi_entry.rs`, `src/main.rs`, `src/arch/x86_64/kernel_main.rs` | Active |
| `riscv64` | SBI/FDT kernel path and UEFI loader target | `src/arch/riscv64/boot.rs`, `src/arch/riscv64/uefi_entry.rs`, `src/arch/riscv64/mod.rs` | Active |
| `aarch64` | UEFI loader and bare-metal kernel target | `src/arch/aarch64/uefi_entry.rs`, `src/arch/aarch64/mod.rs` | Active bring-up |

Per-architecture linker scripts live at the repository root
(`linker_x86_64.ld`, `linker_riscv.ld`, `linker_aarch64.ld`). Custom target
specifications live in `targets/` and are split between kernel images
(`*-kernel.json`) and UEFI loader images (`*-uefi-loader.json`).

---

## Boot Model

The boot layer is intentionally thin:

```text
firmware / loader
    -> architecture entry point
    -> BootInfo construction
    -> kernel_main(&BootInfo)
    -> arch::init(&BootInfo)
    -> architecture-specific early init
    -> shared kernel subsystems
    -> initramfs / schemes / shell / userspace or idle loop
```

Important files:

- `src/main.rs` contains the freestanding kernel binary entry stubs and documents
  the RISC-V, x86_64 UEFI, ARM64 UEFI, and x86_64 direct-kernel paths.
- `src/kernel_main.rs` is the architecture-independent exported entry point.
- `src/arch/mod.rs` selects the concrete architecture implementation and exposes
  the `Arch` HAL alias for common code.
- `src/init/boot_info.rs` defines the shared boot-information structure passed
  from loaders to the kernel.
- `docs/boot-architecture.md` describes the long-term rule that boot methods
  converge into one common kernel initialization path.
- `docs/hybrid-kernel-architecture.md` defines the RustOS hybrid split between
  in-kernel core services and userspace scheme/driver servers.

---

## Repository Layout

```text
.
├── src/                    # Kernel source tree
│   ├── arch/               # Architecture HAL + x86_64, riscv64, aarch64 code
│   ├── block/              # Generic block-device trait and block abstraction
│   ├── console/            # Kernel console output routing
│   ├── core/               # Foundational kernel types/utilities
│   ├── debug/              # GDB RSP, trace, oops/debug support
│   ├── device/             # Hardware-neutral device/bus model, including PCI
│   ├── display/            # Framebuffer, DRM/KMS objects, Wayland pieces
│   ├── drivers/            # Block, GPU, input, network, platform, virtio drivers
│   ├── exec/               # Executable loading helpers
│   ├── firmware/           # ACPI, Device Tree, PSCI, CPU topology
│   ├── fs/                 # VFS, filesystem drivers, FD-backed kernel objects
│   ├── init/               # BootInfo, initramfs, ELF loader, scheme registration
│   ├── input/              # Input event subsystem
│   ├── io_uring/           # io_uring rings and syscall plumbing
│   ├── ipc/                # SysV/POSIX IPC, futexes, Unix sockets, message queues
│   ├── irq/                # Interrupt-controller support outside arch-local code
│   ├── kernel/             # Panic, random, uaccess, and miscellaneous utilities
│   ├── kmtest/             # In-kernel test harness integration
│   ├── mm/                 # PMM, heap, slab, mmap, page fault, swap, KASAN-lite
│   ├── net/                # Ethernet, ARP, IPv4/IPv6, TCP/UDP, DHCP, DNS, sockets
│   ├── proc/               # Processes, threads, scheduler, wait, signals, namespaces
│   ├── security/           # ASLR/canary/seccomp/cgroup/namespace hardening pieces
│   ├── shell/              # Built-in debug shell
│   ├── smp/                # Multi-core bring-up and per-CPU infrastructure
│   ├── sync/               # Kernel synchronization primitives
│   ├── syscall/            # Linux-style syscall dispatcher and syscall modules
│   ├── time/               # Clocks, timers, timerfd, architecture clocksources
│   ├── tty/                # TTY/PTM/PTS, termios, line discipline, serial console
│   ├── kernel_main.rs      # Shared exported entry point
│   ├── lib.rs              # Kernel crate root and module graph
│   └── main.rs             # Binary entry stubs
├── crates/
│   ├── scheme-api/         # Shared userspace/kernel scheme protocol types
│   ├── kmtest/             # kmtest runtime library
│   └── kmtest-macros/      # `#[kmtest]` proc macros
├── userspace/              # Init, shell, smoke tests, libc shim, drivers, Wayland pieces
├── tests/                  # Host/QEMU integration tests and C smoke workloads
├── tools/                  # Host-side helper scripts
├── xtask/                  # `cargo xtask` build/image/initramfs automation
├── docs/                   # Architecture and boot documentation
├── targets/                # Rust custom target JSON specs
└── flake.nix               # Nix development shell
```

---

## Kernel Architecture Model

RustOS uses a hybrid-kernel architecture rather than a purely monolithic or
purely microkernel design:

- The architecture HAL, memory manager, scheduler, interrupt routing, VFS core,
  security enforcement, and common fast paths remain in kernel space.
- Device drivers and resource providers can run as isolated userspace services
  when they can be represented through kernel-mediated schemes and IPC.
- The canonical in-code contract is `kernel::architecture::KERNEL_ARCHITECTURE`,
  which is set to `KernelArchitecture::Hybrid` and logged during `kernel_main`.
- The scheme table provides one namespace for both native kernel handlers and
  `IpcProxyScheme` handlers backed by userspace servers.

See `docs/hybrid-kernel-architecture.md` for the subsystem boundary rules.

---

## Core Subsystems

### Architecture and HAL (`src/arch`)

Common code should use `crate::arch::Arch` and traits/types from
`crate::arch::api` instead of importing architecture modules directly. The
architecture module gates `x86_64`, `riscv64`, or `aarch64` at compile time and
forwards `arch::init()` to that implementation.

### Memory Management (`src/mm`)

The memory subsystem includes physical-frame management, heap bootstrap, slab
allocation, mmap/mlock handlers, copy-on-write faults, page-fault dispatch,
resident-set accounting, swap, per-CPU kernel stacks, and KASAN-lite heap
checking.

### Processes and Scheduling (`src/proc`)

`src/proc` owns the Unix-like task model: process/thread state, PID/TID tables,
fork/clone/exec, wait/reaping, resource limits, scheduler integration, signal
delivery (x86_64 and AArch64), ptrace, namespaces, cgroups, and seccomp filters.

### Signal Delivery (`src/proc/signal.rs`)

Signals are delivered to either a specific thread (`send_signal`) or a thread
group (`send_signal_group`). At each syscall exit the kernel calls
`check_and_deliver` (x86_64) or `check_and_deliver_aarch64` (AArch64) to pop
the highest-priority pending signal and either invoke the userspace handler or
apply the default action (terminate / stop / ignore).

The signal frame pushed on the user stack is ABI-compatible with musl's
`struct ucontext` on both architectures. `sys_rt_sigreturn` /
`sys_rt_sigreturn_aarch64` restore all saved register state and the
pre-signal sigmask on return from the handler. SIGKILL and SIGSTOP cannot be
masked or caught.

### Firmware Interfaces (`src/firmware`)

| Module | Description |
|---|---|
| `acpi` | RSDP → RSDT/XSDT → MADT table walker. Exposes LAPIC/IOAPIC info (x86_64), GIC CPU Interface info (AArch64), FADT/DSDT power management, S3 sleep/resume, P-state CPU frequency scaling, battery status, PCIe ECAM base (`mcfg_base`), NUMA topology (SRAT/SLIT), and PCIe GPE hot-plug. |
| `dt` | Device Tree / FDT helpers for RISC-V and AArch64 bare-metal paths. |
| `psci` | ARM PSCI 1.0 over HVC/SMC conduit. Provides `cpu_on`, `cpu_off`, `system_off`, `system_reset`. Used by the AArch64 SMP bringup path to power on secondary CPUs. |
| `topology` | Discovers secondary CPU MPIDR values from ACPI MADT (type 0x0B GIC CPU Interface entries) or falls back to a QEMU virt heuristic. Called by `smp::init` before issuing PSCI `CPU_ON`. |

### Filesystems and File Descriptors (`src/fs`)

The VFS owns path resolution and file-descriptor dispatch. Filesystem and FD
object support currently includes ext2, ext4, FAT32, exFAT, NTFS, btrfs, NFS,
CDFS, ramfs, tmpfs, procfs, sysfs, devfs, cgroupfs, overlayfs, pipes, pidfds,
eventfd, timerfd, shm, epoll/poll helpers, inotify/fanotify, splice, flock,
ioctl, and an io_uring bridge.

### Device and Driver Model (`src/device`, `src/drivers`, `src/block`)

`src/device` provides the bus-facing model, including PCI enumeration and MSI-X
support. `src/drivers` is split by device class: block, GPU, input, network, and
platform. The separate `src/block` module exposes the generic block-device
abstraction used above concrete drivers such as virtio-blk.

### Networking (`src/net`)

The network stack is organized as Ethernet/ARP, IPv4/IPv6, ICMP/ICMPv6, UDP,
TCP, DHCP, DNS, and BSD-style socket layers.

### IPC, TTY, and User Interaction (`src/ipc`, `src/tty`, `src/shell`)

IPC covers futexes, System V IPC, POSIX message queues, POSIX shared memory,
and Unix-domain sockets. The TTY subsystem implements PTY pairs, devpts,
termios, N_TTY line discipline, and serial-console integration. The kernel also
contains a built-in debug shell.

### Display and Input (`src/display`, `src/input`, `src/drivers/input`)

Display code is split into framebuffer support, DRM/KMS-style objects, and
Wayland-related pieces. Input handling is shared between the generic input event
subsystem and class-specific input drivers.

### Syscalls and Async I/O (`src/syscall`, `src/io_uring`)

The syscall layer is a Linux-style dispatcher with per-area implementations and
architecture-specific trap/syscall entry glue. `src/io_uring` contains ring
allocation, SQE/CQE types, operation handlers, and syscall plumbing.

### Security (`src/security`)

Security code includes ASLR, stack-canary support, seccomp hooks, cgroup support,
namespace support, capability checks, and LSM-style hook scaffolding.

---

## Build and Run

### Requirements

- Rust nightly pinned by `rust-toolchain.toml`.
- `rust-src` / `llvm-tools-preview` for custom targets and EFI/image work.
- QEMU for the architecture you are running.
- Optional but recommended: `nix develop` for a reproducible tool environment.

### Preferred build entry point

Use `cargo xtask` for architecture-aware builds:

```sh
# Defaults to a release RISC-V UEFI build according to xtask.
cargo xtask build

# x86_64 direct kernel ELF + flat kernel.bin
cargo xtask build --arch x86_64 --boot sbi

# x86_64 UEFI image installed under esp/EFI/BOOT/
cargo xtask build --arch x86_64 --boot uefi

# RISC-V SBI/FDT kernel path
cargo xtask build --arch riscv64 --boot sbi

# RISC-V UEFI loader target
cargo xtask build --arch riscv64 --boot uefi

# AArch64 UEFI loader target
cargo xtask build --arch aarch64 --boot uefi

# AArch64 bare-metal kernel target
cargo xtask build --arch aarch64 --boot sbi
```

Buildable image helpers are also provided:

```sh
cargo xtask mkinitramfs --arch x86_64
cargo xtask image --arch x86_64 --boot uefi --initrd
cargo xtask image --arch riscv64 --boot uefi
cargo xtask image --arch aarch64 --boot uefi
```

### QEMU helpers

Repository-root wrappers build and launch common QEMU configurations:

```sh
./run_qemu_x86_64.sh
./run_qemu_riscv.sh
./run_qemu_aarch64.sh
```

The x86_64 and AArch64 wrappers include GDB/test modes; see each script header
for the supported flags.

---

## Cargo Features

The root package currently declares these feature flags:

| Feature | Description |
|---|---|
| `debug` | Convenience bundle for `debug_stub` and `trace`. |
| `debug_stub` | GDB Remote Serial Protocol stub only. |
| `trace` | Function trace/ring-buffer support flushed on panic. |
| `kmtest` | In-kernel test harness dependency and registration. |

When you need feature-specific builds, pass the feature flags to Cargo for the
selected target. For example:

```sh
cargo build --target targets/x86_64-kernel.json \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  --no-default-features --features kmtest
```

---

## Tests

There are three layers of tests/checks in the tree:

- `crates/kmtest` and `crates/kmtest-macros` provide the in-kernel `#[kmtest]`
  harness.
- `userspace/kmtest` provides a userspace runner for kmtest syscalls.
- `tests/` contains C smoke and stress workloads plus shell harnesses for QEMU
  runs.

Common commands:

```sh
cargo xtask smoke
./tests/run_smoke.sh
./tests/run_tests.sh
```

---

## Additional Documentation

- `docs/boot-architecture.md` — boot architecture guidelines and the common
  initialization contract.
- `docs/booting.md` — UEFI, QEMU, ESP, and real-hardware notes.
- `docs/arch_capability_matrix.md` — architecture capability tracking.
