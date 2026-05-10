# rustos

A Rust-based operating system kernel targeting **x86_64** and **RISC-V (rv64gc)**,
with growing Linux ABI compatibility. Boots via UEFI (x86_64 and RISC-V EDK2) or
OpenSBI (RISC-V SBI). Runs under QEMU with virtio block, GPU, and network devices.

> **Toolchain:** `nightly-2025-05-15` (pinned in `rust-toolchain.toml`).  
> Nightly is required for `naked_functions`, `alloc_error_handler`,
> `core_intrinsics`, `abi_x86_interrupt`, and `-Z build-std`.  
> See [Upgrading the toolchain pin](#upgrading-the-toolchain-pin) before bumping.

---

## Features

- **Multi-architecture**: x86_64 (UEFI) and RISC-V rv64gc (UEFI EDK2 / OpenSBI)
- **Process model**: fork/exec/wait, POSIX signals, `clone(2)`, threads
- **Scheduler**: CFS (`SCHED_NORMAL`), `SCHED_FIFO`, `SCHED_RR`, `SCHED_DEADLINE`;
  per-CPU run queues; EDF with CBS admission control
- **Memory**: 4-level page tables (x86_64) / Sv39+Sv48 (RISC-V), demand paging,
  Copy-on-Write (COW), ASLR
- **Filesystems**: ext2, FAT32/VFAT, tmpfs, devfs, procfs, initramfs (cpio), VFS layer
- **Drivers**: virtio-blk, virtio-net, virtio-gpu, PS/2 keyboard, UART, PCIe enumeration
- **Linux syscall compatibility**: ~80 syscalls (see [Syscall Table](#syscall-table-selected))
- **Resource limits**: `RLIMIT_CPU` and `RLIMIT_RTTIME` with SIGXCPU/SIGKILL enforcement
- **IPC**: futex (WAIT/WAKE/WAKE_BITSET/REQUEUE/CMP_REQUEUE, robust lists), pipes, Unix sockets
- **SMP**: AP bringup (APIC trampoline / SBI HSM), per-CPU blocks, IPI dispatch
- **Security**: ASLR, stack canaries, PTI, SMEP/SMAP, seccomp-BPF, capability set
- **musl libc port** — see [`docs/musl_port.md`](docs/musl_port.md)

---

## Repository Layout

```
rustos/
├── src/
│   ├── arch/
│   │   ├── x86_64/     # IDT, APIC, GDT, paging, SMP trampoline
│   │   └── riscv64/    # PLIC, trap handler, SBI/UEFI entry
│   ├── proc/           # scheduler, fork, exec, wait, signals, futex, rlimit
│   ├── mm/             # VMM, PMM, page tables, COW, mmap
│   ├── fs/             # VFS, ext2, FAT32, tmpfs, devfs, procfs, initramfs
│   ├── drivers/        # virtio-{blk,net,gpu}, PS/2, UART, NVMe, PCIe
│   ├── syscall/        # syscall dispatch + individual handlers
│   ├── net/            # TCP/UDP/IP stack
│   ├── smp/            # per-CPU blocks, AP bring-up, IPI
│   ├── security/       # ASLR, canaries, PTI, SMEP/SMAP, seccomp, capset,
│   │                   #   namespaces (ns/), cgroups v1 (cgroups/)
│   ├── sync/           # futex, RwLock, Condvar, WaitQueue
│   ├── ipc/            # SysV msg/sem/shm, POSIX mq  [feature: sysv_ipc]
│   ├── gdbstub/        # GDB RSP stub placeholder    [feature: gdbstub]
│   ├── input/          # /dev/input evdev layer       [feature: input_events]
│   └── wayland/        # Wayland compositor scaffold  [feature: wayland]
├── tests/              # C integration tests (run on Linux host or in-kernel)
├── userspace/          # Minimal init + shell
├── xtask/              # cargo xtask build system
├── docs/
│   ├── musl_port.md
│   └── musl_pipeline.md
├── Dockerfile          # Reproducible dev/CI environment (Ubuntu 24.04)
├── flake.nix           # Nix flake dev shell + nix build
├── run_qemu.sh         # x86_64 QEMU launcher
├── run_qemu_riscv.sh   # RISC-V QEMU launcher (UEFI + SBI modes)
├── Cargo.toml
├── rust-toolchain.toml # Pinned nightly + targets
├── x86_64.ld           # x86_64 linker script
└── linker.ld           # RISC-V linker script
```

---

## Quick Start

Three ways to get a working build environment. Pick one.

### Option A — Docker (recommended for CI / one-shot builds)

```bash
# Build the image once (~3 min on first run, cached after)
docker build -t rustos-dev .

# Drop into an interactive dev shell with the source mounted
docker run --rm -it -v "$(pwd)":/work rustos-dev

# One-shot build without entering the shell
docker run --rm -v "$(pwd)":/work rustos-dev cargo build
```

The image bundles: `clang`/`lld`, `riscv64-unknown-elf-{as,ar}`, `qemu-system-{riscv64,x86_64}`,
`ovmf`, and the pinned `nightly-2025-05-15` toolchain. The toolchain version is
verified at image-build time — a mismatch fails loudly.

### Option B — Nix flake (recommended for local development)

```bash
# Enter the dev shell (downloads pinned toolchain from binary cache)
nix develop

# One-shot build without entering
nix develop --command cargo build

# Reproducible kernel artifact (outputs to result/boot/rustos.efi)
nix build
```

Requires [Nix with flakes enabled](https://nixos.wiki/wiki/Flakes).
All tools, the pinned nightly, and QEMU are provided by the flake —
no manual `rustup` or `apt install` needed.

### Option C — Native (rustup + manual tool install)

```bash
# Rust toolchain (rust-toolchain.toml is read automatically by rustup)
rustup show   # confirms nightly-2025-05-15 is active

# System tools
sudo apt install clang lld nasm qemu-system-riscv64 qemu-system-x86_64 \
                 qemu-efi-riscv64 ovmf binutils-riscv64-linux-gnu  # Debian/Ubuntu
brew install qemu llvm                                              # macOS
```

---

## Building

### RISC-V UEFI (default)

```bash
cargo build          # debug, riscv64-uefi.json
cargo build --release
cargo xtask build    # same as cargo build --release via xtask
```

### RISC-V SBI

```bash
cargo build \
  --target riscv64gc-unknown-none-elf \
  --no-default-features \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem

cargo xtask build --arch riscv64 --boot sbi   # equivalent via xtask
```

### x86_64

```bash
cargo build \
  --target x86_64-unknown-none \
  --no-default-features \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem
```

---

## Running in QEMU

```bash
# x86_64 (serial output to terminal)
./run_qemu.sh
./run_qemu.sh --gpu            # with virtio-gpu window
./run_qemu.sh disk.img         # with a disk image
./run_qemu.sh --gdb            # halt at entry, wait for GDB on :1234

# RISC-V UEFI (default)
./run_qemu_riscv.sh

# RISC-V SBI
./run_qemu_riscv.sh --sbi

# RISC-V GDB
./run_qemu_riscv.sh --gdb
gdb-multiarch \
  -ex 'set arch riscv:rv64' \
  -ex 'file target/riscv64-uefi/release/rustos.efi' \
  -ex 'target remote :1235'
```

`.gdbinit` in the repo root auto-connects to QEMU's gdbserver and loads
the correct architecture. For RISC-V use port `:1235`; for x86_64 use `:1234`.

---

## Feature Flags

The **default build** is a clean, fully functional, testable base kernel.
All WIP or incomplete subsystems are behind opt-in feature flags.

| Feature | Default | Status | Enable with |
|---------|---------|--------|-------------|
| `uefi_boot` | ✅ on | Stable | (always on by default) |
| `sysv_ipc` | ❌ off | Logic complete; `CAP_IPC_OWNER` stub | `--features sysv_ipc` |
| `namespaces` | ❌ off | 5 NS types done; `setns`/nsfs missing | `--features namespaces` |
| `cgroups` | ❌ off | Knob API done; cgroupfs mount missing | `--features cgroups` |
| `gdbstub` | ❌ off | Placeholder; no RSP impl | `--features gdbstub` |
| `input_events` | ❌ off | Stub no-ops; evdev routing missing | `--features input_events` |
| `wayland` | ❌ off | Scaffold only | `--features wayland` |

```bash
# Full WIP build (all features)
cargo build --features sysv_ipc,namespaces,cgroups,gdbstub,input_events,wayland
```

To graduate a feature into `default`: replace all capability stubs with real
enforcement, wire syscall dispatch entries, implement any missing VFS mounts,
then move the feature from the gated table to `default = [...]` in `Cargo.toml`.

---

## Integration Tests

```bash
# Build and run on the Linux host (validates logic against the host kernel)
chmod +x tests/run_tests.sh && ./tests/run_tests.sh

# Run inside the kernel (copy tests into initramfs)
for t in build_tests/*; do cp "$t" initramfs/bin/; done
# then in your init script: /bin/futex_* /bin/sched_* /bin/pipe_* ...
```

Test suite covers: futex thundering-herd, `cmp_requeue`, robust-list death,
RR fairness, CFS `min_vruntime` lag, SCHED_DEADLINE CBS, pipe stress,
VFS concurrent `creat`, and `poll()` vs close-race.

---

## Scheduler

| Policy | Constant | Class | Notes |
|--------|----------|-------|-------|
| `SCHED_NORMAL` | 0 | CFS | Weighted fair-share; `nice` → CFS weight |
| `SCHED_FIFO` | 1 | RT | Run-to-block; preempts lower-priority RT |
| `SCHED_RR` | 2 | RT | Round-robin within a priority band |
| `SCHED_DEADLINE` | 6 | DL | EDF with CBS admission control |

**`RLIMIT_RTTIME`** — RT tasks accumulate `rt_cpu_time_us`. Resets to 0 on any
voluntary block (`futex_wait`, `nanosleep`, `waitpid`, `block_current()`).
Soft limit → `SIGXCPU`; hard limit → `SIGKILL`.

**`RLIMIT_CPU`** — Charged every tick regardless of policy.
Soft crossing → `SIGXCPU` (repeated each second); hard → `SIGKILL`.

---

## Syscall Table (selected)

| NR (x86_64) | Name | Status |
|-------------|------|--------|
| 0 | `read` | ✅ |
| 1 | `write` | ✅ |
| 2 | `open` | ✅ |
| 3 | `close` | ✅ |
| 7 | `waitpid` (compat) | ✅ |
| 9 | `mmap` | ✅ |
| 11 | `munmap` | ✅ |
| 12 | `brk` | ✅ |
| 22 | `pipe` | ✅ |
| 35 | `nanosleep` | ✅ |
| 56 | `clone` | ✅ |
| 57 | `fork` | ✅ |
| 59 | `execve` | ✅ |
| 60 | `exit` | ✅ |
| 61 | `wait4` | ✅ |
| 72 | `fcntl` | ✅ |
| 7 | `poll` | ✅ |
| 202 | `futex` | ✅ (WAIT/WAKE/WAKE_BITSET/REQUEUE/CMP_REQUEUE/robust) |
| 218 | `set_tid_address` | ✅ |
| 228 | `clock_gettime` | ✅ |
| 302 | `prlimit64` | ✅ |
| 314 | `sched_setattr` | ✅ |
| 315 | `sched_getattr` | ✅ |

---

## Upgrading the Toolchain Pin

Three files must always agree on the nightly date:

| File | Key |
|------|-----|
| `rust-toolchain.toml` | `channel = "nightly-YYYY-MM-DD"` |
| `Dockerfile` | `ARG NIGHTLY_DATE=YYYY-MM-DD` |
| `flake.nix` | `pkgs.rust-bin.nightly."YYYY-MM-DD"` |

Steps:
1. Update the date in all three files in a single commit.
2. `cargo build` for each of the three targets (RISC-V UEFI, RISC-V SBI, x86_64).
3. Fix any API churn (check the nightly release notes for breaking changes to
   `naked_functions`, `alloc_error_handler`, or `-Z build-std`).
4. `docker build -t rustos-dev .` to verify the image.
5. `nix develop --command cargo build` to verify the flake.
6. Add a CHANGELOG entry documenting the bump and reason.

---

## Development

```bash
# Fast type-check without linking
cargo check --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins

# Format check (enforced by fmt.yml CI)
cargo fmt --check

# Clippy (bare-metal; no_std)
cargo clippy --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins -- -D warnings

# xtask helpers
cargo xtask build           # RISC-V UEFI release
cargo xtask build --debug   # RISC-V UEFI debug
cargo xtask clean
```

---

## Roadmap

- [ ] Real per-process `nanosleep` timer (APIC one-shot / RISC-V timer interrupt)
- [ ] Scheduler load balancing across CPUs (SMP work-stealing)
- [ ] Full TCP/IP stack (`src/net/`) — connect/accept/send/recv
- [ ] AMD/Intel GPU DRM/KMS driver
- [ ] Expanded musl libc syscall coverage
- [ ] `io_uring` support
- [ ] Graduate `namespaces` + `cgroups` features into default
- [ ] Wire `sysv_ipc` syscall dispatch entries
- [ ] GDB RSP implementation in `gdbstub`

---

## License

MIT
