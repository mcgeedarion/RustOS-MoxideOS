# rustos

> A Rust-based operating system kernel targeting **x86_64** and **RISC-V (rv64gc)**,
> with growing Linux ABI compatibility. Boots via UEFI (x86_64 and RISC-V EDK2) or
> OpenSBI (RISC-V SBI). Runs under QEMU with virtio block, GPU, and network devices.

![build](https://img.shields.io/github/actions/workflow/status/mcgeedarion/rustos/build.yml?label=build)
![license](https://img.shields.io/badge/license-MIT-blue)
![rust](https://img.shields.io/badge/rust-nightly--2025--05--15-orange)
![arch](https://img.shields.io/badge/arch-x86__64%20%7C%20riscv64-lightgrey)
![version](https://img.shields.io/badge/version-0.2.0-green)

> **Toolchain:** `nightly-2025-05-15` (pinned in `rust-toolchain.toml`).  
> Nightly is required for `naked_functions`, `alloc_error_handler`,
> `core_intrinsics`, `abi_x86_interrupt`, and `-Z build-std`.  
> See [Upgrading the Toolchain Pin](#upgrading-the-toolchain-pin) before bumping.

---

## Features

- **Multi-architecture**: x86_64 (UEFI) and RISC-V rv64gc (UEFI EDK2 / OpenSBI)
- **Process model**: fork/exec/wait, POSIX signals, `clone(2)`, threads
- **Scheduler**: CFS (`SCHED_NORMAL`), `SCHED_FIFO`, `SCHED_RR`, `SCHED_DEADLINE`;
  per-CPU run queues; EDF with CBS admission control
- **Memory**: 4-level page tables (x86_64) / Sv39+Sv48 (RISC-V), demand paging,
  Copy-on-Write (COW), ASLR, **slab allocator** (8–1024 byte caches, per-cache SMP locks)
- **Filesystems**: ext2, **ext4**, FAT32/VFAT, tmpfs, devfs, procfs (`/proc/slabinfo`, `/proc/<pid>/ns/`), initramfs (cpio), VFS layer
- **Drivers**: virtio-blk, virtio-net, virtio-gpu, PS/2 keyboard, UART, PCIe enumeration
- **Linux syscall compatibility**: ~80 syscalls (see [Syscall Table](#syscall-table-selected))
- **Resource limits**: `RLIMIT_CPU` and `RLIMIT_RTTIME` with SIGXCPU/SIGKILL enforcement
- **IPC**: SysV msg/sem/shm (NR 29–31, 64–71), POSIX mq (NR 240–245), futex (WAIT/WAKE/WAKE_BITSET/REQUEUE/CMP_REQUEUE, robust lists), pipes, Unix sockets
- **Namespaces**: NEWNS (mount), NEWPID, NEWNET, NEWUTS, NEWIPC, NEWUSER — `unshare(2)`, `setns(2)`, `/proc/<pid>/ns/` nsfs inodes
- **SMP**: AP bringup (APIC trampoline / SBI HSM), per-CPU blocks, IPI dispatch, MM RwLock per address space
- **Security**: ASLR, stack canaries, PTI, SMEP/SMAP, seccomp-BPF, capability set
- **Timers**: real `nanosleep` / `clock_nanosleep` — clock-aware absolute sleeps, EINTR/remainder correctness, `CLOCK_PROCESS_CPUTIME_ID` / `CLOCK_THREAD_CPUTIME_ID`
- **GDB stub**: full RSP implementation over UART/SBI console for both **x86_64** and **RISC-V** — breakpoints, single-step, thread enumeration, `qXfer:features:read`, `vCont`, binary memory writes
- **musl libc port** — see [`docs/musl_port.md`](docs/musl_port.md)

---

## Repository Layout

```text
RustOS/
├── .github/
│   └── workflows/      # GitHub Actions CI workflows
├── docs/               # Project documentation
│   ├── musl_port.md
│   └── musl_pipeline.md
├── src/                # Kernel source
│   ├── arch/
│   │   ├── x86_64/     # x86_64 CPU, traps, paging, APIC, GDT, boot handoff
│   │   └── riscv64/    # RISC-V traps, paging, SBI/UEFI handoff, PLIC/CLINT
│   ├── crt/            # C runtime startup support
│   ├── drivers/        # Device drivers: virtio, PCIe, UART, VGA/GOP, storage, network
│   ├── drm/            # Kernel graphics/display manager abstractions
│   ├── firmware/       # Firmware interfaces such as ACPI/UEFI-facing support
│   ├── fs/             # VFS and filesystems: ext*, FAT/VFAT, tmpfs, devfs, procfs, initramfs
│   ├── gdbstub/        # GDB Remote Serial Protocol stub
│   ├── initramfs/      # Initramfs loading and cpio support
│   ├── input/          # Input/event device layer
│   ├── ipc/            # SysV IPC, POSIX message queues, shared memory, semaphores
│   ├── mm/             # PMM, VMM, paging, slab allocator, COW, mmap
│   ├── net/            # Ethernet, IP, UDP/TCP, sockets, network namespace hooks
│   ├── proc/           # Processes, scheduler, fork/exec/wait, signals, PID namespaces
│   ├── security/       # ASLR, canaries, PTI, seccomp, capabilities, namespaces, cgroups
│   ├── smp/            # Multi-core bring-up, per-CPU state, IPIs
│   ├── sync/           # Locks, wait queues, futexes, synchronization primitives
│   ├── syscall/        # Syscall table, dispatch, Linux ABI compatibility handlers
│   ├── tty/            # TTY, PTY, terminal handling
│   └── wayland/        # Wayland compositor/kernel interface scaffold
├── tests/              # Integration and host-side tests
├── userspace/          # Minimal userspace programs, init, shell, demos
├── xtask/              # Cargo xtask build and image tooling
├── Cargo.toml
├── Dockerfile
├── flake.nix
├── linker.ld           # RISC-V/default linker script
├── run_qemu.sh         # x86_64 QEMU launcher
├── run_qemu_riscv.sh   # RISC-V QEMU launcher
├── rust-toolchain.toml
└── x86_64.ld           # x86_64 linker script
```

---

## Quick Start

Three ways to get a working build environment. Pick one.

### Option A — Docker (recommended for CI / one-shot builds)

```bash
docker build -t rustos-dev .
docker run --rm -it -v "$(pwd)":/work rustos-dev
docker run --rm -v "$(pwd)":/work rustos-dev cargo build
```

The image bundles: `clang`/`lld`, `riscv64-unknown-elf-{as,ar}`, `qemu-system-{riscv64,x86_64}`,
`ovmf`, and the pinned `nightly-2025-05-15` toolchain.

### Option B — Nix flake (recommended for local development)

```bash
nix develop
nix develop --command cargo build
nix build
```

Requires [Nix with flakes enabled](https://nixos.wiki/wiki/Flakes).

### Option C — Native (rustup + manual tool install)

```bash
rustup show
sudo apt install clang lld nasm qemu-system-riscv64 qemu-system-x86_64 \
                 qemu-efi-riscv64 ovmf binutils-riscv64-linux-gnu
brew install qemu llvm
```

---

## Building

### RISC-V UEFI (default)

```bash
cargo build
cargo build --release
cargo xtask build
```

### RISC-V SBI

```bash
cargo build \
  --target riscv64gc-unknown-none-elf \
  --no-default-features \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem
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
./run_qemu.sh
./run_qemu.sh --gpu
./run_qemu.sh disk.img
./run_qemu.sh --gdb            # halt at entry, GDB on :1234
./run_qemu_riscv.sh
./run_qemu_riscv.sh --sbi
./run_qemu_riscv.sh --gdb      # QEMU gdbserver on :1235
gdb-multiarch \
  -ex 'set arch riscv:rv64' \
  -ex 'file target/riscv64-uefi/release/rustos.efi' \
  -ex 'target remote :1235'
```

`.gdbinit` auto-connects and loads the correct architecture.
RISC-V uses port `:1235`; x86_64 uses `:1234`.

---

## GDB Debugging

The `gdbstub` Cargo feature builds a full GDB Remote Serial Protocol stub into
the kernel itself. Both architectures are supported — no QEMU gdbserver required.

### x86_64

```bash
cargo build --target x86_64-unknown-none \
  --no-default-features --features gdbstub \
  -Z build-std=core,alloc,compiler_builtins
./run_qemu.sh
gdb target/x86_64-unknown-none/debug/rustos \
  -ex 'target remote /dev/ttyS0'
```

### RISC-V

```bash
cargo build --no-default-features --features gdbstub \
  -Z build-std=core,alloc,compiler_builtins
./run_qemu_riscv.sh
gdb-multiarch target/riscv64-uefi/debug/rustos.efi \
  -ex 'set arch riscv:rv64' \
  -ex 'target remote /dev/ttyS1'
```

### RSP Packet Support (both architectures)

| Packet | Description |
|--------|-------------|
| `?` | Stop reason (T05 SIGTRAP + thread ID) |
| `g`/`G` | Read/write all registers |
| `p`/`P` | Read/write single register |
| `m`/`M` | Read/write memory (hex) |
| `X` | Write memory (binary, RSP-escaped) |
| `s`/`c` | Single-step / continue (optional address) |
| `Z0`/`z0` | Insert/remove SW breakpoint (up to 16) |
| `H`/`T` | Thread select / thread alive |
| `vCont` | `s` and `c` actions |
| `vKill`/`D`/`k` | Kill / detach |
| `qSupported` | Advertises `swbreak+`, `vContSupported+`, `qXfer:features:read+` |
| `qfThreadInfo`/`qsThreadInfo` | Thread enumeration |
| `qXfer:features:read:target.xml` | Architecture XML |

### Register Files

| Arch | Registers | `g`/`G` size | Single-step |
|------|-----------|-------------|
| x86_64 | 24 (rax–r15, rip, eflags, cs/ss/ds/es/fs/gs) | 192 bytes | `RFLAGS.TF` |
| RISC-V | 33 (zero–t6, pc) | 528 bytes | `sstatus.SSTEP` |

---

## Namespaces

`unshare(2)` (NR 272) and `setns(2)` (NR 308) are fully wired. Each supported
namespace type and its isolation semantics:

| Type | Flag | Isolation |
|------|------|-----------|
| Mount | `CLONE_NEWNS` | Private mount table cloned from parent; `resolve_for_ns` routes all VFS path lookups |
| PID | `CLONE_NEWPID` | Children get local PIDs starting from 2; `getpid()` translates via `pid_ns::local_pid()` |
| Network | `CLONE_NEWNET` | Per-ns interface registry; new ns starts with `lo` only; socket isolation via `check_socket_ns()` |
| UTS | `CLONE_NEWUTS` | NsId tracked; per-ns hostname/domainname (future) |
| IPC | `CLONE_NEWIPC` | NsId tracked; per-ns SysV/POSIX IPC (future) |
| User | `CLONE_NEWUSER` | NsId tracked; uid/gid mapping (future); `CAP_SYS_ADMIN` check for root |

### /proc/<pid>/ns/

Each process exposes 7 namespace symlinks. Tools like `nsenter(1)` use them:

```
/proc/self/ns/mnt  → mnt:[4026531840]
/proc/self/ns/pid  → pid:[4026531836]
/proc/self/ns/net  → net:[4026531992]
/proc/self/ns/uts  → uts:[4026531838]
/proc/self/ns/ipc  → ipc:[4026531839]
/proc/self/ns/user → user:[4026531837]
/proc/self/ns/time → time:[4026531834]
```

Opening a `/proc/<pid>/ns/<name>` path returns a fd that can be passed directly
to `setns(2)` — the fd carries both the symlink content (for `read()`) and the
ns identity (for `setns()`) via the same synthetic fd number.

---

## Feature Flags

The **default build** includes the base kernel, SysV IPC, and namespaces.
WIP subsystems are behind opt-in flags.

| Feature | Default | Status | Enable with |
|---------|---------|--------|-------------|
| `uefi_boot` | ✅ on | Stable | (always on by default) |
| `sysv_ipc` | ✅ on | **Stable** — SysV msg/sem/shm + POSIX mq; NR 29–31, 64–71, 240–245 | (on by default) |
| `namespaces` | ✅ on | **Stable** — 6 NS types; `unshare`/`setns` wired; `/proc/<pid>/ns/` inodes | (on by default) |
| `gdbstub` | ❌ off | **Complete** — x86_64 (UART) + RISC-V (SBI); SW breakpoints, single-step, `target.xml` | `--features gdbstub` |
| `cgroups` | ❌ off | Knob API done; cgroupfs mount missing | `--features cgroups` |
| `input_events` | ❌ off | Stub no-ops; evdev routing missing | `--features input_events` |
| `wayland` | ❌ off | Scaffold only | `--features wayland` |

```bash
# Full WIP build (all optional features)
cargo build --features cgroups,gdbstub,input_events,wayland
```

To graduate a feature: wire all syscall dispatch entries, implement missing VFS
mounts, replace capability stubs, then add to `default = [...]` in `Cargo.toml`.

---

## Integration Tests

```bash
chmod +x tests/run_tests.sh && ./tests/run_tests.sh
for t in build_tests/*; do cp "$t" initramfs/bin/; done
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
voluntary block. Soft limit → `SIGXCPU`; hard limit → `SIGKILL`.

**`RLIMIT_CPU`** — Charged every tick. Soft crossing → `SIGXCPU`; hard → `SIGKILL`.

---

## Syscall Table (selected)

| NR (x86_64) | Name | Status |
|-------------|------|--------|
| 0 | `read` | ✅ |
| 1 | `write` | ✅ |
| 2 | `open` | ✅ |
| 3 | `close` | ✅ |
| 7 | `poll` | ✅ |
| 9 | `mmap` | ✅ |
| 11 | `munmap` | ✅ |
| 12 | `brk` | ✅ |
| 22 | `pipe` | ✅ |
| 29–31 | `shmget`/`shmat`/`shmctl` | ✅ |
| 35 | `nanosleep` | ✅ clock-aware, EINTR/rem correct |
| 56 | `clone` | ✅ |
| 57 | `fork` | ✅ |
| 59 | `execve` | ✅ |
| 60 | `exit` | ✅ |
| 61 | `wait4` | ✅ |
| 64–66 | `semget`/`semop`/`semctl` | ✅ |
| 67 | `shmdt` | ✅ |
| 68–71 | `msgget`/`msgsnd`/`msgrcv`/`msgctl` | ✅ |
| 72 | `fcntl` | ✅ |
| 202 | `futex` | ✅ WAIT/WAKE/WAKE_BITSET/REQUEUE/CMP_REQUEUE/robust |
| 218 | `set_tid_address` | ✅ |
| 228 | `clock_gettime` | ✅ all clock IDs including CPUTIME |
| 230 | `clock_nanosleep` | ✅ TIMER_ABSTIME, clock-aware |
| 240–245 | `mq_open`/`mq_unlink`/`mq_timedsend`/`mq_timedreceive`/`mq_notify`/`mq_getsetattr` | ✅ |
| 272 | `unshare` | ✅ all 6 NS types |
| 302 | `prlimit64` | ✅ |
| 308 | `setns` | ✅ |
| 314 | `sched_setattr` | ✅ |
| 315 | `sched_getattr` | ✅ |

---

## Development

```bash
cargo check --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins
cargo fmt --check
cargo clippy --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins -- -D warnings
cargo xtask build
cargo xtask build --debug
cargo xtask clean
```

---

## Upgrading the Toolchain Pin

Three files must always agree on the nightly date:

| File | Key |
|------|-----|
| `rust-toolchain.toml` | `channel = "nightly-YYYY-MM-DD"` |
| `Dockerfile` | `ARG NIGHTLY_DATE=YYYY-MM-DD` |
| `flake.nix` | `pkgs.rust-bin.nightly."YYYY-MM-DD"` |

1. Update all three in a single commit.
2. `cargo build` for each of the three targets.
3. Fix any API churn from nightly release notes.
4. `docker build -t rustos-dev .` to verify the image.
5. `nix develop --command cargo build` to verify the flake.
6. Add a CHANGELOG entry.

---

## License

MIT
