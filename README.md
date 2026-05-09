# rustos

A Rust-based operating system kernel targeting **x86_64** and **RISC-V (rv64gc)**, with growing Linux ABI compatibility. Boots via UEFI (x86_64 and RISC-V EDK2) or OpenSBI (RISC-V SBI). Runs under QEMU with virtio block, GPU, and network devices.

---

## Features

- **Multi-architecture**: x86_64 (UEFI/BIOS) and RISC-V rv64gc (UEFI EDK2 / OpenSBI)
- **Process model**: fork/exec/wait, POSIX signals, `clone(2)`, namespaces (PID, net)
- **Scheduler**: CFS (Completely Fair Scheduler) with SCHED_NORMAL, SCHED_FIFO, SCHED_RR, and SCHED_DEADLINE; per-CPU run queues
- **Memory**: 4-level page tables (x86_64) / Sv39+Sv48 (RISC-V), demand paging, Copy-on-Write (COW), ASLR
- **Filesystems**: ext2, FAT32/VFAT, initramfs (cpio), VFS layer
- **Drivers**: virtio-blk, virtio-net, virtio-gpu, PS/2 keyboard, UART, NVMe (stub), PCIe enumeration
- **Linux syscall compatibility**: ~80 syscalls implemented (open/read/write/close, mmap, brk, clone, execve, waitpid, nanosleep, futex, sched_setattr, prlimit, …)
- **Resource limits**: `RLIMIT_CPU` (SIGXCPU/SIGKILL enforcement per tick), `RLIMIT_RTTIME` (continuous RT CPU budget, reset on voluntary block)
- **IPC**: futex (FUTEX_WAIT/FUTEX_WAKE/FUTEX_REQUEUE), anonymous pipes, Unix-domain sockets (partial)
- **Security**: stack canaries, PTI (Page Table Isolation), capability stubs
- **Wayland compositor subsystem** (behind `--features wayland`, WIP)
- **musl libc port** — see [`docs/musl_port.md`](docs/musl_port.md)

---

## Repository Layout

```
rustos/
├── src/
│   ├── arch/
│   │   ├── x86_64/        # IDT, APIC timer, GDT, interrupts, paging
│   │   └── riscv64/       # PLIC, trap handler, SBI/UEFI entry
│   ├── proc/              # scheduler, process table, fork, exec, wait,
│   │                      #   signal, futex, nanosleep, rlimit
│   ├── mm/                # VMM, PMM, page tables, COW, mmap
│   ├── fs/                # VFS, ext2, FAT32, initramfs
│   ├── drivers/           # virtio-{blk,net,gpu}, NVMe, PS/2
│   ├── syscall/           # syscall dispatch + individual handlers
│   ├── net/               # TCP/UDP/IP stack (WIP)
│   ├── ipc/               # pipes, futex, Unix sockets
│   ├── smp/               # per-CPU blocks, AP bring-up
│   ├── security/          # capabilities, PTI, canaries
│   └── wayland/           # Wayland compositor (feature-gated)
├── userspace/             # Minimal userspace programs (init, shell)
├── tests/                 # Integration tests
├── xtask/                 # cargo xtask build system
├── docs/
│   ├── musl_port.md
│   └── musl_pipeline.md
├── run_qemu.sh            # x86_64 QEMU launcher
├── run_qemu_riscv.sh      # RISC-V QEMU launcher (UEFI + SBI)
├── Cargo.toml
├── rust-toolchain.toml    # nightly + riscv64gc + x86_64-unknown-none
├── x86_64.ld              # x86_64 linker script
└── linker.ld              # RISC-V linker script
```

---

## Quick Start

### Prerequisites

```bash
# Rust nightly + targets (handled automatically by rust-toolchain.toml)
rustup show   # confirms active toolchain

# QEMU
sudo apt install qemu-system-x86_64 qemu-system-riscv64   # Debian/Ubuntu
brew install qemu                                          # macOS

# RISC-V UEFI firmware (for run_qemu_riscv.sh default mode)
sudo apt install qemu-efi-riscv64                         # Debian/Ubuntu
```

### x86_64

```bash
# Build + run (serial output to terminal)
./run_qemu.sh

# With virtio-gpu window
./run_qemu.sh --gpu

# With a disk image
./run_qemu.sh disk.img

# GDB debug session
./run_qemu.sh --gdb          # Terminal 1: QEMU halts at entry
gdb                          # Terminal 2: .gdbinit auto-connects
```

### RISC-V

```bash
# UEFI boot (default, release build)
./run_qemu_riscv.sh

# SBI boot (debug build)
./run_qemu_riscv.sh --sbi

# GDB debug session
./run_qemu_riscv.sh --gdb
gdb-multiarch \
  -ex 'set arch riscv:rv64' \
  -ex 'file target/riscv64-uefi/release/rustos.efi' \
  -ex 'target remote :1235'
```

### Build only

```bash
# x86_64
cargo build --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem

# RISC-V UEFI
cargo xtask build

# RISC-V SBI (debug)
cargo xtask build --arch riscv64 --boot sbi
```

### Feature flags

| Flag | Default | Description |
|------|---------|-------------|
| `uefi_boot` | ✅ on | RISC-V UEFI boot path (EDK2 RiscVVirt PE/COFF) |
| `wayland` | ❌ off | Wayland compositor subsystem |

```bash
# Enable Wayland build
cargo build --features wayland
```

---

## Scheduler

The kernel implements a multi-policy scheduler:

| Policy | Constant | Class | Notes |
|--------|----------|-------|-------|
| `SCHED_NORMAL` | 0 | CFS | Weighted fair-share; `nice` maps to CFS weight |
| `SCHED_FIFO` | 1 | RT | Run-to-block, priority preempts lower RT tasks |
| `SCHED_RR` | 2 | RT | Round-robin within a priority band |
| `SCHED_DEADLINE` | 6 | DL | EDF with admission control (`dl_admission_test`) |

**`RLIMIT_RTTIME`** — RT tasks accumulate `rt_cpu_time_us`. The budget resets to 0 on any voluntary block (`futex_wait`, `nanosleep`, `waitpid`, `block_current()`). Soft limit → `SIGXCPU`; hard limit → `SIGKILL`.

**`RLIMIT_CPU`** — Charged every tick regardless of scheduling class. Soft crossing → `SIGXCPU` (repeated each second); hard crossing → `SIGKILL`.

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
| 35 | `nanosleep` | ✅ |
| 56 | `clone` | ✅ |
| 57 | `fork` | ✅ |
| 59 | `execve` | ✅ |
| 60 | `exit` | ✅ |
| 61 | `wait4` | ✅ |
| 202 | `futex` | ✅ (WAIT/WAKE/REQUEUE) |
| 218 | `set_tid_address` | ✅ |
| 228 | `clock_gettime` | ✅ |
| 302 | `prlimit64` | ✅ |
| 314 | `sched_setattr` | ✅ |
| 315 | `sched_getattr` | ✅ |

---

## Development

```bash
# Run integration tests
cargo test

# Check without linking (fast feedback)
cargo check --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins

# xtask helpers
cargo xtask build           # RISC-V UEFI release
cargo xtask build --debug   # RISC-V UEFI debug
cargo xtask clean
```

### GDB / debugging

`.gdbinit` in the repo root auto-connects to QEMU's gdbserver on `:1234` (x86_64) and sets the architecture. For RISC-V use port `:1235` (see `run_qemu_riscv.sh --gdb`).

---

## Roadmap

- [ ] Real per-process `nanosleep` timer (APIC one-shot / RISC-V timer interrupt)
- [ ] SMP-aware scheduler (per-CPU run queues, load balancing)
- [ ] Full TCP/IP stack (`src/net/`)
- [ ] AMD/Intel GPU DRM/KMS driver
- [ ] Expanded musl libc syscall coverage
- [ ] `io_uring` support

---

## License

MIT
