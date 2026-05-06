# RustOS

A hobby operating-system kernel written in **Rust**, targeting **RISC-V 64** (primary) and **x86_64** (secondary). Runs on bare metal and under QEMU. No C runtime, no external libc.

---

## Architecture support

| Target | Boot | Paging | Syscall | Status |
|---|---|---|---|---|
| `riscv64gc-unknown-none-elf` | SBI **or** UEFI | sv39 | `ecall` | **Primary** |
| `x86_64-unknown-none` | UEFI | 4-level (PML4) | `syscall`/`sysret` | Secondary |

RISC-V supports two boot modes selectable at build time:
- **SBI** (default) — OpenSBI hands off to `_start` in S-mode; no extra firmware required
- **UEFI** — EDK2 RiscVVirt calls `uefi_start` as a standard EFI application; output is a PE/COFF `.efi` binary installed on a FAT ESP

---

## Feature overview

### Hardware abstraction
- RISC-V: SBI + UEFI boot, CSR helpers, PLIC, CLINT, sv39 trap handling
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

### Userspace programs (compiled into initramfs)
`init`, `sh`, `cat`, `ls`, `echo`, `hello`, `devtest`, `thread_test`

---

## Building

### Prerequisites

```sh
# Rust toolchain (targets are pinned in rust-toolchain.toml — rustup installs them automatically)
rustup toolchain install nightly
rustup component add rust-src llvm-tools-preview

# QEMU
apt install qemu-system-misc             # RISC-V
apt install qemu-system-x86             # x86_64
# or: brew install qemu

# UEFI RISC-V firmware (only needed for --uefi mode)
apt install qemu-efi-riscv64            # Debian/Ubuntu

# x86_64 only: nasm (assembles the multiboot2 entry stub)
apt install nasm
```

The correct nightly toolchain and both targets are pinned in [`rust-toolchain.toml`](rust-toolchain.toml).
Running any `cargo` command will trigger `rustup` to install the toolchain and targets automatically.

### RISC-V 64 — SBI (default)

```sh
cargo build --release   # or: bash build.sh
```

### RISC-V 64 — UEFI

```sh
bash build_riscv.sh --uefi
```

Builds against [`riscv64-uefi.json`](riscv64-uefi.json) (PE/COFF via `lld-link`) and installs
the output to `esp/EFI/BOOT/BOOTRISCV64.EFI`.

### x86_64

```sh
bash build_x86.sh
```

Requires `nasm` on `$PATH` (used by `build.rs` to assemble `src/arch/x86_64/boot.s`).

---

## Running under QEMU

### RISC-V 64 — SBI

```sh
bash run_qemu_riscv.sh
```

### RISC-V 64 — UEFI

```sh
bash run_qemu_riscv.sh --uefi
```

The script auto-detects the EDK2 RISC-V firmware (`RISCV_VIRT_CODE.fd`) from common
install paths, creates a writable vars store on first run, and launches QEMU with
pflash firmware + a FAT virtio drive containing the ESP.

### x86_64

```sh
bash run_qemu.sh
```

All scripts boot straight to the kernel shell. Serial output goes to stdio.

---

## Debugging with GDB

Terminal 1 — start QEMU with GDB stub:

```sh
bash run_qemu_riscv.sh --gdb        # RISC-V SBI  (port :1235)
bash run_qemu_riscv.sh --uefi --gdb # RISC-V UEFI (port :1235)
bash run_qemu.sh --gdb              # x86_64      (port :1234)
```

Terminal 2 — attach:

```sh
# RISC-V
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
# RISC-V (primary)
cargo test --target riscv64gc-unknown-none-elf

# x86_64
cargo test --target x86_64-unknown-none
```

Integration tests live in [`tests/`](tests/). CI runs on every push via [`.github/workflows/`](.github/workflows/).
The `build-riscv` job (debug + release) runs first; `build-x86_64` is the secondary job.

---

## Repository layout

```
src/
  arch/
    riscv64/     # SBI + UEFI entry, CSR, PLIC, sv39 paging, syscall, trampoline
    x86_64/      # GDT, IDT, APIC, UEFI entry, paging, syscall
  fs/            # VFS, ext2, devfs, procfs, pipe, poll, …
  mm/            # PMM, VMM, mmap, page_fault, CoW
  proc/          # PCB, scheduler, fork, exec, signal, futex
  drivers/       # virtio-blk, virtio-net, PCIe, PS/2, TTY
  net/           # ARP, DHCP, DNS, Ethernet, ICMP, IPv4, TCP, UDP
  security/      # capability sets (CapSet)
  shell/         # in-kernel TTY shell
tests/           # integration test harness
tools/           # mkfs helper, symbol scripts
linker.ld          # RISC-V linker script (loads at 0x80200000)
x86_64.ld          # x86_64 linker script
riscv64-uefi.json  # custom Rust target spec (PE/COFF, RISC-V UEFI)
build.sh           # default build (RISC-V SBI release)
build_riscv.sh     # RISC-V builder with --uefi / --debug / --initrd flags
build_x86.sh       # x86_64 builder
run_qemu_riscv.sh  # RISC-V QEMU launcher
run_qemu.sh        # x86_64 QEMU launcher
```

---

## License

MIT
