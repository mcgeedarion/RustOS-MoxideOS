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

# lld (for UEFI PE/COFF linking — usually bundled with clang)
apt install lld
```

### RISC-V 64 — UEFI (default)

```sh
cargo xtask build
# or explicitly:
cargo xtask build --arch riscv64 --boot uefi
```

Produces `esp/EFI/BOOT/BOOTRISCV64.EFI`.

### RISC-V 64 — SBI

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
  --boot    uefi (default) or sbi  — only meaningful for riscv64
  --debug   debug build instead of release
  --initrd  also build + pack initramfs.cpio (SBI mode only)
```

---

## Running under QEMU

### RISC-V 64 — UEFI (default)

```sh
bash run_qemu_riscv.sh
```

### RISC-V 64 — SBI

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

Terminal 1 — start QEMU with GDB stub:

```sh
bash run_qemu_riscv.sh --gdb            # RISC-V UEFI (port :1235)
bash run_qemu_riscv.sh --sbi --gdb      # RISC-V SBI  (port :1235)
bash run_qemu.sh --gdb                  # x86_64      (port :1234)
```

Terminal 2 — attach:

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
Jobs in priority order: **RISC-V UEFI** (debug + release) → RISC-V SBI (debug) → x86_64 (debug + release).

---

## Repository layout

```
src/
  arch/
    riscv64/     # UEFI + SBI entry, CSR, PLIC, sv39 paging, syscall, trampoline
    x86_64/      # GDT, IDT, APIC, UEFI entry, paging, syscall
  fs/            # VFS, ext2, devfs, procfs, pipe, poll, …
  mm/            # PMM, VMM, mmap, page_fault, CoW
  proc/          # PCB, scheduler, fork, exec, signal, futex
  drivers/       # virtio-blk, virtio-net, PCIe, PS/2, TTY
  net/           # ARP, DHCP, DNS, Ethernet, ICMP, IPv4, TCP, UDP
  security/      # capability sets (CapSet)
  shell/         # in-kernel TTY shell
xtask/           # cargo xtask build automation (replaces build shell scripts)
tests/           # integration test harness
tools/           # mkfs helper, symbol scripts
linker.ld          # RISC-V SBI linker script (loads at 0x80200000)
x86_64.ld          # x86_64 linker script
riscv64-uefi.json  # custom Rust target spec (PE/COFF, RISC-V UEFI) — default target
run_qemu_riscv.sh  # RISC-V QEMU launcher: UEFI (default) or --sbi
run_qemu.sh        # x86_64 QEMU launcher
```

---

## License

MIT
