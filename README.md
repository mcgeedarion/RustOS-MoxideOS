# RustOS

A hobby operating-system kernel written in **Rust**, targeting **x86_64** (primary) and **RISC-V 64** (secondary). Runs on bare metal and under QEMU. No C runtime, no external libc.

---

## Architecture support

| Target | Boot | Paging | Syscall | Status |
|---|---|---|---|---|
| `x86_64-unknown-none` | UEFI | 4-level (PML4) | `syscall`/`sysret` | Primary |
| `riscv64gc-unknown-none-elf` | SBI | sv39 | `ecall` | Secondary |

---

## Feature overview

### Hardware abstraction
- x86_64: GDT, IDT, APIC (local + I/O), TSS, `RDMSR`/`WRMSR`, serial UART, PS/2
- RISC-V: SBI boot, CSR helpers, PLIC, CLINT, sv39 trap handling
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
rustup target add x86_64-unknown-none
rustup target add riscv64gc-unknown-none-elf
rustup component add rust-src llvm-tools-preview
# QEMU
apt install qemu-system-x86 qemu-system-misc   # or brew install qemu
```

The correct nightly toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml).

### x86_64

```sh
bash build_x86.sh
```

### RISC-V 64

```sh
bash build.sh
```

---

## Running under QEMU

### x86_64

```sh
bash run_qemu.sh
```

### RISC-V 64

```sh
bash run_qemu_riscv.sh
```

Both scripts boot straight to the kernel shell. Serial output goes to stdio.

---

## Debugging with GDB

Terminal 1 — start QEMU with GDB stub:

```sh
bash run_qemu.sh -s -S          # x86_64
bash run_qemu_riscv.sh -s -S    # RISC-V
```

Terminal 2 — attach:

```sh
gdb target/x86_64-unknown-none/debug/rustos
# .gdbinit loads automatically and connects to :1234
```

[`.gdbinit`](.gdbinit) sets the architecture, loads symbols, connects to `localhost:1234`, and defines helpers (`vmas`, `procs`, `klog`).

---

## Testing

```sh
cargo test --target x86_64-unknown-none
```

Integration tests live in [`tests/`](tests/). CI runs on every push via [`.github/workflows/`](.github/workflows/).

---

## Repository layout

```
src/
  arch/          # x86_64 + riscv64 HAL (Paging, Cpu traits)
  fs/            # VFS, ext2, devfs, procfs, pipe, poll, …
  mm/            # PMM, VMM, mmap, page_fault, CoW
  proc/          # PCB, scheduler, fork, exec, signal, futex
  drivers/       # virtio-blk, virtio-net, PCIe, PS/2, TTY
  net/           # smoltcp integration, socket syscalls
  security/      # capability sets
  shell/         # in-kernel TTY shell
tests/           # integration test harness
tools/           # mkfs helper, symbol scripts
```

---

## License

MIT
