# Musl Userspace Build Pipeline

This document describes how to build static musl-libc userspace binaries
for rustos and boot them via the kernel's ELF loader.

## Prerequisites

### x86_64
```bash
sudo apt install musl-tools    # provides musl-gcc
```

### RISC-V
```bash
# Option A — cross-compiler from apt (Ubuntu 22.04+)
sudo apt install gcc-riscv64-linux-gnu
# Then build musl from source for riscv64-linux-musl, or use:
# https://musl.cc/ — prebuilt toolchains

# Option B — Nix
nix-shell -p pkgsCross.riscv64.musl.dev pkgsCross.riscv64.buildPackages.gcc
```

## Build userspace + initramfs

```bash
# x86_64
./tools/build_userspace.sh

# RISC-V
./tools/build_userspace.sh riscv64
```

Outputs:
- `userspace/build/x86_64/init`    — PID 1 init binary
- `userspace/build/x86_64/hello`   — smoke-test binary
- `initramfs.cpio`                  — CPIO newc archive for QEMU

## Boot with QEMU (x86_64)

Add `-initrd initramfs.cpio` to your QEMU flags in `run_qemu.sh`:

```bash
qemu-system-x86_64 \
  -kernel kernel.bin \
  -initrd initramfs.cpio \
  -nographic \
  -serial mon:stdio
```

## Boot with QEMU (RISC-V)

```bash
qemu-system-riscv64 \
  -machine virt \
  -bios opensbi-riscv64-generic-fw_dynamic.bin \
  -kernel kernel.elf \
  -initrd initramfs.cpio \
  -nographic
```

## Kernel-side integration

The kernel needs to:
1. **Parse the CPIO archive** — find the `init` file entry
2. **Call `elf64::load()`** — map its PT_LOAD segments into a new address space
3. **Build the initial stack** — via `auxv::write_initial_stack()`
4. **Jump to userspace** — via `sysret` (x86_64) or `sret` (RISC-V)

The CPIO base address and size are passed by QEMU via:
- **Multiboot2**: module tag (`mbi_tag_module`)
- **UEFI**: config table entry or command line

### CPIO parser location
Add a CPIO parser at `src/initramfs/mod.rs`. Minimal interface:
```rust
pub fn find_file<'a>(cpio: &'a [u8], path: &str) -> Option<&'a [u8]>;
```

### Syscalls required by musl init
The following syscalls must be implemented in `src/syscall/stubs.rs`
before `init` can run successfully:

| Syscall | Number | Notes |
|---------|--------|-------|
| `write` | 1      | fd=1 stdout, already likely stubbed |
| `exit`  | 60     | process termination |
| `exit_group` | 231 | musl calls this from `exit()` |
| `brk`   | 12     | heap expansion, return `elf.brk` initially |
| `mmap`  | 9      | musl `__init_tls` uses this for TLS block |
| `set_tid_address` | 218 | musl startup; can return 0 stub |
| `arch_prctl` | 158 | musl TLS (`ARCH_SET_FS`); sets FS base |

## Adding a new userspace program

1. Create `userspace/<name>/<name>.c`
2. Add a rule to `userspace/Makefile`:
   ```make
   mybin: $(BUILD_DIR)
       $(CC) $(CFLAGS) -o $(BUILD_DIR)/mybin mybin/mybin.c
   ```
3. Add it to `PROGRAMS` and copy it into the staging dir in `build_initramfs.sh`
4. Rebuild: `./tools/build_userspace.sh`
