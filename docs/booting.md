# RustOS Boot Reference

## Overview

RustOS uses a thin boot layer and a shared kernel entry.  Each supported boot
path constructs `init::boot_info::BootInfo`, jumps to the exported
`kernel_main(&BootInfo)` symbol, and then lets `arch::init()` dispatch into the
active architecture implementation.

The current tree supports:

- `x86_64` UEFI images and a direct-kernel / Multiboot2-style QEMU path.
- `riscv64` UEFI images and an SBI/OpenSBI + FDT path.
- `aarch64` UEFI images and a bare-metal kernel target for board loaders.

The preferred user-facing build entry point is `cargo xtask`; the preferred QEMU
entry point is `scripts/ci/qemu-run.sh`.

---

## Requirements

- Rust nightly pinned by `rust-toolchain.toml`.
- `rust-src` and `llvm-tools-preview` for custom targets and image conversion.
- QEMU for the architecture being run.
- UEFI firmware images for UEFI QEMU modes:
  - OVMF for `x86_64`.
  - EDK2/QEMU EFI for `aarch64` and `riscv64`.
- Optional image tools: `mtools` (`mformat`, `mmd`, `mcopy`) for `cargo xtask
  image`.
- Optional initramfs/userland tools: `cpio` and architecture-appropriate musl
  cross compilers.
- Optional reproducible environment: `nix develop`.

---

## Preferred build commands

`cargo xtask build` defaults to an x86_64 UEFI release build and installs the
removable-media EFI binary under `esp/EFI/BOOT/`.

```sh
# Default: x86_64 UEFI release build.
cargo xtask build

# x86_64 UEFI image installed as esp/EFI/BOOT/BOOTX64.EFI.
cargo xtask build --arch x86_64 --boot uefi

# x86_64 direct-kernel target; also emits kernel.bin for low-level loaders.
cargo xtask build --arch x86_64 --boot sbi

# RISC-V UEFI loader target.
cargo xtask build --arch riscv64 --boot uefi

# RISC-V SBI/OpenSBI kernel path.
cargo xtask build --arch riscv64 --boot sbi

# AArch64 UEFI loader target.
cargo xtask build --arch aarch64 --boot uefi

# AArch64 bare-metal ELF target for board loaders.
cargo xtask build --arch aarch64 --boot sbi
```

Debug builds use `--debug`; optional feature bundles can be supplied with
`--features`.

```sh
cargo xtask build --arch x86_64 --boot uefi --debug
cargo xtask build --arch x86_64 --boot uefi --features debug,kmtest
```

---

## Initramfs and disk images

Build an initramfs for a target architecture:

```sh
cargo xtask mkinitramfs --arch x86_64
cargo xtask mkinitramfs --arch riscv64
cargo xtask mkinitramfs --arch aarch64
```

Build a FAT EFI disk image with the architecture-appropriate removable-media
filename:

```sh
cargo xtask image --arch x86_64 --boot uefi --initrd
cargo xtask image --arch riscv64 --boot uefi
cargo xtask image --arch aarch64 --boot uefi
```

Image names produced by `xtask`:

| Architecture | EFI removable filename | Disk image name |
|---|---|---|
| `x86_64` | `BOOTX64.EFI` | `boot.img` |
| `riscv64` | `BOOTRISCV64.EFI` | `boot-riscv64.img` |
| `aarch64` | `BOOTAA64.EFI` | `boot-aarch64.img` |

The `esp/EFI/BOOT/` directory is the staging root for EFI binaries.  The QEMU
launcher uses `target/esp/` for x86_64 UEFI and `esp/` for the non-x86 UEFI
virt-machine flows; `cargo xtask image` packages the staged EFI binary into a
standalone FAT image.

---

## Direct Cargo builds

`xtask` wraps these Cargo concepts, but direct builds are still useful when
iterating on custom targets:

```sh
cargo build --target targets/x86_64-kernel.json \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  -Z json-target-spec

cargo build --target targets/riscv64-kernel.json \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  -Z json-target-spec

cargo build --target targets/aarch64-kernel.json \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  -Z json-target-spec
```

For x86_64 UEFI, the ELF is converted to a PE/COFF EFI application with
`llvm-objcopy`, `rust-objcopy`, or `objcopy` using the `efi-app-x86_64` target
and subsystem 10.

---

## Unified QEMU launcher

Set `ARCH` and run the unified script:

```sh
ARCH=x86_64  ./scripts/ci/qemu-run.sh
ARCH=riscv64 ./scripts/ci/qemu-run.sh
ARCH=aarch64 ./scripts/ci/qemu-run.sh
```

Common options:

| Option | Description |
|---|---|
| `--boot uefi|multiboot|sbi` | Boot mode. Valid modes depend on `ARCH`. |
| `--release` | Build and run a release kernel. |
| `--gdb` | Halt at entry and expose QEMU GDB server on `:1234`. |
| `--gpu` | Add virtio-gpu and SDL display on x86_64. |
| `--no-net` | Disable virtio networking. |
| `--smoke` | Headless smoke run; wait for the configured serial marker. |
| `--test` | Build kmtest/userspace runner, boot with `init=/bin/kmtest`, and parse results. |
| `--timeout N` | Override smoke/test timeout. |
| `--smoke-marker TEXT` | Override the marker required by smoke mode. |

Valid QEMU boot modes:

| Architecture | Valid QEMU modes | Default |
|---|---|---|
| `x86_64` | `uefi`, `multiboot` | `uefi` |
| `riscv64` | `uefi`, `sbi` | `uefi` |
| `aarch64` | `uefi` | `uefi` |

Examples:

```sh
# x86_64 UEFI through OVMF.
ARCH=x86_64 ./scripts/ci/qemu-run.sh

# x86_64 direct-kernel / Multiboot2-style path.
ARCH=x86_64 ./scripts/ci/qemu-run.sh --boot multiboot

# RISC-V SBI/OpenSBI path.
ARCH=riscv64 ./scripts/ci/qemu-run.sh --boot sbi

# Release build with no virtio-net device.
ARCH=aarch64 ./scripts/ci/qemu-run.sh --release --no-net

# Smoke test with a custom marker and timeout.
ARCH=x86_64 ./scripts/ci/qemu-run.sh --smoke --smoke-marker 'TEST PASS: uart_smoke' --timeout 30

# kmtest mode.
ARCH=x86_64 ./scripts/ci/qemu-run.sh --test --timeout 60
```

---

## QEMU firmware search paths

### x86_64 OVMF

The QEMU launcher checks:

| Path | Notes |
|---|---|
| `/usr/share/OVMF/OVMF_CODE.fd` plus `/usr/share/OVMF/OVMF_VARS.fd` | Ubuntu/Debian split OVMF layout. |
| `/usr/share/ovmf/OVMF.fd` | Common single-file OVMF layout. |
| `/usr/share/edk2/ovmf/OVMF.fd` | Arch-style EDK2 OVMF layout. |
| `/usr/share/qemu/OVMF.fd` | Fedora/openSUSE-style location. |
| `/opt/homebrew/share/qemu/edk2-x86_64-code.fd` | macOS Homebrew QEMU location. |
| `/usr/share/edk2-ovmf/x64/OVMF.fd` | Additional distro location. |

### AArch64 EDK2

The launcher checks:

| Path |
|---|
| `/usr/share/qemu-efi-aarch64/QEMU_EFI.fd` |
| `/usr/share/edk2/aarch64/QEMU_EFI.fd` |
| `/usr/share/qemu/edk2-aarch64-code.fd` |
| `/opt/homebrew/share/qemu/edk2-aarch64-code.fd` |
| `/usr/local/share/qemu/edk2-aarch64-code.fd` |

If a writable VARS file is not discovered, the script creates
`edk2-aarch64-vars.fd` in the repository root.

### RISC-V EDK2

The launcher checks:

| Path |
|---|
| `/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd` |
| `/usr/share/edk2/riscv64/RISCV_VIRT_CODE.fd` |
| `/usr/share/qemu/edk2-riscv-code.fd` |
| `/opt/homebrew/share/qemu/edk2-riscv-code.fd` |
| `/usr/local/share/qemu/edk2-riscv-code.fd` |

If a writable VARS file is not discovered, the script creates
`edk2-riscv-vars.fd` in the repository root.

---

## Real hardware / removable media

For UEFI hardware, build or stage the appropriate EFI binary and copy it to the
removable-media path for the target architecture:

| Architecture | Removable-media path |
|---|---|
| `x86_64` | `EFI/BOOT/BOOTX64.EFI` |
| `riscv64` | `EFI/BOOT/BOOTRISCV64.EFI` |
| `aarch64` | `EFI/BOOT/BOOTAA64.EFI` |

Prepare a USB drive:

```sh
# Replace /dev/sdX with your USB device — destructive.
sudo parted /dev/sdX mklabel gpt
sudo parted /dev/sdX mkpart ESP fat32 1MiB 100%
sudo parted /dev/sdX set 1 esp on
sudo mkfs.fat -F32 /dev/sdX1
```

Copy the staged ESP contents:

```sh
sudo mount /dev/sdX1 /mnt
sudo mkdir -p /mnt/EFI/BOOT
sudo cp -r esp/EFI /mnt/
sudo umount /mnt
```

If you used `cargo xtask image`, you can instead write the generated image to a
device with `dd`; verify the target device carefully before doing so.

---

## BootInfo memory contract

After firmware handoff, `BootInfo` describes the immutable boot-time facts used
by the common kernel:

| Field | Meaning |
|---|---|
| `rsdp_phys` | Physical RSDP address when provided by UEFI/ACPI firmware. |
| `efi_memory_map` | EFI memory-map pointer, byte size, and descriptor size. |
| `framebuffer` | Optional GOP/framebuffer metadata. |
| `initramfs` | Optional initramfs physical range. |
| `cmdline` | Optional command-line physical range. |
| `fdt` | Optional flattened device tree physical range. |
| `boot_hart_id` | Boot hart ID for RISC-V/SBI-style entry paths. |

The common kernel entry logs `BootInfo::priority()` before architecture-specific
initialization so boot logs identify `PRIMARY` x86_64, `SECONDARY` AArch64, or
`TERTIARY` RISC-V early in the serial output.

---

## Cargo features

The root crate declares these feature flags:

| Feature | Description |
|---|---|
| `input_events` | Evdev / virtio-input subsystem; enabled by default. |
| `gdbstub` | GDB Remote Serial Protocol stub; enabled by default. |
| `uefi_boot` | Build as a UEFI loader/application where applicable. |
| `debug` | Convenience bundle for `debug_stub` and `trace`. |
| `debug_stub` | GDB RSP stub only. |
| `trace` | Ring-buffer trace support flushed on panic. |
| `kmtest` | In-kernel test harness registration and dependency. |

Example feature-specific build:

```sh
cargo build --target targets/x86_64-kernel.json \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  -Z json-target-spec \
  --no-default-features --features kmtest
```

---

## GDB debugging

QEMU debugging is the easiest supported path:

```sh
ARCH=x86_64 ./scripts/ci/qemu-run.sh --gdb
ARCH=riscv64 ./scripts/ci/qemu-run.sh --boot sbi --gdb
ARCH=aarch64 ./scripts/ci/qemu-run.sh --gdb
```

The launcher prints the matching `gdb` or `gdb-multiarch` command with the
symbol file and `target remote :1234` line for the selected architecture.

For real hardware, build with `gdbstub`/`debug_stub` as appropriate, connect the
serial adapter used by the target platform, and load the matching kernel symbols
from the target profile directory.
