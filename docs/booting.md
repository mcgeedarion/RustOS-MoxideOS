# RustOS Boot Reference

## Overview

RustOS boots as a **UEFI application** on x86_64.  The build system produces
a PE32+ binary (`BOOTX64.EFI`) that UEFI firmware loads directly — no
bootloader (GRUB, syslinux) is required.  This is the same mechanism used by
Windows, modern Linux distributions with systemd-boot, and most embedded
UEFI OSes.

A legacy multiboot2 path (for GRUB2 or QEMU `-kernel`) is available behind
`--features multiboot2_boot` but is not the primary target.

---

## Build

```bash
# Requires:
#   rustup component add llvm-tools-preview
#   rustup target add x86_64-unknown-none

# Debug build (default = UEFI)
cargo build --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem

# Release build
cargo build --release --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem
```

`build.rs` invokes `llvm-objcopy --target=efi-app-x86_64` to convert the ELF
kernel into a PE32+ UEFI application.  The output is placed at:

```
target/
  esp/
    EFI/
      BOOT/
        BOOTX64.EFI    ← UEFI application image
```

`target/esp/` is the root of a valid EFI System Partition (ESP) directory
tree.  UEFI firmware will find `EFI/BOOT/BOOTX64.EFI` as the removable-media
default boot entry.

---

## QEMU (OVMF)

```bash
# Default — UEFI via OVMF:
./run_qemu.sh

# With a virtio-blk disk image:
./run_qemu.sh disk.img

# With GDB stub:
./run_qemu.sh --gdb

# Release build:
./run_qemu.sh --release

# Legacy multiboot2 (no OVMF needed):
./run_qemu.sh --multiboot

# Headless smoke test: wait up to 20 seconds for the early UART marker.
./run_qemu.sh --smoke --timeout 20

# Userspace smoke test: require PID 1 to print its pass marker.
./run_qemu.sh --smoke --smoke-marker '[init] TEST PASS: userspace_init' --timeout 30
```

`run_qemu.sh --smoke` disables networking and graphics, captures serial output,
and exits successfully only when the configured marker appears.  See
`docs/status.md` for the current vertical-slice checklist.

`run_qemu.sh` searches for OVMF in the following paths:

| Path | Distribution |
|---|---|
| `/usr/share/ovmf/OVMF.fd` | Debian / Ubuntu (`apt install ovmf`) |
| `/usr/share/edk2/ovmf/OVMF.fd` | Arch Linux (`pacman -S edk2-ovmf`) |
| `/usr/share/qemu/OVMF.fd` | Fedora / openSUSE |
| `/opt/homebrew/share/qemu/edk2-x86_64-code.fd` | macOS Homebrew |

The ESP is mounted via QEMU's `fat:rw:` vvfat pseudo-driver — no loop device
or mkdosfs is needed.

---

## Real Hardware (bare-metal)

### 1. Prepare a USB drive

```bash
# Replace /dev/sdX with your USB device — DESTRUCTIVE.
sudo parted /dev/sdX mklabel gpt
sudo parted /dev/sdX mkpart ESP fat32 1MiB 100%
sudo parted /dev/sdX set 1 esp on
sudo mkfs.fat -F32 /dev/sdX1
```

### 2. Copy the ESP

```bash
sudo mount /dev/sdX1 /mnt
sudo cp -r target/esp/EFI /mnt/
sudo umount /mnt
```

### 3. Boot

1. Insert the USB drive.
2. Enter UEFI firmware setup (F2 / Delete / F12 at POST).
3. Select **RustOS** (or `UEFI: <USB drive>`) from the boot menu.
4. Serial output is on COM1 (115200 8N1).  Connect a USB–serial adapter to
   the motherboard COM header to see kernel log output.

### Supported firmware

`uefi_entry.rs` includes explicit compatibility handling for:

- **AMI BIOS** (ASUS, Gigabyte, MSI) — ExitBootServices retry on
  `EFI_INVALID_PARAMETER` per UEFI spec §7.4.6.
- **Insyde H2O** (Lenovo, HP, Dell laptops) — same retry path.
- **Standard UEFI 2.x** — single-call fast path.

---

## Memory Layout (after ExitBootServices)

| Region | Description |
|---|---|
| `0x0000 – 0x00FF` | BIOS data area (untouched) |
| `0x1000 – 0x9FFF` | AP trampoline (SMP) |
| `0x400000+` | Kernel image (`.text`, `.rodata`, `.data`, `.bss`) |
| EFI pool alloc | EFI memory map (pointer in `EFI_MAP_PTR`) |
| GOP base | Framebuffer physical address (`drivers::gop::GOP_INFO`) |
| Above kernel | PMM-managed free RAM |

All physical RAM is identity-mapped by the UEFI page tables at
`ExitBootServices` time.  The kernel's static PMM pool is immediately usable;
`memmap_init()` promotes the EFI memory map into the full PMM on boot.

---

## Feature Flags

| Feature | Description |
|---|---|
| `uefi_boot` (default) | UEFI bare-metal boot via `uefi_start()` |
| `multiboot2_boot` | Legacy GRUB2/QEMU `-kernel` boot |
| `gdbstub` | GDB RSP stub on COM1 (x86_64) or SBI console (RISC-V) |
| `cgroups` | cgroups v2 hierarchy + cgroupfs VFS |
| `sysv_ipc` | System V IPC + POSIX message queues |
| `namespaces` | Linux-compatible namespace isolation |

To build with multiboot2 instead of UEFI:

```bash
cargo build --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  --no-default-features \
  --features multiboot2_boot,sysv_ipc,namespaces
```

---

## GDB Debugging on Real Hardware

1. Build with `--features gdbstub`.
2. Connect a USB–serial adapter to COM1 (9600–115200 baud, 8N1).
3. On the host:
   ```
   gdb
   (gdb) target remote /dev/ttyUSB0
   (gdb) symbol-file target/x86_64-unknown-none/debug/rustos
   ```
4. The kernel will halt at `gdbstub::breakpoint()` calls or hardware
   exceptions and wait for GDB commands.
