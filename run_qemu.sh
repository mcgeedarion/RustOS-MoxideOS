#!/usr/bin/env bash
# run_qemu.sh — Build rustos and launch it in QEMU.
#
# DEFAULT BOOT: bare-metal UEFI via OVMF + FAT ESP image.
#   The kernel is loaded as a PE32+ UEFI application (BOOTX64.EFI),
#   identical to how it boots on real x86_64 hardware.
#
# Usage:
#   ./run_qemu.sh                  # UEFI boot (default, OVMF)
#   ./run_qemu.sh --multiboot      # legacy GRUB2/multiboot2 boot (-kernel)
#   ./run_qemu.sh --release        # build with --release
#   ./run_qemu.sh --gpu            # add virtio-gpu-pci, open SDL/GTK window
#   ./run_qemu.sh --gdb            # halt at entry, wait for GDB on :1234
#   ./run_qemu.sh --no-net         # disable virtio-net entirely
#   ./run_qemu.sh disk.img         # attach a virtio-blk disk image
#   ./run_qemu.sh --gpu --gdb disk.img
#
# UEFI boot prerequisites:
#   - OVMF firmware:  apt install ovmf  |  brew install qemu  (bundled)
#   -  OVMF paths searched (in order):
#       /usr/share/ovmf/OVMF.fd
#       /usr/share/edk2/ovmf/OVMF.fd
#       /usr/share/qemu/OVMF.fd
#       /opt/homebrew/share/qemu/edk2-x86_64-code.fd  (macOS Homebrew)
#   - llvm-tools-preview:  rustup component add llvm-tools-preview
#     (needed by build.rs to produce target/esp/EFI/BOOT/BOOTX64.EFI)
#
# Real hardware (bare-metal) workflow:
#   1. Build:  cargo build --release
#   2. Format a USB drive with a FAT32 EFI System Partition (ESP).
#   3. Copy:   cp -r target/esp/EFI  <mounted-ESP>/
#   4. Boot the machine; select RustOS from the UEFI boot menu.
#   See docs/booting.md for details.
#
# Networking (default — user-mode NAT, no root required):
#   Guest IP (DHCP via QEMU SLIRP): 10.0.2.15/24, GW 10.0.2.2, DNS 10.0.2.3
#
# GDB workflow:
#   Terminal 1:  ./run_qemu.sh --gdb [disk.img]
#   Terminal 2:  gdb   (auto-connects via .gdbinit)

set -euo pipefail

GDB_MODE=0
GPU_MODE=0
NET_MODE=1
MULTIBOOT_MODE=0
RELEASE_MODE=0
DISK=""

for arg in "$@"; do
  case "$arg" in
    --gdb)        GDB_MODE=1 ;;
    --gpu)        GPU_MODE=1 ;;
    --no-net)     NET_MODE=0 ;;
    --multiboot)  MULTIBOOT_MODE=1 ;;
    --release)    RELEASE_MODE=1 ;;
    *)            DISK="$arg" ;;
  esac
done

# ─── Build ───────────────────────────────────────────────────────────────────

if [[ $MULTIBOOT_MODE -eq 1 ]]; then
  echo "[*] Building rustos (multiboot2, $([ $RELEASE_MODE -eq 1 ] && echo release || echo debug))..."
  CARGO_FLAGS=(--target x86_64-unknown-none
    -Z build-std=core,alloc,compiler_builtins
    -Z build-std-features=compiler-builtins-mem
    --no-default-features
    --features multiboot2_boot,sysv_ipc,namespaces)
  [[ $RELEASE_MODE -eq 1 ]] && CARGO_FLAGS+=(--release)
  cargo build "${CARGO_FLAGS[@]}"
  PROFILE=$([ $RELEASE_MODE -eq 1 ] && echo release || echo debug)
  KERNEL="target/x86_64-unknown-none/${PROFILE}/rustos"
else
  echo "[*] Building rustos (UEFI, $([ $RELEASE_MODE -eq 1 ] && echo release || echo debug))..."
  CARGO_FLAGS=(--target x86_64-unknown-none
    -Z build-std=core,alloc,compiler_builtins
    -Z build-std-features=compiler-builtins-mem)
  [[ $RELEASE_MODE -eq 1 ]] && CARGO_FLAGS+=(--release)
  cargo build "${CARGO_FLAGS[@]}"
  # build.rs places the PE image here:
  EFI_IMAGE="target/esp/EFI/BOOT/BOOTX64.EFI"
  if [[ ! -f "$EFI_IMAGE" ]]; then
    echo "[!] $EFI_IMAGE not found. Re-running cargo build to trigger objcopy..."
    cargo build "${CARGO_FLAGS[@]}"
  fi
fi

# ─── Locate OVMF (UEFI firmware) ─────────────────────────────────────────────

if [[ $MULTIBOOT_MODE -eq 0 ]]; then
  OVMF_CANDIDATES=(
    "/usr/share/ovmf/OVMF.fd"
    "/usr/share/edk2/ovmf/OVMF.fd"
    "/usr/share/qemu/OVMF.fd"
    "/opt/homebrew/share/qemu/edk2-x86_64-code.fd"
    "/usr/share/edk2-ovmf/x64/OVMF.fd"
  )
  OVMF=""
  for candidate in "${OVMF_CANDIDATES[@]}"; do
    if [[ -f "$candidate" ]]; then
      OVMF="$candidate"
      break
    fi
  done
  if [[ -z "$OVMF" ]]; then
    echo "[!] OVMF firmware not found. Install with:"
    echo "      Debian/Ubuntu: sudo apt install ovmf"
    echo "      Arch:          sudo pacman -S edk2-ovmf"
    echo "      macOS:         brew install qemu  (bundles OVMF)"
    echo "    Or set OVMF=/path/to/OVMF.fd and re-run."
    exit 1
  fi
  echo "[*] OVMF firmware: $OVMF"

  # Build a temporary FAT ESP disk image for QEMU.
  # QEMU's vvfat pseudo-driver mounts a host directory as a FAT volume
  # directly — no mkdosfs or loop device needed.
  ESP_DIR="target/esp"
  echo "[*] ESP directory: $ESP_DIR  (EFI/BOOT/BOOTX64.EFI)"
fi

# ─── QEMU args ────────────────────────────────────────────────────────────

QEMU_ARGS=(
  -machine q35
  -cpu qemu64,+xsave,+avx
  -m 256M
  -serial stdio
  -no-reboot
  -d guest_errors,cpu_reset
)

if [[ $MULTIBOOT_MODE -eq 1 ]]; then
  # Legacy: QEMU Linux boot protocol / multiboot2 — no UEFI involved.
  echo "[*] Boot mode: multiboot2 (-kernel)"
  QEMU_ARGS+=(-kernel "$KERNEL")
else
  # Primary: UEFI via OVMF + vvfat ESP.
  echo "[*] Boot mode: UEFI (OVMF + BOOTX64.EFI)"
  QEMU_ARGS+=(
    # OVMF flash drives: code (read-only) + vars (writable, in-memory copy).
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF}"
    # ESP as a vvfat FAT volume — OVMF will find EFI/BOOT/BOOTX64.EFI.
    -drive "if=virtio,format=raw,file=fat:rw:${ESP_DIR},label=ESP"
  )
fi

if [[ $NET_MODE -eq 1 ]]; then
  echo "[*] Network: virtio-net-pci (user-mode NAT, guest 10.0.2.15/24)"
  QEMU_ARGS+=(
    -netdev "user,id=net0,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15"
    -device "virtio-net-pci,netdev=net0,id=nic0"
  )
else
  echo "[*] Network: disabled (--no-net)"
fi

if [[ $GPU_MODE -eq 1 ]]; then
  echo "[*] GPU mode: adding virtio-gpu-pci + SDL display"
  QEMU_ARGS+=(
    -device virtio-gpu-pci
    -display sdl,gl=off
  )
else
  QEMU_ARGS+=(-display none)
fi

if [[ -n "$DISK" ]]; then
  echo "[*] Attaching disk: $DISK"
  QEMU_ARGS+=(
    -drive "id=vblk0,file=${DISK},format=raw,if=none"
    -device "virtio-blk-pci,drive=vblk0,id=virtblk0"
  )
else
  echo "[*] No disk image — ramfs only"
fi

if [[ $GDB_MODE -eq 1 ]]; then
  QEMU_ARGS+=(
    -s
    -S
  )
  echo
  echo "  ┌─────────────────────────────────────────────┐"
  echo "  │ GDB mode: kernel halted at entry point.       │"
  echo "  │ In another terminal, run:                     │"
  echo "  │   gdb                                         │"
  echo "  │ (.gdbinit auto-connects and loads symbols)    │"
  echo "  └─────────────────────────────────────────────┘"
  echo
fi

echo "[*] Starting QEMU..."
echo
exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
