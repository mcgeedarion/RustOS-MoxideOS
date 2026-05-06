#!/usr/bin/env bash
# build_riscv.sh — Build rustos for RISC-V.
#
# Supports two boot modes:
#   SBI  (default) — OpenSBI/QEMU -kernel, target riscv64gc-unknown-none-elf
#   UEFI (--uefi)  — EDK2 RiscVVirt, target riscv64-uefi.json, output .efi
#
# Usage:
#   ./build_riscv.sh                 # SBI release build (default)
#   ./build_riscv.sh --debug         # SBI debug build
#   ./build_riscv.sh --uefi          # UEFI release build
#   ./build_riscv.sh --uefi --debug  # UEFI debug build
#   ./build_riscv.sh --initrd        # also build + pack initramfs.cpio (SBI only)
#
# Prerequisites:
#   rustup target add riscv64gc-unknown-none-elf
#   rustup component add rust-src
#   clang / rust-lld
#   # For --uefi:
#   lld (rust-lld is sufficient; invoked automatically via riscv64-uefi.json)
#
# Output files (SBI):
#   target/riscv64gc-unknown-none-elf/{release,debug}/rustos   (ELF)
#
# Output files (UEFI):
#   target/riscv64-uefi/{release,debug}/rustos.efi             (PE/COFF EFI app)
#   esp/EFI/BOOT/BOOTRISCV64.EFI                               (ESP layout)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="release"
BOOT="sbi"
BUILD_INITRD=0

for arg in "$@"; do
  case "$arg" in
    --debug)  PROFILE="debug" ;;
    --uefi)   BOOT="uefi" ;;
    --initrd) BUILD_INITRD=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# ── SBI build (existing path) ────────────────────────────────────────────────

if [[ "$BOOT" == "sbi" ]]; then
  echo "[build_riscv] Building rustos (RISC-V SBI, $PROFILE)..."

  CARGO_ARGS=(
    build
    --target riscv64gc-unknown-none-elf
    -Z build-std=core,alloc,compiler_builtins
    -Z build-std-features=compiler-builtins-mem
  )
  [[ "$PROFILE" == "release" ]] && CARGO_ARGS+=(--release)

  cargo "${CARGO_ARGS[@]}" 2>&1

  KERNEL_ELF="$SCRIPT_DIR/target/riscv64gc-unknown-none-elf/$PROFILE/rustos"
  echo
  echo "[build_riscv] Built: $KERNEL_ELF"

  if command -v llvm-size &>/dev/null; then
    echo; echo "[build_riscv] Size breakdown:"; llvm-size "$KERNEL_ELF"
  elif command -v size &>/dev/null; then
    echo; echo "[build_riscv] Size breakdown:"; size "$KERNEL_ELF"
  fi

  if [[ $BUILD_INITRD -eq 1 ]]; then
    echo
    echo "[build_riscv] Building RISC-V userspace and initramfs..."
    bash "$SCRIPT_DIR/tools/build_userspace.sh" riscv64
    echo "[build_riscv] Initramfs: $SCRIPT_DIR/initramfs.cpio"
  fi

  echo
  echo "[build_riscv] Done."
  echo
  echo "  Kernel ELF : $KERNEL_ELF"
  [[ $BUILD_INITRD -eq 1 ]] && echo "  Initramfs  : $SCRIPT_DIR/initramfs.cpio"
  echo
  echo "  Run with QEMU (SBI):"
  echo "    ./run_qemu_riscv.sh"
  exit 0
fi

# ── UEFI build ───────────────────────────────────────────────────────────────

echo "[build_riscv] Building rustos (RISC-V UEFI, $PROFILE)..."

TARGET_JSON="$SCRIPT_DIR/riscv64-uefi.json"

CARGO_ARGS=(
  build
  --target "$TARGET_JSON"
  --features uefi_boot
  -Z build-std=core,alloc,compiler_builtins
  -Z build-std-features=compiler-builtins-mem
)
[[ "$PROFILE" == "release" ]] && CARGO_ARGS+=(--release)

cargo "${CARGO_ARGS[@]}" 2>&1

# Cargo names the output after the crate, with a .efi extension when os=uefi.
KERNEL_EFI="$SCRIPT_DIR/target/riscv64-uefi/$PROFILE/rustos.efi"

if [[ ! -f "$KERNEL_EFI" ]]; then
  # Some toolchain versions drop the .efi suffix — try without.
  KERNEL_EFI_NOEXT="$SCRIPT_DIR/target/riscv64-uefi/$PROFILE/rustos"
  if [[ -f "$KERNEL_EFI_NOEXT" ]]; then
    KERNEL_EFI="$KERNEL_EFI_NOEXT"
  else
    echo "[build_riscv] ERROR: could not find EFI binary under target/riscv64-uefi/$PROFILE/" >&2
    exit 1
  fi
fi

echo
echo "[build_riscv] Built: $KERNEL_EFI"

# Install into a FAT ESP directory tree that QEMU can mount directly.
ESP="$SCRIPT_DIR/esp"
mkdir -p "$ESP/EFI/BOOT"
cp "$KERNEL_EFI" "$ESP/EFI/BOOT/BOOTRISCV64.EFI"
echo "[build_riscv] Installed: $ESP/EFI/BOOT/BOOTRISCV64.EFI"

echo
echo "[build_riscv] Done."
echo
echo "  EFI binary : $KERNEL_EFI"
echo "  ESP tree   : $ESP/EFI/BOOT/BOOTRISCV64.EFI"
echo
echo "  Run with QEMU (UEFI):"
echo "    ./run_qemu_riscv.sh --uefi"
echo
echo "  Note: requires EDK2 RISC-V firmware (edk2-riscv-code.fd)."
echo "  Install with:  sudo apt install qemu-efi-riscv64   # Debian/Ubuntu"
echo "               or brew install qemu                  # macOS"
