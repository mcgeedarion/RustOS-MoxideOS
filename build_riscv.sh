#!/usr/bin/env bash
# build_riscv.sh — Build rustos for RISC-V (riscv64gc-unknown-none-elf).
#
# Mirrors build_x86.sh for the RISC-V target.  Produces a release ELF kernel
# at target/riscv64gc-unknown-none-elf/release/rustos that can be passed
# directly to QEMU with -kernel (no objcopy stripping needed — QEMU loads
# the ELF natively via OpenSBI).
#
# Usage:
#   ./build_riscv.sh                 # release build (default)
#   ./build_riscv.sh --debug         # debug build
#   ./build_riscv.sh --initrd        # also build + pack initramfs.cpio
#
# Prerequisites:
#   rustup target add riscv64gc-unknown-none-elf
#   rustup component add rust-src
#   clang (for CRT cross-compilation via cc crate)
#   # Optional, for --initrd:
#   riscv64-linux-musl-gcc  (or musl-cross from https://musl.cc/)
#
# Output files:
#   target/riscv64gc-unknown-none-elf/release/rustos   (release ELF)
#   target/riscv64gc-unknown-none-elf/debug/rustos      (debug ELF, --debug)
#   initramfs.cpio                                      (--initrd only)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="riscv64gc-unknown-none-elf"
PROFILE="release"
BUILD_INITRD=0

for arg in "$@"; do
  case "$arg" in
    --debug)  PROFILE="debug" ;;
    --initrd) BUILD_INITRD=1 ;;
    *) echo "Unknown argument: $arg" >&2; exit 1 ;;
  esac
done

# ── Kernel build ────────────────────────────────────────────────────────────

echo "[build_riscv] Building rustos (RISC-V, $PROFILE)..."

CARGO_ARGS=(
  build
  --target "$TARGET"
  -Z build-std=core,alloc,compiler_builtins
  -Z build-std-features=compiler-builtins-mem
)

if [[ "$PROFILE" == "release" ]]; then
  CARGO_ARGS+=(--release)
fi

cargo "${CARGO_ARGS[@]}" 2>&1

KERNEL_ELF="$SCRIPT_DIR/target/$TARGET/$PROFILE/rustos"

echo
echo "[build_riscv] Built: $KERNEL_ELF"

# Print size breakdown (rust-size / llvm-size if available).
if command -v llvm-size &>/dev/null; then
  echo
  echo "[build_riscv] Size breakdown:"
  llvm-size "$KERNEL_ELF"
elif command -v size &>/dev/null; then
  echo
  echo "[build_riscv] Size breakdown:"
  size "$KERNEL_ELF"
fi

# ── Optional: build userspace + initramfs ───────────────────────────────────

if [[ $BUILD_INITRD -eq 1 ]]; then
  echo
  echo "[build_riscv] Building RISC-V userspace and initramfs..."
  bash "$SCRIPT_DIR/tools/build_userspace.sh" riscv64
  echo "[build_riscv] Initramfs: $SCRIPT_DIR/initramfs.cpio"
fi

# ── Summary ─────────────────────────────────────────────────────────────────

echo
echo "[build_riscv] Done."
echo
echo "  Kernel ELF : $KERNEL_ELF"
if [[ $BUILD_INITRD -eq 1 ]]; then
echo "  Initramfs  : $SCRIPT_DIR/initramfs.cpio"
fi
echo
echo "  Run with QEMU:"
if [[ $BUILD_INITRD -eq 1 ]]; then
echo "    qemu-system-riscv64 -machine virt -cpu rv64 -m 256M -bios default \\"
echo "      -kernel $KERNEL_ELF \\"
echo "      -initrd $SCRIPT_DIR/initramfs.cpio \\"
echo "      -serial stdio -display none -no-reboot"
else
echo "    qemu-system-riscv64 -machine virt -cpu rv64 -m 256M -bios default \\"
echo "      -kernel $KERNEL_ELF \\"
echo "      -serial stdio -display none -no-reboot"
fi
echo
echo "  Or use the existing wrapper:"
echo "    ./run_qemu_riscv.sh"
