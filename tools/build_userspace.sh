#!/usr/bin/env bash
# tools/build_userspace.sh
# One-shot: build all userspace binaries and pack them into initramfs.cpio.
#
# Usage:
#   ./tools/build_userspace.sh            # x86_64 (default)
#   ./tools/build_userspace.sh riscv64    # RISC-V
#
# Output:
#   userspace/build/<arch>/init
#   userspace/build/<arch>/hello
#   initramfs.cpio   (CPIO newc archive — pass to QEMU as -initrd)

set -euo pipefail

ARCH=${1:-x86_64}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
USERSPACE="$REPO_ROOT/userspace"

echo "[build_userspace] Building userspace for ARCH=$ARCH"
cd "$USERSPACE"
make ARCH="$ARCH"

echo "[build_userspace] Packing initramfs for ARCH=$ARCH"
bash "$SCRIPT_DIR/build_initramfs.sh" "$ARCH"

echo "[build_userspace] Done. Output: $REPO_ROOT/initramfs.cpio"
