#!/usr/bin/env bash
# tools/mkdisk.sh — create a blank ext2 disk image for rustos.
#
# Usage:
#   ./tools/mkdisk.sh [size_mb] [output]
#
#   size_mb   Disk size in MiB (default: 128)
#   output    Output image path  (default: disk.img)
#
# The resulting image can be passed to QEMU:
#   -drive file=disk.img,if=virtio,format=raw

set -euo pipefail

SIZE=${1:-128}
OUT=${2:-disk.img}

echo "[mkdisk] Creating ${SIZE} MiB ext2 image: $OUT"
dd if=/dev/zero of="$OUT" bs=1M count="$SIZE" status=none
mkfs.ext2 -b 4096 -L rustos "$OUT" >/dev/null
echo "[mkdisk] Done: $OUT (${SIZE} MiB ext2)"
