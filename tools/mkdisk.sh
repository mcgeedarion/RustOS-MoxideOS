#!/usr/bin/env bash
# tools/mkdisk.sh — create a blank ext2 disk image for rustos.
#
# Usage:
#   ./tools/mkdisk.sh [size_mb] [output]
#
#   size_mb   Disk size in MiB (default: 128)
#   output    Output image path  (default: disk.img)

set -euo pipefail

SIZE=${1:-128}
OUT=${2:-disk.img}

# Validate size is a positive integer
if ! [[ "$SIZE" =~ ^[0-9]+$ ]] || (( SIZE <= 0 )); then
    echo "[mkdisk] Error: size_mb must be a positive integer, got '$SIZE'" >&2
    exit 1
fi

# Check if output file already exists
if [[ -e "$OUT" ]]; then
    echo "[mkdisk] Error: output file already exists: '$OUT'" >&2
    exit 1
fi

echo "[mkdisk] Creating ${SIZE} MiB ext2 image: $OUT"
dd if=/dev/zero of="$OUT" bs=1M count="$SIZE" status=none
mkfs.ext2 -b 4096 -L rustos "$OUT" 2>&1 | grep -v "^mke2fs" || true
echo "[mkdisk] Done: $OUT (${SIZE} MiB ext2)"