#!/bin/bash
# Create a blank ext2 disk image for rustos
set -e
SIZE=${1:-128}  # MB
OUT=${2:-disk.img}
dd if=/dev/zero of="$OUT" bs=1M count=$SIZE
mkfs.ext2 -b 4096 -L rustos "$OUT"
echo "Created $OUT ($SIZE MB ext2)"
