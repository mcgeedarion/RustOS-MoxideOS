#!/usr/bin/env bash
# tools/build_initramfs.sh
# Packs userspace/build/<arch>/ binaries into a CPIO newc initramfs.
#
# The resulting initramfs.cpio can be passed directly to QEMU:
#   -initrd initramfs.cpio
#
# The kernel reads the CPIO archive from memory (the address is passed via
# the boot protocol / multiboot2 module tag or UEFI config table) and
# extracts binaries into a ramfs before exec'ing /init.
#
# Usage:
#   ./tools/build_initramfs.sh [arch]    # arch defaults to x86_64

set -euo pipefail

ARCH=${1:-x86_64}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$REPO_ROOT/userspace/build/$ARCH"
OUTPUT="$REPO_ROOT/initramfs.cpio"

if [ ! -d "$BIN_DIR" ]; then
  echo "[build_initramfs] ERROR: $BIN_DIR does not exist. Run build_userspace.sh first."
  exit 1
fi

echo "[build_initramfs] Creating initramfs from $BIN_DIR"

# Build a staging directory with the expected filesystem layout.
STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

mkdir -p "$STAGING"/{bin,dev,proc,sys,tmp}

# Copy binaries.
cp "$BIN_DIR/init"  "$STAGING/init"
cp "$BIN_DIR/hello" "$STAGING/bin/hello"
chmod 755 "$STAGING/init" "$STAGING/bin/hello"

# Strip debug info to shrink the image (ignore errors if strip unavailable).
strip "$STAGING/init"  2>/dev/null || true
strip "$STAGING/bin/hello" 2>/dev/null || true

# Create the CPIO archive (newc format, no compression — kernel decompresses
# if needed; for now keep it plain for simplicity).
(
  cd "$STAGING"
  find . | cpio --create --format=newc --quiet
) > "$OUTPUT"

echo "[build_initramfs] Written: $OUTPUT ($(du -sh "$OUTPUT" | cut -f1))"
echo "[build_initramfs] QEMU flag: -initrd $OUTPUT"
