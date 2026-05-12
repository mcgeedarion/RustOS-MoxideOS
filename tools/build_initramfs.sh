#!/usr/bin/env bash
# tools/build_initramfs.sh — pack userspace and test binaries into a CPIO initramfs.
#
# The resulting initramfs.cpio is passed directly to QEMU:
#   -initrd initramfs.cpio
#
# The kernel reads the CPIO archive from memory and extracts it into a
# ramfs before exec'ing /init.
#
# Usage:
#   ./tools/build_initramfs.sh [arch]    # arch defaults to x86_64
#
# Environment:
#   MUSL_GCC   musl-gcc binary to use when building tests (default: musl-gcc)

set -euo pipefail

ARCH=${1:-x86_64}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$REPO_ROOT/userspace/build/$ARCH"
TEST_BIN_DIR="$REPO_ROOT/build_tests"
OUTPUT="$REPO_ROOT/initramfs.cpio"

if [ ! -d "$BIN_DIR" ]; then
    echo "[build_initramfs] ERROR: $BIN_DIR not found. Run build_userspace.sh first."
    exit 1
fi

echo "[build_initramfs] Creating initramfs from $BIN_DIR"

# ── Staging directory ────────────────────────────────────────────────────────

STAGING=$(mktemp -d)
trap 'rm -rf "$STAGING"' EXIT

mkdir -p "$STAGING"/{bin,dev,proc,sys,tmp}

# ── Userspace binaries ───────────────────────────────────────────────────────

cp "$BIN_DIR/init"  "$STAGING/init"
cp "$BIN_DIR/hello" "$STAGING/bin/hello"
chmod 755 "$STAGING/init" "$STAGING/bin/hello"

strip "$STAGING/init"       2>/dev/null || true
strip "$STAGING/bin/hello"  2>/dev/null || true

# ── Test binaries (optional) ─────────────────────────────────────────────────
#
# If build_tests/ exists (produced by tests/run_tests.sh) copy every binary
# into /bin/ so they can be exec'd directly inside the kernel under QEMU.
# Also copy tests/run_tests.sh as /bin/run_tests so the full suite can be
# driven from a serial console or an automated expect script.

if [ -d "$TEST_BIN_DIR" ]; then
    echo "[build_initramfs] Staging test binaries from $TEST_BIN_DIR"
    for bin in "$TEST_BIN_DIR"/*; do
        [ -f "$bin" ] && [ -x "$bin" ] || continue
        name="$(basename "$bin")"
        cp "$bin" "$STAGING/bin/$name"
        strip "$STAGING/bin/$name" 2>/dev/null || true
    done
    if [ -f "$REPO_ROOT/tests/run_tests.sh" ]; then
        cp "$REPO_ROOT/tests/run_tests.sh" "$STAGING/bin/run_tests"
        chmod 755 "$STAGING/bin/run_tests"
    fi
else
    echo "[build_initramfs] NOTE: $TEST_BIN_DIR not found — skipping test binaries."
    echo "[build_initramfs]       Run tests/run_tests.sh first to include them."
fi

# ── Pack CPIO archive ────────────────────────────────────────────────────────

(
    cd "$STAGING"
    find . | cpio --create --format=newc --quiet
) > "$OUTPUT"

echo "[build_initramfs] Written: $OUTPUT ($(du -sh "$OUTPUT" | cut -f1))"
echo "[build_initramfs] QEMU flag: -initrd $OUTPUT"
