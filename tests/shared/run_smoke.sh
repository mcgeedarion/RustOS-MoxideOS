#!/usr/bin/env bash
# tests/shared/run_smoke.sh
#
# Minimal userspace smoke binary build + host sanity check.
# Used by QEMU smoke boots (installed as /bin/smoke in the initramfs).
#
# Usage:
#   ARCH=<arch> ./tests/shared/run_smoke.sh
#   (defaults to x86_64 if ARCH is unset)

set -euo pipefail

ARCH="${ARCH:-x86_64}"

case "$ARCH" in
  aarch64) CC="${CC_AARCH64:-aarch64-linux-gnu-gcc}" ;;
  riscv64) CC="${CC_RISCV64:-riscv64-linux-gnu-gcc}" ;;
  x86_64)  CC="${MUSL_GCC:-musl-gcc}" ;;
  *)       echo "[!] Unsupported ARCH='${ARCH}'" >&2; exit 2 ;;
esac

CFLAGS="-static -O1 -Wall -Wextra -Wno-unused-parameter"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../../build_smoke/${ARCH}"
mkdir -p "$BUILD_DIR"

SRC="${SCRIPT_DIR}/smoke_userspace.c"
BIN="${BUILD_DIR}/smoke_userspace"

printf 'Building %-30s ... ' "smoke_userspace [${ARCH}]"
if ! $CC $CFLAGS -o "$BIN" "$SRC" 2>"${BUILD_DIR}/smoke_userspace.log"; then
    echo 'BUILD FAIL'
    sed 's/^/    /' "${BUILD_DIR}/smoke_userspace.log"
    exit 1
fi
echo 'ok'

# Skip host execution when cross-compiling.
if [[ "$ARCH" != "$(uname -m | sed 's/aarch64/aarch64/;s/x86_64/x86_64/;s/riscv64/riscv64/')" ]]; then
    echo "  (cross-build for ${ARCH} — skipping host execution)"
    exit 0
fi

printf 'Running  %-30s ... ' "smoke_userspace"
output="$("$BIN" 2>/dev/null)"
exit_code=$?

if echo "$output" | grep -q 'SMOKE OK'; then
    echo "PASS"
    exit 0
fi

echo "FAIL (exit=${exit_code})"
"$BIN" 2>&1 || true
exit 1
