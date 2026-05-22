#!/usr/bin/env bash
# tests/run_smoke.sh
#
# Minimal userspace smoke test used by QEMU smoke boots.
# Builds a tiny "smoke" binary that prints a fixed marker and exits 0.
# Intended to be installed as /bin/smoke in the initramfs.
#
# Host usage (sanity check without QEMU):
#   ./tests/run_smoke.sh
#
# The QEMU-side wiring is done via:
#   - userspace/Makefile (installs /bin/smoke)
#   - init(8) or a small shell script that execs /bin/smoke during boot

set -euo pipefail

CC=${MUSL_GCC:-musl-gcc}
CFLAGS="-static -O1 -Wall -Wextra -Wno-unused-parameter"
BUILD_DIR="./build_smoke"
mkdir -p "$BUILD_DIR"

SRC="tests/smoke_userspace.c"
BIN="$BUILD_DIR/smoke_userspace"

printf 'Building %-30s ... ' "smoke_userspace"
if ! $CC $CFLAGS -o "$BIN" "$SRC" 2>"$BUILD_DIR/smoke_userspace.log"; then
    echo 'BUILD FAIL'
    sed 's/^/    /' "$BUILD_DIR/smoke_userspace.log"
    exit 1
fi
echo 'ok'

printf 'Running  %-30s ... ' "smoke_userspace"
output="$($BIN 2>/dev/null)"
exit_code=$?

if echo "$output" | grep -q 'SMOKE OK'; then
    echo "PASS"
    exit 0
fi

echo "FAIL (exit=$exit_code)"
"$BIN" 2>&1 || true
exit 1
