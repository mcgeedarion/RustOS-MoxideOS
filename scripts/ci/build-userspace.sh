#!/usr/bin/env bash
# scripts/ci/build-userspace.sh
#
# Builds all userspace binaries for the given ARCH, ensuring the musl
# cross-compiler is installed first.
#
# Usage:
#   ARCH=aarch64 ./scripts/ci/build-userspace.sh
#
# Environment variables:
#   ARCH          x86_64 | riscv64 | aarch64  (default: x86_64)
#   TARGET        Optional single Makefile target (default: all)
#   SKIP_TOOLCHAIN_CHECK
#                 Set to 1 to skip install-musl-toolchain.sh (toolchain
#                 already guaranteed on PATH, e.g. inside a Docker image).

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCH="${ARCH:-x86_64}"
TARGET="${1:-all}"

# ── 1. Ensure toolchain ───────────────────────────────────────────────────────

if [[ "${SKIP_TOOLCHAIN_CHECK:-0}" != "1" ]]; then
  ARCH="$ARCH" bash "${ROOT_DIR}/scripts/ci/install-musl-toolchain.sh"
fi

# install-musl-toolchain.sh may have extended PATH; re-export it so make sees it.
export PATH

# ── 2. Build ──────────────────────────────────────────────────────────────────

echo "[userspace] Building ARCH=${ARCH} target=${TARGET}..."
make -C "${ROOT_DIR}/userspace" ARCH="${ARCH}" "${TARGET}"
echo "[userspace] Done. Outputs in ${ROOT_DIR}/userspace/build/${ARCH}/"
