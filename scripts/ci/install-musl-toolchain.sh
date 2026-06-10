#!/usr/bin/env bash
# scripts/ci/install-musl-toolchain.sh
#
# Ensures a static musl cross-compile toolchain is available for the given
# ARCH.  If the cross-compiler is already on PATH nothing is done.  Otherwise
# it tries (in order):
#
#   1. apt install  (Debian/Ubuntu CI runners)
#   2. Build musl from source into PREFIX (default: /opt/musl/<arch>)
#
# Supported ARCH values: aarch64  riscv64  x86_64
#
# Environment variables (all optional):
#   ARCH          Target arch (default: aarch64)
#   PREFIX        Install prefix for from-source builds
#                 (default: /opt/musl/<arch>)
#   MUSL_VERSION  musl-libc version to fetch (default: 1.2.5)
#   GCC_VERSION   GCC version to pair with musl  (default: 13.2.0)
#   JOBS          Parallel build jobs            (default: nproc)
#
# Exit codes:
#   0  toolchain is ready on PATH
#   1  install failed

set -euo pipefail

ARCH="${ARCH:-aarch64}"
MUSL_VERSION="${MUSL_VERSION:-1.2.5}"
GCC_VERSION="${GCC_VERSION:-13.2.0}"
JOBS="${JOBS:-$(nproc)}"

# Derive toolchain triplet and apt package name per arch.
case "$ARCH" in
  aarch64)
    TRIPLET="aarch64-linux-musl"
    CC_BIN="aarch64-linux-musl-gcc"
    APT_PKG="gcc-aarch64-linux-gnu"
    ;;
  riscv64)
    TRIPLET="riscv64-linux-musl"
    CC_BIN="riscv64-linux-musl-gcc"
    APT_PKG="gcc-riscv64-linux-gnu"
    ;;
  x86_64)
    TRIPLET="x86_64-linux-musl"
    CC_BIN="musl-gcc"
    APT_PKG="musl-tools"
    ;;
  *)
    echo "[!] Unsupported ARCH='${ARCH}'" >&2
    exit 1
    ;;
esac

PREFIX="${PREFIX:-/opt/musl/${ARCH}}"

# ── Already present? ─────────────────────────────────────────────────────────

if command -v "$CC_BIN" >/dev/null 2>&1; then
  echo "[toolchain] ${CC_BIN} already on PATH — nothing to do."
  exit 0
fi

# Also check the install prefix from a previous run.
if [[ -x "${PREFIX}/bin/${CC_BIN}" ]]; then
  echo "[toolchain] Found ${PREFIX}/bin/${CC_BIN} — adding to PATH."
  export PATH="${PREFIX}/bin:${PATH}"
  exit 0
fi

echo "[toolchain] ${CC_BIN} not found — attempting install for ARCH=${ARCH}."

# ── Strategy 1: apt ──────────────────────────────────────────────────────────

if command -v apt-get >/dev/null 2>&1; then
  echo "[toolchain] Trying apt-get install ${APT_PKG} ..."
  if sudo apt-get install -y --no-install-recommends "${APT_PKG}" 2>/dev/null; then
    # For aarch64/riscv64 the apt package gives us a glibc cross-compiler, not
    # a musl one.  We still need to build musl itself; the cross-gcc is enough
    # to bootstrap it.
    if [[ "$ARCH" == "x86_64" ]]; then
      echo "[toolchain] apt install OK: $(${CC_BIN} --version | head -1)"
      exit 0
    fi
    echo "[toolchain] apt gave us a glibc cross-gcc; building musl on top of it."
    BOOTSTRAP_GCC="${TRIPLET}-gcc"
  else
    echo "[toolchain] apt install failed or unavailable; falling back to from-source build."
    BOOTSTRAP_GCC=""
  fi
fi

# ── Strategy 2: build musl from source ──────────────────────────────────────
#
# We build a minimal musl-cross-make toolchain:
#   musl-cross-make: https://github.com/richfelker/musl-cross-make
# This produces a fully static aarch64-linux-musl-gcc.

echo "[toolchain] Building musl cross-toolchain for ${TRIPLET} (this takes a while)..."

BUILD_TMP="$(mktemp -d /tmp/musl-cross-make.XXXXXX)"
trap 'rm -rf "$BUILD_TMP"' EXIT

# Download musl-cross-make.
MCM_URL="https://github.com/richfelker/musl-cross-make/archive/refs/heads/master.tar.gz"
echo "[toolchain] Fetching musl-cross-make..."
curl -fsSL "$MCM_URL" | tar -xz -C "$BUILD_TMP" --strip-components=1

# Write config.mak for the target arch.
cat > "${BUILD_TMP}/config.mak" <<CONFIG
TARGET = ${TRIPLET}
OUTPUT = ${PREFIX}
MUSL_VER = ${MUSL_VERSION}
GCC_VER  = ${GCC_VERSION}

# Minimal build: no C++ or Fortran.
GCC_CONFIG += --disable-libstdc++-v3 --disable-libgomp --disable-libquadmath
GCC_CONFIG += --disable-libsanitizer --disable-libmpx

# Static host toolchain so the resulting gcc has no host-lib deps.
COMMON_CONFIG += --disable-nls --enable-languages=c
COMMON_CONFIG += CFLAGS="-O2 -pipe" CXXFLAGS="-O2 -pipe"
CONFIG

echo "[toolchain] Running make -j${JOBS} install ..."
sudo mkdir -p "$PREFIX"
make -C "$BUILD_TMP" -j"${JOBS}" install

# Add to PATH for the rest of this shell session.
export PATH="${PREFIX}/bin:${PATH}"

# Verify.
if command -v "$CC_BIN" >/dev/null 2>&1; then
  echo "[toolchain] Build OK: $(${CC_BIN} --version | head -1)"
else
  echo "[!] Build completed but ${CC_BIN} not found on PATH." >&2
  echo "    Add ${PREFIX}/bin to your PATH and retry." >&2
  exit 1
fi
