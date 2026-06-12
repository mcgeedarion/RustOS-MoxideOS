#!/usr/bin/env bash
# scripts/ci/build.sh — Arch-aware kernel build for CI.
#
# Required env:
#   ARCH    aarch64 | riscv64 | x86_64
#
# Optional env:
#   RELEASE    1 => --release  (default: 0)
#   BOOT       uefi | sbi | baremetal  (default: uefi)
#   FEATURES   extra --features value appended verbatim
#
# Sets/exports on success:
#   KERNEL_ELF   path to the built kernel ELF
#   CARGO_TARGET Rust target triple / JSON path used
#   PROFILE      debug | release
#
# Exit codes:
#   0  success
#   1  build failed or ELF not found
#   2  bad arguments

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# ── Validate required inputs ────────────────────────────────────────────────

ARCH="${ARCH:-}"
[[ -z "$ARCH" ]] && { echo "[!] ARCH is required (aarch64|riscv64|x86_64)" >&2; exit 2; }

case "$ARCH" in
  aarch64|riscv64|x86_64) ;;
  *) echo "[!] Unsupported ARCH='${ARCH}'" >&2; exit 2 ;;
esac

RELEASE="${RELEASE:-0}"
BOOT="${BOOT:-uefi}"
FEATURES="${FEATURES:-}"

case "$ARCH:$BOOT" in
  aarch64:uefi|aarch64:baremetal|riscv64:uefi|riscv64:sbi|x86_64:uefi) ;;
  *) echo "[!] Unsupported build contract: ARCH=${ARCH} BOOT=${BOOT}" >&2; exit 2 ;;
esac

# ── Per-arch target + ELF path ──────────────────────────────────────────────

case "$ARCH:$BOOT" in
  aarch64:uefi)
    CARGO_TARGET="${ROOT_DIR}/targets/aarch64-uefi-loader.json"
    TARGET_DIR="aarch64-uefi-loader"
    ;;
  aarch64:baremetal)
    CARGO_TARGET="${ROOT_DIR}/targets/aarch64-kernel.json"
    TARGET_DIR="aarch64-kernel"
    ;;
  riscv64:uefi)
    CARGO_TARGET="${ROOT_DIR}/targets/riscv64-uefi-loader.json"
    TARGET_DIR="riscv64-uefi-loader"
    ;;
  riscv64:sbi)
    CARGO_TARGET="riscv64gc-unknown-none-elf"
    TARGET_DIR="riscv64gc-unknown-none-elf"
    ;;
  x86_64:uefi)
    CARGO_TARGET="${ROOT_DIR}/targets/x86_64-kernel.json"
    TARGET_DIR="x86_64-kernel"
    ;;
esac

PROFILE=$([ "$RELEASE" = 1 ] && echo release || echo debug)
KERNEL_ELF="target/${TARGET_DIR}/${PROFILE}/rustos"
EXTRA_FLAGS=()

# ── Append optional extra features ─────────────────────────────────────────

[[ -n "$FEATURES" ]] && EXTRA_FLAGS+=(--features "$FEATURES")

# ── Build ───────────────────────────────────────────────────────────────────

echo "[build] ARCH=${ARCH}  TARGET=${CARGO_TARGET}  PROFILE=${PROFILE}  BOOT=${BOOT}"

cargo build \
  --target "$CARGO_TARGET" \
  "${EXTRA_FLAGS[@]}" \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem \
  -Z target-spec-json \
  $([ "$RELEASE" = 1 ] && echo --release)

# ── Verify output ───────────────────────────────────────────────────────────

if [[ ! -f "$KERNEL_ELF" ]]; then
  echo "[!] ELF not found: ${KERNEL_ELF}" >&2
  exit 1
fi

export KERNEL_ELF CARGO_TARGET PROFILE
echo "[build] OK  ${KERNEL_ELF}  ($(du -sh "$KERNEL_ELF" | cut -f1))"
