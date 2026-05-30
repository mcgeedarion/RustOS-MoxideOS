#!/usr/bin/env bash
# build_aarch64.sh — Build rustos for AArch64 (UEFI only).
#
# Usage:
#   ./build_aarch64.sh [--debug] [--features <feat>] [--initrd]
#
# This is a thin wrapper around `cargo xtask build --arch aarch64`.
# The EFI binary is installed to esp/EFI/BOOT/BOOTAA64.EFI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

DEBUG_FLAG=""
FEATURES=""
INITRD_FLAG=""

for arg in "$@"; do
  case "$arg" in
    --debug)       DEBUG_FLAG="--debug" ;;
    --initrd)      INITRD_FLAG="--initrd" ;;
    --features=*)  FEATURES="${arg#--features=}" ;;
    --features)    ;; # handled positionally below
    *)             ;;
  esac
done

# Two-token --features <val> handling.
ARGS=("$@")
for ((i=0; i<${#ARGS[@]}; i++)); do
  if [[ "${ARGS[$i]}" == "--features" && $((i+1)) -lt ${#ARGS[@]} ]]; then
    FEATURES="${ARGS[$((i+1))]}"
  fi
done

XTASK_ARGS=(build --arch aarch64 --boot uefi)
[[ -n "$DEBUG_FLAG" ]]  && XTASK_ARGS+=(--debug)
[[ -n "$INITRD_FLAG" ]] && XTASK_ARGS+=(--initrd)
[[ -n "$FEATURES" ]]    && XTASK_ARGS+=(--features "$FEATURES")

exec cargo xtask "${XTASK_ARGS[@]}"
