#!/usr/bin/env bash
# build_aarch64.sh — Build rustos for AArch64 (UEFI only).
#
# This is a thin wrapper around `cargo xtask build --arch aarch64`.
# The EFI binary is installed to esp/EFI/BOOT/BOOTAA64.EFI.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Show help message
show_help() {
  cat << 'EOF'
Usage: ./build_aarch64.sh [OPTIONS]

Build RustOS for AArch64 (UEFI only).

Options:
  --debug       Build in debug mode
  --initrd      Include initrd in build
  --features    Specify cargo features
  --help, -h    Show this help message

Examples:
  ./build_aarch64.sh
  ./build_aarch64.sh --debug
  ./build_aarch64.sh --features "smp,acpi"
  ./build_aarch64.sh --debug --initrd
EOF
}

# Check dependencies
if ! command -v cargo &> /dev/null; then
  echo "Error: cargo not found. Please install Rust." >&2
  exit 1
fi

# Parse arguments
DEBUG_FLAG=""
FEATURES=""
INITRD_FLAG=""

for arg in "$@"; do
  case "$arg" in
    --debug)       DEBUG_FLAG="--debug" ;;
    --initrd)      INITRD_FLAG="--initrd" ;;
    --features=*)  FEATURES="${arg#--features=}" ;;
    --help|-h)     show_help; exit 0 ;;
    --features)    ;; # Handled positionally below
    *)             echo "Error: Unknown option: $arg" >&2; show_help; exit 1 ;;
  esac
done

# Handle --features <value> (space-separated argument)
for ((i=0; i<$#; i++)); do
  if [[ "${!i}" == "--features" ]] && [[ $((i+1)) -lt $# ]]; then
    FEATURES="${@:$((i+2)):1}"
  fi
done

# Build cargo xtask arguments
XTASK_ARGS=(build --arch aarch64 --boot uefi)
[[ -n "$DEBUG_FLAG" ]]  && XTASK_ARGS+=(--debug)
[[ -n "$INITRD_FLAG" ]] && XTASK_ARGS+=(--initrd)
[[ -n "$FEATURES" ]]    && XTASK_ARGS+=(--features "$FEATURES")

# Execute cargo xtask with error handling
if ! cargo xtask "${XTASK_ARGS[@]}"; then
  echo "Error: cargo xtask build failed" >&2
  exit 1
fi
