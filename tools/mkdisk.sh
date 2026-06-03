#!/usr/bin/env bash
# tools/mkdisk.sh — create a blank ext2 disk image for rustos.
#
# Usage:
#   ./tools/mkdisk.sh [size] [output]
#
#   size      Disk size in MiB (default: 128). Supports K/M/G suffixes (e.g., 256M, 1G)
#   output    Output image path (default: disk.img)
#
# Environment:
#   VERBOSE   Set to 1 for verbose output (default: 0)

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

VERBOSE=${VERBOSE:-0}
SIZE_INPUT=${1:-128}
OUT=${2:-disk.img}

# ============================================================================
# Functions
# ============================================================================

log_info() {
    echo "[mkdisk] $*"
}

log_error() {
    echo "[mkdisk] Error: $*" >&2
}

log_verbose() {
    if (( VERBOSE == 1 )); then
        echo "[mkdisk] $*"
    fi
}

# Parse size with optional K/M/G suffix
parse_size() {
    local input=$1
    
    if [[ $input =~ ^([0-9]+)([KMG])?$ ]]; then
        local num=${BASH_REMATCH[1]}
        local unit=${BASH_REMATCH[2]:-M}
        
        case $unit in
            K) echo $((num / 1024)) ;;
            M) echo $num ;;
            G) echo $((num * 1024)) ;;
        esac
        return 0
    else
        return 1
    fi
}

# Check if a command exists
require_command() {
    local cmd=$1
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_error "required command not found: '$cmd'"
        exit 1
    fi
    log_verbose "found command: $cmd"
}

# ============================================================================
# Validation
# ============================================================================

# Check for required commands
require_command dd
require_command mkfs.ext2

# Parse and validate size
if ! SIZE=$(parse_size "$SIZE_INPUT"); then
    log_error "invalid size format: '$SIZE_INPUT' (use format: 128, 256M, 1G, etc.)"
    exit 1
fi

if (( SIZE <= 0 )); then
    log_error "size must be a positive integer, got '$SIZE' MiB"
    exit 1
fi

# Check if output file already exists
if [[ -e "$OUT" ]]; then
    log_error "output file already exists: '$OUT'"
    exit 1
fi

# Validate output directory exists and is writable
OUT_DIR=$(dirname "$OUT")
if [[ ! -d "$OUT_DIR" ]]; then
    log_error "output directory does not exist: '$OUT_DIR'"
    exit 1
fi

if [[ ! -w "$OUT_DIR" ]]; then
    log_error "output directory is not writable: '$OUT_DIR'"
    exit 1
fi

# Check available disk space
AVAILABLE_KB=$(df "$OUT_DIR" | awk 'NR==2 {print $4}')
REQUIRED_KB=$((SIZE * 1024))

if (( REQUIRED_KB > AVAILABLE_KB )); then
    log_error "insufficient disk space in '$OUT_DIR'"
    log_error "  required: $SIZE MiB ($REQUIRED_KB KB)"
    log_error "  available: $((AVAILABLE_KB / 1024)) MiB ($AVAILABLE_KB KB)"
    exit 1
fi

log_verbose "disk space check passed: $((AVAILABLE_KB / 1024)) MiB available"

# ============================================================================
# Cleanup on error
# ============================================================================

cleanup() {
    if [[ -e "$OUT" ]]; then
        log_verbose "cleaning up partial image: $OUT"
        rm -f "$OUT"
    fi
}

trap cleanup ERR

# ============================================================================
# Interactive confirmation (if attached to terminal)
# ============================================================================

if [[ -t 0 ]]; then
    read -p "[mkdisk] Create ${SIZE} MiB ext2 disk image at '$OUT'? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "aborted"
        exit 0
    fi
fi

# ============================================================================
# Create disk image
# ============================================================================

log_info "creating ${SIZE} MiB ext2 image: $OUT"

# Create blank image with progress indicator
log_verbose "writing ${SIZE} MiB of zeros..."
dd if=/dev/zero of="$OUT" bs=1M count="$SIZE" status=progress 2>&1 || {
    log_error "failed to create image"
    exit 1
}

# Format as ext2
log_verbose "formatting as ext2..."
mkfs.ext2 -b 4096 -L rustos "$OUT" >/dev/null 2>&1 || {
    log_error "failed to format image"
    exit 1
}

log_info "done: $OUT (${SIZE} MiB ext2)"
log_verbose "image is ready for use"
