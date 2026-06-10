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
#   VERBOSE    Set to 1 for debug output (default: 0)
#   MUSL_GCC   musl-gcc binary to use when building tests (default: musl-gcc)
#
# Exit Codes:
#   0  Success
#   1  Missing build prerequisites (BIN_DIR not found)
#   2  Missing required tools (cpio, find, etc.)
#   3  Invalid architecture specified
#   4  Failed to create temporary directory
#   5  Failed to copy essential binaries
#   6  Failed to create CPIO archive

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────

VERBOSE=${VERBOSE:-0}
ARCH=${1:-x86_64}

# Enable debug mode if VERBOSE is set
if [ "$VERBOSE" = "1" ]; then
    set -x
fi

# ── Helper Functions ─────────────────────────────────────────────────────────

log_info() {
    echo "[build_initramfs] $*" >&2
}

log_warn() {
    echo "[build_initramfs] WARNING: $*" >&2
}

log_error() {
    echo "[build_initramfs] ERROR: $*" >&2
}

check_command() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log_error "Required tool not found: $cmd"
        return 1
    fi
    return 0
}

validate_architecture() {
    case "$ARCH" in
        x86_64|aarch64|riscv64|arm|i386)
            return 0
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            log_info "Supported architectures: x86_64, aarch64, riscv64, arm, i386"
            return 1
            ;;
    esac
}

get_file_size() {
    local file="$1"
    # Use stat if available (most systems), fall back to du
    if stat -c%s "$file" >/dev/null 2>&1; then
        stat -c%s "$file"
    elif stat -f%z "$file" >/dev/null 2>&1; then
        stat -f%z "$file"
    else
        # Fallback to du (less reliable but universal)
        du -b "$file" 2>/dev/null | cut -f1
    fi
}

format_file_size() {
    local bytes="$1"
    if [ "$bytes" -ge 1048576 ]; then
        echo "scale=2; $bytes / 1048576" | bc -l 2>/dev/null | xargs printf "%.1fM" || echo "${bytes}B"
    elif [ "$bytes" -ge 1024 ]; then
        echo "scale=2; $bytes / 1024" | bc -l 2>/dev/null | xargs printf "%.1fK" || echo "${bytes}B"
    else
        echo "${bytes}B"
    fi
}

strip_binary() {
    local binary="$1"
    if strip "$binary" 2>/dev/null; then
        if [ "$VERBOSE" = "1" ]; then
            log_info "Stripped: $binary"
        fi
        return 0
    else
        log_warn "Could not strip $binary (binary may already be stripped or invalid)"
        return 0  # Don't fail the build; stripping is optional
    fi
}

# ── Dependency Checks ────────────────────────────────────────────────────────

log_info "Checking dependencies..."
if ! check_command cpio; then
    log_error "Install cpio to build initramfs"
    exit 2
fi
if ! check_command find; then
    log_error "find command not available"
    exit 2
fi
if ! check_command mktemp; then
    log_error "mktemp command not available"
    exit 2
fi

# ── Path Setup ───────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN_DIR="$REPO_ROOT/userspace/build/$ARCH"
TEST_BIN_DIR="$REPO_ROOT/build_tests/$ARCH"
OUTPUT="$REPO_ROOT/initramfs.cpio"

log_info "Architecture: $ARCH"
log_info "Repository root: $REPO_ROOT"
log_info "Output file: $OUTPUT"

# ── Validation ───────────────────────────────────────────────────────────────

if ! validate_architecture; then
    exit 3
fi

if [ ! -d "$BIN_DIR" ]; then
    log_error "$BIN_DIR not found"
    log_info "Please run build_userspace.sh first for architecture: $ARCH"
    exit 1
fi

log_info "Using binaries from: $BIN_DIR"

# ── Staging directory ────────────────────────────────────────────────────────

log_info "Creating temporary staging directory..."
STAGING=$(mktemp -d) || {
    log_error "Failed to create temporary directory"
    exit 4
}
trap 'rm -rf "$STAGING"' EXIT

if [ "$VERBOSE" = "1" ]; then
    log_info "Staging directory: $STAGING"
fi

mkdir -p "$STAGING"/{bin,dev,proc,sys,tmp} || {
    log_error "Failed to create staging directories"
    exit 4
}

# ── Userspace binaries ───────────────────────────────────────────────────────

log_info "Staging userspace binaries..."

# Copy and validate /init
if [ ! -f "$BIN_DIR/init" ]; then
    log_error "Required binary not found: $BIN_DIR/init"
    exit 5
fi
if ! cp "$BIN_DIR/init" "$STAGING/init"; then
    log_error "Failed to copy init to staging directory"
    exit 5
fi
chmod 755 "$STAGING/init"
strip_binary "$STAGING/init"
log_info "Staged: init"

# Copy and validate /bin/hello
if [ ! -f "$BIN_DIR/hello" ]; then
    log_error "Required binary not found: $BIN_DIR/hello"
    exit 5
fi
if ! cp "$BIN_DIR/hello" "$STAGING/bin/hello"; then
    log_error "Failed to copy hello to staging directory"
    exit 5
fi
chmod 755 "$STAGING/bin/hello"
strip_binary "$STAGING/bin/hello"
log_info "Staged: hello"

# ── Test binaries (optional) ─────────────────────────────────────────────────
#
# If build_tests/<arch>/ exists (produced by tests/shared/run_tests.sh), copy
# every executable test binary into /bin/ so it can be exec'd directly inside
# the kernel under QEMU.
# Also copy tests/run_tests.sh as /bin/run_tests so the full suite can be
# driven from a serial console or an automated expect script.

test_count=0
if [ -d "$TEST_BIN_DIR" ]; then
    log_info "Scanning test binaries from: $TEST_BIN_DIR"
    for bin in "$TEST_BIN_DIR"/*; do
        if [ ! -e "$bin" ]; then
            # Empty directory
            continue
        fi
        
        if [ ! -f "$bin" ]; then
            if [ "$VERBOSE" = "1" ]; then
                log_warn "Skipping non-file: $bin"
            fi
            continue
        fi
        
        if [ ! -x "$bin" ]; then
            if [ "$VERBOSE" = "1" ]; then
                log_warn "Skipping non-executable: $bin"
            fi
            continue
        fi
        
        name="$(basename "$bin")"
        if ! cp "$bin" "$STAGING/bin/$name"; then
            log_warn "Failed to copy test binary: $bin"
            continue
        fi
        chmod 755 "$STAGING/bin/$name"
        strip_binary "$STAGING/bin/$name"
        ((test_count++))
    done
    
    log_info "Staged $test_count test binary/ies"
    
    # Copy test runner script if it exists
    if [ -f "$REPO_ROOT/tests/run_tests.sh" ]; then
        if cp "$REPO_ROOT/tests/run_tests.sh" "$STAGING/bin/run_tests"; then
            chmod 755 "$STAGING/bin/run_tests"
            log_info "Staged: run_tests (test runner script)"
        else
            log_warn "Failed to copy test runner script"
        fi
    else
        if [ "$VERBOSE" = "1" ]; then
            log_warn "Test runner script not found: $REPO_ROOT/tests/run_tests.sh"
        fi
    fi
else
    log_info "NOTE: Test binaries directory not found: $TEST_BIN_DIR"
    log_info "      To include test binaries, run tests/shared/run_tests.sh first"
fi

# ── Pack CPIO archive ────────────────────────────────────────────────────────

log_info "Creating CPIO archive..."
if ! (cd "$STAGING" && find . -print0 | cpio --create --format=newc --quiet --null > "$OUTPUT" 2>/dev/null); then
    log_error "Failed to create CPIO archive"
    exit 6
fi

# ── Output Summary ───────────────────────────────────────────────────────────

size_bytes=$(get_file_size "$OUTPUT")
size_human=$(format_file_size "$size_bytes")

log_info "✓ Successfully created initramfs"
log_info "Output file: $OUTPUT"
log_info "File size: $size_human ($size_bytes bytes)"
log_info "QEMU flag: -initrd $OUTPUT"
