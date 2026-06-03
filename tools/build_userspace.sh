#!/usr/bin/env bash
# tools/build_userspace.sh
# One-shot: build all userspace binaries and pack them into initramfs.cpio.
#
# Usage:
#   ./tools/build_userspace.sh              # x86_64 (default)
#   ./tools/build_userspace.sh riscv64      # RISC-V
#   ./tools/build_userspace.sh x86_64 --clean  # Clean rebuild
#
# Environment Variables:
#   VERBOSE=1       Enable verbose output
#
# Output:
#   userspace/build/<arch>/init
#   userspace/build/<arch>/hello
#   initramfs.cpio   (CPIO newc archive — pass to QEMU as -initrd)
#
# Troubleshooting:
#   If build fails, try: ./tools/build_userspace.sh <arch> --clean
#   For verbose output: VERBOSE=1 ./tools/build_userspace.sh <arch>
#   Check that 'make' and 'bash' are available in your PATH

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

ARCH=${1:-x86_64}
CLEAN_BUILD=${2:-}
VERBOSE=${VERBOSE:-0}
VALID_ARCHS=("x86_64" "riscv64")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
USERSPACE="$REPO_ROOT/userspace"
BUILD_DIR="$USERSPACE/build/$ARCH"

START_TIME=$(date +%s)

# ============================================================================
# Helper Functions
# ============================================================================

log_info() {
  echo "[build_userspace] $*"
}

log_error() {
  echo "[build_userspace] ERROR: $*" >&2
}

log_success() {
  echo "[build_userspace] ✓ $*"
}

verbose_log() {
  if [[ "$VERBOSE" == "1" ]]; then
    echo "[build_userspace] DEBUG: $*"
  fi
}

# ============================================================================
# Validation
# ============================================================================

validate_dependencies() {
  local missing_deps=0
  for cmd in make bash; do
    if ! command -v "$cmd" &> /dev/null; then
      log_error "Required command not found: '$cmd'"
      missing_deps=$((missing_deps + 1))
    fi
  done
  
  if [[ $missing_deps -gt 0 ]]; then
    log_error "Please install missing dependencies and try again."
    exit 1
  fi
  
  verbose_log "All required dependencies found"
}

validate_architecture() {
  if [[ ! " ${VALID_ARCHS[@]} " =~ " ${ARCH} " ]]; then
    log_error "Unsupported ARCH='$ARCH'"
    echo "Valid architectures: ${VALID_ARCHS[*]}" >&2
    exit 1
  fi
  
  verbose_log "Architecture validation passed: $ARCH"
}

validate_paths() {
  if [[ ! -d "$USERSPACE" ]]; then
    log_error "Userspace directory not found: $USERSPACE"
    exit 1
  fi
  
  if [[ ! -f "$SCRIPT_DIR/build_initramfs.sh" ]]; then
    log_error "build_initramfs.sh not found: $SCRIPT_DIR/build_initramfs.sh"
    exit 1
  fi
  
  verbose_log "Path validation passed"
  verbose_log "  REPO_ROOT: $REPO_ROOT"
  verbose_log "  USERSPACE: $USERSPACE"
  verbose_log "  BUILD_DIR: $BUILD_DIR"
}

# ============================================================================
# Build Functions
# ============================================================================

clean_build() {
  if [[ -d "$BUILD_DIR" ]]; then
    log_info "Cleaning previous build directory: $BUILD_DIR"
    rm -rf "$BUILD_DIR"
    verbose_log "Build directory cleaned"
  fi
}

build_userspace() {
  log_info "Building userspace for ARCH=$ARCH"
  
  if [[ ! -f "$USERSPACE/Makefile" ]]; then
    log_error "Makefile not found in $USERSPACE"
    exit 1
  fi
  
  if ! cd "$USERSPACE" && make ARCH="$ARCH"; then
    log_error "Userspace build failed for ARCH=$ARCH"
    exit 1
  fi
  
  log_success "Userspace build completed"
}

pack_initramfs() {
  log_info "Packing initramfs for ARCH=$ARCH"
  
  if ! bash "$SCRIPT_DIR/build_initramfs.sh" "$ARCH"; then
    log_error "Initramfs packing failed"
    exit 1
  fi
  
  log_success "Initramfs packing completed"
}

verify_outputs() {
  local missing_outputs=0
  local expected_outputs=(
    "$BUILD_DIR/init"
    "$BUILD_DIR/hello"
    "$REPO_ROOT/initramfs.cpio"
  )
  
  log_info "Verifying build outputs..."
  
  for output in "${expected_outputs[@]}"; do
    if [[ -e "$output" ]]; then
      local size=$(du -h "$output" | cut -f1)
      verbose_log "✓ Found: $output ($size)"
    else
      log_error "Expected output not found: $output"
      missing_outputs=$((missing_outputs + 1))
    fi
  done
  
  if [[ $missing_outputs -gt 0 ]]; then
    log_error "$missing_outputs expected output(s) not found"
    exit 1
  fi
  
  log_success "All expected outputs verified"
}

print_summary() {
  local end_time=$(date +%s)
  local elapsed=$((end_time - START_TIME))
  local minutes=$((elapsed / 60))
  local seconds=$((elapsed % 60))
  
  echo ""
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║                   BUILD COMPLETED SUCCESSFULLY              ║"
  echo "╠════════════════════════════════════════════════════════════╣"
  echo "║ Architecture:    $ARCH"
  echo "║ Build time:      ${minutes}m ${seconds}s"
  echo "║ Output archive:  initramfs.cpio"
  echo "║ Location:        $REPO_ROOT/initramfs.cpio"
  echo "║                                                            ║"
  echo "║ Next step: Pass to QEMU with -initrd flag                 ║"
  echo "╚════════════════════════════════════════════════════════════╝"
  echo ""
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
  log_info "Starting build ($(date '+%Y-%m-%d %H:%M:%S'))"
  verbose_log "VERBOSE mode enabled"
  
  # Validation phase
  validate_dependencies
  validate_architecture
  validate_paths
  
  # Clean build if requested
  if [[ "$CLEAN_BUILD" == "--clean" ]]; then
    clean_build
  fi
  
  # Build phase
  build_userspace
  pack_initramfs
  
  # Verification phase
  verify_outputs
  
  # Summary
  print_summary
}

# Run main function
main "$@"
