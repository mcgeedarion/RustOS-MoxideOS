#!/usr/bin/env bash
# build.sh — default build (RISC-V UEFI, release).
#
# Produces:  esp/EFI/BOOT/BOOTRISCV64.EFI
#
# For SBI mode:   ./build_riscv.sh --sbi
# For x86_64:     ./build_x86.sh
# For debug:      ./build_riscv.sh --debug
set -euo pipefail
exec bash "$(dirname "$0")/build_riscv.sh"
