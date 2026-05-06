#!/usr/bin/env bash
# build.sh — default build script (RISC-V SBI, release).
# Equivalent to: cargo build --release
# For UEFI or debug options use build_riscv.sh.
# For x86_64 use build_x86.sh.
set -euo pipefail
exec cargo build --release
