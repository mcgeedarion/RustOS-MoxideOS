#!/usr/bin/env bash
# build_x86.sh — Build rustos for x86_64.
#
# Prerequisites:
#   nasm          (assembles src/arch/x86_64/boot.s via build.rs)
#   clang         (cross-compiles src/crt/crt0.c via the cc crate)
#
# Output:
#   target/x86_64-unknown-none/release/rustos  (ELF)
#   kernel.bin                                  (flat binary, objcopy stripped)
set -euo pipefail

cargo build --release \
  --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem

objcopy -O binary target/x86_64-unknown-none/release/rustos kernel.bin
echo "Built: kernel.bin"
