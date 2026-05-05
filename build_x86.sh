#!/bin/bash
set -e
cargo build --release \
  --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem 2>&1
objcopy -O binary target/x86_64-unknown-none/release/rustos kernel.bin
echo "Built: kernel.bin"
