#!/bin/bash
set -e
export CARGO_UNSTABLE_BUILD_STD=true
cargo build --release 2>&1
objcopy -O binary target/x86_64-unknown-none/release/rustos kernel.bin
echo "Built: kernel.bin"
