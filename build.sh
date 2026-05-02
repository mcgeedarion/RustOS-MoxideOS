#!/bin/bash
set -e
cargo build --release --target riscv64gc-unknown-none-elf
