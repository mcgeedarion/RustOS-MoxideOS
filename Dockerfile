# syntax=docker/dockerfile:1
# ────────────────────────────────────────────────────────────────────────────
# rustos — reproducible build + development environment
#
# Build:  docker build -t rustos-dev .
# Shell:  docker run --rm -it -v "$(pwd)":/work rustos-dev
# Build kernel (RISC-V UEFI):
#   docker run --rm -v "$(pwd)":/work rustos-dev cargo build
# Build kernel (x86_64):
#   docker run --rm -v "$(pwd)":/work rustos-dev \
#     cargo build --target x86_64-unknown-none --no-default-features \
#       -Z build-std=core,alloc,compiler_builtins \
#       -Z build-std-features=compiler-builtins-mem
#
# IMPORTANT: keep NIGHTLY_DATE in sync with rust-toolchain.toml and flake.nix.
# ────────────────────────────────────────────────────────────────────────────

FROM ubuntu:24.04

ARG NIGHTLY_DATE=2025-05-15
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update -q && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    clang \
    lld \
    nasm \
    binutils-riscv64-linux-gnu \
    qemu-system-misc \
    qemu-system-x86 \
    ovmf \
    git \
    make \
    python3 \
    && rm -rf /var/lib/apt/lists/*

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path \
        --default-toolchain "nightly-${NIGHTLY_DATE}" \
        --component rust-src,llvm-tools-preview,rustfmt,clippy \
        --target riscv64gc-unknown-none-elf \
        --target x86_64-unknown-none

# Verify the toolchain is exactly what we expect — makes mismatches obvious
# at image-build time rather than silently falling back.
RUN rustup show active-toolchain | grep -q "nightly-${NIGHTLY_DATE}" \
    || { echo "ERROR: toolchain mismatch — expected nightly-${NIGHTLY_DATE}"; exit 1; }

WORKDIR /work

# Pre-fetch cargo registry index so the first `cargo build` is faster.
# The actual source tree is NOT baked in — mount it at runtime.
RUN cargo search --limit 0 2>/dev/null || true

CMD ["bash"]
