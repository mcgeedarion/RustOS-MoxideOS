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

# ── Build-time arguments ─────────────────────────────────────────────────────
# Must match rust-toolchain.toml channel and flake.nix rustToolchain.
ARG NIGHTLY_DATE=2025-05-15
ARG DEBIAN_FRONTEND=noninteractive

# ── System packages ───────────────────────────────────────────────────────────
# clang / lld   : linker for riscv64-uefi.json (PE/COFF) and x86_64-unknown-none
# binutils-riscv64-linux-gnu : riscv64-unknown-elf-as / ar for build.rs uentry.S
# qemu-system-{misc,x86}     : smoke-test the kernel image inside the container
# curl / ca-certs             : rustup installer
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

# ── Rust (rustup) ─────────────────────────────────────────────────────────────
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

# ── Working directory ─────────────────────────────────────────────────────────
# Source is mounted at runtime (-v "$(pwd)":/work); we pre-warm the cargo
# registry cache by copying manifests and doing a dependency-only fetch.
WORKDIR /work

# Pre-fetch cargo registry index so the first `cargo build` is faster.
# The actual source tree is NOT baked in — mount it at runtime.
RUN cargo search --limit 0 2>/dev/null || true

# ── Default command ───────────────────────────────────────────────────────────
CMD ["bash"]
