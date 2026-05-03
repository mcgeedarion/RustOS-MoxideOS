#!/usr/bin/env bash
# run_qemu.sh — Build rustos and launch it in QEMU.
#
# Usage:
#   ./run_qemu.sh            # ramfs only (no disk)
#   ./run_qemu.sh disk.img   # attach a virtio-blk disk image
#
# Requirements:
#   rustup target add x86_64-unknown-none
#   cargo install bootimage   (optional, only needed for BIOS iso)
#   qemu-system-x86_64

set -euo pipefail

KERNEL=target/x86_64-unknown-none/debug/rustos
DISK="${1:-}"

# ─── Build ───────────────────────────────────────────────────────────────────────

echo "[*] Building rustos..."
cargo build \
  --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem

# ─── QEMU args ──────────────────────────────────────────────────────────────────

QEMU_ARGS=(
  -machine q35               # modern chipset: PCIe, APIC, IOMMU-capable
  -cpu qemu64,+xsave,+avx   # XSAVE + AVX so xsave_init() sees them
  -m 256M                    # 256 MiB RAM
  -kernel "$KERNEL"          # Multiboot2 / direct ELF64 load
  -serial stdio              # COM1 -> your terminal
  -display none              # headless
  -no-reboot                 # stop on triple-fault instead of rebooting
  -d guest_errors,cpu_reset  # log triple-faults to stderr
)

# Attach disk if provided.
if [[ -n "$DISK" ]]; then
  echo "[*] Attaching disk: $DISK"
  QEMU_ARGS+=(
    -drive "id=vblk0,file=${DISK},format=raw,if=none"
    -device "virtio-blk-device,drive=vblk0,id=virtblk0"
  )
else
  echo "[*] No disk image — ramfs only"
fi

echo "[*] Starting QEMU..."
echo
exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
