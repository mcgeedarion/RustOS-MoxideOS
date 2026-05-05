#!/usr/bin/env bash
# run_qemu_riscv.sh — Build rustos (RISC-V) and launch it in QEMU.
#
# Usage:
#   ./run_qemu_riscv.sh            # ramfs only (no disk)
#   ./run_qemu_riscv.sh disk.img   # attach a virtio-blk disk image
#
# Requirements:
#   rustup target add riscv64gc-unknown-none-elf
#   qemu-system-riscv64
#   OpenSBI firmware (qemu-system-riscv64 ships it as bios=default)

set -euo pipefail

KERNEL=target/riscv64gc-unknown-none-elf/debug/rustos
DISK="${1:-}"

# ─── Build (debug) ────────────────────────────────────────────────────────────────────────────

echo "[*] Building rustos (RISC-V debug)..."
cargo build \
  --target riscv64gc-unknown-none-elf \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem

# ─── QEMU args ──────────────────────────────────────────────────────────────────────────

QEMU_ARGS=(
  -machine virt              # RISC-V virt: virtio-mmio, PLIC, CLINT
  -cpu rv64                  # generic rv64 with standard extensions
  -m 256M                    # 256 MiB RAM
  -bios default              # OpenSBI (bundled with QEMU); hands off to -kernel
  -kernel "$KERNEL"          # ELF64 payload loaded at 0x80200000 by OpenSBI
  -serial stdio              # UART0 -> your terminal
  -display none              # headless
  -no-reboot                 # stop on reset instead of rebooting
  -d guest_errors,cpu_reset  # log faults to stderr
)

# Attach disk if provided.
# On the RISC-V virt machine, virtio devices are MMIO-mapped, so the
# correct device type is virtio-blk-device (not virtio-blk-pci).
if [[ -n "$DISK" ]]; then
  echo "[*] Attaching disk: $DISK"
  QEMU_ARGS+=(
    -drive "id=vblk0,file=${DISK},format=raw,if=none"
    -device "virtio-blk-device,drive=vblk0,id=virtblk0"
  )
else
  echo "[*] No disk image — ramfs only"
fi

echo "[*] Starting QEMU (RISC-V)..."
echo
exec qemu-system-riscv64 "${QEMU_ARGS[@]}"
