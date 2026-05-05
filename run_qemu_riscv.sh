#!/usr/bin/env bash
# run_qemu_riscv.sh — Build rustos (RISC-V) and launch it in QEMU.
#
# Usage:
#   ./run_qemu_riscv.sh                  # normal run
#   ./run_qemu_riscv.sh --gdb            # halt at entry, wait for GDB on :1235
#   ./run_qemu_riscv.sh disk.img         # attach a virtio-blk disk image
#   ./run_qemu_riscv.sh --gdb disk.img   # both
#
# GDB workflow (RISC-V uses port 1235 to avoid clash with x86 on :1234):
#   Terminal 1:  ./run_qemu_riscv.sh --gdb [disk.img]
#   Terminal 2:  gdb-multiarch -ex 'set arch riscv:rv64' \
#                              -ex 'file target/riscv64gc-unknown-none-elf/debug/rustos' \
#                              -ex 'target remote :1235'
#
# Requirements:
#   rustup target add riscv64gc-unknown-none-elf
#   qemu-system-riscv64
#   OpenSBI firmware (bundled with QEMU as bios=default)

set -euo pipefail

KERNEL=target/riscv64gc-unknown-none-elf/debug/rustos
GDB_MODE=0
DISK=""

for arg in "$@"; do
  case "$arg" in
    --gdb)     GDB_MODE=1 ;;
    *)         DISK="$arg" ;;
  esac
done

# ─── Build (debug) ────────────────────────────────────────────────────────────────────────────

echo "[*] Building rustos (RISC-V debug)..."
cargo build \
  --target riscv64gc-unknown-none-elf \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem

# ─── QEMU args ──────────────────────────────────────────────────────────────────────────

QEMU_ARGS=(
  -machine virt
  -cpu rv64
  -m 256M
  -bios default
  -kernel "$KERNEL"
  -serial stdio
  -display none
  -no-reboot
  -d guest_errors,cpu_reset
)

if [[ -n "$DISK" ]]; then
  echo "[*] Attaching disk: $DISK"
  QEMU_ARGS+=(
    -drive "id=vblk0,file=${DISK},format=raw,if=none"
    -device "virtio-blk-device,drive=vblk0,id=virtblk0"
  )
else
  echo "[*] No disk image — ramfs only"
fi

if [[ $GDB_MODE -eq 1 ]]; then
  # Use port 1235 to avoid clashing with x86 gdbserver on :1234.
  QEMU_ARGS+=(
    -gdb tcp::1235
    -S
  )
  echo
  echo "  ┌─────────────────────────────────────────────┐"
  echo "  │ GDB mode: kernel halted at entry point.       │"
  echo "  │ In another terminal, run:                     │"
  echo "  │   gdb-multiarch \\                             │"
  echo "  │     -ex 'set arch riscv:rv64' \\               │"
  echo "  │     -ex 'file target/riscv64gc-unknown-none-elf/debug/rustos' \\"
  echo "  │     -ex 'target remote :1235'                 │"
  echo "  └─────────────────────────────────────────────┘"
  echo
fi

echo "[*] Starting QEMU (RISC-V)..."
echo
exec qemu-system-riscv64 "${QEMU_ARGS[@]}"
