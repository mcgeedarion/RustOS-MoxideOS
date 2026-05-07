#!/usr/bin/env bash
# run_qemu.sh — Build rustos (debug) and launch it in QEMU.
#
# Usage:
#   ./run_qemu.sh                  # normal run (serial only)
#   ./run_qemu.sh --gpu            # add virtio-gpu-pci, open SDL/GTK window
#   ./run_qemu.sh --gdb            # halt at entry, wait for GDB on :1234
#   ./run_qemu.sh disk.img         # attach a virtio-blk disk image
#   ./run_qemu.sh --gpu --gdb disk.img
#
# GDB workflow:
#   Terminal 1:  ./run_qemu.sh --gdb [disk.img]
#   Terminal 2:  gdb   (auto-connects via .gdbinit)
#
# Requirements:
#   rustup target add x86_64-unknown-none
#   qemu-system-x86_64  (with SDL2 or GTK for --gpu)

set -euo pipefail

KERNEL=target/x86_64-unknown-none/debug/rustos
GDB_MODE=0
GPU_MODE=0
DISK=""

for arg in "$@"; do
  case "$arg" in
    --gdb) GDB_MODE=1 ;;
    --gpu) GPU_MODE=1 ;;
    *)     DISK="$arg" ;;
  esac
done

# ─── Build (debug) ───────────────────────────────────────────────────────────

echo "[*] Building rustos (debug)..."
cargo build \
  --target x86_64-unknown-none \
  -Z build-std=core,alloc,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem

# ─── QEMU args ────────────────────────────────────────────────────────────

QEMU_ARGS=(
  -machine q35
  -cpu qemu64,+xsave,+avx
  -m 256M
  -kernel "$KERNEL"
  -serial stdio
  -no-reboot
  -d guest_errors,cpu_reset
)

if [[ $GPU_MODE -eq 1 ]]; then
  echo "[*] GPU mode: adding virtio-gpu-pci + SDL display"
  # virtio-gpu-pci exposes a PCI device (vendor=0x1AF4 device=0x1050).
  # The kernel driver (src/drivers/virtio_gpu.rs) will discover it via PCI
  # scan and use it as /dev/fb0.
  QEMU_ARGS+=(
    -device virtio-gpu-pci
    -display sdl,gl=off     # use SDL2; swap to gtk or egl-headless as needed
  )
else
  QEMU_ARGS+=(-display none)
fi

if [[ -n "$DISK" ]]; then
  echo "[*] Attaching disk: $DISK"
  QEMU_ARGS+=(
    -drive "id=vblk0,file=${DISK},format=raw,if=none"
    -device "virtio-blk-pci,drive=vblk0,id=virtblk0"
  )
else
  echo "[*] No disk image — ramfs only"
fi

if [[ $GDB_MODE -eq 1 ]]; then
  QEMU_ARGS+=(
    -s        # open gdbserver on TCP :1234
    -S        # halt CPU at startup, wait for GDB `continue`
  )
  echo
  echo "  ┌─────────────────────────────────────────────┐"
  echo "  │ GDB mode: kernel halted at entry point.       │"
  echo "  │ In another terminal, run:                     │"
  echo "  │   gdb                                         │"
  echo "  │ (.gdbinit auto-connects and loads symbols)    │"
  echo "  └─────────────────────────────────────────────┘"
  echo
fi

echo "[*] Starting QEMU..."
echo
exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
