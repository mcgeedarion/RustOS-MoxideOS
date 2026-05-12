#!/usr/bin/env bash
# run_qemu.sh — Build rustos (debug) and launch it in QEMU.
#
# Usage:
#   ./run_qemu.sh                  # normal run (serial only, user-mode NAT NIC)
#   ./run_qemu.sh --gpu            # add virtio-gpu-pci, open SDL/GTK window
#   ./run_qemu.sh --gdb            # halt at entry, wait for GDB on :1234
#   ./run_qemu.sh --no-net         # disable virtio-net entirely
#   ./run_qemu.sh disk.img         # attach a virtio-blk disk image
#   ./run_qemu.sh --gpu --gdb disk.img
#
# Networking (default — user-mode NAT, no root required):
#   virtio-net-pci exposes PCI vendor=0x1AF4 device=0x1041 (modern) or
#   0x1000 (legacy).  QEMU's "user" backend provides NAT so the kernel can
#   reach the host network without a TAP device or root privileges.
#   Guest IP (DHCP via QEMU SLIRP): 10.0.2.15/24, GW 10.0.2.2, DNS 10.0.2.3
#
#   To use a TAP bridge instead (needs root / CAP_NET_ADMIN):
#     sudo ip tuntap add dev tap0 mode tap
#     sudo ip link set tap0 up
#     then replace "-netdev user,..." with:
#       -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
#       -device virtio-net-pci,netdev=net0
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
NET_MODE=1   # 1 = user-mode NAT virtio-net (default), 0 = disabled
DISK=""

for arg in "$@"; do
  case "$arg" in
    --gdb)    GDB_MODE=1 ;;
    --gpu)    GPU_MODE=1 ;;
    --no-net) NET_MODE=0 ;;
    *)        DISK="$arg" ;;
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

if [[ $NET_MODE -eq 1 ]]; then
  echo "[*] Network: virtio-net-pci (user-mode NAT, guest 10.0.2.15/24)"
  QEMU_ARGS+=(
    -netdev "user,id=net0,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15"
    -device "virtio-net-pci,netdev=net0,id=nic0"
  )
else
  echo "[*] Network: disabled (--no-net)"
fi

if [[ $GPU_MODE -eq 1 ]]; then
  echo "[*] GPU mode: adding virtio-gpu-pci + SDL display"
  QEMU_ARGS+=(
    -device virtio-gpu-pci
    -display sdl,gl=off
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
    -s
    -S
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
