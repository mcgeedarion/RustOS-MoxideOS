#!/usr/bin/env bash
# run_qemu_riscv.sh — Build rustos (RISC-V) and launch it in QEMU.
#
# Boot modes:
#   UEFI (default) — EDK2 RiscVVirt pflash firmware, FAT ESP virtio drive
#   SBI  (--sbi)   — OpenSBI firmware, -kernel ELF
#
# Usage:
#   ./run_qemu_riscv.sh                       # UEFI, release build (default)
#   ./run_qemu_riscv.sh --sbi                 # SBI, debug build
#   ./run_qemu_riscv.sh --gdb                 # UEFI + GDB halt on :1235
#   ./run_qemu_riscv.sh --sbi --gdb           # SBI  + GDB halt on :1235
#   ./run_qemu_riscv.sh disk.img              # UEFI + virtio-blk disk
#   ./run_qemu_riscv.sh --sbi disk.img        # SBI  + virtio-blk disk
#
# GDB workflow:
#   Terminal 1:  ./run_qemu_riscv.sh --gdb [--sbi] [disk.img]
#   Terminal 2:  gdb-multiarch -ex 'set arch riscv:rv64' \
#                              -ex 'file target/riscv64-uefi/release/rustos.efi' \
#                              -ex 'target remote :1235'
#
# Requirements:
#   rustup target add riscv64gc-unknown-none-elf
#   qemu-system-riscv64
#   UEFI mode: qemu-efi-riscv64 package (provides edk2-riscv-code.fd)
#              sudo apt install qemu-efi-riscv64   # Debian/Ubuntu
#   SBI mode:  OpenSBI bundled with QEMU (-bios default)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GDB_MODE=0
BOOT="uefi"
DISK=""

for arg in "$@"; do
  case "$arg" in
    --gdb)  GDB_MODE=1 ;;
    --sbi)  BOOT="sbi" ;;
    --uefi) BOOT="uefi" ;;
    *)      DISK="$arg" ;;
  esac
done

# ── GDB banner helper ───────────────────────────────────────────────────────────
gdb_banner() {
  local sym_file
  if [[ "$BOOT" == "uefi" ]]; then
    sym_file="target/riscv64-uefi/release/rustos.efi"
  else
    sym_file="target/riscv64gc-unknown-none-elf/debug/rustos"
  fi
  echo
  echo "  ┌─────────────────────────────────────────────────────┐"
  echo "  │ GDB mode: kernel halted at entry point.             │"
  echo "  │ In another terminal, run:                           │"
  echo "  │   gdb-multiarch \\                                   │"
  echo "  │     -ex 'set arch riscv:rv64' \\                     │"
  echo "  │     -ex 'file ${sym_file}' \\"
  echo "  │     -ex 'target remote :1235'                       │"
  echo "  └─────────────────────────────────────────────────────┘"
  echo
}

# ══════════════════════════════════════════════════════════════════════════════
# UEFI boot path (default)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$BOOT" == "uefi" ]]; then
  echo "[*] Building rustos (RISC-V UEFI release)..."
  bash "$SCRIPT_DIR/build_riscv.sh"

  # Locate EDK2 RISC-V firmware.
  FW_SEARCH=(
    "/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd"
    "/usr/share/edk2/riscv64/RISCV_VIRT_CODE.fd"
    "/usr/share/qemu/edk2-riscv-code.fd"
    "/opt/homebrew/share/qemu/edk2-riscv-code.fd"
    "/usr/local/share/qemu/edk2-riscv-code.fd"
  )
  FW_CODE=""
  for p in "${FW_SEARCH[@]}"; do
    if [[ -f "$p" ]]; then FW_CODE="$p"; break; fi
  done

  if [[ -z "$FW_CODE" ]]; then
    echo "[!] EDK2 RISC-V firmware not found.  Install with:" >&2
    echo "      sudo apt install qemu-efi-riscv64   # Debian/Ubuntu" >&2
    echo "      brew install qemu                   # macOS" >&2
    exit 1
  fi

  FW_VARS="$SCRIPT_DIR/edk2-riscv-vars.fd"
  if [[ ! -f "$FW_VARS" ]]; then
    VARS_TEMPLATE="${FW_CODE/CODE/VARS}"
    if [[ -f "$VARS_TEMPLATE" ]]; then
      cp "$VARS_TEMPLATE" "$FW_VARS"
    else
      dd if=/dev/zero of="$FW_VARS" bs=1M count=64 2>/dev/null
    fi
  fi

  ESP="$SCRIPT_DIR/esp"

  QEMU_ARGS=(
    -machine virt
    -cpu rv64
    -m 512M
    -drive "if=pflash,unit=0,format=raw,file=${FW_CODE},readonly=on"
    -drive "if=pflash,unit=1,format=raw,file=${FW_VARS}"
    -drive "file=fat:rw:${ESP}/,format=raw,if=virtio"
    -serial stdio
    -display none
    -no-reboot
    -d guest_errors,cpu_reset
  )

  if [[ -n "$DISK" ]]; then
    QEMU_ARGS+=(
      -drive "id=vblk0,file=${DISK},format=raw,if=none"
      -device "virtio-blk-device,drive=vblk0,id=virtblk0"
    )
  fi

  if [[ $GDB_MODE -eq 1 ]]; then
    QEMU_ARGS+=(-gdb tcp::1235 -S)
    gdb_banner
  fi

  echo "[*] Starting QEMU (RISC-V UEFI)..."
  echo "    Firmware : $FW_CODE"
  echo "    ESP      : $ESP/EFI/BOOT/BOOTRISCV64.EFI"
  echo
  exec qemu-system-riscv64 "${QEMU_ARGS[@]}"
fi

# ══════════════════════════════════════════════════════════════════════════════
# SBI boot path
# ══════════════════════════════════════════════════════════════════════════════

KERNEL=target/riscv64gc-unknown-none-elf/debug/rustos

echo "[*] Building rustos (RISC-V SBI debug)..."
bash "$SCRIPT_DIR/build_riscv.sh" --sbi --debug

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
  QEMU_ARGS+=(-gdb tcp::1235 -S)
  gdb_banner
fi

echo "[*] Starting QEMU (RISC-V SBI)..."
echo
exec qemu-system-riscv64 "${QEMU_ARGS[@]}"
