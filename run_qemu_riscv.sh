#!/usr/bin/env bash
# run_qemu_riscv.sh — Build rustos (RISC-V) and launch it in QEMU.
#
# Boot modes:
#   SBI  (default) — OpenSBI firmware, -kernel ELF
#   UEFI (--uefi)  — EDK2 RiscVVirt pflash firmware, FAT ESP virtio drive
#
# Usage:
#   ./run_qemu_riscv.sh                       # SBI, debug build
#   ./run_qemu_riscv.sh --uefi                # UEFI, release build
#   ./run_qemu_riscv.sh --gdb                 # SBI + GDB halt on :1235
#   ./run_qemu_riscv.sh --uefi --gdb          # UEFI + GDB halt on :1235
#   ./run_qemu_riscv.sh disk.img              # SBI + virtio-blk disk
#   ./run_qemu_riscv.sh --uefi disk.img       # UEFI + virtio-blk disk
#
# GDB workflow:
#   Terminal 1:  ./run_qemu_riscv.sh --gdb [--uefi] [disk.img]
#   Terminal 2:  gdb-multiarch -ex 'set arch riscv:rv64' \
#                              -ex 'file target/riscv64gc-unknown-none-elf/debug/rustos' \
#                              -ex 'target remote :1235'
#
# Requirements:
#   rustup target add riscv64gc-unknown-none-elf
#   qemu-system-riscv64
#   SBI mode:  OpenSBI bundled with QEMU (-bios default)
#   UEFI mode: qemu-efi-riscv64 package (provides edk2-riscv-code.fd)
#              sudo apt install qemu-efi-riscv64   # Debian/Ubuntu

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GDB_MODE=0
BOOT="sbi"
DISK=""

for arg in "$@"; do
  case "$arg" in
    --gdb)  GDB_MODE=1 ;;
    --uefi) BOOT="uefi" ;;
    *)      DISK="$arg" ;;
  esac
done

# ── GDB banner helper ─────────────────────────────────────────────────────────
gdb_banner() {
  echo
  echo "  ┌─────────────────────────────────────────────────────┐"
  echo "  │ GDB mode: kernel halted at entry point.             │"
  echo "  │ In another terminal, run:                           │"
  echo "  │   gdb-multiarch \\                                   │"
  echo "  │     -ex 'set arch riscv:rv64' \\                     │"
  echo "  │     -ex 'file target/riscv64gc-unknown-none-elf/debug/rustos' \\" 
  echo "  │     -ex 'target remote :1235'                       │"
  echo "  └─────────────────────────────────────────────────────┘"
  echo
}

# ══════════════════════════════════════════════════════════════════════════════
# SBI boot path (original)
# ══════════════════════════════════════════════════════════════════════════════
if [[ "$BOOT" == "sbi" ]]; then

  KERNEL=target/riscv64gc-unknown-none-elf/debug/rustos

  echo "[*] Building rustos (RISC-V SBI debug)..."
  cargo build \
    --target riscv64gc-unknown-none-elf \
    -Z build-std=core,alloc,compiler_builtins \
    -Z build-std-features=compiler-builtins-mem

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
fi

# ══════════════════════════════════════════════════════════════════════════════
# UEFI boot path
# ══════════════════════════════════════════════════════════════════════════════

# Build (release — UEFI images are typically release builds).
echo "[*] Building rustos (RISC-V UEFI release)..."
bash "$SCRIPT_DIR/build_riscv.sh" --uefi

# Locate EDK2 RISC-V firmware.  Common distro paths:
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
  echo "    Then re-run this script." >&2
  exit 1
fi

# Writable vars store (copy once; reuse across runs).
FW_VARS="$SCRIPT_DIR/edk2-riscv-vars.fd"
if [[ ! -f "$FW_VARS" ]]; then
  # Try to find a template vars file alongside the code file.
  VARS_TEMPLATE="${FW_CODE/CODE/VARS}"
  if [[ -f "$VARS_TEMPLATE" ]]; then
    cp "$VARS_TEMPLATE" "$FW_VARS"
  else
    # Fall back: create an empty 64 MiB file (EDK2 will initialise it).
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
  echo "[*] Attaching disk: $DISK"
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
