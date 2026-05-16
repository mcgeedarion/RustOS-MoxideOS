#!/usr/bin/env bash
# run_qemu.sh — Build rustos (x86_64) and launch it under QEMU.
#
# Usage:
#   ./run_qemu.sh [options] [disk.img]
#
# Options:
#   --multiboot   Legacy GRUB2/multiboot2 boot (-kernel), instead of UEFI
#   --release     Build with --release (default: debug)
#   --gpu         Add virtio-gpu-pci and open an SDL/GTK display window
#   --gdb         Halt at entry, wait for GDB on :1234
#   --no-net      Disable virtio-net
#   --smoke       Run headless, capture serial, and require a boot marker
#   --timeout N   Smoke-test timeout in seconds (default: 20)
#   --smoke-marker TEXT
#                Marker required in serial output (default: TEST PASS: uart_smoke)
#
# Boot modes:
#   UEFI (default) — OVMF pflash + vvfat ESP; identical to real hardware.
#   multiboot2     — QEMU -kernel; useful for GRUB2-based testing.
#
# OVMF search order:
#   /usr/share/ovmf/OVMF.fd
#   /usr/share/edk2/ovmf/OVMF.fd
#   /usr/share/qemu/OVMF.fd
#   /opt/homebrew/share/qemu/edk2-x86_64-code.fd   (macOS Homebrew)
#   /usr/share/edk2-ovmf/x64/OVMF.fd
#
# Real-hardware workflow:
#   1. cargo build --release
#   2. Format a USB with a FAT32 ESP.
#   3. cp -r target/esp/EFI <mounted-ESP>/
#   4. Boot and select RustOS in the UEFI menu.
#   See docs/booting.md for details.
#
# Networking: user-mode NAT (no root needed).
#   Guest: 10.0.2.15/24, GW 10.0.2.2, DNS 10.0.2.3
#
# GDB workflow:
#   Terminal 1: ./run_qemu.sh --gdb [disk.img]
#   Terminal 2: gdb   (.gdbinit auto-connects and loads symbols)

set -euo pipefail

# ── Argument parsing ─────────────────────────────────────────────────────────

GDB_MODE=0
GPU_MODE=0
NET_MODE=1
MULTIBOOT_MODE=0
RELEASE_MODE=0
SMOKE_MODE=0
SMOKE_TIMEOUT=20
SMOKE_MARKER="TEST PASS: uart_smoke"
DISK=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gdb)       GDB_MODE=1; shift ;;
    --gpu)       GPU_MODE=1; shift ;;
    --no-net)    NET_MODE=0; shift ;;
    --multiboot) MULTIBOOT_MODE=1; shift ;;
    --release)   RELEASE_MODE=1; shift ;;
    --smoke)     SMOKE_MODE=1; NET_MODE=0; GPU_MODE=0; shift ;;
    --timeout)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -eq 0 ]]; then
        echo "[!] --timeout requires a positive integer number of seconds" >&2
        exit 2
      fi
      SMOKE_TIMEOUT="$2"
      shift 2
      ;;
    --timeout=*)
      SMOKE_TIMEOUT="${1#--timeout=}"
      if [[ ! "$SMOKE_TIMEOUT" =~ ^[0-9]+$ || "$SMOKE_TIMEOUT" -eq 0 ]]; then
        echo "[!] --timeout requires a positive integer number of seconds" >&2
        exit 2
      fi
      shift
      ;;
    --smoke-marker)
      if [[ $# -lt 2 ]]; then
        echo "[!] --smoke-marker requires a marker string" >&2
        exit 2
      fi
      SMOKE_MARKER="$2"
      shift 2
      ;;
    --smoke-marker=*) SMOKE_MARKER="${1#--smoke-marker=}"; shift ;;
    --*)
      echo "[!] Unknown option: $1" >&2
      exit 2
      ;;
    *)
      if [[ -n "$DISK" ]]; then
        echo "[!] Multiple disk images specified: '$DISK' and '$1'" >&2
        exit 2
      fi
      DISK="$1"
      shift
      ;;
  esac
done

if [[ "$SMOKE_MODE" -eq 1 && "$GDB_MODE" -eq 1 ]]; then
  echo "[!] --smoke cannot be combined with --gdb" >&2
  exit 2
fi

PROFILE=$([ "$RELEASE_MODE" -eq 1 ] && echo release || echo debug)

# ── Build ────────────────────────────────────────────────────────────────────

CARGO_FLAGS=(
  --target x86_64-unknown-none
  -Z build-std=core,alloc,compiler_builtins
  -Z build-std-features=compiler-builtins-mem
)
[[ "$RELEASE_MODE" -eq 1 ]] && CARGO_FLAGS+=(--release)

if [[ "$MULTIBOOT_MODE" -eq 1 ]]; then
  echo "[*] Building rustos (multiboot2, $PROFILE)..."
  CARGO_FLAGS+=(--no-default-features --features multiboot2_boot,sysv_ipc,namespaces)
  cargo build "${CARGO_FLAGS[@]}"
  KERNEL="target/x86_64-unknown-none/${PROFILE}/rustos"
else
  echo "[*] Building rustos (UEFI, $PROFILE)..."
  cargo build "${CARGO_FLAGS[@]}"
  EFI_IMAGE="target/esp/EFI/BOOT/BOOTX64.EFI"
  if [[ ! -f "$EFI_IMAGE" ]]; then
    echo "[*] $EFI_IMAGE not found — re-running cargo build to trigger objcopy..."
    cargo build "${CARGO_FLAGS[@]}"
  fi
fi

# ── Locate OVMF ──────────────────────────────────────────────────────────────

if [[ "$MULTIBOOT_MODE" -eq 0 ]]; then
  OVMF_CANDIDATES=(
    /usr/share/ovmf/OVMF.fd
    /usr/share/edk2/ovmf/OVMF.fd
    /usr/share/qemu/OVMF.fd
    /opt/homebrew/share/qemu/edk2-x86_64-code.fd
    /usr/share/edk2-ovmf/x64/OVMF.fd
  )
  OVMF=""
  for candidate in "${OVMF_CANDIDATES[@]}"; do
    [[ -f "$candidate" ]] && { OVMF="$candidate"; break; }
  done

  if [[ -z "$OVMF" ]]; then
    echo "[!] OVMF firmware not found. Install with:" >&2
    echo "      Debian/Ubuntu: sudo apt install ovmf" >&2
    echo "      Arch:          sudo pacman -S edk2-ovmf" >&2
    echo "      macOS:         brew install qemu" >&2
    echo "    Or export OVMF=/path/to/OVMF.fd and re-run." >&2
    exit 1
  fi
  echo "[*] OVMF: $OVMF"
fi

# ── Assemble QEMU arguments ──────────────────────────────────────────────────

QEMU_ARGS=(
  -machine q35
  -cpu qemu64,+xsave,+avx
  -m 256M
  -serial stdio
  -no-reboot
  -d guest_errors,cpu_reset
)

if [[ "$MULTIBOOT_MODE" -eq 1 ]]; then
  echo "[*] Boot: multiboot2 (-kernel)"
  QEMU_ARGS+=(-kernel "$KERNEL")
else
  echo "[*] Boot: UEFI (OVMF + BOOTX64.EFI)"
  QEMU_ARGS+=(
    -drive "if=pflash,format=raw,readonly=on,file=${OVMF}"
    -drive "if=virtio,format=raw,file=fat:rw:target/esp,label=ESP"
  )
fi

if [[ "$NET_MODE" -eq 1 ]]; then
  echo "[*] Network: virtio-net-pci (user-mode NAT, guest 10.0.2.15/24)"
  QEMU_ARGS+=(
    -netdev "user,id=net0,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15"
    -device "virtio-net-pci,netdev=net0,id=nic0"
  )
else
  echo "[*] Network: disabled"
fi

if [[ "$GPU_MODE" -eq 1 ]]; then
  echo "[*] GPU: virtio-gpu-pci + SDL display"
  QEMU_ARGS+=(-device virtio-gpu-pci -display sdl,gl=off)
else
  QEMU_ARGS+=(-display none)
fi

if [[ -n "$DISK" ]]; then
  echo "[*] Disk: $DISK"
  QEMU_ARGS+=(
    -drive "id=vblk0,file=${DISK},format=raw,if=none"
    -device "virtio-blk-pci,drive=vblk0,id=virtblk0"
  )
else
  echo "[*] No disk image — ramfs only"
fi

if [[ "$GDB_MODE" -eq 1 ]]; then
  QEMU_ARGS+=(-s -S)
  cat <<'GDB'

  ┌─────────────────────────────────────────────┐
  │ GDB mode: kernel halted at entry point.     │
  │ In another terminal:                        │
  │   gdb  (.gdbinit auto-connects + symbols)   │
  └─────────────────────────────────────────────┘

GDB
fi

if [[ "$SMOKE_MODE" -eq 1 ]]; then
  if ! command -v timeout >/dev/null 2>&1; then
    echo "[!] --smoke requires the 'timeout' command" >&2
    exit 1
  fi

  LOG_FILE=$(mktemp "${TMPDIR:-/tmp}/rustos-smoke.XXXXXX.log")
  trap 'rm -f "$LOG_FILE"' EXIT

  echo "[*] Starting QEMU smoke test (${SMOKE_TIMEOUT}s timeout)..."
  echo "[*] Waiting for serial marker: ${SMOKE_MARKER}"
  echo

  set +e
  timeout "${SMOKE_TIMEOUT}" qemu-system-x86_64 "${QEMU_ARGS[@]}" >"$LOG_FILE" 2>&1
  QEMU_STATUS=$?
  set -e

  cat "$LOG_FILE"

  if grep -Fq "$SMOKE_MARKER" "$LOG_FILE"; then
    echo "[*] Smoke marker found: ${SMOKE_MARKER}"
    exit 0
  fi

  echo "[!] Smoke marker not found before timeout: ${SMOKE_MARKER}" >&2
  if [[ "$QEMU_STATUS" -ne 124 ]]; then
    echo "[!] QEMU exited with status ${QEMU_STATUS}" >&2
  fi
  exit 1
fi

echo "[*] Starting QEMU..."
echo
exec qemu-system-x86_64 "${QEMU_ARGS[@]}"
