#!/usr/bin/env bash
# run_qemu_aarch64.sh — Build rustos (AArch64) and launch it under QEMU.
#
# Usage:
#   ./run_qemu_aarch64.sh [options] [disk.img]
#
# Options:
#   --gdb      Halt at entry, wait for GDB on :1234
#   --no-net   Disable virtio-net
#   --test     Run the kmtest suite: builds with --features kmtest,
#              boots with init=/bin/kmtest, captures serial output,
#              and exits with the kmtest runner's exit code.
#              Implies --no-net, headless.
#   --timeout N  Test timeout in seconds (default: 60)
#
# Boot mode: UEFI only — EDK2 AArch64 pflash + vvfat ESP.
#
# Networking: virtio-net-device (MMIO, user-mode NAT, guest 10.0.2.15/24).
#
# EDK2 firmware search order:
#   /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
#   /usr/share/edk2/aarch64/QEMU_EFI.fd
#   /usr/share/qemu/edk2-aarch64-code.fd
#   /opt/homebrew/share/qemu/edk2-aarch64-code.fd
#   /usr/local/share/qemu/edk2-aarch64-code.fd
#
# GDB workflow:
#   Terminal 1: ./run_qemu_aarch64.sh --gdb [disk.img]
#   Terminal 2: gdb-multiarch \
#                 -ex 'set arch aarch64' \
#                 -ex 'file target/aarch64-uefi/release/rustos.efi' \
#                 -ex 'target remote :1234'
#
# Requirements:
#   qemu-system-aarch64
#   sudo apt install qemu-efi-aarch64   # Debian/Ubuntu
#   brew install qemu                   # macOS

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Argument parsing ──────────────────────────────────────────────────────────

GDB_MODE=0
NET_MODE=1
TEST_MODE=0
TEST_TIMEOUT=60
DISK=""

for arg in "$@"; do
  case "$arg" in
    --gdb)       GDB_MODE=1 ;;
    --no-net)    NET_MODE=0 ;;
    --test)      TEST_MODE=1; NET_MODE=0 ;;
    --timeout=*) TEST_TIMEOUT="${arg#--timeout=}" ;;
    --timeout)   ;; # handled via positional scan below
    *)           DISK="$arg" ;;
  esac
done

ARGS=("$@")
for ((i=0; i<${#ARGS[@]}; i++)); do
  if [[ "${ARGS[$i]}" == "--timeout" && $((i+1)) -lt ${#ARGS[@]} ]]; then
    TEST_TIMEOUT="${ARGS[$((i+1))]}"
  fi
done

if [[ "$TEST_MODE" -eq 1 && "$GDB_MODE" -eq 1 ]]; then
  echo "[!] --test cannot be combined with --gdb" >&2
  exit 2
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

add_net_args() {
  local -n _arr=$1
  if [[ "$NET_MODE" -eq 1 ]]; then
    echo "[*] Network: virtio-net-device (MMIO, user-mode NAT, guest 10.0.2.15/24)"
    _arr+=(
      -netdev "user,id=net0,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15"
      -device "virtio-net-device,netdev=net0,id=nic0"
    )
  else
    echo "[*] Network: disabled"
  fi
}

gdb_banner() {
  cat <<GDB

  ┌─────────────────────────────────────────────────┐
  │ GDB mode: kernel halted at entry point.           │
  │ In another terminal:                              │
  │   gdb-multiarch \\                                │
  │     -ex 'set arch aarch64' \\                     │
  │     -ex 'file target/aarch64-uefi/release/rustos.efi' \\
  │     -ex 'target remote :1234'                     │
  └─────────────────────────────────────────────────┘

GDB
}

run_kmtest() {
  local qemu_bin=$1; shift
  local -n _qargs=$1; shift

  if ! command -v timeout >/dev/null 2>&1; then
    echo "[!] --test requires the 'timeout' command" >&2
    exit 1
  fi

  LOG_FILE=$(mktemp "${TMPDIR:-/tmp}/rustos-kmtest.XXXXXX.log")
  trap 'rm -f "$LOG_FILE"' EXIT

  echo "[*] Starting QEMU kmtest run (${TEST_TIMEOUT}s timeout)..."
  echo

  set +e
  timeout "${TEST_TIMEOUT}" "$qemu_bin" "${_qargs[@]}" >"$LOG_FILE" 2>&1
  QEMU_STATUS=$?
  set -e

  echo "---------- serial log ----------"
  cat "$LOG_FILE"
  echo "--------------------------------"

  echo
  echo "[*] kmtest results:"
  grep '^  \(PASS\|FAIL\)' "$LOG_FILE" || true
  SUMMARY=$(grep '^kmtest: .* passed' "$LOG_FILE" || true)
  echo "${SUMMARY:-[!] no summary line found}"

  if echo "$SUMMARY" | grep -qE '^kmtest: ([0-9]+)/\1 passed$'; then
    echo "[✓] All tests passed."
    exit 0
  fi

  if grep -q '^  FAIL ' "$LOG_FILE"; then
    NFAIL=$(grep -c '^  FAIL ' "$LOG_FILE" || true)
    echo "[!] ${NFAIL} test(s) failed." >&2
    exit 1
  fi

  if [[ -z "$SUMMARY" ]]; then
    echo "[!] kmtest summary not found in serial output" >&2
    echo "    (was the kernel built with --features kmtest?)" >&2
    exit 2
  fi

  echo "[!] Some tests failed (see summary above)." >&2
  exit 1
}

# ── Build ─────────────────────────────────────────────────────────────────────

BUILD_FLAGS=()
[[ "$TEST_MODE" -eq 1 ]] && BUILD_FLAGS+=(--features kmtest)
echo "[*] Building rustos (AArch64 UEFI release${TEST_MODE:+ + kmtest})..."
bash "$SCRIPT_DIR/build_aarch64.sh" "${BUILD_FLAGS[@]}"

if [[ "$TEST_MODE" -eq 1 ]]; then
  echo "[*] Building kmtest userspace runner..."
  (cd "$SCRIPT_DIR/userspace" && make ARCH=aarch64 kmtest 2>&1)
fi

# ── EDK2 firmware ─────────────────────────────────────────────────────────────

FW_SEARCH=(
  /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
  /usr/share/edk2/aarch64/QEMU_EFI.fd
  /usr/share/qemu/edk2-aarch64-code.fd
  /opt/homebrew/share/qemu/edk2-aarch64-code.fd
  /usr/local/share/qemu/edk2-aarch64-code.fd
)
FW_CODE=""
for p in "${FW_SEARCH[@]}"; do
  [[ -f "$p" ]] && { FW_CODE="$p"; break; }
done

if [[ -z "$FW_CODE" ]]; then
  echo "[!] EDK2 AArch64 firmware not found. Install with:" >&2
  echo "      sudo apt install qemu-efi-aarch64   # Debian/Ubuntu" >&2
  echo "      brew install qemu                   # macOS" >&2
  exit 1
fi

FW_VARS="$SCRIPT_DIR/edk2-aarch64-vars.fd"
if [[ ! -f "$FW_VARS" ]]; then
  VARS_TEMPLATE="${FW_CODE/CODE/VARS}"
  if [[ -f "$VARS_TEMPLATE" ]]; then
    cp "$VARS_TEMPLATE" "$FW_VARS"
  else
    dd if=/dev/zero of="$FW_VARS" bs=1M count=64 2>/dev/null
  fi
fi

# ── QEMU args ─────────────────────────────────────────────────────────────────

QEMU_ARGS=(
  -machine virt
  -cpu cortex-a57
  -m 512M
  -drive "if=pflash,unit=0,format=raw,file=${FW_CODE},readonly=on"
  -drive "if=pflash,unit=1,format=raw,file=${FW_VARS}"
  -drive "file=fat:rw:${SCRIPT_DIR}/esp/,format=raw,if=virtio"
  -serial stdio
  -display none
  -no-reboot
  -d guest_errors,cpu_reset
)

[[ "$TEST_MODE" -eq 1 ]] && QEMU_ARGS+=(-append "init=/bin/kmtest")

add_net_args QEMU_ARGS

if [[ -n "$DISK" ]]; then
  echo "[*] Disk: $DISK"
  QEMU_ARGS+=(
    -drive "id=vblk0,file=${DISK},format=raw,if=none"
    -device "virtio-blk-device,drive=vblk0,id=virtblk0"
  )
else
  echo "[*] No disk image — ramfs only"
fi

[[ "$GDB_MODE" -eq 1 ]] && { QEMU_ARGS+=(-gdb tcp::1234 -S); gdb_banner; }

if [[ "$TEST_MODE" -eq 1 ]]; then
  run_kmtest qemu-system-aarch64 QEMU_ARGS
fi

echo "[*] Starting QEMU (AArch64 UEFI)..."
echo "    Firmware : $FW_CODE"
echo "    ESP      : $SCRIPT_DIR/esp/EFI/BOOT/BOOTAA64.EFI"
echo
exec qemu-system-aarch64 "${QEMU_ARGS[@]}"
