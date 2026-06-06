#!/usr/bin/env bash
# scripts/ci/qemu-run.sh — Unified QEMU launcher for rustos.
#
# Replaces run_qemu_x86_64.sh, run_qemu_aarch64.sh, and run_qemu_riscv.sh.
# All per-arch differences are handled internally; callers only set ARCH.
#
# Usage:
#   ARCH=<arch> ./scripts/ci/qemu-run.sh [options] [disk.img]
#
#   arch values: x86_64 | aarch64 | riscv64
#
# Options (all arches unless noted):
#   --boot <mode>   Boot protocol.  Per-arch defaults and valid modes:
#                     x86_64:  uefi (default) | multiboot
#                     aarch64: uefi (default)
#                     riscv64: uefi (default) | sbi
#   --release       Build with --release (default: debug)
#   --gpu           Add virtio-gpu and open SDL display (x86_64 only)
#   --gdb           Halt at entry, wait for GDB on :1234
#   --no-net        Disable virtio-net
#   --smoke         Headless: boot, assert SMOKE_MARKER, exit 0/1
#   --test          kmtest mode: build with --features kmtest,
#                   boot with init=/bin/kmtest, parse results.
#                   Implies --no-net, headless.
#   --timeout N     Smoke/test timeout in seconds
#                     (smoke default: 20; test default: 60)
#   --smoke-marker TEXT
#                   Serial string required in smoke mode
#                   (default: "TEST PASS: uart_smoke")
#
# Firmware search paths
# ──────────────────────────────────────────────────────────────────────────
#   x86_64 OVMF:
#     /usr/share/OVMF/OVMF_CODE.fd  (Ubuntu ovmf package — split layout)
#     /usr/share/ovmf/OVMF.fd
#     /usr/share/edk2/ovmf/OVMF.fd
#     /usr/share/qemu/OVMF.fd
#     /opt/homebrew/share/qemu/edk2-x86_64-code.fd
#     /usr/share/edk2-ovmf/x64/OVMF.fd
#   aarch64 EDK2:
#     /usr/share/qemu-efi-aarch64/QEMU_EFI.fd
#     /usr/share/edk2/aarch64/QEMU_EFI.fd
#     /usr/share/qemu/edk2-aarch64-code.fd
#     /opt/homebrew/share/qemu/edk2-aarch64-code.fd
#     /usr/local/share/qemu/edk2-aarch64-code.fd
#   riscv64 EDK2:
#     /usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd
#     /usr/share/edk2/riscv64/RISCV_VIRT_CODE.fd
#     /usr/share/qemu/edk2-riscv-code.fd
#     /opt/homebrew/share/qemu/edk2-riscv-code.fd
#     /usr/local/share/qemu/edk2-riscv-code.fd
#
# GDB workflow:
#   Terminal 1: ARCH=<arch> ./scripts/ci/qemu-run.sh --gdb [--boot sbi]
#   Terminal 2: gdb-multiarch (see per-arch banner printed on launch)
#
# Networking: user-mode NAT (no root needed).
#   Guest: 10.0.2.15/24, GW 10.0.2.2, DNS 10.0.2.3

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ────────────────────────────────────────────────────────────────────────────
# Architecture selection
# ────────────────────────────────────────────────────────────────────────────

ARCH="${ARCH:-}"
if [[ -z "$ARCH" ]]; then
  echo "[!] ARCH is required. Set ARCH=x86_64|aarch64|riscv64" >&2
  exit 2
fi

case "$ARCH" in
  x86_64|aarch64|riscv64) ;;
  *)
    echo "[!] Unsupported ARCH='${ARCH}'. Valid values: x86_64 aarch64 riscv64" >&2
    exit 2
    ;;
esac

# ────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ────────────────────────────────────────────────────────────────────────────

BOOT="uefi"
RELEASE_MODE=0
GDB_MODE=0
GPU_MODE=0
NET_MODE=1
SMOKE_MODE=0
TEST_MODE=0
SMOKE_TIMEOUT=20
TEST_TIMEOUT=60
SMOKE_MARKER="TEST PASS: uart_smoke"
DISK=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --boot)
      [[ $# -lt 2 ]] && { echo "[!] --boot requires a mode argument" >&2; exit 2; }
      BOOT="$2"; shift 2 ;;
    --boot=*)         BOOT="${1#--boot=}"; shift ;;
    --release)        RELEASE_MODE=1; shift ;;
    --gdb)            GDB_MODE=1; shift ;;
    --gpu)            GPU_MODE=1; shift ;;
    --no-net)         NET_MODE=0; shift ;;
    --smoke)          SMOKE_MODE=1; NET_MODE=0; GPU_MODE=0; shift ;;
    --test)           TEST_MODE=1; NET_MODE=0; GPU_MODE=0; shift ;;
    --timeout)
      if [[ $# -lt 2 || ! "$2" =~ ^[0-9]+$ || "$2" -eq 0 ]]; then
        echo "[!] --timeout requires a positive integer" >&2; exit 2
      fi
      SMOKE_TIMEOUT="$2"; TEST_TIMEOUT="$2"; shift 2 ;;
    --timeout=*)
      val="${1#--timeout=}"
      [[ ! "$val" =~ ^[0-9]+$ || "$val" -eq 0 ]] && \
        { echo "[!] --timeout requires a positive integer" >&2; exit 2; }
      SMOKE_TIMEOUT="$val"; TEST_TIMEOUT="$val"; shift ;;
    --smoke-marker)
      [[ $# -lt 2 ]] && { echo "[!] --smoke-marker requires a string" >&2; exit 2; }
      SMOKE_MARKER="$2"; shift 2 ;;
    --smoke-marker=*) SMOKE_MARKER="${1#--smoke-marker=}"; shift ;;
    --*) echo "[!] Unknown option: $1" >&2; exit 2 ;;
    *)
      [[ -n "$DISK" ]] && { echo "[!] Multiple disk images: '$DISK' and '$1'" >&2; exit 2; }
      DISK="$1"; shift ;;
  esac
done

# Validate mode combinations.
[[ "$SMOKE_MODE" -eq 1 && "$GDB_MODE" -eq 1 ]]  && { echo "[!] --smoke cannot be combined with --gdb" >&2; exit 2; }
[[ "$TEST_MODE"  -eq 1 && "$GDB_MODE" -eq 1 ]]  && { echo "[!] --test cannot be combined with --gdb" >&2; exit 2; }
[[ "$TEST_MODE"  -eq 1 && "$SMOKE_MODE" -eq 1 ]] && { echo "[!] --test cannot be combined with --smoke" >&2; exit 2; }
[[ "$GPU_MODE"   -eq 1 && "$ARCH" != "x86_64" ]] && { echo "[!] --gpu is only supported on x86_64" >&2; exit 2; }

# Validate --boot value per arch.
case "$ARCH" in
  x86_64)
    [[ "$BOOT" == "uefi" || "$BOOT" == "multiboot" ]] || \
      { echo "[!] x86_64 --boot must be 'uefi' or 'multiboot'" >&2; exit 2; } ;;
  aarch64)
    [[ "$BOOT" == "uefi" ]] || \
      { echo "[!] aarch64 only supports --boot uefi" >&2; exit 2; } ;;
  riscv64)
    [[ "$BOOT" == "uefi" || "$BOOT" == "sbi" ]] || \
      { echo "[!] riscv64 --boot must be 'uefi' or 'sbi'" >&2; exit 2; } ;;
esac

PROFILE=$([ "$RELEASE_MODE" -eq 1 ] && echo release || echo debug)

# ────────────────────────────────────────────────────────────────────────────
# Build
# ────────────────────────────────────────────────────────────────────────────

cd "$ROOT_DIR"

# Resolve cargo target and ELF path.
case "$ARCH" in
  x86_64)
    # Both UEFI and multiboot paths compile from the same x86_64-unknown-none
    # target with the default feature set; entry points (uefi_entry.rs vs
    # multiboot2_entry.rs) are unconditionally compiled in src/main.rs and
    # selected by the firmware/loader, not by Cargo features.
    CARGO_TARGET="x86_64-unknown-none"
    CARGO_EXTRA_FLAGS=()
    KERNEL_ELF="target/${CARGO_TARGET}/${PROFILE}/rustos"
    QEMU_BIN="qemu-system-x86_64"
    ;;
  aarch64)
    CARGO_TARGET="${ROOT_DIR}/targets/aarch64-kernel.json"
    CARGO_EXTRA_FLAGS=()
    KERNEL_ELF="target/aarch64-kernel/${PROFILE}/rustos"
    QEMU_BIN="qemu-system-aarch64"
    ;;
  riscv64)
    if [[ "$BOOT" == "sbi" ]]; then
      CARGO_TARGET="riscv64gc-unknown-none-elf"
      CARGO_EXTRA_FLAGS=()
    else
      CARGO_TARGET="${ROOT_DIR}/targets/riscv64-kernel.json"
      CARGO_EXTRA_FLAGS=()
    fi
    KERNEL_ELF="target/riscv64gc-unknown-none-elf/${PROFILE}/rustos"
    QEMU_BIN="qemu-system-riscv64"
    ;;
esac

CARGO_BUILD_FLAGS=(
  --target "$CARGO_TARGET"
  "${CARGO_EXTRA_FLAGS[@]}"
  -Z build-std=core,alloc,compiler_builtins
  -Z build-std-features=compiler-builtins-mem
)
[[ "$RELEASE_MODE" -eq 1 ]] && CARGO_BUILD_FLAGS+=(--release)
[[ "$TEST_MODE"    -eq 1 ]] && CARGO_BUILD_FLAGS+=(--features kmtest)

echo "[*] Building rustos (${ARCH}, ${BOOT}, ${PROFILE}${TEST_MODE:+, kmtest})..."
cargo build "${CARGO_BUILD_FLAGS[@]}"

if [[ ! -f "$KERNEL_ELF" ]]; then
  echo "[!] ELF not found at ${KERNEL_ELF}" >&2
  exit 1
fi
echo "[*] Kernel: $(file "${KERNEL_ELF}")"

# Build the userspace kmtest runner when in --test mode.
if [[ "$TEST_MODE" -eq 1 ]]; then
  echo "[*] Building kmtest userspace runner (${ARCH})..."
  (cd "${ROOT_DIR}/userspace" && make ARCH="${ARCH}" kmtest 2>&1)
fi

# ────────────────────────────────────────────────────────────────────────────
# Firmware lookup (UEFI modes)
# ────────────────────────────────────────────────────────────────────────────

FW_CODE=""
FW_VARS=""

find_firmware() {
  # Usage: find_firmware FW_CODE_VAR FW_VARS_VAR candidate1 candidate2 ...
  local -n _code_ref=$1; local -n _vars_ref=$2; shift 2
  for p in "$@"; do
    if [[ -f "$p" ]]; then
      _code_ref="$p"
      local vars_candidate="${p/CODE/VARS}"
      if [[ -f "$vars_candidate" ]]; then
        _vars_ref="$vars_candidate"
      fi
      return 0
    fi
  done
  return 1
}

if [[ "$BOOT" == "uefi" ]]; then
  case "$ARCH" in
    x86_64)
      # Split-layout (Ubuntu ovmf): CODE + VARS are separate files.
      if [[ -f "/usr/share/OVMF/OVMF_CODE.fd" ]]; then
        FW_CODE="/usr/share/OVMF/OVMF_CODE.fd"
        FW_VARS_SRC="/usr/share/OVMF/OVMF_VARS.fd"
        FW_VARS_COPY="/tmp/OVMF_VARS_${ARCH}.fd"
        cp "$FW_VARS_SRC" "$FW_VARS_COPY"
        FW_VARS="$FW_VARS_COPY"
      else
        find_firmware FW_CODE FW_VARS \
          /usr/share/ovmf/OVMF.fd \
          /usr/share/edk2/ovmf/OVMF.fd \
          /usr/share/qemu/OVMF.fd \
          /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
          /usr/share/edk2-ovmf/x64/OVMF.fd || true
      fi
      if [[ -z "$FW_CODE" ]]; then
        echo "[!] OVMF not found. Install: sudo apt install ovmf" >&2; exit 1
      fi
      echo "[*] OVMF: $FW_CODE"
      ;;
    aarch64)
      find_firmware FW_CODE FW_VARS \
        /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
        /usr/share/edk2/aarch64/QEMU_EFI.fd \
        /usr/share/qemu/edk2-aarch64-code.fd \
        /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
        /usr/local/share/qemu/edk2-aarch64-code.fd || true
      if [[ -z "$FW_CODE" ]]; then
        echo "[!] EDK2 AArch64 not found. Install: sudo apt install qemu-efi-aarch64" >&2; exit 1
      fi
      # Create a writable VARS file if none came from find_firmware.
      if [[ -z "$FW_VARS" ]]; then
        FW_VARS="${ROOT_DIR}/edk2-aarch64-vars.fd"
        [[ -f "$FW_VARS" ]] || dd if=/dev/zero of="$FW_VARS" bs=1M count=64 2>/dev/null
      fi
      echo "[*] EDK2 AArch64: $FW_CODE"
      ;;
    riscv64)
      find_firmware FW_CODE FW_VARS \
        /usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd \
        /usr/share/edk2/riscv64/RISCV_VIRT_CODE.fd \
        /usr/share/qemu/edk2-riscv-code.fd \
        /opt/homebrew/share/qemu/edk2-riscv-code.fd \
        /usr/local/share/qemu/edk2-riscv-code.fd || true
      if [[ -z "$FW_CODE" ]]; then
        echo "[!] EDK2 RISC-V not found. Install: sudo apt install qemu-efi-riscv64" >&2; exit 1
      fi
      if [[ -z "$FW_VARS" ]]; then
        FW_VARS="${ROOT_DIR}/edk2-riscv-vars.fd"
        [[ -f "$FW_VARS" ]] || dd if=/dev/zero of="$FW_VARS" bs=1M count=64 2>/dev/null
      fi
      echo "[*] EDK2 RISC-V: $FW_CODE"
      ;;
  esac
fi

# ────────────────────────────────────────────────────────────────────────────
# Assemble QEMU args
# ────────────────────────────────────────────────────────────────────────────

QEMU_ARGS=(
  -serial stdio
  -no-reboot
  -d guest_errors,cpu_reset
)

case "$ARCH" in
  x86_64)
    QEMU_ARGS+=(-machine q35 -cpu qemu64,+xsave,+avx -m 256M)
    if [[ "$BOOT" == "multiboot" ]]; then
      echo "[*] Boot: multiboot2 (-kernel)"
      QEMU_ARGS+=(-kernel "$KERNEL_ELF")
    else
      echo "[*] Boot: x86_64 UEFI (OVMF)"
      QEMU_ARGS+=(
        -drive "if=pflash,format=raw,readonly=on,file=${FW_CODE}"
        -drive "if=pflash,format=raw,file=${FW_VARS}"
        -drive "if=virtio,format=raw,file=fat:rw:${ROOT_DIR}/target/esp,label=ESP"
      )
    fi
    ;;
  aarch64)
    QEMU_ARGS+=(-machine virt -cpu cortex-a57 -m 512M)
    echo "[*] Boot: AArch64 UEFI (EDK2)"
    QEMU_ARGS+=(
      -drive "if=pflash,unit=0,format=raw,file=${FW_CODE},readonly=on"
      -drive "if=pflash,unit=1,format=raw,file=${FW_VARS}"
      -drive "file=fat:rw:${ROOT_DIR}/esp/,format=raw,if=virtio"
    )
    ;;
  riscv64)
    QEMU_ARGS+=(-machine virt -cpu rv64 -m 256M)
    if [[ "$BOOT" == "sbi" ]]; then
      echo "[*] Boot: RISC-V SBI (OpenSBI)"
      QEMU_ARGS+=(-bios default -kernel "$KERNEL_ELF")
    else
      echo "[*] Boot: RISC-V UEFI (EDK2)"
      QEMU_ARGS+=(
        -drive "if=pflash,unit=0,format=raw,file=${FW_CODE},readonly=on"
        -drive "if=pflash,unit=1,format=raw,file=${FW_VARS}"
        -drive "file=fat:rw:${ROOT_DIR}/esp/,format=raw,if=virtio"
      )
    fi
    ;;
esac

# kmtest: pass init= and attach cpio initrd.
if [[ "$TEST_MODE" -eq 1 ]]; then
  echo "[*] kmtest mode: init=/bin/kmtest"
  KMTEST_CPIO=$(mktemp "${TMPDIR:-/tmp}/rustos-initrd-${ARCH}.XXXXXX.cpio")
  trap 'rm -f "$KMTEST_CPIO"' EXIT
  find "${ROOT_DIR}/userspace/build/${ARCH}" -mindepth 1 \
    | cpio -o -H newc --quiet > "$KMTEST_CPIO"
  QEMU_ARGS+=(-initrd "$KMTEST_CPIO" -append "init=/bin/kmtest")
fi

# Networking.
if [[ "$NET_MODE" -eq 1 ]]; then
  # x86_64 uses PCI bus; ARM and RISC-V virt machines use MMIO.
  if [[ "$ARCH" == "x86_64" ]]; then
    NIC_DEVICE="virtio-net-pci"
  else
    NIC_DEVICE="virtio-net-device"
  fi
  echo "[*] Network: ${NIC_DEVICE} (user-mode NAT, guest 10.0.2.15/24)"
  QEMU_ARGS+=(
    -netdev "user,id=net0,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15"
    -device "${NIC_DEVICE},netdev=net0,id=nic0"
  )
else
  echo "[*] Network: disabled"
fi

# GPU (x86_64 only, already validated above).
if [[ "$GPU_MODE" -eq 1 ]]; then
  echo "[*] GPU: virtio-gpu-pci + SDL display"
  QEMU_ARGS+=(-device virtio-gpu-pci -display sdl,gl=off)
else
  QEMU_ARGS+=(-display none)
fi

# Disk image.
if [[ -n "$DISK" ]]; then
  echo "[*] Disk: $DISK"
  if [[ "$ARCH" == "x86_64" ]]; then
    DISK_DEVICE="virtio-blk-pci"
  else
    DISK_DEVICE="virtio-blk-device"
  fi
  QEMU_ARGS+=(
    -drive "id=vblk0,file=${DISK},format=raw,if=none"
    -device "${DISK_DEVICE},drive=vblk0,id=virtblk0"
  )
else
  echo "[*] No disk image — ramfs only"
fi

# GDB.
if [[ "$GDB_MODE" -eq 1 ]]; then
  QEMU_ARGS+=(-gdb tcp::1234 -S)
  case "$ARCH" in
    x86_64)
      SYM_FILE="target/x86_64-unknown-none/${PROFILE}/rustos"
      GDB_ARCH_FLAG=""
      GDB_BIN="gdb"
      ;;
    aarch64)
      SYM_FILE="target/aarch64-kernel/${PROFILE}/rustos"
      GDB_ARCH_FLAG="-ex 'set arch aarch64'"
      GDB_BIN="gdb-multiarch"
      ;;
    riscv64)
      SYM_FILE="target/riscv64gc-unknown-none-elf/${PROFILE}/rustos"
      GDB_ARCH_FLAG="-ex 'set arch riscv:rv64'"
      GDB_BIN="gdb-multiarch"
      ;;
  esac
  cat <<GDB

  ┌───────────────────────────────────────────────┐
  │ GDB mode: ${ARCH} kernel halted at entry.         │
  │ In another terminal:                              │
  │   ${GDB_BIN} \\                                    │
  │     ${GDB_ARCH_FLAG} \\                            │
  │     -ex 'file ${SYM_FILE}' \\                     │
  │     -ex 'target remote :1234'                     │
  └───────────────────────────────────────────────┘

GDB
fi

# ────────────────────────────────────────────────────────────────────────────
# Smoke mode
# ────────────────────────────────────────────────────────────────────────────

if [[ "$SMOKE_MODE" -eq 1 ]]; then
  LOG_FILE=$(mktemp "${TMPDIR:-/tmp}/rustos-smoke-${ARCH}.XXXXXX.log")
  trap 'rm -f "$LOG_FILE"' EXIT
  echo "[*] Smoke test (${ARCH}, ${SMOKE_TIMEOUT}s): waiting for '${SMOKE_MARKER}'"
  set +e
  timeout "${SMOKE_TIMEOUT}" "$QEMU_BIN" "${QEMU_ARGS[@]}" >"$LOG_FILE" 2>&1
  QEMU_STATUS=$?
  set -e
  cat "$LOG_FILE"
  if grep -Fq "$SMOKE_MARKER" "$LOG_FILE"; then
    echo "[✓] Smoke marker found."; exit 0
  fi
  echo "[!] Smoke marker not found before timeout." >&2
  [[ "$QEMU_STATUS" -ne 124 ]] && echo "[!] QEMU exited with status ${QEMU_STATUS}" >&2
  exit 1
fi

# ────────────────────────────────────────────────────────────────────────────
# Test (kmtest) mode
#
# Exit-code contract:
#   0  all tests passed
#   1  one or more tests failed
#   2  harness error (summary line missing — not built with --features kmtest)
# ────────────────────────────────────────────────────────────────────────────

if [[ "$TEST_MODE" -eq 1 ]]; then
  LOG_FILE=$(mktemp "${TMPDIR:-/tmp}/rustos-kmtest-${ARCH}.XXXXXX.log")
  trap 'rm -f "$LOG_FILE"' EXIT
  echo "[*] kmtest run (${ARCH}, ${TEST_TIMEOUT}s timeout)..."
  set +e
  timeout "${TEST_TIMEOUT}" "$QEMU_BIN" "${QEMU_ARGS[@]}" >"$LOG_FILE" 2>&1
  QEMU_STATUS=$?
  set -e
  echo "---------- serial log (${ARCH}) ----------"
  cat "$LOG_FILE"
  echo "------------------------------------------"
  echo
  echo "[*] kmtest results (${ARCH}):"
  grep '^  \(PASS\|FAIL\)' "$LOG_FILE" || true
  SUMMARY=$(grep '^kmtest: .* passed' "$LOG_FILE" || true)
  echo "${SUMMARY:-[!] no summary line found}"
  if echo "$SUMMARY" | grep -qE '^kmtest: ([0-9]+)/\1 passed$'; then
    echo "[✓] All ${ARCH} kmtests passed."; exit 0
  fi
  if grep -q '^  FAIL ' "$LOG_FILE"; then
    NFAIL=$(grep -c '^  FAIL ' "$LOG_FILE" || true)
    echo "[!] ${NFAIL} test(s) failed on ${ARCH}." >&2; exit 1
  fi
  if [[ -z "$SUMMARY" ]]; then
    echo "[!] kmtest summary not found (built with --features kmtest?)" >&2; exit 2
  fi
  echo "[!] Some tests failed." >&2; exit 1
fi

# ────────────────────────────────────────────────────────────────────────────
# Interactive mode
# ────────────────────────────────────────────────────────────────────────────

echo "[*] Starting ${QEMU_BIN} (${ARCH}, ${BOOT}, ${PROFILE})..."
echo
exec "$QEMU_BIN" "${QEMU_ARGS[@]}"
