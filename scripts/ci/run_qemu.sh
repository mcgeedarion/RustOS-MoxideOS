#!/usr/bin/env bash
# scripts/ci/run_qemu.sh — Unified QEMU launcher for RustOS.
#
# Canonical run contract:
#   aarch64: uefi | baremetal
#   riscv64: uefi | sbi
#   x86_64:  uefi
#
# Canonical ESP path:
#   target/esp/<arch>/EFI/BOOT/BOOT*.EFI
#
# Default ARCH is x86_64.
# Override with:  ARCH=riscv64 ./scripts/ci/run_qemu.sh --boot uefi ...

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCH="${ARCH:-x86_64}"
BOOT="uefi"
RELEASE_MODE=0
GDB_MODE=0
GPU_MODE=0
NET_MODE=1
SMOKE_MODE=0
TEST_MODE=0
TIMEOUT_SECS=60
SMOKE_MARKER="SMOKE OK: userspace_smoke"
DISK=""

usage() {
  cat <<'USAGE'
Usage:
  ARCH=<aarch64|riscv64|x86_64> ./scripts/ci/run_qemu.sh [options] [disk.img]

Options:
  --boot <uefi|sbi|baremetal>
  --release
  --gpu               x86_64 only
  --gdb               wait for GDB on :1234
  --no-net
  --smoke             headless smoke run; waits for smoke marker
  --test              headless kmtest run; parses PASS/FAIL summary
  --timeout <seconds>
  --smoke-marker <text>
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --boot) BOOT="${2:?--boot requires a mode}"; shift 2 ;;
    --boot=*) BOOT="${1#--boot=}"; shift ;;
    --release) RELEASE_MODE=1; shift ;;
    --gdb) GDB_MODE=1; shift ;;
    --gpu) GPU_MODE=1; shift ;;
    --no-net) NET_MODE=0; shift ;;
    --smoke) SMOKE_MODE=1; NET_MODE=0; GPU_MODE=0; shift ;;
    --test) TEST_MODE=1; NET_MODE=0; GPU_MODE=0; shift ;;
    --timeout) TIMEOUT_SECS="${2:?--timeout requires seconds}"; shift 2 ;;
    --timeout=*) TIMEOUT_SECS="${1#--timeout=}"; shift ;;
    --smoke-marker) SMOKE_MARKER="${2:?--smoke-marker requires text}"; shift 2 ;;
    --smoke-marker=*) SMOKE_MARKER="${1#--smoke-marker=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    --*) echo "[!] Unknown option: $1" >&2; usage; exit 2 ;;
    *)
      [[ -n "$DISK" ]] && { echo "[!] Multiple disk images: '$DISK' and '$1'" >&2; exit 2; }
      DISK="$1"; shift ;;
  esac
done

case "$ARCH" in
  aarch64|riscv64|x86_64) ;;
  *) echo "[!] Unsupported ARCH='$ARCH'" >&2; exit 2 ;;
esac

case "$ARCH:$BOOT" in
  aarch64:uefi|aarch64:baremetal|riscv64:uefi|riscv64:sbi|x86_64:uefi) ;;
  *) echo "[!] Unsupported run contract: ARCH=$ARCH --boot $BOOT" >&2; exit 2 ;;
esac

[[ "$SMOKE_MODE" -eq 1 && "$TEST_MODE" -eq 1 ]] && { echo "[!] --smoke and --test are mutually exclusive" >&2; exit 2; }
[[ "$GDB_MODE" -eq 1 && ( "$SMOKE_MODE" -eq 1 || "$TEST_MODE" -eq 1 ) ]] && { echo "[!] --gdb cannot be combined with --smoke/--test" >&2; exit 2; }
[[ "$GPU_MODE" -eq 1 && "$ARCH" != "x86_64" ]] && { echo "[!] --gpu is only supported on x86_64" >&2; exit 2; }
[[ ! "$TIMEOUT_SECS" =~ ^[0-9]+$ || "$TIMEOUT_SECS" -eq 0 ]] && { echo "[!] --timeout requires a positive integer" >&2; exit 2; }

PROFILE=$([[ "$RELEASE_MODE" -eq 1 ]] && echo release || echo debug)
ESP_ROOT="${ROOT_DIR}/target/esp/${ARCH}"
ESP_BOOT_DIR="${ESP_ROOT}/EFI/BOOT"

case "$ARCH:$BOOT" in
  aarch64:uefi) CARGO_TARGET="${ROOT_DIR}/targets/aarch64-uefi-loader.json"; TARGET_DIR="aarch64-uefi-loader"; EFI_NAME="BOOTAA64.EFI" ;;
  aarch64:baremetal) CARGO_TARGET="${ROOT_DIR}/targets/aarch64-kernel.json"; TARGET_DIR="aarch64-kernel" ;;
  riscv64:uefi) CARGO_TARGET="${ROOT_DIR}/targets/riscv64-uefi-loader.json"; TARGET_DIR="riscv64-uefi-loader"; EFI_NAME="BOOTRISCV64.EFI" ;;
  riscv64:sbi) CARGO_TARGET="riscv64gc-unknown-none-elf"; TARGET_DIR="riscv64gc-unknown-none-elf" ;;
  x86_64:uefi) CARGO_TARGET="${ROOT_DIR}/targets/x86_64-kernel.json"; TARGET_DIR="x86_64-kernel"; EFI_NAME="BOOTX64.EFI" ;;
esac

pick_kernel_artifact() {
  local base="${ROOT_DIR}/target/${TARGET_DIR}/${PROFILE}/rustos"

  if [[ "$BOOT" == "uefi" && "$ARCH" != "x86_64" && -f "${base}.efi" ]]; then
    echo "${base}.efi"
    return 0
  fi

  if [[ -f "$base" ]]; then
    echo "$base"
    return 0
  fi

  if [[ -f "${base}.efi" ]]; then
    echo "${base}.efi"
    return 0
  fi

  return 1
}

CARGO_FLAGS=(build --target "$CARGO_TARGET" -Z build-std=core,alloc,compiler_builtins -Z build-std-features=compiler-builtins-mem -Z json-target-spec)
[[ "$RELEASE_MODE" -eq 1 ]] && CARGO_FLAGS+=(--release)
if [[ "$TEST_MODE" -eq 1 ]]; then
  CARGO_FLAGS+=(--features kmtest)
elif [[ "$BOOT" == "uefi" ]]; then
  CARGO_FLAGS+=(--features uefi_boot)
fi

cd "$ROOT_DIR"
echo "[*] Building rustos (${ARCH}, ${BOOT}, ${PROFILE})..."
cargo "${CARGO_FLAGS[@]}"
KERNEL_ELF="$(pick_kernel_artifact)" || {
  echo "[!] Kernel artifact not found under ${ROOT_DIR}/target/${TARGET_DIR}/${PROFILE}" >&2
  exit 1
}

find_objcopy() {
  if [[ -n "${OBJCOPY:-}" ]]; then echo "$OBJCOPY"; return 0; fi
  for tool in llvm-objcopy rust-objcopy objcopy; do
    command -v "$tool" >/dev/null 2>&1 && { echo "$tool"; return 0; }
  done
  return 1
}

if [[ "$BOOT" == "uefi" ]]; then
  mkdir -p "$ESP_BOOT_DIR"
  EFI_IMAGE="${ESP_BOOT_DIR}/${EFI_NAME}"
  if [[ "$ARCH" == "x86_64" ]]; then
    OBJCOPY_BIN="$(find_objcopy)" || { echo "[!] objcopy is required for x86_64 UEFI" >&2; exit 1; }
    "$OBJCOPY_BIN" --target=efi-app-x86_64 --subsystem=10 "$KERNEL_ELF" "$EFI_IMAGE"
  else
    cp "$KERNEL_ELF" "$EFI_IMAGE"
  fi
  echo "[*] ESP: ${EFI_IMAGE}"
fi

find_existing_file() {
  for path in "$@"; do
    [[ -f "$path" ]] && { echo "$path"; return 0; }
  done
  return 1
}

FW_CODE=""
FW_VARS=""
FW_KIND=""
if [[ "$BOOT" == "uefi" ]]; then
  case "$ARCH" in
    aarch64)
      FW_KIND="edk2"
      FW_CODE="$(find_existing_file \
        /usr/share/AAVMF/AAVMF_CODE.fd \
        /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
        /usr/share/edk2/aarch64/QEMU_EFI.fd \
        /usr/share/qemu/edk2-aarch64-code.fd \
        /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
        /usr/local/share/qemu/edk2-aarch64-code.fd)" || {
        echo "[!] AArch64 EDK2 not found" >&2
        exit 1
      }
      FW_VARS="${ROOT_DIR}/target/edk2-aarch64-vars.fd"
      AARCH64_VARS_TEMPLATE="$(find_existing_file /usr/share/AAVMF/AAVMF_VARS.fd || true)"
      if [[ -n "$AARCH64_VARS_TEMPLATE" ]]; then
        [[ -f "$FW_VARS" ]] || cp "$AARCH64_VARS_TEMPLATE" "$FW_VARS"
      else
        [[ -f "$FW_VARS" ]] || dd if=/dev/zero of="$FW_VARS" bs=1M count=64 2>/dev/null
      fi
      ;;
    riscv64)
      if FW_CODE="$(find_existing_file \
        /usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd \
        /usr/share/edk2/riscv64/RISCV_VIRT_CODE.fd \
        /usr/share/qemu/edk2-riscv-code.fd \
        /usr/share/qemu/edk2-riscv64-code.fd \
        /opt/homebrew/share/qemu/edk2-riscv-code.fd \
        /usr/local/share/qemu/edk2-riscv-code.fd)"; then
        FW_KIND="edk2"
        FW_VARS="${ROOT_DIR}/target/edk2-riscv-vars.fd"
        [[ -f "$FW_VARS" ]] || dd if=/dev/zero of="$FW_VARS" bs=1M count=64 2>/dev/null
      elif FW_CODE="$(find_existing_file \
        /usr/lib/u-boot/qemu-riscv64_smode/uboot.elf \
        /usr/lib/u-boot/qemu-riscv64/uboot.elf \
        /usr/share/u-boot/qemu-riscv64_smode/uboot.elf \
        /usr/share/u-boot/qemu-riscv64/uboot.elf \
        /usr/lib/u-boot/qemu-riscv64_smode/u-boot.bin \
        /usr/share/u-boot/qemu-riscv64_smode/u-boot.bin)"; then
        FW_KIND="uboot"
      else
        echo "[!] RISC-V UEFI firmware not found. Install qemu-efi-riscv64 or u-boot-qemu." >&2
        exit 1
      fi
      ;;
    x86_64)
      FW_KIND="edk2"
      if [[ -f /usr/share/OVMF/OVMF_CODE.fd ]]; then
        FW_CODE=/usr/share/OVMF/OVMF_CODE.fd
        FW_VARS=/tmp/OVMF_VARS_${ARCH}.fd
        cp /usr/share/OVMF/OVMF_VARS.fd "$FW_VARS"
      else
        FW_CODE="$(find_existing_file /usr/share/ovmf/OVMF.fd /usr/share/edk2/ovmf/OVMF.fd /usr/share/qemu/OVMF.fd /opt/homebrew/share/qemu/edk2-x86_64-code.fd /usr/share/edk2-ovmf/x64/OVMF.fd)" || { echo "[!] OVMF not found" >&2; exit 1; }
        FW_VARS="${FW_CODE/CODE/VARS}"
        [[ -f "$FW_VARS" ]] || FW_VARS="$FW_CODE"
      fi
      ;;
  esac
fi

# -m 256M floor for all arches; -no-reboot -no-shutdown ensures immediate exit
# on triple fault rather than spinning in a reset loop.
# -serial stdio streams kernel output to stdout for log capture; never use
# -serial mon:stdio in CI (it mixes monitor and serial into the same stream).
case "$ARCH" in
  aarch64) QEMU_BIN=qemu-system-aarch64; QEMU_ARGS=(-serial stdio -no-reboot -no-shutdown -d guest_errors,cpu_reset -machine virt -cpu cortex-a57 -m 256M) ;;
  riscv64) QEMU_BIN=qemu-system-riscv64; QEMU_ARGS=(-serial stdio -no-reboot -no-shutdown -d guest_errors,cpu_reset -machine virt -cpu rv64 -m 256M) ;;
  x86_64) QEMU_BIN=qemu-system-x86_64; QEMU_ARGS=(-serial stdio -no-reboot -no-shutdown -d guest_errors,cpu_reset -machine q35 -cpu qemu64,+xsave,+avx -m 256M) ;;
esac

case "$ARCH:$BOOT" in
  aarch64:uefi)
    QEMU_ARGS+=(-drive "if=pflash,unit=0,format=raw,file=${FW_CODE},readonly=on" -drive "if=pflash,unit=1,format=raw,file=${FW_VARS}" -drive "file=fat:rw:${ESP_ROOT},format=raw,if=virtio")
    ;;
  riscv64:uefi)
    if [[ "$FW_KIND" == "edk2" ]]; then
      QEMU_ARGS+=(-drive "if=pflash,unit=0,format=raw,file=${FW_CODE},readonly=on" -drive "if=pflash,unit=1,format=raw,file=${FW_VARS}" -drive "file=fat:rw:${ESP_ROOT},format=raw,if=virtio")
    else
      QEMU_ARGS+=(-bios "$FW_CODE" -drive "file=fat:rw:${ESP_ROOT},format=raw,if=virtio")
    fi
    ;;
  aarch64:baremetal) QEMU_ARGS+=(-kernel "$KERNEL_ELF") ;;
  riscv64:sbi) QEMU_ARGS+=(-bios default -kernel "$KERNEL_ELF") ;;
  x86_64:uefi) QEMU_ARGS+=(-drive "if=pflash,format=raw,readonly=on,file=${FW_CODE}" -drive "if=pflash,format=raw,file=${FW_VARS}" -drive "if=virtio,format=raw,file=fat:rw:${ESP_ROOT},label=ESP") ;;
esac

cleanup() {
  rm -rf "${KMTEST_STAGE:-}" "${SMOKE_STAGE:-}"
  rm -f "${KMTEST_CPIO:-}" "${SMOKE_CPIO:-}" "${LOG_FILE:-}"
}
trap cleanup EXIT

if [[ "$TEST_MODE" -eq 1 ]]; then
  echo "[*] Building kmtest userspace runner (${ARCH})..."
  (cd "${ROOT_DIR}/userspace" && make ARCH="${ARCH}" kmtest)
  KMTEST_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/rustos-kmtest-${ARCH}.XXXXXX")"
  KMTEST_CPIO="$(mktemp "${TMPDIR:-/tmp}/rustos-kmtest-${ARCH}.XXXXXX.cpio")"
  mkdir -p "$KMTEST_STAGE/bin"
  cp "${ROOT_DIR}/userspace/build/${ARCH}/kmtest" "$KMTEST_STAGE/bin/kmtest"
  (cd "$KMTEST_STAGE" && find . | sort | cpio -o -H newc --quiet > "$KMTEST_CPIO")
  QEMU_ARGS+=(-initrd "$KMTEST_CPIO" -append "init=/bin/kmtest")
fi

if [[ "$SMOKE_MODE" -eq 1 ]]; then
  echo "[*] Building smoke userspace runner (${ARCH})..."
  (cd "${ROOT_DIR}/userspace" && make ARCH="${ARCH}" smoke)
  SMOKE_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/rustos-smoke-${ARCH}.XXXXXX")"
  SMOKE_CPIO="$(mktemp "${TMPDIR:-/tmp}/rustos-smoke-${ARCH}.XXXXXX.cpio")"
  mkdir -p "$SMOKE_STAGE/bin"
  cp "${ROOT_DIR}/userspace/build/${ARCH}/smoke" "$SMOKE_STAGE/bin/smoke"
  (cd "$SMOKE_STAGE" && find . | sort | cpio -o -H newc --quiet > "$SMOKE_CPIO")
  QEMU_ARGS+=(-initrd "$SMOKE_CPIO" -append "init=/bin/smoke")
fi

if [[ "$NET_MODE" -eq 1 ]]; then
  if [[ "$ARCH" == "x86_64" ]]; then NIC_DEVICE=virtio-net-pci; else NIC_DEVICE=virtio-net-device; fi
  QEMU_ARGS+=(-netdev "user,id=net0,net=10.0.2.0/24,host=10.0.2.2,dns=10.0.2.3,dhcpstart=10.0.2.15" -device "${NIC_DEVICE},netdev=net0,id=nic0")
fi

if [[ "$GPU_MODE" -eq 1 ]]; then
  QEMU_ARGS+=(-device virtio-gpu-pci -display sdl,gl=off)
else
  QEMU_ARGS+=(-display none)
fi

if [[ -n "$DISK" ]]; then
  if [[ "$ARCH" == "x86_64" ]]; then DISK_DEVICE=virtio-blk-pci; else DISK_DEVICE=virtio-blk-device; fi
  QEMU_ARGS+=(-drive "id=vblk0,file=${DISK},format=raw,if=none" -device "${DISK_DEVICE},drive=vblk0,id=virtblk0")
fi

if [[ "$GDB_MODE" -eq 1 ]]; then
  QEMU_ARGS+=(-gdb tcp::1234 -S)
  echo "[*] GDB: target remote :1234, symbols: ${KERNEL_ELF}"
fi

if [[ "$SMOKE_MODE" -eq 1 || "$TEST_MODE" -eq 1 ]]; then
  LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/rustos-${ARCH}.XXXXXX.log")"
  set +e
  timeout "$TIMEOUT_SECS" "$QEMU_BIN" "${QEMU_ARGS[@]}" >"$LOG_FILE" 2>&1
  QEMU_STATUS=$?
  set -e
  cat "$LOG_FILE"
  if [[ "$SMOKE_MODE" -eq 1 ]]; then
    grep -Fq "$SMOKE_MARKER" "$LOG_FILE" && { echo "[✓] Smoke marker found."; exit 0; }
    echo "[!] Smoke marker not found before timeout." >&2
    [[ "$QEMU_STATUS" -ne 124 ]] && echo "[!] QEMU exited with status ${QEMU_STATUS}" >&2
    exit 1
  fi
  grep '^  \(PASS\|FAIL\)' "$LOG_FILE" || true
  SUMMARY="$(grep '^kmtest: .* passed' "$LOG_FILE" || true)"
  echo "${SUMMARY:-[!] no summary line found}"
  if echo "$SUMMARY" | grep -qE '^kmtest: ([0-9]+)/\1 passed'; then
    echo "[✓] All ${ARCH} kmtests passed."
    exit 0
  fi
  grep -q '^  FAIL ' "$LOG_FILE" && exit 1
  exit 2
fi

echo "[*] Starting ${QEMU_BIN} (${ARCH}, ${BOOT}, ${PROFILE}, firmware=${FW_KIND:-none})..."
exec "$QEMU_BIN" "${QEMU_ARGS[@]}"
