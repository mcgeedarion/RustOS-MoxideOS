#!/usr/bin/env bash
# scripts/ci/collect-logs.sh — Validate serial log and run arch-specific tests.
#
# Called after qemu-run.sh has written logs/ARCH/serial.log.
#
# Required env:
#   ARCH    x86_64 | aarch64 | riscv64
#
# Optional env:
#   LOG_DIR    directory containing serial.log (default: logs/ARCH)
#   OUT_DIR    artifact output directory       (default: artifacts/ARCH)
#   SKIP_ARCH_TESTS  1 => only check shared markers, skip arch test binaries
#
# Exit codes:
#   0  all markers found, all arch tests passed
#   1  one or more checks failed
#   2  bad arguments or missing log

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ARCH="${ARCH:-}"
[[ -z "$ARCH" ]] && { echo "[!] ARCH is required" >&2; exit 2; }

case "$ARCH" in
  x86_64|aarch64|riscv64) ;;
  *) echo "[!] Unsupported ARCH='${ARCH}'" >&2; exit 2 ;;
esac

LOG_DIR="${LOG_DIR:-${ROOT_DIR}/logs/${ARCH}}"
OUT_DIR="${OUT_DIR:-${ROOT_DIR}/artifacts/${ARCH}}"
SKIP_ARCH_TESTS="${SKIP_ARCH_TESTS:-0}"

mkdir -p "$OUT_DIR"

SERIAL_LOG="${LOG_DIR}/serial.log"
if [[ ! -f "$SERIAL_LOG" ]]; then
  echo "[!] Serial log not found: ${SERIAL_LOG}" >&2
  exit 2
fi

PASS=0
FAIL=0
REPORT="${OUT_DIR}/test-report.txt"
: > "$REPORT"

check_marker() {
  local marker="$1"
  if grep -Fq "$marker" "$SERIAL_LOG"; then
    echo "  PASS  marker: ${marker}"
    echo "PASS marker:${marker}" >> "$REPORT"
    (( PASS++ )) || true
  else
    echo "  FAIL  marker: ${marker}" >&2
    echo "FAIL marker:${marker}" >> "$REPORT"
    (( FAIL++ )) || true
  fi
}

# ── Shared markers (emitted by arch-independent kernel paths) ───────────────

echo "[collect] Checking shared markers (${ARCH})..."
check_marker "BOOT_OK"
check_marker "MM_INIT_OK"
check_marker "IRQ_INIT_OK"
check_marker "PLATFORM_OK"

# ── Arch-specific markers ───────────────────────────────────────────────────

echo "[collect] Checking arch-specific markers (${ARCH})..."
case "$ARCH" in
  x86_64)
    check_marker "GDT_OK"
    check_marker "IDT_OK"
    check_marker "APIC_OK"
    check_marker "SYSCALL_OK"
    check_marker "VMM_OK"
    check_marker "HPET_OK"
    check_marker "ACPI_OK"
    ;;
  aarch64)
    check_marker "MAIR_OK"
    check_marker "TTBR_OK"
    check_marker "VBAR_OK"
    check_marker "SGI_OK"
    check_marker "SVC_OK"
    check_marker "PSCI_OK"
    check_marker "FDT_OK"
    ;;
  riscv64)
    check_marker "SATP_OK"
    check_marker "STVEC_OK"
    check_marker "SBI_OK"
    check_marker "SOFT_IRQ_OK"
    check_marker "ECALL_OK"
    check_marker "CLINT_OK"
    check_marker "FDT_OK"
    ;;
esac

# ── Compile and run arch test binaries ─────────────────────────────────────

if [[ "$SKIP_ARCH_TESTS" != "1" ]]; then
  ARCH_TEST_DIR="${ROOT_DIR}/tests/arch/${ARCH}"
  echo "[collect] Running arch test binaries (${ARCH})..."

  for category in boot mm irq platform; do
    TEST_SRC="${ARCH_TEST_DIR}/${category}/${category}_test.c"
    if [[ ! -f "$TEST_SRC" ]]; then
      echo "  SKIP  ${category}_test (no source at ${TEST_SRC})"
      continue
    fi

    TEST_BIN="${OUT_DIR}/${category}_test"
    cc -O0 -std=c11 \
      -I"${ROOT_DIR}/tests/shared" \
      "$TEST_SRC" \
      -o "$TEST_BIN"

    set +e
    "$TEST_BIN" "$SERIAL_LOG"
    RC=$?
    set -e

    if [[ $RC -eq 0 ]]; then
      echo "  PASS  ${category}_test"
      echo "PASS arch:${ARCH}:${category}" >> "$REPORT"
      (( PASS++ )) || true
    elif [[ $RC -eq 77 ]]; then
      echo "  SKIP  ${category}_test (TEST_SKIP)"
      echo "SKIP arch:${ARCH}:${category}" >> "$REPORT"
    else
      echo "  FAIL  ${category}_test (exit ${RC})" >&2
      echo "FAIL arch:${ARCH}:${category}" >> "$REPORT"
      (( FAIL++ )) || true
    fi
  done
fi

# ── Copy serial log into artifact dir ──────────────────────────────────────

cp "$SERIAL_LOG" "${OUT_DIR}/serial.log"

# ── Summary ─────────────────────────────────────────────────────────────────

TOTAL=$(( PASS + FAIL ))
echo
echo "[collect] ${ARCH}: ${PASS}/${TOTAL} passed, ${FAIL} failed"
echo "SUMMARY arch:${ARCH} pass:${PASS} fail:${FAIL} total:${TOTAL}" >> "$REPORT"

if [[ $FAIL -gt 0 ]]; then
  echo "[!] ${FAIL} check(s) failed on ${ARCH}" >&2
  exit 1
fi

echo "[collect] All checks passed for ${ARCH}."
