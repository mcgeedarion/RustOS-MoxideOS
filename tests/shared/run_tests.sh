#!/usr/bin/env bash
# tests/shared/run_tests.sh
#
# Build and run the full concurrent stress test suite against rustos.
#
# Usage:
#   ARCH=<arch> ./tests/shared/run_tests.sh
#
#   arch values: x86_64 | aarch64 | riscv64
#   (defaults to x86_64 if ARCH is unset)
#
# Cross-compiler selection (overridable via env):
#   x86_64   MUSL_GCC   musl-gcc
#   aarch64  CC_AARCH64 aarch64-linux-gnu-gcc  -static-pie or musl cross
#   riscv64  CC_RISCV64 riscv64-linux-gnu-gcc
#
# Each test binary is compiled and executed on the host for fast build
# verification, then the same binaries are dropped into the kernel
# initramfs for full integration testing under QEMU.
#
# Build artefacts land under build_tests/<arch>/ so outputs for different
# architectures never collide in parallel CI runs.

set -euo pipefail

ARCH="${ARCH:-x86_64}"

case "$ARCH" in
  x86_64|aarch64|riscv64) ;;
  *) echo "[!] Unsupported ARCH='${ARCH}'. Use: x86_64 aarch64 riscv64" >&2; exit 2 ;;
esac

# ── Compiler selection ────────────────────────────────────────────────────

case "$ARCH" in
  x86_64)
    CC="${MUSL_GCC:-musl-gcc}"
    CFLAGS_EXTRA=""
    ;;
  aarch64)
    CC="${CC_AARCH64:-aarch64-linux-gnu-gcc}"
    CFLAGS_EXTRA="--sysroot=/usr/aarch64-linux-gnu -static"
    ;;
  riscv64)
    CC="${CC_RISCV64:-riscv64-linux-gnu-gcc}"
    CFLAGS_EXTRA="--sysroot=/usr/riscv64-linux-gnu -static"
    ;;
esac

CFLAGS="-static -O1 -Wall -Wextra -Wno-unused-parameter ${CFLAGS_EXTRA}"

if ! command -v "$CC" >/dev/null 2>&1; then
  echo "[!] Compiler not found: ${CC}" >&2
  echo "    Set CC_${ARCH^^} or install the cross-toolchain." >&2
  exit 1
fi

# ── Paths ─────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/../../build_tests/${ARCH}"
mkdir -p "$BUILD_DIR"

PASS=0
FAIL=0
SKIP=0

# ── Test runner ───────────────────────────────────────────────────────────

run_test() {
    local name="$1"
    local src="$2"
    local bin="${BUILD_DIR}/${name}"
    local output=""
    local exit_code=0

    printf 'Building %-30s ... ' "$name"
    if ! $CC $CFLAGS -o "$bin" "$src" -lpthread -lrt \
           2>"${BUILD_DIR}/${name}.log"; then
        echo 'BUILD FAIL'
        sed 's/^/    /' "${BUILD_DIR}/${name}.log"
        FAIL=$((FAIL + 1))
        return
    fi
    echo 'ok'

    # Skip execution when cross-compiling for a non-native arch.
    if [[ "$ARCH" != "$(uname -m | sed 's/aarch64/aarch64/;s/x86_64/x86_64/;s/riscv64/riscv64/')" ]]; then
        echo "  (cross-build only — skipping host execution for ${ARCH})"
        SKIP=$((SKIP + 1))
        return
    fi

    printf 'Running  %-30s ... ' "$name"
    set +e
    output=$("$bin" 2>/dev/null)
    exit_code=$?
    set -e

    case "$output" in
        *PASS*)
            if [[ "$exit_code" -eq 0 ]]; then
                echo "PASS"
                PASS=$((PASS + 1))
            else
                echo "FAIL (exit=${exit_code}, emitted PASS)"
                "$bin" 2>&1 || true
                FAIL=$((FAIL + 1))
            fi
            ;;
        *SKIP*) echo "SKIP"; SKIP=$((SKIP + 1)) ;;
        *)
            echo "FAIL (exit=${exit_code})"
            "$bin" 2>&1 || true
            FAIL=$((FAIL + 1))
            ;;
    esac
}

echo "=== rustos shared tests [${ARCH}] ==="
echo

# ── Test list (shared — all architectures) ────────────────────────────────
# These tests exercise syscall-level behaviour that must work identically
# on x86_64, AArch64, and RISC-V.  The source lives in tests/shared/.
# Arch-specific tests live in tests/arch/<arch>/ and are not run here.

SHARED="${SCRIPT_DIR}"

# --- Futex ---
run_test futex_thundering_herd  "${SHARED}/futex_thundering_herd.c"
run_test futex_cmp_requeue      "${SHARED}/futex_cmp_requeue.c"
run_test futex_robust_death     "${SHARED}/futex_robust_death.c"

# --- Scheduler ---
run_test sched_rr_fairness      "${SHARED}/sched_rr_fairness.c"
run_test sched_cfs_fairness     "${SHARED}/sched_cfs_fairness.c"
run_test sched_deadline_cbs     "${SHARED}/sched_deadline_cbs.c"

# --- IPC / IO ---
run_test pipe_stress            "${SHARED}/pipe_stress.c"
run_test poll_close_race        "${SHARED}/poll_close_race.c"
run_test epoll_basic            "${SHARED}/epoll_basic.c"

# --- Process / Signal ---
run_test fork_exec_wait         "${SHARED}/fork_exec_wait.c"
run_test signal_restart         "${SHARED}/signal_restart.c"

# --- Memory ---
run_test mmap_cow_fork          "${SHARED}/mmap_cow_fork.c"

# --- Threads ---
run_test pthread_test           "${SHARED}/pthread_test.c"
run_test pthread_barrier        "${SHARED}/pthread_barrier.c"

# --- VFS ---
run_test vfs_concurrent_creat   "${SHARED}/vfs_concurrent_creat.c"
run_test vfs_rename_unlink      "${SHARED}/vfs_rename_unlink.c"

echo
echo "Results [${ARCH}]: ${PASS} passed  ${SKIP} skipped  ${FAIL} failed"
echo

[ "$FAIL" -eq 0 ]
