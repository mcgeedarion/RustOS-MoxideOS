#!/usr/bin/env bash
# tests/run_tests.sh
#
# Build and run the full concurrent stress test suite against rustos.
# Requires musl-gcc (or override: MUSL_GCC=/path/to/musl-gcc).
#
# Usage:
#   ./tests/run_tests.sh
#
# Each test binary is compiled with musl-gcc -static and executed directly
# (on Linux host for build verification) or dropped into the kernel image
# initramfs and run via exec for full kernel integration testing.

set -euo pipefail

CC=${MUSL_GCC:-musl-gcc}
CFLAGS="-static -O1 -Wall -Wextra -Wno-unused-parameter"
BUILD_DIR="./build_tests"
mkdir -p "$BUILD_DIR"

PASS=0
FAIL=0
SKIP=0

run_test() {
    local name="$1"
    local src="$2"
    local bin="$BUILD_DIR/$name"

    printf 'Building %-30s ... ' "$name"
    if ! $CC $CFLAGS -o "$bin" "$src" -lpthread -lrt 2>"$BUILD_DIR/$name.log"; then
        echo 'BUILD FAIL'
        sed 's/^/    /' "$BUILD_DIR/$name.log"
        FAIL=$((FAIL + 1))
        return
    fi
    echo 'ok'

    printf 'Running  %-30s ... ' "$name"
    # Capture stdout for PASS/SKIP/FAIL detection; suppress on first run.
    output=$("$bin" 2>/dev/null)
    exit_code=$?

    case "$output" in
        *PASS*) echo "PASS"; PASS=$((PASS + 1)) ;;
        *SKIP*) echo "SKIP"; SKIP=$((SKIP + 1)) ;;
        *)
            echo "FAIL (exit=$exit_code)"
            # Rerun with both stdout+stderr visible so the 'detail:' line
            # written to stderr by test_helpers.h appears in CI logs.
            "$bin" 2>&1 || true
            FAIL=$((FAIL + 1))
            ;;
    esac
}

echo "=== rustos concurrent stress tests ==="
echo

# --- Futex ---
run_test futex_thundering_herd  tests/futex_thundering_herd.c
run_test futex_cmp_requeue      tests/futex_cmp_requeue.c
run_test futex_robust_death     tests/futex_robust_death.c

# --- Scheduler ---
run_test sched_rr_fairness      tests/sched_rr_fairness.c
run_test sched_cfs_fairness     tests/sched_cfs_fairness.c
run_test sched_deadline_cbs     tests/sched_deadline_cbs.c

# --- IPC / IO ---
run_test pipe_stress            tests/pipe_stress.c
run_test poll_close_race        tests/poll_close_race.c
run_test epoll_basic            tests/epoll_basic.c

# --- Process / Signal ---
run_test fork_exec_wait         tests/fork_exec_wait.c
run_test signal_restart         tests/signal_restart.c

# --- Memory ---
run_test mmap_cow_fork          tests/mmap_cow_fork.c

# --- Threads ---
run_test pthread_test           tests/pthread_test.c
run_test pthread_barrier        tests/pthread_barrier.c

# --- VFS ---
run_test vfs_concurrent_creat   tests/vfs_concurrent_creat.c
run_test vfs_rename_unlink      tests/vfs_rename_unlink.c

echo
echo "Results: $PASS passed  $SKIP skipped  $FAIL failed"
echo

[ "$FAIL" -eq 0 ]
