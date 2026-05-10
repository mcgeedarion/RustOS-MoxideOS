#!/bin/sh
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

set -e

CC=${MUSL_GCC:-musl-gcc}
CFLAGS="-static -O1 -Wall -Wextra -Wno-unused-parameter"
BUILD_DIR="./build_tests"
mkdir -p "$BUILD_DIR"

PASS=0
FAIL=0
SKIP=0

run_test() {
    name="$1"
    src="$2"
    bin="$BUILD_DIR/$name"

    printf 'Building %-30s ... ' "$name"
    if ! $CC $CFLAGS -o "$bin" "$src" -lpthread -lrt 2>"$BUILD_DIR/$name.log"; then
        echo 'BUILD FAIL'
        cat "$BUILD_DIR/$name.log" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        return
    fi
    echo 'ok'

    printf 'Running  %-30s ... ' "$name"
    output=$("$bin" 2>/dev/null)
    exit_code=$?

    case "$output" in
        *PASS*) echo "PASS"; PASS=$((PASS + 1)) ;;
        *SKIP*) echo "SKIP"; SKIP=$((SKIP + 1)) ;;
        *)
            echo "FAIL (exit=$exit_code)"
            "$bin" || true  # rerun to capture stderr
            FAIL=$((FAIL + 1))
            ;;
    esac
}

echo "=== rustos concurrent stress tests ==="
echo

run_test futex_thundering_herd  tests/futex_thundering_herd.c
run_test futex_cmp_requeue      tests/futex_cmp_requeue.c
run_test futex_robust_death     tests/futex_robust_death.c
run_test sched_rr_fairness      tests/sched_rr_fairness.c
run_test sched_cfs_fairness     tests/sched_cfs_fairness.c
run_test sched_deadline_cbs     tests/sched_deadline_cbs.c
run_test pipe_stress            tests/pipe_stress.c
run_test vfs_concurrent_creat   tests/vfs_concurrent_creat.c
run_test poll_close_race        tests/poll_close_race.c

echo
echo "Results: $PASS passed  $SKIP skipped  $FAIL failed"
echo

[ "$FAIL" -eq 0 ]
