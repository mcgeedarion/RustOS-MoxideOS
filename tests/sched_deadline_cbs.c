/* tests/sched_deadline_cbs.c
 *
 * Stress: SCHED_DEADLINE CBS budget exhaustion and replenishment.
 *
 * Sets runtime=5ms, deadline=period=10ms. After burning 5ms of budget
 * the thread yields; it must be rescheduled at the next 10ms boundary.
 * Over 5 periods at least 4 must show correct replenishment timing.
 * Skips if sched_setattr (NR 314) is not wired.
 * Targets tick() CBS logic (src/proc/scheduler.rs).
 */
#define _GNU_SOURCE
#include <sched.h>
#include <time.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <stdio.h>
#include "test_helpers.h"

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#ifdef SCHED_DEADLINE
struct sched_attr {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t  sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
};
#endif

int main(void) {
#ifdef SCHED_DEADLINE
    struct sched_attr attr = {
        .size           = sizeof(attr),
        .sched_policy   = SCHED_DEADLINE,
        .sched_runtime  = 5000000ULL,  /* 5 ms */
        .sched_deadline = 10000000ULL, /* 10 ms */
        .sched_period   = 10000000ULL, /* 10 ms */
    };

    if (syscall(314, 0, &attr, 0) != 0)
        TEST_SKIP("sched_setattr (NR 314) not wired");

    int      ok    = 0;
    uint64_t start = now_ns();

    for (int rep = 0; rep < 5; rep++) {
        uint64_t burst_end = now_ns() + 5000000ULL;
        while (now_ns() < burst_end) {}
        sched_yield();
        if (now_ns() - start >= (uint64_t)(rep + 1) * 8000000ULL)
            ok++;
    }

    if (ok < 4)
        TEST_FAILF("%d/5 periods showed correct replenishment (need 4)", ok);

    TEST_PASS();
#else
    TEST_SKIP("SCHED_DEADLINE not defined in headers");
#endif
}
