/* tests/sched_deadline_cbs.c
 *
 * Stress test: SCHED_DEADLINE CBS budget exhaustion and replenishment.
 *
 * Sets up a deadline task with runtime=5ms, deadline=period=10ms.
 * After burning 5ms of budget the thread yields; it must be rescheduled
 * at the next 10ms period boundary. Over 5 periods, at least 4 must show
 * correct replenishment timing. Targets tick() CBS logic in
 * src/proc/scheduler.rs.
 *
 * Falls back to SKIP if sched_setattr (NR 314) is not wired.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>

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
        .sched_runtime  = 5000000ULL,   /* 5 ms  */
        .sched_deadline = 10000000ULL,  /* 10 ms */
        .sched_period   = 10000000ULL,  /* 10 ms */
    };

    if (syscall(314, 0, &attr, 0) != 0) {
        write(1, "SCHED_DL SKIP\n", 14);
        return 0;
    }

    int periods_ok = 0;
    uint64_t start = now_ns();

    for (int rep = 0; rep < 5; rep++) {
        /* Burn ~5ms of CPU budget */
        uint64_t burst_end = now_ns() + 5000000ULL;
        while (now_ns() < burst_end) {}

        sched_yield(); /* CBS should park us until next period */

        uint64_t elapsed = now_ns() - start;
        /* Expect at least 80% of (rep+1) * 10ms elapsed */
        uint64_t min_expected = (uint64_t)(rep + 1) * 8000000ULL;
        if (elapsed >= min_expected)
            periods_ok++;
    }

    if (periods_ok >= 4) {
        write(1, "SCHED_DL PASS\n", 14);
        return 0;
    }
    dprintf(2, "SCHED_DL FAIL: only %d/5 periods showed correct replenishment\n",
            periods_ok);
    return 1;
#else
    write(1, "SCHED_DL SKIP (SCHED_DEADLINE not defined)\n", 43);
    return 0;
#endif
}
