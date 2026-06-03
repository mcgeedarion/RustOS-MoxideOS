/* tests/shared/sched_deadline_cbs.c
 *
 * Smoke: SCHED_DEADLINE CBS admission and execution.
 */
#define _GNU_SOURCE
#include <sched.h>
#include <pthread.h>
#include <time.h>
#include <stdatomic.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include "test_helpers.h"

#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

struct sched_attr {
    __u32 size;
    __u32 sched_policy;
    __u64 sched_flags;
    __s32 sched_nice;
    __u32 sched_priority;
    __u64 sched_runtime;
    __u64 sched_deadline;
    __u64 sched_period;
};

#include <sys/syscall.h>
static int sched_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags) {
    return (int)syscall(314, pid, attr, flags);
}

static atomic_int finished = 0;

static void *dl_thread(void *arg) {
    (void)arg;
    struct sched_attr attr = {
        .size           = sizeof(attr),
        .sched_policy   = SCHED_DEADLINE,
        .sched_runtime  = 10 * 1000000ULL,
        .sched_deadline = 20 * 1000000ULL,
        .sched_period   = 20 * 1000000ULL,
    };
    int r = sched_setattr(0, &attr, 0);
    if (r < 0) { atomic_store(&finished, 2); return NULL; }
    volatile long x = 0;
    for (long i = 0; i < 5000000L; i++) x += i;
    (void)x;
    atomic_store(&finished, 1);
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, dl_thread, NULL);
    pthread_join(t, NULL);
    int f = atomic_load(&finished);
    if (f == 2) TEST_SKIP("SCHED_DEADLINE not available");
    if (f != 1) TEST_FAIL("deadline thread did not finish");
    TEST_PASS();
}
