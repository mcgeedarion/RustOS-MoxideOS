/* tests/sched_cfs_fairness.c
 *
 * Stress: SCHED_NORMAL (CFS) fairness.
 *
 * N threads at equal nice level run for RUN_SEC seconds. Every thread's
 * iteration count must fall within ±30% of the mean. Validates
 * min_vruntime lag-capping in RunQueue::enqueue (src/proc/scheduler.rs).
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <time.h>
#include <sched.h>
#include <stdio.h>
#include "test_helpers.h"

#define N       8
#define RUN_SEC 2

static atomic_long counters[N];
static atomic_int  go = 0;

static void *runner(void *arg) {
    int id = (int)(long)arg;
    while (!atomic_load(&go))
        sched_yield();

    struct timespec dl, now;
    clock_gettime(CLOCK_MONOTONIC, &dl);
    dl.tv_sec += RUN_SEC;

    do {
        atomic_fetch_add(&counters[id], 1);
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (now.tv_sec < dl.tv_sec ||
             (now.tv_sec == dl.tv_sec && now.tv_nsec < dl.tv_nsec));
    return NULL;
}

int main(void) {
    pthread_t t[N];
    for (int i = 0; i < N; i++)
        pthread_create(&t[i], NULL, runner, (void *)(long)i);

    atomic_store(&go, 1);
    for (int i = 0; i < N; i++)
        pthread_join(t[i], NULL);

    long total = 0;
    long mn = atomic_load(&counters[0]);
    long mx = mn;
    for (int i = 0; i < N; i++) {
        long v = atomic_load(&counters[i]);
        total += v;
        if (v < mn) mn = v;
        if (v > mx) mx = v;
    }
    double mean = (double)total / N;

    if ((double)mn < mean * 0.70 || (double)mx > mean * 1.30)
        TEST_FAILF("min=%ld max=%ld mean=%.0f window=[%.0f,%.0f]",
                   mn, mx, mean, mean * 0.70, mean * 1.30);

    TEST_PASS();
}
