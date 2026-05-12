/* tests/sched_cfs_fairness.c
 *
 * Stress test: SCHED_NORMAL (CFS) fairness.
 *
 * N threads at the same nice level run for RUN_SEC seconds. All threads
 * must fall within ±30% of the mean iteration count. Validates the
 * min_vruntime lag-capping in RunQueue::enqueue (src/proc/scheduler.rs).
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>

#define N       8
#define RUN_SEC 2

static atomic_long counters[N];
static atomic_int  go = 0;

static void *runner(void *arg) {
    int id = (int)(long)arg;
    while (!atomic_load(&go)) sched_yield();

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += RUN_SEC;

    struct timespec now;
    do {
        atomic_fetch_add(&counters[id], 1);
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (now.tv_sec < deadline.tv_sec ||
             (now.tv_sec == deadline.tv_sec &&
              now.tv_nsec < deadline.tv_nsec));
    return NULL;
}

int main(void) {
    pthread_t t[N];
    for (int i = 0; i < N; i++)
        pthread_create(&t[i], NULL, runner, (void*)(long)i);

    atomic_store(&go, 1);
    for (int i = 0; i < N; i++) pthread_join(t[i], NULL);

    long total = 0, mn, mx;
    mn = mx = atomic_load(&counters[0]);
    for (int i = 0; i < N; i++) {
        long v = atomic_load(&counters[i]);
        total += v;
        if (v < mn) mn = v;
        if (v > mx) mx = v;
    }
    double mean = (double)total / N;
    double lo   = mean * 0.70;
    double hi   = mean * 1.30;

    if ((double)mn >= lo && (double)mx <= hi) {
        puts("PASS");
        return 0;
    }
    dprintf(2, "SCHED_CFS FAIL: min=%ld max=%ld mean=%.0f window=[%.0f,%.0f]\n",
            mn, mx, mean, lo, hi);
    return 1;
}
